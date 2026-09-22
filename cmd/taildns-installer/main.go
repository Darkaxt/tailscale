// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command taildns-installer transactionally installs a matching TailDNS
// daemon, CLI, resolver, and tray set over an existing Windows installation.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	releaseManifestName  = "taildns-windows-update.json"
	releaseSignatureName = "taildns-windows-update.json.sig"
)

// updatePublicKeyBase64 is populated by the trusted release build. It contains
// only the public Ed25519 update-manifest key.
var updatePublicKeyBase64 string

type releaseFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type releaseManifest struct {
	SchemaVersion   int           `json:"schemaVersion"`
	Product         string        `json:"product"`
	UpstreamVersion string        `json:"upstreamVersion"`
	Sequence        uint64        `json:"sequence"`
	Platform        string        `json:"platform"`
	Arch            string        `json:"arch"`
	CoreCommit      string        `json:"coreCommit"`
	Files           []releaseFile `json:"files"`
}

func (m releaseManifest) version() string {
	return fmt.Sprintf("%s+%d", m.UpstreamVersion, m.Sequence)
}

type machineIdentity struct {
	NodeID         string   `json:"nodeId"`
	TailscaleIPs   []string `json:"tailscaleIPs"`
	TailnetLockKey string   `json:"tailnetLockKey"`
	DNSName        string   `json:"-"`
}

type fileRecord struct {
	Path          string `json:"path"`
	OriginalPath  string `json:"originalPath,omitempty"`
	OriginalHash  string `json:"originalSha256,omitempty"`
	InstalledHash string `json:"installedSha256"`
	Existed       bool   `json:"existed"`
}

type registryValueRecord struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Kind    uint32 `json:"kind,omitempty"`
	Existed bool   `json:"existed"`
}

type startupRecord struct {
	OfficialLink       fileRecord          `json:"officialLink"`
	TailDNSRunValue    registryValueRecord `json:"taildnsRunValue"`
	OfficialGUIRunning bool                `json:"officialGuiRunning"`
}

type deploymentRecord struct {
	SchemaVersion          int                   `json:"schemaVersion"`
	InstalledAtUTC         string                `json:"installedAtUtc"`
	Version                string                `json:"version"`
	UpstreamVersion        string                `json:"upstreamVersion"`
	Sequence               uint64                `json:"sequence"`
	CoreCommit             string                `json:"coreCommit"`
	ServicePath            string                `json:"servicePath"`
	Files                  map[string]fileRecord `json:"files"`
	PreservedComponentHash map[string]string     `json:"preservedComponentSha256"`
	OriginalUpdateCheck    bool                  `json:"originalAutoUpdateCheck"`
	OriginalUpdateApply    bool                  `json:"originalAutoUpdateApply"`
	BaselineIdentity       machineIdentity       `json:"baselineIdentity"`
	Startup                startupRecord         `json:"startup"`
}

type installResult struct {
	Action             string          `json:"action"`
	Version            string          `json:"version,omitempty"`
	ServicePath        string          `json:"servicePath,omitempty"`
	Identity           machineIdentity `json:"identity,omitempty"`
	ResolverConfigured bool            `json:"resolverConfigured,omitempty"`
	RolledBack         bool            `json:"rolledBack,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "TailDNS installer:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("taildns-installer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	action := fs.String("action", "install", "install, rollback, or status")
	payload := fs.String("payload", "", "release payload directory")
	dnsEndpoint := fs.String("dns-endpoint", "", "optional HTTPS DNS endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	payloadDir := *payload
	if payloadDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locating installer: %w", err)
		}
		payloadDir = filepath.Dir(exe)
	}

	var (
		result installResult
		err    error
	)
	switch *action {
	case "install":
		manifest, verifyErr := verifyRelease(payloadDir, updatePublicKeyBase64)
		if verifyErr != nil {
			return verifyErr
		}
		result, err = platformInstall(payloadDir, manifest, *dnsEndpoint)
	case "rollback":
		result, err = platformRollback()
	case "status":
		result, err = platformStatus()
	default:
		return fmt.Errorf("unknown action %q", *action)
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func verifyRelease(dir, publicKeyBase64 string) (releaseManifest, error) {
	var zero releaseManifest
	manifestPath := filepath.Join(dir, releaseManifestName)
	signaturePath := filepath.Join(dir, releaseSignatureName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return zero, fmt.Errorf("reading release manifest: %w", err)
	}
	signatureText, err := os.ReadFile(signaturePath)
	if err != nil {
		return zero, fmt.Errorf("reading release signature: %w", err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyBase64))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return zero, errors.New("installer has no valid TailDNS update public key")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return zero, errors.New("release signature is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), raw, signature) {
		return zero, errors.New("release manifest signature is invalid")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var manifest releaseManifest
	if err := dec.Decode(&manifest); err != nil {
		return zero, fmt.Errorf("parsing release manifest: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return zero, err
	}
	if err := validateManifest(manifest); err != nil {
		return zero, err
	}
	for _, file := range manifest.Files {
		path := filepath.Join(dir, file.Name)
		info, err := os.Stat(path)
		if err != nil {
			return zero, fmt.Errorf("required payload %s: %w", file.Name, err)
		}
		if !info.Mode().IsRegular() || info.Size() != file.Size {
			return zero, fmt.Errorf("payload %s size/type mismatch", file.Name)
		}
		rawFile, err := os.ReadFile(path)
		if err != nil {
			return zero, fmt.Errorf("reading payload %s: %w", file.Name, err)
		}
		hash := sha256.Sum256(rawFile)
		if !strings.EqualFold(hex.EncodeToString(hash[:]), file.SHA256) {
			return zero, fmt.Errorf("payload %s hash mismatch", file.Name)
		}
	}
	return manifest, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("release manifest contains trailing JSON")
		}
		return fmt.Errorf("parsing release manifest trailer: %w", err)
	}
	return nil
}

var (
	upstreamVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	commitRE          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashRE            = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validateManifest(manifest releaseManifest) error {
	if manifest.SchemaVersion != 1 || manifest.Product != "TailDNS" {
		return errors.New("unsupported release manifest identity")
	}
	if !upstreamVersionRE.MatchString(manifest.UpstreamVersion) || manifest.Sequence == 0 {
		return errors.New("release version is malformed")
	}
	if manifest.Platform != "windows" || manifest.Arch != "amd64" {
		return errors.New("release platform is not windows/amd64")
	}
	if !commitRE.MatchString(manifest.CoreCommit) {
		return errors.New("release core commit is malformed")
	}
	required := map[string]bool{
		"taildnsd.exe":          false,
		"tailscale.exe":         false,
		"taildns.exe":           false,
		"taildns-ipn.exe":       false,
		"taildns-installer.exe": false,
	}
	if len(manifest.Files) != len(required) {
		return errors.New("release manifest has an unexpected payload set")
	}
	for _, file := range manifest.Files {
		seen, ok := required[file.Name]
		if !ok || seen || filepath.Base(file.Name) != file.Name {
			return fmt.Errorf("release manifest has invalid payload name %q", file.Name)
		}
		if file.Size <= 0 || !hashRE.MatchString(strings.ToLower(file.SHA256)) {
			return fmt.Errorf("release manifest has invalid metadata for %s", file.Name)
		}
		required[file.Name] = true
	}
	return nil
}

func verifyIdentityContinuity(before, after machineIdentity) error {
	if before.NodeID == "" || before.NodeID != after.NodeID {
		return errors.New("TailDNS activation changed the node ID")
	}
	if before.TailnetLockKey == "" || before.TailnetLockKey != after.TailnetLockKey {
		return errors.New("TailDNS activation changed or lost the Tailnet Lock signing key")
	}
	beforeIPs := append([]string(nil), before.TailscaleIPs...)
	afterIPs := append([]string(nil), after.TailscaleIPs...)
	sort.Strings(beforeIPs)
	sort.Strings(afterIPs)
	if strings.Join(beforeIPs, "\n") != strings.Join(afterIPs, "\n") {
		return errors.New("TailDNS activation changed the tailnet addresses")
	}
	return nil
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func expectedRuntime() error {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("TailDNS installer supports only windows/amd64, running on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return nil
}
