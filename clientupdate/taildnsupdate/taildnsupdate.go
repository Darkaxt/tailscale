// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package taildnsupdate verifies TailDNS Windows update manifests.
package taildnsupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

var updatePublicKeyBase64 string

type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Product         string `json:"product"`
	UpstreamVersion string `json:"upstreamVersion"`
	Sequence        uint64 `json:"sequence"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	CoreCommit      string `json:"coreCommit"`
	Files           []File `json:"files"`
}

var (
	currentRE = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)-taildns\.([1-9][0-9]*)$`)
	baseRE    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	hexRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func PublicKey() string { return updatePublicKeyBase64 }

type githubRelease struct {
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

const maxDownloadSize = 256 << 20

func PrepareLatest(ctx context.Context, client *http.Client, apiURL, destination, currentLong, publicKeyBase64 string) (Manifest, error) {
	if client == nil {
		client = http.DefaultClient
	}
	apiRaw, err := get(ctx, client, apiURL, 4<<20)
	if err != nil {
		return Manifest{}, err
	}
	var release githubRelease
	if err := json.Unmarshal(apiRaw, &release); err != nil {
		return Manifest{}, fmt.Errorf("parsing TailDNS release metadata: %w", err)
	}
	assets := map[string]string{}
	for _, a := range release.Assets {
		assets[a.Name] = a.URL
	}
	for _, name := range []string{"taildns-windows-update.json", "taildns-windows-update.json.sig", "taildns-windows-amd64.zip"} {
		if assets[name] == "" {
			return Manifest{}, fmt.Errorf("TailDNS release is missing %s", name)
		}
	}
	manifestRaw, err := get(ctx, client, assets["taildns-windows-update.json"], 4<<20)
	if err != nil {
		return Manifest{}, err
	}
	signature, err := get(ctx, client, assets["taildns-windows-update.json.sig"], 4<<20)
	if err != nil {
		return Manifest{}, err
	}
	manifest, err := VerifyManifest(manifestRaw, signature, publicKeyBase64, currentLong)
	if err != nil {
		return Manifest{}, err
	}
	archive, err := get(ctx, client, assets["taildns-windows-amd64.zip"], maxDownloadSize)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.RemoveAll(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return Manifest{}, err
	}
	if err := extractVerified(archive, destination, manifest); err != nil {
		os.RemoveAll(destination)
		return Manifest{}, err
	}
	for name, data := range map[string][]byte{
		"taildns-windows-update.json":     manifestRaw,
		"taildns-windows-update.json.sig": signature,
	} {
		if err := os.WriteFile(filepath.Join(destination, name), data, 0o600); err != nil {
			os.RemoveAll(destination)
			return Manifest{}, fmt.Errorf("staging %s: %w", name, err)
		}
	}
	return manifest, nil
}

func get(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "TailDNS-Windows-Updater")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: %s", url, res.Status)
	}
	if res.ContentLength > limit {
		return nil, fmt.Errorf("download %s exceeds size limit", url)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("download %s exceeds size limit", url)
	}
	return raw, nil
}

func extractVerified(archive []byte, destination string, manifest Manifest) error {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("opening TailDNS update archive: %w", err)
	}
	want := map[string]File{}
	for _, file := range manifest.Files {
		want[file.Name] = file
	}
	seen := map[string]bool{}
	for _, zf := range zr.File {
		base := filepath.Base(zf.Name)
		file, ok := want[base]
		if !ok {
			continue
		}
		if seen[base] || zf.FileInfo().Mode()&os.ModeSymlink != 0 || zf.FileInfo().IsDir() {
			return errors.New("invalid TailDNS update archive entry")
		}
		seen[base] = true
		r, err := zf.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(r, file.Size+1))
		closeErr := r.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if int64(len(data)) != file.Size {
			return fmt.Errorf("size mismatch for %s", base)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			return fmt.Errorf("hash mismatch for %s", base)
		}
		if err := os.WriteFile(filepath.Join(destination, base), data, 0o700); err != nil {
			return err
		}
	}
	if len(seen) != len(want) {
		return errors.New("TailDNS update archive is missing required payload files")
	}
	return nil
}

func VerifyManifest(raw, signature []byte, publicKeyBase64, currentLong string) (Manifest, error) {
	var m Manifest
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyBase64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return m, errors.New("invalid TailDNS update public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return m, errors.New("invalid TailDNS update manifest signature")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("invalid TailDNS update manifest: %w", err)
	}
	if m.SchemaVersion != 1 || m.Product != "TailDNS" || m.Platform != "windows" || m.Arch != runtime.GOARCH || !baseRE.MatchString(m.UpstreamVersion) || m.Sequence == 0 || !commitRE.MatchString(m.CoreCommit) {
		return Manifest{}, errors.New("TailDNS update manifest identity does not match this client")
	}
	if err := validateFiles(m.Files); err != nil {
		return Manifest{}, err
	}
	match := currentRE.FindStringSubmatch(currentLong)
	if len(match) != 3 {
		return Manifest{}, fmt.Errorf("current version %q is not a TailDNS release", currentLong)
	}
	currentSequence, _ := strconv.ParseUint(match[2], 10, 64)
	cmp, err := compareBaseVersion(m.UpstreamVersion, match[1])
	if err != nil {
		return Manifest{}, err
	}
	if cmp < 0 || (cmp == 0 && m.Sequence <= currentSequence) {
		return Manifest{}, errors.New("TailDNS update manifest is not newer than the installed release")
	}
	return m, nil
}

func validateFiles(files []File) error {
	want := []string{"taildns-installer.exe", "taildns-ipn.exe", "taildns.exe", "taildnsd.exe", "tailscale.exe"}
	got := make([]string, 0, len(files))
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Name] || f.Size <= 0 || !hexRE.MatchString(f.SHA256) {
			return errors.New("invalid TailDNS update file manifest")
		}
		seen[f.Name] = true
		got = append(got, f.Name)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return errors.New("TailDNS update manifest has an unexpected file set")
	}
	return nil
}

func compareBaseVersion(a, b string) (int, error) {
	parse := func(v string) ([3]uint64, error) {
		var out [3]uint64
		parts := strings.Split(v, ".")
		if len(parts) != 3 {
			return out, fmt.Errorf("invalid version %q", v)
		}
		for i, part := range parts {
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return out, fmt.Errorf("invalid version %q", v)
			}
			out[i] = n
		}
		return out, nil
	}
	av, err := parse(a)
	if err != nil {
		return 0, err
	}
	bv, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, nil
		}
		if av[i] > bv[i] {
			return 1, nil
		}
	}
	return 0, nil
}
