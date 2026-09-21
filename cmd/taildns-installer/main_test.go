// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyReleaseManifest(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"taildnsd.exe":          []byte("daemon"),
		"tailscale.exe":         []byte("cli"),
		"taildns.exe":           []byte("resolver"),
		"taildns-installer.exe": []byte("installer"),
	}
	manifestFiles := make([]releaseFile, 0, len(files))
	for name, contents := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(contents)
		manifestFiles = append(manifestFiles, releaseFile{
			Name:   name,
			SHA256: hex.EncodeToString(hash[:]),
			Size:   int64(len(contents)),
		})
	}
	manifest := releaseManifest{
		SchemaVersion:   1,
		Product:         "TailDNS",
		UpstreamVersion: "1.102.4",
		Sequence:        1,
		Platform:        "windows",
		Arch:            "amd64",
		CoreCommit:      "6e187510953cf63e9c3c2938239e1a6fd4dd751b",
		Files:           manifestFiles,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(private, raw)
	manifestPath := filepath.Join(dir, releaseManifestName)
	signaturePath := filepath.Join(dir, releaseSignatureName)
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := verifyRelease(dir, base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatalf("verifyRelease: %v", err)
	}
	if got.UpstreamVersion != "1.102.4" || got.Sequence != 1 {
		t.Fatalf("verified manifest = %+v", got)
	}

	t.Run("tampered manifest", func(t *testing.T) {
		tampered := append([]byte(nil), raw...)
		tampered[len(tampered)-1] ^= 1
		if err := os.WriteFile(manifestPath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyRelease(dir, base64.StdEncoding.EncodeToString(public)); err == nil {
			t.Fatal("tampered manifest was accepted")
		}
		if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "taildnsd.exe"), []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyRelease(dir, base64.StdEncoding.EncodeToString(public)); err == nil {
			t.Fatal("tampered payload was accepted")
		}
	})
}

func TestValidateManifestRejectsWrongReleaseIdentity(t *testing.T) {
	valid := releaseManifest{
		SchemaVersion:   1,
		Product:         "TailDNS",
		UpstreamVersion: "1.102.4",
		Sequence:        1,
		Platform:        "windows",
		Arch:            "amd64",
		CoreCommit:      "6e187510953cf63e9c3c2938239e1a6fd4dd751b",
		Files: []releaseFile{
			{Name: "taildnsd.exe", SHA256: strings.Repeat("0", 64), Size: 1},
			{Name: "tailscale.exe", SHA256: strings.Repeat("0", 64), Size: 1},
			{Name: "taildns.exe", SHA256: strings.Repeat("0", 64), Size: 1},
			{Name: "taildns-installer.exe", SHA256: strings.Repeat("0", 64), Size: 1},
		},
	}
	if err := validateManifest(valid); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	tests := []struct {
		name string
		edit func(*releaseManifest)
	}{
		{"zero sequence", func(m *releaseManifest) { m.Sequence = 0 }},
		{"manufactured upstream version", func(m *releaseManifest) { m.UpstreamVersion = "1.102.5-taildns" }},
		{"wrong platform", func(m *releaseManifest) { m.Platform = "linux" }},
		{"wrong architecture", func(m *releaseManifest) { m.Arch = "arm64" }},
		{"missing commit", func(m *releaseManifest) { m.CoreCommit = "" }},
		{"missing payload", func(m *releaseManifest) { m.Files = m.Files[:3] }},
		{"extra payload", func(m *releaseManifest) {
			m.Files = append(m.Files, releaseFile{Name: "other.exe", SHA256: strings.Repeat("0", 64), Size: 1})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := valid
			m.Files = append([]releaseFile(nil), valid.Files...)
			tt.edit(&m)
			if err := validateManifest(m); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestIdentityContinuity(t *testing.T) {
	before := machineIdentity{
		NodeID:         "n1",
		TailscaleIPs:   []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
		TailnetLockKey: "tlpub:abc",
	}
	after := machineIdentity{
		NodeID:         "n1",
		TailscaleIPs:   []string{"fd7a:115c:a1e0::1", "100.64.0.1"},
		TailnetLockKey: "tlpub:abc",
	}
	if err := verifyIdentityContinuity(before, after); err != nil {
		t.Fatalf("matching identity rejected: %v", err)
	}
	after.NodeID = "n2"
	if err := verifyIdentityContinuity(before, after); err == nil {
		t.Fatal("changed node ID was accepted")
	}
}

func TestDeploymentRecordDoesNotContainPrivateState(t *testing.T) {
	record := deploymentRecord{
		SchemaVersion: 3,
		Version:       "1.102.4+1",
		ServicePath:   `"C:\Program Files\Tailscale\tailscaled.exe"`,
		BaselineIdentity: machineIdentity{
			NodeID:         "n1",
			TailscaleIPs:   []string{"100.64.0.1"},
			TailnetLockKey: "tlpub:abc",
		},
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PrivateNodeKey", "NetworkLockKey", "server-state", "dns.controld.com"} {
		if containsFold(string(raw), forbidden) {
			t.Fatalf("deployment record contains forbidden value %q: %s", forbidden, raw)
		}
	}
}
