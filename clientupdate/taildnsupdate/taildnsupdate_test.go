// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildnsupdate

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyManifestOrderingAndSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		SchemaVersion:   1,
		Product:         "TailDNS",
		UpstreamVersion: "1.103.0",
		Sequence:        6,
		Platform:        "windows",
		Arch:            "amd64",
		CoreCommit:      strings.Repeat("a", 40),
		Files:           requiredFilesForTest(),
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, raw)
	key := base64.StdEncoding.EncodeToString(pub)
	sigText := []byte(base64.StdEncoding.EncodeToString(sig))

	got, err := VerifyManifest(raw, sigText, key, "1.103.0-taildns.5")
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 6 {
		t.Fatalf("sequence = %d, want 6", got.Sequence)
	}

	for name, mutate := range map[string]func([]byte, []byte) (string, string){
		"bad signature": func(raw, sig []byte) (string, string) {
			return string(raw), base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		"replay": func(raw, sig []byte) (string, string) {
			var replay Manifest
			if err := json.Unmarshal(raw, &replay); err != nil {
				t.Fatal(err)
			}
			replay.Sequence = 5
			changed, err := json.Marshal(replay)
			if err != nil {
				t.Fatal(err)
			}
			return string(changed), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, changed))
		},
		"wrong arch": func(raw, sig []byte) (string, string) {
			var wrong Manifest
			if err := json.Unmarshal(raw, &wrong); err != nil {
				t.Fatal(err)
			}
			wrong.Arch = "arm64"
			changed, err := json.Marshal(wrong)
			if err != nil {
				t.Fatal(err)
			}
			return string(changed), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, changed))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, changedSig := mutate(raw, sig)
			if _, err := VerifyManifest([]byte(changed), []byte(changedSig), key, "1.103.0-taildns.5"); err == nil {
				t.Fatal("VerifyManifest succeeded, want error")
			}
		})
	}
}

func requiredFilesForTest() []File {
	names := []string{"taildnsd.exe", "tailscale.exe", "taildns.exe", "taildns-ipn.exe", "taildns-installer.exe"}
	files := make([]File, 0, len(names))
	for _, name := range names {
		files = append(files, File{Name: name, SHA256: strings.Repeat("1", 64), Size: 1})
	}
	return files
}

func TestCompareBaseVersion(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want int
	}{
		{"1.103.0", "1.103.0", 0},
		{"1.103.1", "1.103.0", 1},
		{"1.104.0", "1.103.99", 1},
		{"1.102.9", "1.103.0", -1},
	} {
		got, err := compareBaseVersion(tt.a, tt.b)
		if err != nil || got != tt.want {
			t.Fatalf("compareBaseVersion(%q, %q) = %d, %v; want %d", tt.a, tt.b, got, err, tt.want)
		}
	}
}

func TestExtractVerifiedRejectsHashMismatch(t *testing.T) {
	contents := []byte("expected")
	sum := sha256.Sum256(contents)
	manifest := Manifest{Files: []File{{Name: "taildnsd.exe", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(contents))}}}
	makeZip := func(data []byte) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create("taildnsd.exe")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	if err := extractVerified(makeZip(contents), t.TempDir(), manifest); err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
	if err := extractVerified(makeZip([]byte("tampered")), t.TempDir(), manifest); err == nil {
		t.Fatal("hash-mismatched archive accepted")
	}
}
