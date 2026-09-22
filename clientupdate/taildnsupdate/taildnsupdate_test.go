// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildnsupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareLatestStagesInstallerVerificationInputs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string][]byte{
		"taildnsd.exe":          []byte("daemon"),
		"tailscale.exe":         []byte("cli"),
		"taildns.exe":           []byte("resolver"),
		"taildns-ipn.exe":       []byte("tray"),
		"taildns-installer.exe": []byte("installer"),
	}
	manifest := Manifest{
		SchemaVersion:   1,
		Product:         "TailDNS",
		UpstreamVersion: "1.103.0",
		Sequence:        6,
		Platform:        "windows",
		Arch:            "amd64",
		CoreCommit:      strings.Repeat("a", 40),
	}
	for name, data := range payload {
		sum := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, File{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifestRaw)))
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, data := range payload {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			json.NewEncoder(w).Encode(map[string]any{"assets": []map[string]string{
				{"name": "taildns-windows-update.json", "browser_download_url": server.URL + "/manifest"},
				{"name": "taildns-windows-update.json.sig", "browser_download_url": server.URL + "/signature"},
				{"name": "taildns-windows-amd64.zip", "browser_download_url": server.URL + "/archive"},
			}})
		case "/manifest":
			w.Write(manifestRaw)
		case "/signature":
			w.Write(signature)
		case "/archive":
			w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	destination := filepath.Join(t.TempDir(), "candidate")
	if _, err := PrepareLatest(context.Background(), server.Client(), server.URL+"/latest", destination, "1.103.0-taildns.5", base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{
		"taildns-windows-update.json":     manifestRaw,
		"taildns-windows-update.json.sig": signature,
	} {
		got, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatalf("reading staged %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("staged %s does not match verified download", name)
		}
	}
}

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
