// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestValidateBaselineVersionAllowsARealCoreUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		version versionJSON
		wantErr bool
	}{
		{
			name:    "official older core",
			version: versionJSON{Short: "1.102.4", Long: "1.102.4", GitCommit: strings.Repeat("1", 40)},
		},
		{
			name:    "adopt existing TailDNS overlay",
			version: versionJSON{Short: "1.102.4", Long: "1.102.4-taildns.1", GitCommit: strings.Repeat("2", 40)},
		},
		{
			name:    "missing version identity",
			version: versionJSON{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBaselineVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateBaselineVersion(%+v) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

func TestTailDNSRunCommandQuotesExecutable(t *testing.T) {
	path := `C:\Program Files\Tailscale\taildns-ipn.exe`
	if got, want := tailDNSRunCommand(path), `"C:\Program Files\Tailscale\taildns-ipn.exe"`; got != want {
		t.Fatalf("tailDNSRunCommand = %q, want %q", got, want)
	}
}

func TestValidateUpdateTransitionRejectsReplay(t *testing.T) {
	active := deploymentRecord{SchemaVersion: 4, UpstreamVersion: "1.103.0", Sequence: 5}
	if err := validateUpdateTransition(active, releaseManifest{UpstreamVersion: "1.103.0", Sequence: 6}); err != nil {
		t.Fatalf("newer update rejected: %v", err)
	}
	for _, sequence := range []uint64{4, 5} {
		if err := validateUpdateTransition(active, releaseManifest{UpstreamVersion: "1.103.0", Sequence: sequence}); err == nil {
			t.Fatalf("sequence %d accepted", sequence)
		}
	}
	if err := validateUpdateTransition(active, releaseManifest{UpstreamVersion: "1.102.9", Sequence: 99}); err == nil {
		t.Fatal("older upstream base accepted")
	}
}

func TestValidateDaemonExecutable(t *testing.T) {
	if err := validateDaemonExecutable(os.Getenv("ComSpec")); err != nil {
		t.Fatalf("valid executable rejected: %v", err)
	}
	invalid := filepath.Join(t.TempDir(), "invalid.exe")
	if err := os.WriteFile(invalid, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDaemonExecutable(invalid); err == nil {
		t.Fatal("invalid executable accepted")
	}
}

func TestValidateIdentityStatusAllowsControlPlaneReconnect(t *testing.T) {
	var status statusJSON
	status.BackendState = "Running"
	status.HaveNodeKey = true
	status.Self.ID = "n1"
	status.Self.DNSName = "beacon.example.ts.net."
	status.Self.TailscaleIPs = []string{"100.64.0.1"}
	status.Self.Online = false
	if err := validateIdentityStatus(status); err != nil {
		t.Fatalf("authenticated running identity rejected while control plane reconnects: %v", err)
	}
	status.HaveNodeKey = false
	if err := validateIdentityStatus(status); err == nil {
		t.Fatal("identity without a node key accepted")
	}
}

func TestDeploymentRecordCoversMatchingTrayPayload(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	install := filepath.Join(root, "install")
	programData := filepath.Join(root, "program-data")
	for _, dir := range []string{payload, install, programData} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths := installPaths{
		InstallDir:      install,
		Daemon:          filepath.Join(install, "tailscaled.exe"),
		CLI:             filepath.Join(install, "tailscale.exe"),
		Resolver:        filepath.Join(install, "taildns.exe"),
		Tray:            filepath.Join(install, "taildns-ipn.exe"),
		GUI:             filepath.Join(install, "tailscale-ipn.exe"),
		Wintun:          filepath.Join(install, "wintun.dll"),
		OfficialStartup: filepath.Join(root, "startup", "Tailscale.lnk"),
		ProgramData:     programData,
		Record:          filepath.Join(programData, recordName),
	}
	for name, contents := range map[string]string{
		"taildnsd.exe":    "new-daemon",
		"tailscale.exe":   "new-cli",
		"taildns.exe":     "new-resolver",
		"taildns-ipn.exe": "new-tray",
	} {
		if err := os.WriteFile(filepath.Join(payload, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{
		paths.Daemon: "old-daemon",
		paths.CLI:    "old-cli",
		paths.GUI:    "official-gui",
		paths.Wintun: "official-wintun",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := releaseManifest{UpstreamVersion: "1.103.312", Sequence: 15, CoreCommit: strings.Repeat("3", 40)}
	record, err := createDeploymentRecord(paths, `"C:\Program Files\Tailscale\tailscaled.exe"`, payload, manifest, machineIdentity{NodeID: "n1"}, prefsJSON{})
	if err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion != 4 || len(record.Files) != 4 {
		t.Fatalf("deployment record = schema %d, files %#v", record.SchemaVersion, record.Files)
	}
	tray := record.Files["taildns-ipn.exe"]
	if tray.Path != paths.Tray || tray.Existed || tray.InstalledHash == "" {
		t.Fatalf("tray record = %#v", tray)
	}
	if record.PreservedComponentHash["tailscale-ipn.exe"] == "" || record.PreservedComponentHash["wintun.dll"] == "" {
		t.Fatalf("preserved components = %#v", record.PreservedComponentHash)
	}

	if err := os.Remove(paths.GUI); err != nil {
		t.Fatal(err)
	}
	paths.ProgramData = filepath.Join(root, "program-data-without-official-gui")
	paths.Record = filepath.Join(paths.ProgramData, recordName)
	withoutGUI, err := createDeploymentRecord(paths, `"C:\Program Files\Tailscale\tailscaled.exe"`, payload, manifest, machineIdentity{NodeID: "n1"}, prefsJSON{})
	if err != nil {
		t.Fatalf("installation without proprietary GUI was rejected: %v", err)
	}
	if _, preserved := withoutGUI.PreservedComponentHash["tailscale-ipn.exe"]; preserved {
		t.Fatalf("missing proprietary GUI was recorded as preserved: %#v", withoutGUI.PreservedComponentHash)
	}
}

// Regression 2026-11-27: ReplaceFile cannot delete an image that a running
// process still maps, which failed the +76 core update and its rollback and
// left the Tailscale service stopped. The replacement must still succeed.
func TestReplaceFromPayloadReplacesRunningExecutable(t *testing.T) {
	dir := t.TempDir()
	running := filepath.Join(dir, "tailscale.exe")
	ping, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"))
	if err != nil {
		t.Skipf("PING.EXE unavailable: %v", err)
	}
	if err := os.WriteFile(running, ping, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(running, "-n", "60", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	payload := filepath.Join(dir, "payload.exe")
	want := []byte("new core image")
	if err := os.WriteFile(payload, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFromPayload(payload, running); err != nil {
		t.Fatalf("replacing a running executable: %v", err)
	}
	got, err := os.ReadFile(running)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("destination was not replaced")
	}
	if _, err := os.Stat(running + ".taildns-staged"); !os.IsNotExist(err) {
		t.Fatalf("staged file left behind: %v", err)
	}

	// Once the old image is no longer in use, the next replacement removes it.
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err := replaceFromPayload(payload, running); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(running + asideSuffix + "*"); len(left) != 0 {
		t.Fatalf("stale aside images left behind: %v", left)
	}
}

// The 2026-11-27 failure mode: another process holds the installed image open
// without delete sharing, so ReplaceFile and a rename both fail until it closes.
func TestReplaceFromPayloadWaitsForTransientLock(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "tailscaled.exe")
	if err := os.WriteFile(destination, []byte("old core image"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(1500 * time.Millisecond)
		windows.CloseHandle(handle)
		close(released)
	}()
	defer func() { <-released }()

	payload := filepath.Join(dir, "payload.exe")
	want := []byte("new core image")
	if err := os.WriteFile(payload, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFromPayload(payload, destination); err != nil {
		t.Fatalf("replacing a transiently locked executable: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("destination was not replaced")
	}
}

func TestReplaceFromPayloadGivesUpAfterRetryWindow(t *testing.T) {
	previous := replaceRetryWindow
	replaceRetryWindow = time.Second
	defer func() { replaceRetryWindow = previous }()
	dir := t.TempDir()
	destination := filepath.Join(dir, "tailscale.exe")
	if err := os.WriteFile(destination, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(destination)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	payload := filepath.Join(dir, "payload.exe")
	if err := os.WriteFile(payload, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFromPayload(payload, destination); err == nil {
		t.Fatal("replacement of a permanently locked file reported success")
	}
	if got, _ := os.ReadFile(destination); string(got) != "old" {
		t.Fatalf("original changed after failed replacement: %q", got)
	}
	if _, err := os.Stat(destination + ".taildns-staged"); !os.IsNotExist(err) {
		t.Fatalf("staged file left behind: %v", err)
	}
}
