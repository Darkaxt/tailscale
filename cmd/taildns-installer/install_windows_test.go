// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
