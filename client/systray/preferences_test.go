// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/types/opt"
)

type recordingPrefsEditor struct {
	edits []*ipn.MaskedPrefs
}

type recordingLocalDNSClient struct {
	status *ipn.LocalDNSStatus
	edits  []ipn.LocalDNSUpdate
}

func (r *recordingLocalDNSClient) LocalDNSStatus(context.Context) (*ipn.LocalDNSStatus, error) {
	copy := *r.status
	return &copy, nil
}

func (r *recordingLocalDNSClient) EditLocalDNS(_ context.Context, update ipn.LocalDNSUpdate) (*ipn.LocalDNSStatus, error) {
	r.edits = append(r.edits, update)
	copy := *r.status
	copy.Configured = update.Enabled
	copy.Endpoint = update.Endpoint
	return &copy, nil
}

func (r *recordingPrefsEditor) EditPrefs(_ context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	r.edits = append(r.edits, mp)
	return &mp.Prefs, nil
}

func TestPreferenceSnapshotPreservesWindowsControls(t *testing.T) {
	prefs := &ipn.Prefs{
		ShieldsUp:   true,
		CorpDNS:     false,
		RouteAll:    true,
		ForceDaemon: true,
		AutoUpdate:  ipn.AutoUpdatePrefs{Check: true, Apply: opt.NewBool(true)},
	}
	got := preferenceSnapshot(prefs)
	want := []preferenceItem{
		{action: prefAllowIncoming, title: "Allow incoming connections", checked: false, available: true},
		{action: prefUseDNS, title: "Use TailDNS settings", checked: false, available: true},
		{action: prefUseSubnets, title: "Use Tailscale subnets", checked: true, available: true},
		{action: prefAutoUpdate, title: "Automatically install updates (available after TailDNS updater activation)", checked: true},
		{action: prefUnattended, title: "Run unattended", checked: true, available: true},
	}
	if len(got) != len(want) {
		t.Fatalf("preferenceSnapshot returned %d items, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestPreferenceEditMasksOnlySelectedSetting(t *testing.T) {
	tests := []struct {
		name    string
		action  preferenceAction
		enabled bool
		check   func(*testing.T, *ipn.MaskedPrefs)
	}{
		{"allow incoming", prefAllowIncoming, true, func(t *testing.T, mp *ipn.MaskedPrefs) {
			if !mp.ShieldsUpSet || mp.ShieldsUp {
				t.Fatalf("incoming edit = %#v", mp)
			}
		}},
		{"dns", prefUseDNS, true, func(t *testing.T, mp *ipn.MaskedPrefs) {
			if !mp.CorpDNSSet || !mp.CorpDNS {
				t.Fatalf("DNS edit = %#v", mp)
			}
		}},
		{"subnets", prefUseSubnets, false, func(t *testing.T, mp *ipn.MaskedPrefs) {
			if !mp.RouteAllSet || mp.RouteAll {
				t.Fatalf("subnet edit = %#v", mp)
			}
		}},
		{"auto update", prefAutoUpdate, true, func(t *testing.T, mp *ipn.MaskedPrefs) {
			if !mp.AutoUpdateSet.CheckSet || !mp.AutoUpdateSet.ApplySet || !mp.AutoUpdate.Check || !mp.AutoUpdate.Apply.EqualBool(true) {
				t.Fatalf("auto-update edit = %#v", mp)
			}
		}},
		{"unattended", prefUnattended, false, func(t *testing.T, mp *ipn.MaskedPrefs) {
			if !mp.ForceDaemonSet || mp.ForceDaemon {
				t.Fatalf("unattended edit = %#v", mp)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp, err := preferenceEdit(tt.action, tt.enabled)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, mp)
		})
	}
}

func TestResetPreferenceEditRestoresWindowsDefaultsAndDisablesOverride(t *testing.T) {
	mp := resetPreferenceEdit()
	if !mp.ShieldsUpSet || mp.ShieldsUp {
		t.Fatalf("reset did not allow incoming connections: %#v", mp)
	}
	if !mp.CorpDNSSet || !mp.CorpDNS || !mp.RouteAllSet || !mp.RouteAll {
		t.Fatalf("reset did not restore DNS/routes defaults: %#v", mp)
	}
	if !mp.ExitNodeIDSet || !mp.ExitNodeID.IsZero() || !mp.ExitNodeAllowLANAccessSet || mp.ExitNodeAllowLANAccess {
		t.Fatalf("reset did not clear exit-node preferences: %#v", mp)
	}
	if !mp.ForceDaemonSet || mp.ForceDaemon {
		t.Fatalf("reset did not clear unattended mode: %#v", mp)
	}
	if !mp.LocalDNSOverrideSet || mp.LocalDNSOverride {
		t.Fatalf("reset did not disable the TailDNS resolver override: %#v", mp)
	}
}

func TestApplyPreferenceUsesAuthenticatedEditor(t *testing.T) {
	editor := new(recordingPrefsEditor)
	if err := applyPreference(context.Background(), editor, prefUseDNS, false); err != nil {
		t.Fatal(err)
	}
	if len(editor.edits) != 1 || !editor.edits[0].CorpDNSSet || editor.edits[0].CorpDNS {
		t.Fatalf("edits = %#v", editor.edits)
	}
}

func TestApplyLocalDNSPinsClipboardEndpointToCurrentProfile(t *testing.T) {
	client := &recordingLocalDNSClient{status: &ipn.LocalDNSStatus{ProfileID: "profile-1"}}
	endpoint := "https://dns.controld.com/test-profile"
	if err := applyLocalDNS(context.Background(), client, endpoint); err != nil {
		t.Fatal(err)
	}
	want := ipn.LocalDNSUpdate{ProfileID: "profile-1", Enabled: true, Endpoint: endpoint}
	if len(client.edits) != 1 || client.edits[0] != want {
		t.Fatalf("edits = %#v, want %#v", client.edits, want)
	}
}

func TestApplyLocalDNSRejectsInvalidClipboardWithoutMutation(t *testing.T) {
	client := &recordingLocalDNSClient{status: &ipn.LocalDNSStatus{ProfileID: "profile-1"}}
	if err := applyLocalDNS(context.Background(), client, "http://dns.example/query"); err == nil {
		t.Fatal("invalid endpoint unexpectedly accepted")
	}
	if len(client.edits) != 0 {
		t.Fatalf("invalid endpoint mutated daemon: %#v", client.edits)
	}
}

func TestDisableLocalDNSPinsEditToCurrentProfile(t *testing.T) {
	client := &recordingLocalDNSClient{status: &ipn.LocalDNSStatus{ProfileID: "profile-1", Configured: true}}
	if err := disableLocalDNS(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	want := ipn.LocalDNSUpdate{ProfileID: "profile-1"}
	if len(client.edits) != 1 || client.edits[0] != want {
		t.Fatalf("edits = %#v, want %#v", client.edits, want)
	}
}
