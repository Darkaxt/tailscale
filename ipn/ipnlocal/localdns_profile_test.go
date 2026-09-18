// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

// Exercise the real preference store while keeping the control plane synthetic.
func TestLocalDNSFollowProfileIsolation(t *testing.T) {
	b := newTestBackend(t)
	host := "first.dns.controld.com"
	observing := false
	b.SetLocalDNSPlatform(func() (string, string, error) { return host, "opportunistic", nil }, func(enabled bool) error { observing = enabled; return nil })
	addProfile := func(id tailcfg.UserID, name string, follow bool) ipn.LoginProfileView {
		t.Helper()
		b.pm.SwitchToNewProfile()
		if b.Prefs().LocalDNSOverride() || b.Prefs().LocalDNSFollowAndroid() {
			t.Fatal("new profile inherited override")
		}
		p := b.Prefs().AsStruct()
		p.CorpDNS, p.WantRunning, p.LocalDNSOverride = true, true, true
		p.LoggedOut = false
		p.LocalDNSFollowAndroid = follow
		p.LocalDNSResolver = "https://manual.example/" + name
		p.Persist = &persist.Persist{NodeID: tailcfg.StableNodeID(name), PrivateNodeKey: key.NewNode(), UserProfile: tailcfg.UserProfile{ID: id, LoginName: name + "@example.com"}}
		if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatal(err)
		}
		return b.pm.CurrentProfile()
	}
	first := addProfile(1, "first", true)
	b.NotifyLocalDNSPlatformChanged()
	if !observing || b.localDNSAppliedEndpoint != "https://dns.controld.com/first" {
		t.Fatal("first follow not applied")
	}
	second := addProfile(2, "second", false)
	host = "changed.dns.controld.com"
	b.NotifyLocalDNSPlatformChanged() // Represents a callback queued by first.
	if observing || b.localDNSAppliedEndpoint != "https://manual.example/second" {
		t.Fatal("previous profile callback escaped ownership")
	}
	if b.localDNSAppliedProfile != second.ID() {
		t.Fatal("applied status belongs to previous profile")
	}
	if err := b.EditLocalDNS(nil, ipn.LocalDNSUpdate{ProfileID: first.ID(), Enabled: true, FollowAndroid: true}); err == nil {
		t.Fatal("old editor crossed profile boundary")
	}
	if _, _, err := b.pm.SwitchToProfileByID(first.ID()); err != nil {
		t.Fatal(err)
	}
	b.NotifyLocalDNSPlatformChanged()
	if !observing || b.localDNSAppliedEndpoint != "https://dns.controld.com/changed" {
		t.Fatal("restored follow did not read latest platform value")
	}
	if b.Prefs().LocalDNSResolver() != "https://manual.example/first" {
		t.Fatal("follow replaced independent saved manual endpoint")
	}
	if err := b.pm.DeleteProfile(first.ID()); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.syncLocalDNSObservationLocked()
	b.mu.Unlock()
	if observing || b.Prefs().LocalDNSFollowAndroid() || b.Prefs().LocalDNSOverride() {
		t.Fatal("deleted profile retained follow ownership")
	}
}

func TestLocalDNSFollowObservationFailureAndModeStatus(t *testing.T) {
	b := newTestBackend(t)
	p := &ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSFollowAndroid: true, Persist: &persist.Persist{PrivateNodeKey: key.NewNode()}}
	if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.state = ipn.Running
	fail, reads := true, 0
	mode := "opportunistic"
	b.SetLocalDNSPlatform(func() (string, string, error) { reads++; return "test.dns.controld.com", mode, nil }, func(bool) error {
		if fail {
			return errors.New("diagnostic-secret-must-not-escape")
		}
		return nil
	})
	b.NotifyLocalDNSPlatformChanged()
	status := b.LocalDNSStatus()
	if reads != 0 || status.Applied || status.Endpoint != "" || status.Reason != "Android provider unavailable or unsupported; default DNS fails closed" {
		t.Fatal("registration failure was not redacted and fail-closed")
	}
	fail = false
	b.NotifyLocalDNSPlatformChanged()
	if !b.LocalDNSStatus().Applied {
		t.Fatal("re-registration did not recover")
	}
	for _, nextMode := range []string{"hostname", ""} {
		mode = nextMode
		b.NotifyLocalDNSPlatformChanged()
		status = b.LocalDNSStatus()
		if status.Applied || status.Endpoint != "https://dns.controld.com/test" || status.SystemMode != mode {
			t.Fatal("conflicted/unknown mode falsely claimed effective or changed provider")
		}
	}
	mode = "opportunistic"
	b.NotifyLocalDNSPlatformChanged()
	if !b.LocalDNSStatus().Applied {
		t.Fatal("automatic mode did not recover status")
	}
}

func TestLocalDNSFollowDisconnectUnregistersImmediately(t *testing.T) {
	b := newTestBackend(t)
	p := &ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSFollowAndroid: true, Persist: &persist.Persist{PrivateNodeKey: key.NewNode()}}
	if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.state = ipn.Running
	observing := false
	b.SetLocalDNSPlatform(func() (string, string, error) { return "test.dns.controld.com", "opportunistic", nil }, func(enabled bool) error { observing = enabled; return nil })
	if !observing {
		t.Fatal("test setup did not register")
	}
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{WantRunningSet: true}); err != nil {
		t.Fatal(err)
	}
	if observing {
		t.Fatal("disconnect retained observer until another settings event")
	}
}
