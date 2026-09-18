// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
	"testing"
)

func TestLocalDNSFollowSource(t *testing.T) {
	b := newTestBackend(t)
	host, mode := "first.dns.controld.com", "opportunistic"
	observing := false
	b.SetLocalDNSPlatform(func() (string, string, error) {
		if !observing {
			t.Error("source read before observation registration")
		}
		return host, mode, nil
	}, func(enable bool) error { observing = enable; return nil })
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSFollowAndroid: true, LocalDNSResolver: "https://manual.example/query", Persist: &persist.Persist{PrivateNodeKey: key.NewNode()}}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.syncLocalDNSObservationLocked()
	endpoint, _, err := b.localDNSPlatformEndpointLocked()
	b.mu.Unlock()
	if !observing || endpoint != "https://dns.controld.com/first" || err != nil {
		t.Fatal("initial follow read failed")
	}
	host = "unknown.example"
	b.NotifyLocalDNSPlatformChanged()
	b.mu.Lock()
	endpoint, _, err = b.localDNSPlatformEndpointLocked()
	b.mu.Unlock()
	if endpoint != "" || err == nil {
		t.Fatal("unsupported source retained an old endpoint")
	}
	if b.localDNSAppliedEndpoint != "" {
		t.Fatal("unsupported source left stale provider applied")
	}
	if b.Prefs().LocalDNSResolver() != "https://manual.example/query" {
		t.Fatal("follow overwrote manual endpoint")
	}
	host = "second-client-name.dns.controld.com"
	b.NotifyLocalDNSPlatformChanged()
	b.mu.Lock()
	endpoint, _, err = b.localDNSPlatformEndpointLocked()
	b.mu.Unlock()
	if endpoint != "https://dns.controld.com/second/client-name" || err != nil {
		t.Fatal("invalid-to-valid recovery failed")
	}
	if b.localDNSAppliedEndpoint != endpoint {
		t.Fatal("latest provider was not applied")
	}
	// A queued callback after leaving follow must not replace the manual source.
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{LocalDNSFollowAndroid: false}, LocalDNSFollowAndroidSet: true}); err != nil {
		t.Fatal(err)
	}
	host = "old-callback.dns.controld.com"
	b.NotifyLocalDNSPlatformChanged()
	if observing || b.localDNSAppliedEndpoint != "https://manual.example/query" {
		t.Fatal("late callback escaped manual mode")
	}
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: false}, WantRunningSet: true}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.syncLocalDNSObservationLocked()
	b.mu.Unlock()
	if observing {
		t.Fatal("stopped VPN retained observer")
	}
}

func TestLocalDNSFollowReadDenied(t *testing.T) {
	b := newTestBackend(t)
	b.SetLocalDNSPlatform(func() (string, string, error) { return "", "", errors.New("denied") }, func(bool) error { return nil })
	b.mu.Lock()
	endpoint, _, err := b.localDNSPlatformEndpointLocked()
	b.mu.Unlock()
	if endpoint != "" || err == nil {
		t.Fatal("denied read did not fail closed")
	}
}

func TestLocalDNSFollowPolicyObservation(t *testing.T) {
	var polc policytest.Config
	polc.EnableRegisterChangeCallback()
	b := newTestBackend(t, polc)
	observing := false
	b.SetLocalDNSPlatform(func() (string, string, error) {
		return "example.dns.controld.com", "opportunistic", nil
	}, func(enabled bool) error { observing = enabled; return nil })
	p := &ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSFollowAndroid: true, Persist: &persist.Persist{PrivateNodeKey: key.NewNode()}}
	if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.authReconfig()
	if !observing {
		t.Fatal("eligible follow did not observe")
	}
	polc.Set(pkey.EnableTailscaleDNS, "always")
	if observing {
		t.Fatal("managed policy retained unnecessary observer")
	}
	if !b.Prefs().LocalDNSFollowAndroid() {
		t.Fatal("policy erased follow preference")
	}
}
