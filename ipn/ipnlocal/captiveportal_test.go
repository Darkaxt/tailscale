// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_captiveportal

package ipnlocal

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

func TestCaptivePortalDNSAndRoutingAreTemporary(t *testing.T) {
	p := &ipn.Prefs{WantRunning: true, CorpDNS: true, LocalDNSOverride: true, LocalDNSResolver: "https://dns.example/query", ExitNodeID: "exit-node"}
	before, _ := json.Marshal(p)
	effective := captivePortalPrefs(p.View(), true)
	if effective.ExitNodeID() != "" || effective.ExitNodeIP().IsValid() {
		t.Fatal("exit routing not paused")
	}
	nm := &netmap.NetworkMap{DNS: tailcfg.DNSConfig{Resolvers: []*dnstype.Resolver{{Addr: "9.9.9.9"}}, Routes: map[string][]*dnstype.Resolver{".": {{Addr: "8.8.8.8"}}, "private.example.": {{Addr: "100.64.0.2"}}, "local.example.": nil}}}
	cfg := dnsConfigForNetmap(nm, nil, p.View(), false, t.Logf, "windows", nil)
	dns := []netip.Addr{netip.MustParseAddr("192.168.200.1")}
	composeCaptivePortalDNS(cfg, dns)
	if !reflect.DeepEqual(cfg.DefaultResolvers, []*dnstype.Resolver{{Addr: "192.168.200.1"}}) {
		t.Fatal("hotel DNS not selected")
	}
	if _, ok := cfg.Routes[dnsname.FQDN(".")]; ok {
		t.Fatal("catch-all still owns default DNS")
	}
	if _, ok := cfg.Routes["local.example."]; !ok {
		t.Fatal("authoritative route lost")
	}
	// No exit node in this case allows verification of an eligible split route.
	plain := p.Clone()
	plain.ExitNodeID = ""
	extraRoutes := map[string][]*dnstype.Resolver{"connector.example.": {{Addr: "100.64.0.3"}}}
	cfg = dnsConfigForNetmap(nm, nil, plain.View(), false, t.Logf, "windows", extraRoutes)
	composeCaptivePortalDNS(cfg, dns)
	if !reflect.DeepEqual(cfg.Routes["private.example."], nm.DNS.Routes["private.example."]) {
		t.Fatal("split route changed")
	}
	if !reflect.DeepEqual(cfg.Routes["connector.example."], extraRoutes["connector.example."]) {
		t.Fatal("extension split route changed during captive portal login")
	}
	after, _ := json.Marshal(p)
	if string(after) != string(before) {
		t.Fatal("saved preferences changed")
	}
	restored := captivePortalPrefs(p.View(), false)
	if restored.ExitNodeID() != p.ExitNodeID {
		t.Fatal("selected exit node not restored")
	}
	cfg = dnsConfigForNetmap(nm, nil, restored, false, t.Logf, "windows", nil)
	if len(cfg.DefaultResolvers) != 1 || cfg.DefaultResolvers[0].Addr != p.LocalDNSResolver || !cfg.DefaultResolvers[0].LocalOverride {
		t.Fatal("custom DoH not restored")
	}
}

func TestCaptivePortalRejectsStaleAndUnknownEvidence(t *testing.T) {
	b := newTestBackend(t)
	b.goos = "windows"
	b.state = ipn.Running
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSResolver: "https://dns.example/query"}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	profile := b.pm.CurrentProfile().ID()
	b.windowsPortal.network = "network-one"
	b.windowsPortal.generation = 7
	servers := []netip.Addr{netip.MustParseAddr("192.168.200.1")}
	for _, bad := range []struct {
		profile    ipn.ProfileID
		generation uint64
		status     portalProbeResult
	}{{profile, 6, portalProbeCaptive}, {"other", 7, portalProbeCaptive}, {profile, 7, portalProbeUnknown}} {
		b.recordCaptivePortalProbeLocked(bad.profile, bad.generation, bad.status, servers)
		if b.windowsPortal.active {
			t.Fatal("bad evidence enabled bypass")
		}
	}
	b.recordCaptivePortalProbeLocked(profile, 7, portalProbeCaptive, servers)
	if !b.windowsPortal.active {
		t.Fatal("confirmed portal not enabled")
	}
	b.recordCaptivePortalProbeLocked(profile, 7, portalProbeUnknown, servers)
	if !b.windowsPortal.active {
		t.Fatal("outage treated as completed login")
	}
	b.recordCaptivePortalProbeLocked(profile, 7, portalProbeValidated, servers)
	if b.windowsPortal.active {
		t.Fatal("validated network not restored")
	}
}

func TestCaptivePortalHonorsManagedDNS(t *testing.T) {
	var policy policytest.Config
	policy.Set(pkey.EnableTailscaleDNS, "always")
	b := newTestBackend(t, policy)
	b.goos = "windows"
	b.state = ipn.Running
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, WantRunning: true}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.windowsPortal.network = "network"
	b.windowsPortal.generation = 1
	b.recordCaptivePortalProbeLocked(b.pm.CurrentProfile().ID(), 1, portalProbeCaptive, []netip.Addr{netip.MustParseAddr("192.168.200.1")})
	if b.windowsPortal.active {
		t.Fatal("managed DNS bypassed")
	}
}

func TestCaptivePortalHonorsManagedExitNode(t *testing.T) {
	var policy policytest.Config
	policy.Set(pkey.ExitNodeID, "managed-exit")
	b := newTestBackend(t, policy)
	b.goos = "windows"
	b.state = ipn.Running
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, WantRunning: true, ExitNodeID: "managed-exit"}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.windowsPortal.network = "network"
	b.windowsPortal.generation = 1
	if b.recordCaptivePortalProbeLocked(b.pm.CurrentProfile().ID(), 1, portalProbeCaptive, []netip.Addr{netip.MustParseAddr("192.168.200.1")}) || b.windowsPortal.active {
		t.Fatal("managed exit-node routing bypassed")
	}
}

func TestCaptivePortalLifecycleAndAppliedStatus(t *testing.T) {
	b := newTestBackend(t)
	b.goos = "windows"
	b.state = ipn.Running
	saved := &ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSResolver: "https://dns.example/query"}
	if err := b.pm.SetPrefs(saved.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	profile := b.pm.CurrentProfile().ID()
	b.windowsPortal = captivePortalRuntime{network: "network", generation: 1, profile: profile, active: true, dns: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}
	status := b.LocalDNSStatus()
	if !status.CaptivePortal || status.Applied || !strings.Contains(status.Reason, "not applied") {
		t.Fatal("unapplied exception misreported")
	}
	b.windowsPortal.applied = true
	if s := b.LocalDNSStatus(); !s.CaptivePortal || s.Applied || !strings.Contains(s.Reason, "local network DNS") {
		t.Fatal("active exception misreported as custom DoH")
	}
	b.windowsPortal.profile = "another"
	if b.captivePortalActiveLocked() {
		t.Fatal("previous profile state active")
	}
	b.windowsPortal.profile = profile
	for _, tc := range []string{"disconnect", "logout", "DNS off", "expired", "shutdown", "blocked", "other OS"} {
		t.Run(tc, func(t *testing.T) {
			p := saved.Clone()
			b.state = ipn.Running
			b.keyExpired = false
			b.shutdownCalled = false
			b.blocked = false
			b.goos = "windows"
			switch tc {
			case "disconnect":
				p.WantRunning = false
			case "logout":
				p.LoggedOut = true
			case "DNS off":
				p.CorpDNS = false
			case "expired":
				b.keyExpired = true
			case "shutdown":
				b.shutdownCalled = true
			case "blocked":
				b.blocked = true
			case "other OS":
				b.goos = "android"
			}
			if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
				t.Fatal(err)
			}
			if b.captivePortalActiveLocked() {
				t.Fatal("lifecycle gate bypassed")
			}
		})
	}
	b.shutdownCalled = false
}
