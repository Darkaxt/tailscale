// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"reflect"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

func TestLocalDNSDefaultOverride(t *testing.T) {
	const endpoint = "https://dns.controld.com/test-profile"
	var prefs ipn.Prefs
	if err := json.Unmarshal([]byte(`{"CorpDNS":true,"WantRunning":true,"LocalDNSOverride":true,"LocalDNSResolver":"`+endpoint+`"}`), &prefs); err != nil {
		t.Fatal(err)
	}
	nm := &netmap.NetworkMap{DNS: tailcfg.DNSConfig{
		Resolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}},
		Routes: map[string][]*dnstype.Resolver{
			".":                {{Addr: "8.8.8.8"}},
			"private.example.": {{Addr: "100.64.0.2"}},
			"local.example.":   nil,
		},
		Domains: []string{"private.example"},
	}}
	before, _ := json.Marshal(nm)
	got := dnsConfigForNetmap(nm, nil, prefs.View(), false, t.Logf, "android")
	if want := []*dnstype.Resolver{{Addr: endpoint, LocalOverride: true}}; !reflect.DeepEqual(got.DefaultResolvers, want) {
		t.Errorf("default resolver = %v; want selected endpoint", got.DefaultResolvers)
	}
	if _, present := got.Routes[dnsname.FQDN(".")]; present {
		t.Error("root route must not bypass the selected default")
	}
	if !reflect.DeepEqual(got.Routes["private.example."], nm.DNS.Routes["private.example."]) {
		t.Error("private route changed")
	}
	if route, ok := got.Routes["local.example."]; !ok || len(route) != 0 {
		t.Error("authoritative empty route lost")
	}
	after, _ := json.Marshal(nm)
	if string(before) != string(after) {
		t.Error("source netmap mutated")
	}
	if got := dnsConfigForNetmap(nil, nil, prefs.View(), false, t.Logf, "android"); got != nil {
		t.Error("missing netmap must remain unconfigured")
	}
	if got := dnsConfigForNetmap(nm, nil, prefs.View(), true, t.Logf, "android"); len(got.DefaultResolvers) != 0 {
		t.Error("expired key must not install override")
	}
	prefs.CorpDNS = false
	if got := dnsConfigForNetmap(nm, nil, prefs.View(), false, t.Logf, "android"); len(got.DefaultResolvers) != 0 {
		t.Error("accept-DNS off must not install override")
	}
}

func TestLocalDNSManagedPolicy(t *testing.T) {
	var polc policytest.Config
	polc.Set(pkey.EnableTailscaleDNS, "always")
	b := newTestBackend(t, polc)
	if err := b.CheckPrefs(&ipn.Prefs{LocalDNSOverride: true, LocalDNSResolver: "https://dns.controld.com/test"}); err == nil {
		t.Fatal("managed DNS must reject local override at backend boundary")
	}
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, LocalDNSOverride: true, LocalDNSResolver: "https://dns.controld.com/test"}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: false}, WantRunningSet: true}); err != nil {
		t.Fatalf("retained local choice blocked unrelated disconnect: %v", err)
	}
}

func TestLocalDNSStaleProfile(t *testing.T) {
	b := newTestBackend(t)
	before := b.Prefs()
	err := b.EditLocalDNS(nil, ipn.LocalDNSUpdate{ProfileID: "stale-profile", Enabled: true, Endpoint: "https://dns.example/query"})
	if err == nil {
		t.Fatal("stale profile update accepted")
	}
	if !before.Equals(b.Prefs()) {
		t.Fatal("stale update changed active profile")
	}
}

func TestLocalDNSPolicyTransition(t *testing.T) {
	var polc policytest.Config
	polc.EnableRegisterChangeCallback()
	b := newTestBackend(t, polc)
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, WantRunning: true, LocalDNSOverride: true, LocalDNSResolver: "https://dns.example/query", Persist: &persist.Persist{PrivateNodeKey: key.NewNode()}}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	b.authReconfig()
	if b.localDNSAppliedEndpoint == "" {
		t.Fatal("test setup did not apply local DNS")
	}
	polc.Set(pkey.EnableTailscaleDNS, "always")
	if b.localDNSAppliedEndpoint != "" {
		t.Fatal("policy takeover left local resolver installed when CorpDNS was already true")
	}
	if !b.Prefs().LocalDNSOverride() {
		t.Fatal("policy takeover erased the saved user preference")
	}
}

func TestLocalDNSValidation(t *testing.T) {
	b := newTestBackend(t)
	for _, endpoint := range []string{
		"", "http://dns.example/query", "tls://dns.example", "https://127.0.0.1/query",
		"https://dns.example", "https://user:pass@dns.example/query", "https://dns.example/query?id=secret",
		"https://dns.example/query#fragment", "https://dns.example:8443/query", "https://dns.example/%zz",
		"https://dns.example/a%0ab", "https://bad_host.example/query",
	} {
		t.Run(endpoint, func(t *testing.T) {
			p := &ipn.Prefs{LocalDNSOverride: true, LocalDNSResolver: endpoint}
			if err := b.CheckPrefs(p); err == nil {
				t.Error("accepted invalid local resolver")
			}
		})
	}
	for _, endpoint := range []string{"https://dns.controld.com/Example-ID", "https://resolver.example:443/dns-query"} {
		if err := b.CheckPrefs(&ipn.Prefs{LocalDNSOverride: true, LocalDNSResolver: endpoint}); err != nil {
			t.Errorf("valid resolver rejected: %v", err)
		}
	}
}
