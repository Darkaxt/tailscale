// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"net/netip"
	"tailscale.com/control/controlknobs"
	"tailscale.com/types/dnstype"
	"testing"
)

func TestLocalDNSBaseBootstrap(t *testing.T) {
	baseIP := netip.MustParseAddr("192.0.2.53")
	platform := &fakeOSConfigurator{BaseConfig: OSConfig{Nameservers: []netip.Addr{baseIP}}}
	m := &Manager{os: platform, goos: "android", knobs: &controlknobs.Knobs{}}
	selected := &dnstype.Resolver{Addr: "https://resolver.example/query", LocalOverride: true}
	config := Config{DefaultResolvers: []*dnstype.Resolver{selected}}
	rcfg, _, err := m.compileConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	got := rcfg.Routes["."][0]
	if len(got.LocalBootstrapResolvers) != 1 || got.LocalBootstrapResolvers[0] != baseIP {
		t.Fatal("base DNS did not reach local transport")
	}
	if len(selected.LocalBootstrapResolvers) != 0 {
		t.Fatal("source config mutated")
	}
	platform.BaseConfig.Nameservers = []netip.Addr{netip.MustParseAddr("192.0.2.54")}
	rcfg, _, err = m.compileConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if rcfg.Routes["."][0].LocalBootstrapResolvers[0] == baseIP {
		t.Fatal("network change retained stale base DNS")
	}
}
