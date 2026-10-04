// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && !ts_omit_captiveportal

package ipnlocal

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/captivedetection"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// Observe the boundary while forwarding to the real userspace test engine.
// It has no installed Windows TUN and cannot reconfigure the user's service.
type portalRecordingEngine struct {
	wgengine.Engine
	dns    *dns.Config
	routes *router.Config
}

func TestWindowsCaptivePortalNetworkOwnership(t *testing.T) {
	b := newTestBackend(t)
	b.goos = "windows"
	b.state = ipn.Running
	if err := b.pm.SetPrefs((&ipn.Prefs{CorpDNS: true, WantRunning: true}).View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	profile := b.pm.CurrentProfile().ID()
	servers := []netip.Addr{netip.MustParseAddr("192.168.200.1")}
	b.updateWindowsCaptiveNetworkLocked(captivedetection.LoginNetwork{Key: "network-a", DNS: servers})
	generation := b.windowsPortal.generation
	b.recordCaptivePortalProbeLocked(profile, generation, portalProbeCaptive, servers)
	if !b.windowsPortal.active {
		t.Fatal("login session missing")
	}
	// A -> B -> A still invalidates the old A result, even if DNS is identical.
	b.updateWindowsCaptiveNetworkLocked(captivedetection.LoginNetwork{Key: "network-b", DNS: servers})
	b.updateWindowsCaptiveNetworkLocked(captivedetection.LoginNetwork{Key: "network-a", DNS: servers})
	if b.windowsPortal.active || b.recordCaptivePortalProbeLocked(profile, generation, portalProbeCaptive, servers) {
		t.Fatal("old network-generation evidence reused")
	}
	b.recordCaptivePortalProbeLocked(profile, b.windowsPortal.generation, portalProbeCaptive, servers)
	b.windowsPortal.profile = "previous-profile"
	if !b.updateWindowsCaptiveNetworkLocked(captivedetection.LoginNetwork{Key: "network-a", DNS: servers}) || b.windowsPortal.active {
		t.Fatal("profile change did not invalidate temporary configuration")
	}
}

func (e *portalRecordingEngine) Reconfig(w *wgcfg.Config, r *router.Config, d *dns.Config) error {
	e.dns = d
	e.routes = r
	return e.Engine.Reconfig(w, r, d)
}

func TestWindowsCaptivePortalRealEngineTransition(t *testing.T) {
	b := newTestBackend(t)
	b.goos = "windows"
	b.state = ipn.Running
	// Drive probe transitions deterministically rather than starting real external
	// connectivity probes in this engine-boundary regression.
	b.windowsPortalWake = make(chan struct{}, 1)
	prefs := &ipn.Prefs{WantRunning: true, CorpDNS: true, LocalDNSOverride: true, LocalDNSResolver: "https://dns.example/query", ExitNodeID: "selected-exit", Persist: &persist.Persist{PrivateNodeKey: key.NewNode()}}
	if err := b.pm.SetPrefs(prefs.View(), ipn.NetworkProfile{}); err != nil {
		t.Fatal(err)
	}
	recorded := &portalRecordingEngine{Engine: b.e}
	b.e = recorded
	b.mu.Lock()
	b.syncWindowsCaptiveNetworkLocked()
	b.mu.Unlock()
	if b.windowsPortal.network == "" {
		t.Skip("no physical IPv4 default network")
	}
	var validated atomic.Bool
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}}
	for _, addr := range []string{"127.0.0.1:0", "127.0.0.2:0"} {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !validated.Load() {
				http.Redirect(w, r, "https://eu.network-auth.com/splash/test", 302)
				return
			}
			w.Header().Set("X-Tailscale-Response", "response "+r.Header.Get("X-Tailscale-Challenge"))
			w.WriteHeader(204)
		}))
		listener, err := net.Listen("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		s.Listener = listener
		s.Start()
		t.Cleanup(s.Close)
		dm.Regions[1].Nodes = append(dm.Regions[1].Nodes, &tailcfg.DERPNode{IPv4: strings.TrimPrefix(s.URL, "http://"), CanPort80: true})
	}
	detector := captivedetection.NewDetector(t.Logf)
	portalEvidence := detector.ProbeLogin(context.Background(), 0, dm)
	if portalEvidence != captivedetection.LoginCaptive {
		t.Fatal("redirect was not detected")
	}
	saved := b.Prefs()
	b.mu.Lock()
	if !b.recordCaptivePortalProbeLocked(b.pm.CurrentProfile().ID(), b.windowsPortal.generation, windowsPortalEvidence(portalEvidence), []netip.Addr{netip.MustParseAddr("192.168.200.1")}) {
		b.mu.Unlock()
		t.Fatal("positive detection rejected")
	}
	b.authReconfigLocked()
	b.mu.Unlock()
	if !b.windowsPortal.applied || recorded.dns.DefaultResolvers[0].Addr != "192.168.200.1" {
		t.Fatal("hotel DNS did not reach real engine")
	}
	for _, r := range recorded.routes.Routes {
		if r.Bits() == 0 {
			t.Fatal("exit default route still installed")
		}
	}
	if !saved.Equals(b.Prefs()) {
		t.Fatal("saved prefs changed during login")
	}
	validated.Store(true)
	validationEvidence := detector.ProbeLogin(context.Background(), 0, dm)
	if validationEvidence != captivedetection.LoginValidated {
		t.Fatal("positive validation was not detected")
	}
	b.mu.Lock()
	b.recordCaptivePortalProbeLocked(b.pm.CurrentProfile().ID(), b.windowsPortal.generation, windowsPortalEvidence(validationEvidence), nil)
	b.authReconfigLocked()
	b.mu.Unlock()
	if b.localDNSAppliedEndpoint != prefs.LocalDNSResolver {
		t.Fatal("custom DNS not reapplied")
	}
	defaults := 0
	for _, r := range recorded.routes.Routes {
		if r.Bits() == 0 {
			defaults++
		}
	}
	if defaults != 2 {
		t.Fatalf("exit route restoration has %d defaults", defaults)
	}
	if !reflect.DeepEqual(b.Prefs().AsStruct(), saved.AsStruct()) {
		t.Fatal("restore changed settings")
	}
}
