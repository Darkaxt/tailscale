// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"net/netip"
	"runtime"
	"slices"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
)

type captivePortalRuntime struct {
	network    string
	generation uint64
	profile    ipn.ProfileID
	active     bool
	applied    bool
	dns        []netip.Addr
}

// Keep detector dependencies behind the Windows feature build boundary.
type portalProbeResult uint8

const (
	portalProbeUnknown portalProbeResult = iota
	portalProbeCaptive
	portalProbeValidated
)

var captivePortalLoginWarning = health.Register(&health.Warnable{
	Code: "taildns-captive-login", Title: "Wi-Fi login mode", Severity: health.SeverityHigh,
	Text:                health.StaticMessage("Wi-Fi login mode requested: temporary local network DNS and direct internet routing. Check resolver status for application state. Saved DNS and exit-node choices are unchanged."),
	ImpactsConnectivity: true,
})

func captivePortalPrefs(p ipn.PrefsView, active bool) ipn.PrefsView {
	if !active {
		return p
	}
	copy := p.AsStruct()
	copy.ExitNodeID = ""
	copy.ExitNodeIP = netip.Addr{}
	copy.AutoExitNode = ""
	return copy.View()
}

func composeCaptivePortalDNS(cfg *dns.Config, servers []netip.Addr) {
	if cfg == nil || !cfg.AcceptDNS {
		return
	}
	cfg.DefaultResolvers = nil
	for _, ip := range servers {
		cfg.DefaultResolvers = append(cfg.DefaultResolvers, &dnstype.Resolver{Addr: ip.String()})
	}
	delete(cfg.Routes, dnsname.FQDN("."))
}

func (b *LocalBackend) captivePortalEligibleLocked() bool {
	p := b.pm.CurrentPrefs()
	if !buildfeatures.HasCaptivePortal || cmp.Or(b.goos, runtime.GOOS) != "windows" || b.shutdownCalled || b.blocked || b.state != ipn.Running || b.keyExpired ||
		!p.Valid() || !p.WantRunning() || p.LoggedOut() || !p.CorpDNS() || b.sys.ControlKnobs().DisableCaptivePortalDetection.Load() {
		return false
	}
	policy, err := b.polc.GetPreferenceOption(pkey.EnableTailscaleDNS, ptype.ShowChoiceByPolicy)
	if err != nil || !policy.Show() {
		return false
	}
	if p.ExitNodeID() != "" || p.ExitNodeIP().IsValid() || p.AutoExitNode().IsSet() {
		managed, err := b.polc.HasAnyOf(pkey.ExitNodeID, pkey.ExitNodeIP)
		if err != nil || managed {
			return false
		}
	}
	return true
}

func (b *LocalBackend) captivePortalActiveLocked() bool {
	s := &b.windowsPortal
	return s.active && s.network != "" && len(s.dns) != 0 && s.profile == b.pm.CurrentProfile().ID() && b.captivePortalEligibleLocked()
}

// No configuration is persisted. Unknown evidence neither enables nor ends a
// session. The caller must re-read the network before committing the result.
func (b *LocalBackend) recordCaptivePortalProbeLocked(profile ipn.ProfileID, generation uint64, result portalProbeResult, servers []netip.Addr) bool {
	s := &b.windowsPortal
	if result == portalProbeUnknown {
		return false
	}
	if profile != b.pm.CurrentProfile().ID() || generation != s.generation || s.network == "" || !b.captivePortalEligibleLocked() {
		return false
	}
	active := s.active
	if result == portalProbeCaptive && len(servers) != 0 {
		active = true
	}
	if result == portalProbeValidated {
		active = false
	}
	if active == s.active && (!active || slices.Equal(s.dns, servers)) {
		return false
	}
	s.active = active
	s.profile = profile
	s.dns = nil
	if active {
		s.dns = slices.Clone(servers)
	}
	b.setCaptivePortalHealthLocked()
	return true
}

func (b *LocalBackend) setCaptivePortalHealthLocked() {
	if b.captivePortalActiveLocked() {
		b.health.SetUnhealthy(captivePortalLoginWarning, health.Args{})
	} else {
		b.health.SetHealthy(captivePortalLoginWarning)
	}
}

func (b *LocalBackend) wakeWindowsCaptivePortalLocked() {
	if b.windowsPortalWake != nil {
		select {
		case b.windowsPortalWake <- struct{}{}:
		default:
		}
	}
}
