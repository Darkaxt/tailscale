// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && !ts_omit_captiveportal

package ipnlocal

import (
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/captivedetection"
	"tailscale.com/net/netmon"
)

func windowsPortalEvidence(result captivedetection.LoginStatus) portalProbeResult {
	switch result {
	case captivedetection.LoginCaptive:
		return portalProbeCaptive
	case captivedetection.LoginValidated:
		return portalProbeValidated
	default:
		return portalProbeUnknown
	}
}

func (b *LocalBackend) startWindowsCaptivePortalLocked() {
	if b.windowsPortalWake != nil {
		return
	}
	b.windowsPortalWake = make(chan struct{}, 1)
	b.goTracker.Go(b.monitorWindowsCaptivePortal)
	b.wakeWindowsCaptivePortalLocked()
}

func (b *LocalBackend) syncWindowsCaptiveNetworkLocked() bool {
	network, err := captivedetection.WindowsLoginNetwork()
	if err != nil {
		return false
	} // an inspection failure is not successful login
	return b.updateWindowsCaptiveNetworkLocked(network)
}

func (b *LocalBackend) updateWindowsCaptiveNetworkLocked(network captivedetection.LoginNetwork) bool {
	s := &b.windowsPortal
	stale := s.network != network.Key || s.profile != b.pm.CurrentProfile().ID() || s.active && !b.captivePortalEligibleLocked()
	if !stale {
		return false
	}
	wasActive := s.active
	s.network = network.Key
	s.generation++
	s.active = false
	s.dns = nil
	s.profile = b.pm.CurrentProfile().ID()
	s.applied = false
	b.setCaptivePortalHealthLocked()
	return wasActive
}

func (b *LocalBackend) monitorWindowsCaptivePortal() {
	unregister := b.sys.NetMon.Get().RegisterChangeCallback(func(*netmon.ChangeDelta) {
		b.mu.Lock()
		b.wakeWindowsCaptivePortalLocked()
		b.mu.Unlock()
	})
	defer unregister()
	// Poll only during a confirmed login session, to detect completion when the
	// interface configuration does not change. This never expires the session.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	detector := captivedetection.NewDetector(func(string, ...any) {}) // never log URLs
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-b.windowsPortalWake:
		case <-ticker.C:
			b.mu.Lock()
			active := b.captivePortalActiveLocked()
			b.mu.Unlock()
			if !active {
				continue
			}
		}
		network, err := captivedetection.WindowsLoginNetwork()
		if err != nil {
			continue
		}
		b.mu.Lock()
		if b.updateWindowsCaptiveNetworkLocked(network) {
			b.authReconfigLocked()
			prefs := b.pm.CurrentPrefs()
			b.sendLocked(ipn.Notify{Prefs: &prefs})
		}
		profile, generation := b.pm.CurrentProfile().ID(), b.windowsPortal.generation
		eligible := b.captivePortalEligibleLocked() && b.windowsPortal.network == network.Key
		var dm = b.currentNode().DERPMap()
		b.mu.Unlock()
		if !eligible {
			continue
		}
		result := detector.ProbeLogin(b.ctx, network.Index, dm)
		// An inspection failure must not let evidence for an old network commit.
		// It also does not prove login completion or expire an active session.
		current, err := captivedetection.WindowsLoginNetwork()
		if err != nil {
			continue
		}
		b.mu.Lock()
		changed := b.updateWindowsCaptiveNetworkLocked(current)
		if b.recordCaptivePortalProbeLocked(profile, generation, windowsPortalEvidence(result), network.DNS) {
			changed = true
		}
		if changed {
			b.authReconfigLocked()
			prefs := b.pm.CurrentPrefs()
			b.sendLocked(ipn.Notify{Prefs: &prefs})
		}
		b.mu.Unlock()
	}
}
