// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
)

// EditLocalDNS rejects edits from an editor belonging to another profile.
func (b *LocalBackend) EditLocalDNS(actor ipnauth.Actor, update ipn.LocalDNSUpdate) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if update.ProfileID == "" || update.ProfileID != b.pm.CurrentProfile().ID() {
		return errors.New("profile changed; reload DNS settings")
	}
	_, err := b.editPrefsLocked(actor, &ipn.MaskedPrefs{
		Prefs:               ipn.Prefs{LocalDNSOverride: update.Enabled, LocalDNSResolver: update.Endpoint},
		LocalDNSOverrideSet: true, LocalDNSResolverSet: true,
	})
	return err
}

// LocalDNSStatus returns profile-scoped status for the authenticated LocalAPI.
func (b *LocalBackend) LocalDNSStatus() ipn.LocalDNSStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.pm.CurrentPrefs()
	if !p.Valid() {
		return ipn.LocalDNSStatus{Reason: "No profile"}
	}
	s := ipn.LocalDNSStatus{ProfileID: b.pm.CurrentProfile().ID(), Configured: p.LocalDNSOverride(), Endpoint: p.LocalDNSResolver()}
	switch {
	case !s.Configured:
		s.Reason = "Using Tailscale DNS selection"
	case !p.CorpDNS():
		s.Reason = "Accept DNS is disabled"
	case b.keyExpired:
		s.Reason = "Node key expired"
	case b.state != ipn.Running || !p.WantRunning() || p.LoggedOut():
		s.Reason = "Tailscale is not running"
	default:
		policy, err := b.polc.GetPreferenceOption(pkey.EnableTailscaleDNS, ptype.ShowChoiceByPolicy)
		if err != nil || !policy.Show() {
			s.Reason = "DNS is managed by policy"
		} else if b.localDNSAppliedProfile == b.pm.CurrentProfile().ID() && b.localDNSAppliedEndpoint == s.Endpoint {
			s.Applied = true
			s.Reason = "Applied; provider reachability not verified"
		} else {
			s.Reason = "Not applied"
		}
	}
	return s
}
