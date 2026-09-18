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
	if update.FollowAndroid && b.localDNSReadPlatform == nil {
		return errors.New("Android provider source unavailable")
	}
	endpoint := update.Endpoint
	if update.FollowAndroid {
		endpoint = b.pm.CurrentPrefs().LocalDNSResolver()
	}
	_, err := b.editPrefsLocked(actor, &ipn.MaskedPrefs{
		Prefs:               ipn.Prefs{LocalDNSOverride: update.Enabled, LocalDNSResolver: endpoint, LocalDNSFollowAndroid: update.FollowAndroid},
		LocalDNSOverrideSet: true, LocalDNSResolverSet: true, LocalDNSFollowAndroidSet: true,
	})
	b.syncLocalDNSObservationLocked()
	return err
}

// SetLocalDNSPlatform installs platform-owned observation and synchronous reads.
// Callbacks must not reenter the backend synchronously. Observation is installed
// before the first read so a concurrent save cannot be missed.
func (b *LocalBackend) SetLocalDNSPlatform(read func() (string, string, error), observe func(bool) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.localDNSReadPlatform = read
	b.localDNSObservePlatform = observe
	b.syncLocalDNSObservationLocked()
}

func (b *LocalBackend) syncLocalDNSObservationLocked() {
	p := b.pm.CurrentPrefs()
	want := !b.shutdownCalled && p.Valid() && p.LocalDNSOverride() && p.LocalDNSFollowAndroid() && p.WantRunning() && !p.LoggedOut() && p.CorpDNS()
	if want {
		policy, err := b.polc.GetPreferenceOption(pkey.EnableTailscaleDNS, ptype.ShowChoiceByPolicy)
		want = err == nil && policy.Show()
	}
	if b.localDNSObservePlatform == nil || want == b.localDNSObserving {
		return
	}
	err := b.localDNSObservePlatform(want)
	b.localDNSObservationFailed = err != nil
	if err == nil {
		b.localDNSObserving = want
	}
}

func (b *LocalBackend) localDNSPlatformEndpointLocked() (endpoint, mode string, err error) {
	if b.localDNSReadPlatform == nil || b.localDNSObservationFailed {
		return "", "", errors.New("Android provider observation unavailable")
	}
	host, mode, err := b.localDNSReadPlatform()
	if err != nil {
		return "", mode, errors.New("Android provider could not be read")
	}
	endpoint, err = ipn.AndroidDNSProvider(host)
	return endpoint, mode, err
}

// NotifyLocalDNSPlatformChanged carries no cached value/profile. Even an old
// callback can only read and reconfigure the current profile and current source.
func (b *LocalBackend) NotifyLocalDNSPlatformChanged() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.authReconfigLocked()
	p := b.pm.CurrentPrefs()
	b.sendLocked(ipn.Notify{Prefs: &p})
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
	s.FollowAndroid = p.LocalDNSFollowAndroid()
	s.ManualEndpoint = p.LocalDNSResolver()
	var sourceErr error
	if s.Configured && s.FollowAndroid {
		s.Endpoint, s.SystemMode, sourceErr = b.localDNSPlatformEndpointLocked()
	}
	switch {
	case !s.Configured:
		s.Reason = "Using Tailscale DNS selection"
	case !p.CorpDNS():
		s.Reason = "Accept DNS is disabled"
	case b.keyExpired:
		s.Reason = "Node key expired"
	case b.state != ipn.Running || !p.WantRunning() || p.LoggedOut():
		s.Reason = "Tailscale is not running"
	case sourceErr != nil:
		s.Reason = "Android provider unavailable or unsupported; default DNS fails closed"
	case s.FollowAndroid && s.SystemMode != "opportunistic" && s.SystemMode != "off":
		s.Reason = "Android Private DNS mode conflicted or unknown; effectiveness unverified"
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
