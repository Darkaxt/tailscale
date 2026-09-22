// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"fmt"

	"tailscale.com/ipn"
	"tailscale.com/types/opt"
	"tailscale.com/util/syspolicy/pkey"
)

type prefsEditor interface {
	EditPrefs(context.Context, *ipn.MaskedPrefs) (*ipn.Prefs, error)
}

func preferencePolicyKey(action preferenceAction) pkey.Key {
	switch action {
	case prefAllowIncoming:
		return pkey.EnableIncomingConnections
	case prefUseDNS:
		return pkey.EnableTailscaleDNS
	case prefUseSubnets:
		return pkey.EnableTailscaleSubnets
	case prefAutoUpdate:
		return pkey.ApplyUpdates
	case prefUnattended:
		return pkey.EnableServerMode
	default:
		return ""
	}
}

type localDNSClient interface {
	LocalDNSStatus(context.Context) (*ipn.LocalDNSStatus, error)
	EditLocalDNS(context.Context, ipn.LocalDNSUpdate) (*ipn.LocalDNSStatus, error)
}

type preferenceAction string

const (
	prefAllowIncoming preferenceAction = "allow-incoming"
	prefUseDNS        preferenceAction = "use-dns"
	prefUseSubnets    preferenceAction = "use-subnets"
	prefAutoUpdate    preferenceAction = "auto-update"
	prefUnattended    preferenceAction = "unattended"
)

type preferenceItem struct {
	action    preferenceAction
	title     string
	checked   bool
	available bool
}

func preferenceSnapshot(prefs *ipn.Prefs) []preferenceItem {
	if prefs == nil {
		return nil
	}
	return []preferenceItem{
		{action: prefAllowIncoming, title: "Allow incoming connections", checked: !prefs.ShieldsUp, available: true},
		{action: prefUseDNS, title: "Use TailDNS settings", checked: prefs.CorpDNS, available: true},
		{action: prefUseSubnets, title: "Use Tailscale subnets", checked: prefs.RouteAll, available: true},
		{action: prefAutoUpdate, title: "Automatically install TailDNS updates", checked: prefs.AutoUpdate.Apply.EqualBool(true), available: true},
		{action: prefUnattended, title: "Run unattended", checked: prefs.ForceDaemon, available: true},
	}
}

func preferenceEdit(action preferenceAction, enabled bool) (*ipn.MaskedPrefs, error) {
	mp := new(ipn.MaskedPrefs)
	switch action {
	case prefAllowIncoming:
		mp.ShieldsUp = !enabled
		mp.ShieldsUpSet = true
	case prefUseDNS:
		mp.CorpDNS = enabled
		mp.CorpDNSSet = true
	case prefUseSubnets:
		mp.RouteAll = enabled
		mp.RouteAllSet = true
	case prefAutoUpdate:
		mp.AutoUpdate = ipn.AutoUpdatePrefs{Check: enabled, Apply: opt.NewBool(enabled)}
		mp.AutoUpdateSet = ipn.AutoUpdatePrefsMask{CheckSet: true, ApplySet: true}
	case prefUnattended:
		mp.ForceDaemon = enabled
		mp.ForceDaemonSet = true
	default:
		return nil, fmt.Errorf("unknown tray preference %q", action)
	}
	return mp, nil
}

func resetPreferenceEdit() *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll:   true,
			CorpDNS:    true,
			AutoUpdate: ipn.AutoUpdatePrefs{Check: true, Apply: opt.NewBool(false)},
		},
		RouteAllSet:               true,
		ExitNodeIDSet:             true,
		ExitNodeAllowLANAccessSet: true,
		CorpDNSSet:                true,
		LocalDNSOverrideSet:       true,
		ShieldsUpSet:              true,
		ForceDaemonSet:            true,
		AutoUpdateSet:             ipn.AutoUpdatePrefsMask{CheckSet: true, ApplySet: true},
	}
}

func applyPreference(ctx context.Context, editor prefsEditor, action preferenceAction, enabled bool) error {
	mp, err := preferenceEdit(action, enabled)
	if err != nil {
		return err
	}
	_, err = editor.EditPrefs(ctx, mp)
	return err
}

func applyLocalDNS(ctx context.Context, client localDNSClient, endpoint string) error {
	if err := ipn.ValidateLocalDNSResolver(endpoint); err != nil {
		return err
	}
	status, err := client.LocalDNSStatus(ctx)
	if err != nil {
		return err
	}
	_, err = client.EditLocalDNS(ctx, ipn.LocalDNSUpdate{
		ProfileID: status.ProfileID,
		Enabled:   true,
		Endpoint:  endpoint,
	})
	return err
}

func disableLocalDNS(ctx context.Context, client localDNSClient) error {
	status, err := client.LocalDNSStatus(ctx)
	if err != nil {
		return err
	}
	_, err = client.EditLocalDNS(ctx, ipn.LocalDNSUpdate{ProfileID: status.ProfileID})
	return err
}
