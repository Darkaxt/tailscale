// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package systray

import (
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

func TestPolicyGatesWindowsControlSurface(t *testing.T) {
	policy := setting.NewSnapshot(map[pkey.Key]setting.RawItem{
		pkey.AdminConsoleVisibility: setting.RawItemOf(ptype.HiddenByPolicy),
		pkey.EnableTailscaleDNS:     setting.RawItemOf(ptype.AlwaysByPolicy),
		pkey.AlwaysOn:               setting.RawItemOf(true),
	})
	if policyVisible(policy, pkey.AdminConsoleVisibility) {
		t.Fatal("hidden admin console policy was ignored")
	}
	if policyPreferenceEditable(policy, pkey.EnableTailscaleDNS) {
		t.Fatal("managed DNS preference remained editable")
	}
	if enabled, configured := policyBool(policy, pkey.AlwaysOn); !configured || !enabled {
		t.Fatalf("AlwaysOn = (%v, %v), want (true, true)", enabled, configured)
	}
	if !policyVisible(policy, pkey.NetworkDevicesVisibility) {
		t.Fatal("unconfigured visibility must default to visible")
	}
	if !policyPreferenceEditable(policy, pkey.EnableTailscaleSubnets) {
		t.Fatal("unconfigured preference must remain editable")
	}
}
