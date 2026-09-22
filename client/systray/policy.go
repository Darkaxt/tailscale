// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package systray

import (
	"strings"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
)

func policyVisible(policy *policyclient.PolicySnapshot, key pkey.Key) bool {
	value := policy.Get(key)
	switch value := value.(type) {
	case ptype.Visibility:
		return value.Show()
	case string:
		return !strings.EqualFold(value, "hide")
	default:
		return true
	}
}

func policyPreferenceEditable(policy *policyclient.PolicySnapshot, key pkey.Key) bool {
	value := policy.Get(key)
	switch value := value.(type) {
	case ptype.PreferenceOption:
		return value.Show()
	case string:
		return !strings.EqualFold(value, "always") && !strings.EqualFold(value, "never")
	default:
		return true
	}
}

func policyBool(policy *policyclient.PolicySnapshot, key pkey.Key) (value, configured bool) {
	value, configured = policy.Get(key).(bool)
	return value, configured
}
