// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_syspolicy

package systray

import (
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

func policyVisible(*policyclient.PolicySnapshot, pkey.Key) bool { return true }

func policyPreferenceEditable(*policyclient.PolicySnapshot, pkey.Key) bool { return true }

func policyBool(*policyclient.PolicySnapshot, pkey.Key) (bool, bool) { return false, false }
