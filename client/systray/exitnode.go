// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
)

func exitNodeLANEdit(enabled bool) *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{
		Prefs:                     ipn.Prefs{ExitNodeAllowLANAccess: enabled},
		ExitNodeAllowLANAccessSet: true,
	}
}

func runExitNodeEdit(current []netip.Prefix, enabled bool) *ipn.MaskedPrefs {
	routes := make([]netip.Prefix, 0, len(current)+2)
	for _, route := range current {
		if route.Bits() != 0 {
			routes = append(routes, route)
		}
	}
	if enabled {
		routes = append(routes, tsaddr.ExitRoutes()...)
	}
	return &ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: routes},
		AdvertiseRoutesSet: true,
	}
}
