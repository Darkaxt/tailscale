// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"net/netip"
	"testing"

	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
)

func TestExitNodeLANEdit(t *testing.T) {
	mp := exitNodeLANEdit(true)
	if !mp.ExitNodeAllowLANAccessSet || !mp.ExitNodeAllowLANAccess {
		t.Fatalf("edit = %#v", mp)
	}
}

func TestRunExitNodeEditPreservesNonExitRoutes(t *testing.T) {
	subnet := netip.MustParsePrefix("192.0.2.0/24")
	on := runExitNodeEdit([]netip.Prefix{subnet}, true)
	if !on.AdvertiseRoutesSet || !tsaddr.ContainsExitRoutes(views.SliceOf(on.AdvertiseRoutes)) {
		t.Fatalf("enable edit = %#v", on)
	}
	if len(on.AdvertiseRoutes) != 3 || on.AdvertiseRoutes[0] != subnet {
		t.Fatalf("enable routes = %v", on.AdvertiseRoutes)
	}
	off := runExitNodeEdit(on.AdvertiseRoutes, false)
	if !off.AdvertiseRoutesSet || len(off.AdvertiseRoutes) != 1 || off.AdvertiseRoutes[0] != subnet {
		t.Fatalf("disable routes = %v", off.AdvertiseRoutes)
	}
}
