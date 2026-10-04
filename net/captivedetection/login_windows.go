// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
)

// LoginNetwork is a snapshot of one physical IPv4 default network. Key is an
// opaque network-generation fingerprint, not a hostname or a portal token.
type LoginNetwork struct {
	Key   string
	Index int
	DNS   []netip.Addr
}

func WindowsLoginNetwork() (LoginNetwork, error) {
	a, err := netmon.GetWindowsDefault(windows.AF_INET)
	if err != nil {
		return LoginNetwork{}, err
	}
	if a == nil || (a.IfType != winipcfg.IfTypeEthernetCSMACD && a.IfType != winipcfg.IfTypeIEEE80211) {
		return LoginNetwork{}, nil
	}
	n := LoginNetwork{Index: int(a.IfIndex)}
	identity := []string{fmt.Sprint(a.LUID), a.NetworkGUID.String()}
	for p := a.FirstUnicastAddress; p != nil; p = p.Next {
		identity = append(identity, "ip:"+p.Address.IP().String())
	}
	for p := a.FirstGatewayAddress; p != nil; p = p.Next {
		identity = append(identity, "gw:"+p.Address.IP().String())
	}
	for p := a.FirstDNSServerAddress; p != nil; p = p.Next {
		ip, ok := netip.AddrFromSlice(p.Address.IP())
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsUnspecified() || ip.IsLoopback() || tsaddr.IsTailscaleIP(ip) {
			continue
		}
		if ip.Is6() && ip.IsLinkLocalUnicast() {
			ip = ip.WithZone(fmt.Sprint(a.IPv6IfIndex))
		}
		n.DNS = append(n.DNS, ip)
		identity = append(identity, "dns:"+ip.String())
	}
	sort.Strings(identity)
	n.Key = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(identity))))
	return n, nil
}
