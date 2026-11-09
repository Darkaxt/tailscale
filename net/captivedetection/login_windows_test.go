// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"net/netip"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func loginTestAddress(text string) windows.SocketAddress {
	ip := netip.MustParseAddr(text)
	if ip.Is4() {
		a := &windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: ip.As4()}
		return windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(a)), SockaddrLength: int32(unsafe.Sizeof(*a))}
	}
	a := &windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: ip.As16()}
	return windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(a)), SockaddrLength: int32(unsafe.Sizeof(*a))}
}

func TestWindowsLoginNetworkMatchesRouteLUID(t *testing.T) {
	wrong := &winipcfg.IPAdapterAddresses{LUID: 10, IfIndex: 100}
	want := &winipcfg.IPAdapterAddresses{LUID: 20, IfIndex: 200}
	got := loginNetworkForInterface(20, []*winipcfg.IPAdapterAddresses{wrong, want})
	if got.Index != 200 || got.Key == "" {
		t.Fatalf("selected network = %+v; want index 200 with identity", got)
	}
	if other := loginNetworkForInterface(10, []*winipcfg.IPAdapterAddresses{wrong, want}); other.Key == got.Key {
		t.Fatal("different adapters share a network-generation fingerprint")
	}
	for _, adapters := range [][]*winipcfg.IPAdapterAddresses{nil, {wrong}} {
		if got := loginNetworkForInterface(20, adapters); !reflect.DeepEqual(got, LoginNetwork{}) {
			t.Fatalf("missing selected adapter = %+v; want no current network", got)
		}
	}
}

func TestWindowsLoginNetworkPreservesScopedDNSAndFingerprint(t *testing.T) {
	adapter := &winipcfg.IPAdapterAddresses{LUID: 20, IfIndex: 200, IPv6IfIndex: 201}
	var dns *windows.IpAdapterDnsServerAdapter
	for _, address := range []string{"fe80::53", "9.9.9.9", "100.100.100.100", "127.0.0.1", "0.0.0.0"} {
		dns = &windows.IpAdapterDnsServerAdapter{Next: dns, Address: loginTestAddress(address)}
	}
	adapter.FirstDNSServerAddress = dns
	adapter.FirstUnicastAddress = &windows.IpAdapterUnicastAddress{Address: loginTestAddress("192.0.2.10")}
	adapter.FirstGatewayAddress = &winipcfg.IPAdapterGatewayAddress{Address: loginTestAddress("192.0.2.1")}
	adapters := []*winipcfg.IPAdapterAddresses{adapter}
	got := loginNetworkForInterface(20, adapters)
	wantDNS := []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("fe80::53%201")}
	if !reflect.DeepEqual(got.DNS, wantDNS) {
		t.Fatalf("DNS = %v; want %v", got.DNS, wantDNS)
	}
	if again := loginNetworkForInterface(20, adapters); again.Key != got.Key {
		t.Fatal("unchanged snapshot changed its fingerprint")
	}
	adapter.FirstUnicastAddress.Address = loginTestAddress("192.0.2.11")
	if next := loginNetworkForInterface(20, adapters); next.Key == got.Key {
		t.Fatal("changed local address did not change network fingerprint")
	}
	adapter.FirstUnicastAddress.Address = loginTestAddress("192.0.2.10")
	adapter.FirstGatewayAddress.Address = loginTestAddress("192.0.2.2")
	if next := loginNetworkForInterface(20, adapters); next.Key == got.Key {
		t.Fatal("changed gateway did not change network fingerprint")
	}
}
