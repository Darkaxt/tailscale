// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
)

// getLocalDoHClient uses route-aware dials for user-selected DNS. Unlike the
// legacy provider transport it must honor exit-node routing regardless of
// control-plane feature knobs. Only the resolver hostname may use bootstrap;
// ordinary question names never go to bootstrap or another default resolver.
func (f *forwarder) getLocalDoHClient(selected *dnstype.Resolver) (*http.Client, error) {
	endpoint := selected.Addr
	f.mu.Lock()
	defer f.mu.Unlock()
	key := "local:" + endpoint
	if c := f.dohClient[key]; c != nil {
		return c, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("invalid local DoH endpoint")
	}
	c := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     dohIdleConnTimeout,
			MaxIdleConnsPerHost: 1,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil || host != u.Hostname() || port != "443" || !strings.HasPrefix(network, "tcp") {
					return nil, errors.New("unexpected local DoH dial target")
				}
				ips := publicdns.DoHIPsOfBase(endpoint)
				if len(ips) == 0 {
					ips, err = f.lookupLocalDoHHost(ctx, host, selected.LocalBootstrapResolvers)
					if err != nil || len(ips) == 0 {
						return nil, errors.New("local DoH bootstrap failed")
					}
				}
				dial := dnscache.Dialer(f.dialer.UserDial, &dnscache.Resolver{
					SingleHost: host, SingleHostStaticResult: ips, Logf: logger.Discard,
				})
				return dial(ctx, network, address)
			},
		},
	}
	if f.dohClient == nil {
		f.dohClient = make(map[string]*http.Client)
	}
	f.dohClient[key] = c
	return c, nil
}

// lookupLocalDoHHost uses explicit base DNS IPs through Tailscale's protected
// system dialer. It never calls the OS default lookup (which could recurse into
// quad-100). This can expose the provider hostname in plaintext outside an exit
// node, but it never receives or resolves an ordinary user's DNS question.
func (f *forwarder) lookupLocalDoHHost(ctx context.Context, host string, servers []netip.Addr) ([]netip.Addr, error) {
	for _, server := range servers {
		if !server.IsValid() || server.IsUnspecified() || server.IsLoopback() || tsaddr.IsTailscaleIP(server) {
			continue
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// SystemDial wraps net.Conn, so it does not retain net.PacketConn.
			// Use DNS-over-TCP explicitly to match Go's stream DNS framing.
			return f.dialer.SystemDial(ctx, "tcp", net.JoinHostPort(server.String(), "53"))
		}}
		ips, err := resolver.LookupNetIP(ctx, "ip", host)
		if err == nil && len(ips) != 0 {
			return ips, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("local DoH base DNS bootstrap unavailable")
}

// retireLocalDoHClientsLocked prevents reuse of idle connections across DNS
// configuration/exit-node changes and bounds the cache to the current selection.
func (f *forwarder) retireLocalDoHClientsLocked() {
	for key, client := range f.dohClient {
		if strings.HasPrefix(key, "local:") {
			client.CloseIdleConnections()
			delete(f.dohClient, key)
		}
	}
}
