// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"tailscale.com/tailcfg"
)

// LoginStatus separates an outage from positive portal or internet evidence.
// Unknown must not enable login mode or restore a previously captive network.
type LoginStatus uint8

const (
	LoginUnknown LoginStatus = iota
	LoginCaptive
	LoginValidated
)

// ProbeLogin checks known endpoints without DNS, proxies, cookies or redirect
// following. The Windows socket is bound to the supplied physical interface.
// Probe timeouts are diagnostic boundaries, never login-mode expiry timers.
func (d *Detector) ProbeLogin(ctx context.Context, ifIndex int, dm *tailcfg.DERPMap) LoginStatus {
	endpoints := availableEndpoints(dm, 0, d.logf, "windows")
	validated := 0
	probed := map[netip.Addr]bool{}
	for _, e := range endpoints {
		ip, err := netip.ParseAddr(e.URL.Hostname())
		if err != nil || !ip.Is4() || probed[ip] {
			continue
		}
		if len(probed) == 5 {
			break
		}
		probed[ip] = true
		if ctx.Err() != nil {
			return LoginUnknown
		}
		switch d.probeLoginEndpoint(ctx, ifIndex, e) {
		case LoginCaptive:
			return LoginCaptive
		case LoginValidated:
			validated++
		}
	}
	// More than one independent probe reduces premature restoration on networks
	// that whitelist a connectivity endpoint. No response/error means unknown.
	if validated >= 2 {
		return LoginValidated
	}
	return LoginUnknown
}

func (d *Detector) probeLoginEndpoint(ctx context.Context, ifIndex int, e Endpoint) LoginStatus {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL.String(), nil)
	if err != nil {
		return LoginUnknown
	}
	req.Header.Set("Cache-Control", "no-cache, no-store")
	if e.SupportsTailscaleChallenge {
		req.Header.Set("X-Tailscale-Challenge", "ts_"+e.URL.Host)
	}
	d.mu.Lock()
	d.currIfIndex = ifIndex
	d.mu.Unlock()
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return LoginUnknown
	}
	defer resp.Body.Close()
	// Only a redirect is positive evidence. 404/403/5xx, arbitrary HTML and
	// TLS/DNS/transport failures must not cause plaintext fallback.
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
		u, err := resp.Location()
		if err != nil || !safeLoginLocation(u) {
			return LoginUnknown
		}
		return LoginCaptive
	}
	if resp.StatusCode != e.StatusCode {
		return LoginUnknown
	}
	if e.responseLooksLikeCaptive(resp, func(string, ...any) {}) {
		return LoginUnknown
	}
	return LoginValidated
}

func safeLoginLocation(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" &&
		u.User == nil && !strings.ContainsAny(u.String(), "\r\n\t")
}
