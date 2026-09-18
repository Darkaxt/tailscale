// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"unicode"

	"tailscale.com/util/dnsname"
)

// LocalDNSStatus distinguishes a saved choice from a successfully applied
// engine configuration. Applied is not an assertion of provider reachability.
type LocalDNSStatus struct {
	ProfileID  ProfileID
	Configured bool
	Endpoint   string
	Applied    bool
	Reason     string
}

// LocalDNSUpdate pins a UI edit to the profile from which it was loaded.
type LocalDNSUpdate struct {
	ProfileID ProfileID
	Enabled   bool
	Endpoint  string
}

// ValidateLocalDNSResolver checks the fork's deliberately restricted DoH input
// contract. Errors never include the endpoint, which can identify an account.
func ValidateLocalDNSResolver(endpoint string) error {
	invalid := errors.New("local DNS requires an HTTPS DNS hostname, path, and optional port 443; credentials, queries, fragments and whitespace are not allowed")
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(endpoint, "#") ||
		(u.Port() != "" && u.Port() != "443") || strings.HasSuffix(u.Host, ":") {
		return invalid
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return invalid
	}
	if dnsname.ValidHostname(u.Hostname()) != nil {
		return invalid
	}
	for _, value := range []string{endpoint, u.Path} {
		if strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return invalid
		}
	}
	return nil
}
