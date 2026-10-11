// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/types/dnstype"
)

const localDNSRecoveryEndpoint = "https://cloudflare-dns.com/dns-query"

var localDNSRecovery = health.Register(&health.Warnable{
	Code:     "local-dns-encrypted-recovery",
	Title:    "DNS provider unavailable",
	Severity: health.SeverityLow,
	Text:     health.StaticMessage("The selected DNS provider failed. Public DNS is using Cloudflare over HTTPS; provider filtering is temporarily bypassed."),
})

// localDNSUnavailable deliberately excludes DNS rcodes, configuration errors,
// HTTP 4xx/redirects, and certificate rejection. None proves a provider outage.
func localDNSUnavailable(err error) bool {
	var cert *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	if errors.As(err, &cert) || errors.As(err, &authority) || errors.As(err, &invalid) || errors.As(err, &hostname) {
		return false
	}
	var op *net.OpError
	var network net.Error
	return errors.Is(err, errServerFailure) || errors.As(err, &op) ||
		(errors.As(err, &network) && network.Timeout()) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// localDNSResponseValid rejects a mismatched or malformed reply before recovery
// can report success. A legitimate negative/block answer remains authoritative.
func localDNSResponseValid(query, response []byte) bool {
	var q, r dns.Message
	if q.Unpack(query) != nil || r.Unpack(response) != nil || !r.Response ||
		r.ID != q.ID || r.OpCode != q.OpCode || len(q.Questions) == 0 || len(q.Questions) != len(r.Questions) {
		return false
	}
	for i, question := range q.Questions {
		answer := r.Questions[i]
		if question.Type != answer.Type || question.Class != answer.Class || !strings.EqualFold(question.Name.String(), answer.Name.String()) {
			return false
		}
	}
	return true
}

// noteLocalDNSRecovery prevents a late query from restoring an obsolete warning
// after a profile/network/DNS reconfiguration.
func (f *forwarder) noteLocalDNSRecovery(fq *forwardQuery, active bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !fq.localDefault || fq.routesGeneration != f.routesGeneration {
		return false
	}
	if active {
		f.health.SetUnhealthy(localDNSRecovery, nil)
	} else {
		f.health.SetHealthy(localDNSRecovery)
	}
	return true
}

func (f *forwarder) sendLocalDNS(ctx context.Context, fq *forwardQuery, selected *dnstype.Resolver) ([]byte, error) {
	client, err := f.getLocalDoHClient(selected)
	if err != nil {
		return nil, err // unavailable Android source is not a transport outage
	}
	res, err := f.sendDoH(ctx, selected.Addr, client, fq.packet)
	if err == nil {
		if fq.localDefault && !localDNSResponseValid(fq.packet, res) {
			return nil, errors.New("invalid local DNS response")
		}
		f.noteLocalDNSRecovery(fq, false)
		return checkResponseSizeAndSetTC(res, fq.packet, fq.family, f.logf), nil
	}
	// Do not wrap transport errors: http errors can include the private URL.
	f.mu.Lock()
	current := fq.localDefault && fq.routesGeneration == f.routesGeneration
	f.mu.Unlock()
	if ctx.Err() != nil || !localDNSUnavailable(err) || selected.Addr == localDNSRecoveryEndpoint || !current {
		return nil, errors.New("local DoH query failed; no fallback attempted")
	}
	// The same dedicated transport preserves exit routing, verifies TLS and
	// rejects redirects. Its maintained static IPs do not depend on failed DHCP.
	fallback := &dnstype.Resolver{Addr: localDNSRecoveryEndpoint, LocalOverride: true}
	client, err = f.getLocalDoHClient(fallback)
	if err == nil && ctx.Err() == nil {
		res, err = f.sendDoH(ctx, fallback.Addr, client, fq.packet)
		if err == nil && localDNSResponseValid(fq.packet, res) && ctx.Err() == nil {
			f.noteLocalDNSRecovery(fq, true)
			return checkResponseSizeAndSetTC(res, fq.packet, fq.family, f.logf), nil
		}
	}
	return nil, errors.New("local DoH and encrypted outage recovery failed")
}
