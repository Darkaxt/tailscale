// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package resolver

import (
	"io"
	"net/http"
	"strings"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestLocalDNSResponseMetadataSurvivesPrimaryAndRecovery(t *testing.T) {
	const primary = "https://resolver.example/private-profile"
	for _, recover := range []bool{false, true} {
		t.Run(map[bool]string{false: "primary", true: "recovery"}[recover], func(t *testing.T) {
			query := makeTestRequest(t, "example.com.", dns.TypeA, 0)
			client := &http.Client{Transport: localDoHRoundTrip(func(r *http.Request) (*http.Response, error) {
				if recover && r.URL.String() == primary {
					return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
				}
				var reply dns.Message
				if err := reply.Unpack(query); err != nil {
					t.Fatal(err)
				}
				reply.Response = true
				wire, err := reply.Pack()
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {dohType}, "X-Test-Source": {r.URL.String()}}, Body: io.NopCloser(strings.NewReader(string(wire)))}, nil
			})}
			f := &forwarder{logf: t.Logf, health: health.NewTracker(eventbustest.NewBus(t))}
			selected := &dnstype.Resolver{Addr: primary, LocalOverride: true}
			f.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{".": {selected}}, true)
			f.dohClient = map[string]*http.Client{"local:" + primary: client, "local:" + localDNSRecoveryEndpoint: client}
			result, err := f.send(t.Context(), &forwardQuery{packet: query, family: "udp", localDefault: true, routesGeneration: f.routesGeneration}, resolverAndDelay{name: selected})
			if err != nil {
				t.Fatal(err)
			}
			want := primary
			if recover {
				want = localDNSRecoveryEndpoint
			}
			if result.DoHMeta == nil || result.DoHMeta.RequestURL.String() != want || result.DoHMeta.ResponseHeader.Get("X-Test-Source") != want {
				t.Fatalf("metadata did not identify actual responder: %#v", result.DoHMeta)
			}
			if !localDNSResponseValid(query, result.Bs) {
				t.Fatal("response wire changed")
			}
			if f.health.IsUnhealthy(localDNSRecovery) != recover {
				t.Fatal("recovery health changed")
			}
		})
	}
}
