// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestLocalDNSOutageRecovery(t *testing.T) {
	const primary = "https://resolver.example/private-profile"
	const fallback = "https://cloudflare-dns.com/dns-query"
	for _, tt := range []struct {
		name                                                   string
		status                                                 int
		rcode                                                  dns.RCode
		transport                                              error
		suffix                                                 dnsname.FQDN
		explicit, cancelled, fallbackFails, malformed, recover bool
		wantFallback                                           bool
		wantCode                                               dns.RCode
	}{
		{name: "HTTP503", status: 503, wantFallback: true},
		{name: "connection-refused", transport: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, wantFallback: true},
		{name: "healthy", status: 200},
		{name: "NXDOMAIN", status: 200, rcode: dns.RCodeNameError, wantCode: dns.RCodeNameError},
		{name: "REFUSED", status: 200, rcode: dns.RCodeRefused, wantCode: dns.RCodeRefused},
		{name: "SERVFAIL-not-proof-of-outage", status: 200, rcode: dns.RCodeServerFailure, wantCode: dns.RCodeServerFailure},
		{name: "HTTP403", status: 403, wantCode: dns.RCodeServerFailure},
		{name: "redirect", status: 302, wantCode: dns.RCodeServerFailure},
		{name: "certificate-rejected", transport: x509.UnknownAuthorityError{}, wantCode: dns.RCodeServerFailure},
		{name: "split-route", status: 503, suffix: "example.com.", wantCode: dns.RCodeServerFailure},
		{name: "explicit-exit-query", status: 503, explicit: true, wantCode: dns.RCodeServerFailure},
		{name: "cancelled", status: 503, cancelled: true},
		{name: "both-fail", status: 503, fallbackFails: true, wantFallback: true, wantCode: dns.RCodeServerFailure},
		{name: "malformed-fallback", status: 503, malformed: true, wantFallback: true, wantCode: dns.RCodeServerFailure},
		{name: "return-to-primary", status: 503, recover: true, wantFallback: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			var orderMu sync.Mutex
			var primaryStatus atomic.Int32
			primaryStatus.Store(int32(tt.status))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				packet, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				var msg dns.Message
				if err := msg.Unpack(packet); err != nil {
					t.Error(err)
					return
				}
				msg.Response = true
				msg.RCode = tt.rcode
				status := int(primaryStatus.Load())
				if r.URL.Path == "/fallback" {
					status, msg.RCode = 200, dns.RCodeSuccess
					if tt.fallbackFails {
						status = 503
					}
					if tt.malformed {
						msg.ID++
					}
				}
				w.Header().Set("Content-Type", dohType)
				w.WriteHeader(status)
				answer, _ := msg.Pack()
				w.Write(answer)
			}))
			defer server.Close()
			client := func(label, path string) *http.Client {
				return &http.Client{Transport: localDoHRoundTrip(func(r *http.Request) (*http.Response, error) {
					orderMu.Lock()
					order = append(order, label)
					orderMu.Unlock()
					if label == "primary" && tt.transport != nil {
						return nil, tt.transport
					}
					r = r.Clone(r.Context())
					u, _ := url.Parse(server.URL + path)
					r.URL = u
					return server.Client().Transport.RoundTrip(r)
				})}
			}
			bus := eventbustest.NewBus(t)
			ht := health.NewTracker(bus)
			f := &forwarder{logf: t.Logf, health: ht}
			suffix := tt.suffix
			if suffix == "" {
				suffix = "."
			}
			selected := &dnstype.Resolver{Addr: primary, LocalOverride: true}
			f.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{suffix: {selected}}, true)
			f.dohClient = map[string]*http.Client{"local:" + primary: client("primary", "/primary"), "local:" + fallback: client("fallback", "/fallback")}
			query := packet{bs: makeTestRequest(t, "www.example.com.", dns.TypeA, 0), family: "udp"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelled {
				cancel()
			}
			run := func() {
				responses := make(chan *Response, 1)
				var explicit []resolverAndDelay
				if tt.explicit {
					explicit = []resolverAndDelay{{name: selected}}
				}
				err := f.forwardWithDestChan(ctx, query, responses, explicit...)
				if tt.cancelled {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var response dns.Message
				if err := response.Unpack((<-responses).Bs); err != nil {
					t.Fatal(err)
				}
				if response.RCode != tt.wantCode {
					t.Errorf("rcode=%v; want %v", response.RCode, tt.wantCode)
				}
			}
			run()
			orderMu.Lock()
			gotOrder := append([]string(nil), order...)
			orderMu.Unlock()
			wantOrder := []string{"primary"}
			if tt.cancelled { // primary may be scheduled before or after cancellation
				for _, label := range gotOrder {
					if label == "fallback" {
						t.Fatal("fallback after cancellation")
					}
				}
				return
			}
			if tt.wantFallback {
				wantOrder = append(wantOrder, "fallback")
			}
			if !reflect.DeepEqual(gotOrder, wantOrder) {
				t.Fatalf("request order=%v; want %v", gotOrder, wantOrder)
			}
			if got, want := ht.IsUnhealthy(localDNSRecovery), tt.wantFallback && !tt.fallbackFails && !tt.malformed; got != want {
				t.Fatalf("recovery warning=%v; want %v", got, want)
			}
			if tt.recover {
				primaryStatus.Store(200)
				run()
				orderMu.Lock()
				defer orderMu.Unlock()
				if !reflect.DeepEqual(order, []string{"primary", "fallback", "primary"}) {
					t.Fatalf("did not return to primary: %v", order)
				}
				if ht.IsUnhealthy(localDNSRecovery) {
					t.Fatal("recovery warning survived primary recovery")
				}
			}
			f.setRoutes(nil, false)
			if ht.IsUnhealthy(localDNSRecovery) {
				t.Fatal("recovery warning survived reconfiguration")
			}
		})
	}
}

func TestLocalDNSOutageReconfiguration(t *testing.T) {
	const primary = "https://resolver.example/private-profile"
	entered, release := make(chan struct{}), make(chan struct{})
	f := &forwarder{logf: t.Logf, health: health.NewTracker(eventbustest.NewBus(t))}
	f.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: primary, LocalOverride: true}}}, true)
	f.dohClient = map[string]*http.Client{"local:" + primary: {Transport: localDoHRoundTrip(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 503, Body: io.NopCloser(http.NoBody)}, nil
	})}}
	responses, done := make(chan *Response, 1), make(chan error, 1)
	go func() {
		done <- f.forwardWithDestChan(t.Context(), packet{bs: makeTestRequest(t, "www.example.com.", dns.TypeA, 0), family: "udp"}, responses)
	}()
	<-entered
	f.setRoutes(nil, false)
	var fallbackCalls atomic.Int32
	f.dohClient = map[string]*http.Client{"local:" + localDNSRecoveryEndpoint: {Transport: localDoHRoundTrip(func(*http.Request) (*http.Response, error) {
		fallbackCalls.Add(1)
		return nil, errors.New("unexpected fallback after disabling DNS")
	})}}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if fallbackCalls.Load() != 0 || f.health.IsUnhealthy(localDNSRecovery) {
		t.Fatal("old query initiated recovery after configuration changed")
	}
}

func TestLocalDNSOutageProtectedNames(t *testing.T) {
	r := newResolver(t)
	defer r.Close()
	const primary = "https://resolver.example/private-profile"
	if err := r.SetConfig(Config{
		AcceptDNS: true,
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			".": {{Addr: primary, LocalOverride: true}}, "private.example.": nil,
		},
		LocalDomains: []dnsname.FQDN{"private.example."},
		Hosts:        map[dnsname.FQDN][]netip.Addr{"node.private.example.": {netip.MustParseAddr("100.64.0.1")}},
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	client := &http.Client{Transport: localDoHRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("private query leaked to HTTPS resolver")
	})}
	r.forwarder.dohClient = map[string]*http.Client{"local:" + primary: client, "local:" + localDNSRecoveryEndpoint: client}
	for _, tt := range []struct {
		name string
		code dns.RCode
	}{
		{"node.private.example.", dns.RCodeSuccess}, {"missing.private.example.", dns.RCodeNameError},
	} {
		response, err := r.Query(t.Context(), makeTestRequest(t, tt.name, dns.TypeA, 0), "udp", netip.AddrPort{})
		if err != nil {
			t.Fatal(err)
		}
		var msg dns.Message
		if err := msg.Unpack(response.Bs); err != nil {
			t.Fatal(err)
		}
		if msg.RCode != tt.code {
			t.Fatalf("private response=%v; want %v", msg.RCode, tt.code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("private/authoritative query reached public transport")
	}
}

func TestLocalDNSOutageSameProvider(t *testing.T) {
	f := &forwarder{logf: t.Logf, health: health.NewTracker(eventbustest.NewBus(t))}
	f.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: localDNSRecoveryEndpoint, LocalOverride: true}}}, true)
	var calls atomic.Int32
	f.dohClient = map[string]*http.Client{"local:" + localDNSRecoveryEndpoint: {Transport: localDoHRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
	})}}
	responses := make(chan *Response, 1)
	if err := f.forwardWithDestChan(t.Context(), packet{bs: makeTestRequest(t, "example.com.", dns.TypeA, 0), family: "udp"}, responses); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("retried failed provider as its own fallback")
	}
}

func TestLocalDNSOutageResponseIdentity(t *testing.T) {
	query := makeTestRequest(t, "WWW.example.com.", dns.TypeA, 0)
	var msg dns.Message
	if err := msg.Unpack(query); err != nil {
		t.Fatal(err)
	}
	msg.Response = true
	msg.Questions[0].Name = dns.MustNewName("www.EXAMPLE.com.")
	response, _ := msg.Pack()
	if !localDNSResponseValid(query, response) {
		t.Fatal("rejected DNS case-insensitive question match")
	}
	msg.Questions[0].Name = dns.MustNewName("other.example.com.")
	response, _ = msg.Pack()
	if localDNSResponseValid(query, response) {
		t.Fatal("accepted reply for another name")
	}
	if localDNSResponseValid(query, []byte("malformed")) {
		t.Fatal("accepted malformed DNS")
	}
}

// Host integration proof only: a controlled HTTP 503 followed by a real public
// HTTPS query. It uses no private resolver identifier or device configuration.
func TestLocalDNSOutageRecoveryLive(t *testing.T) {
	if os.Getenv("TS_TEST_LOCAL_DNS_RECOVERY_LIVE") != "1" {
		t.Skip("explicit live test opt-in required")
	}
	bus := eventbustest.NewBus(t)
	monitor, err := netmon.New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	dialer := tsdial.NewDialer(monitor)
	defer dialer.Close()
	f := newForwarder(t.Logf, monitor, nil, dialer, health.NewTracker(bus), nil)
	defer f.Close()
	const primary = "https://unavailable.example/dns-query"
	f.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: primary, LocalOverride: true}}}, true)
	f.dohClient = map[string]*http.Client{"local:" + primary: {Transport: localDoHRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
	})}}
	ctx, cancel := context.WithTimeout(t.Context(), dnsQueryTimeout) // same existing DNS protocol boundary
	defer cancel()
	responses := make(chan *Response, 1)
	if err := f.forwardWithDestChan(ctx, packet{bs: makeTestRequest(t, "example.com.", dns.TypeA, 0), family: "udp"}, responses); err != nil {
		t.Fatal(err)
	}
	var answer dns.Message
	if err := answer.Unpack((<-responses).Bs); err != nil {
		t.Fatal(err)
	}
	if answer.RCode != dns.RCodeSuccess || len(answer.Answers) == 0 {
		t.Fatal("no real fallback answer")
	}
	if !f.health.IsUnhealthy(localDNSRecovery) {
		t.Fatal("real fallback did not expose degraded provider health")
	}
}
