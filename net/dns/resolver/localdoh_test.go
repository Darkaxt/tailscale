// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"

	dns "golang.org/x/net/dns/dnsmessage"

	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/eventbus/eventbustest"
)

type localDoHRoundTrip func(*http.Request) (*http.Response, error)

func (fn localDoHRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestLocalDoHUsesDedicatedTransport(t *testing.T) {
	const endpoint = "https://resolver.example/secret-profile"
	called := false
	client := &http.Client{Transport: localDoHRoundTrip(func(r *http.Request) (*http.Response, error) {
		called = true
		if r.URL.String() != endpoint {
			t.Error("provider endpoint changed")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{dohType}}, Body: io.NopCloser(strings.NewReader("123456789012"))}, nil
	})}
	f := &forwarder{logf: t.Logf, dohClient: map[string]*http.Client{"local:" + endpoint: client}}
	_, err := f.send(context.Background(), &forwardQuery{packet: make([]byte, 12), family: "udp"}, resolverAndDelay{name: &dnstype.Resolver{Addr: endpoint, LocalOverride: true}})
	if err != nil || !called {
		t.Fatalf("local DoH transport not used: called=%v err=%v", called, err)
	}
}

func TestLocalDoHFailureDoesNotFallbackOrLeakEndpoint(t *testing.T) {
	const endpoint = "https://resolver.example/private-profile"
	calls := 0
	client := &http.Client{Transport: localDoHRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("failure for " + endpoint)
	})}
	// No network dialer is installed: any attempt at plaintext fallback cannot
	// succeed unnoticed. Composition tests separately assert a sole default.
	f := &forwarder{logf: t.Logf, dohClient: map[string]*http.Client{"local:" + endpoint: client}}
	_, err := f.send(t.Context(), &forwardQuery{packet: make([]byte, 12), family: "udp"}, resolverAndDelay{name: &dnstype.Resolver{Addr: endpoint, LocalOverride: true}})
	if err == nil || calls != 1 {
		t.Fatalf("failure/fallback result: calls=%d err=%v", calls, err)
	}
	if strings.Contains(err.Error(), "private-profile") || strings.Contains(err.Error(), "resolver.example") {
		t.Fatal("private endpoint leaked in diagnostic error")
	}
}

func TestLocalDoHBootstrapOnlyProvider(t *testing.T) {
	dialer := tsdial.NewDialer(netmon.NewStatic())
	defer dialer.Close()
	questions := make(chan string, 8)
	dialer.SetSystemDialerForTest(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "192.0.2.53:53" {
			t.Errorf("unexpected bootstrap target %s %s", network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			packet := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, packet); err != nil {
				return
			}
			var request dns.Message
			if err := request.Unpack(packet); err != nil {
				t.Error(err)
				return
			}
			q := request.Questions[0]
			questions <- q.Name.String()
			request.Response = true
			request.RecursionAvailable = true
			if q.Type == dns.TypeA {
				request.Answers = []dns.Resource{{Header: dns.ResourceHeader{Name: q.Name, Type: dns.TypeA, Class: dns.ClassINET}, Body: &dns.AResource{A: [4]byte{192, 0, 2, 80}}}}
			}
			response, err := request.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(response)))
			server.Write(append(size[:], response...))
		}()
		return client, nil
	})
	f := &forwarder{dialer: dialer}
	servers := []netip.Addr{netip.MustParseAddr("100.100.100.100"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.53")}
	ips, err := f.lookupLocalDoHHost(t.Context(), "provider.example.", servers)
	if err != nil || len(ips) != 1 || ips[0].Unmap() != netip.MustParseAddr("192.0.2.80") {
		t.Fatalf("bootstrap result %v %v", ips, err)
	}
	for len(questions) > 0 {
		if name := <-questions; name != "provider.example." {
			t.Fatalf("unexpected bootstrap question %s", name)
		}
	}
	if _, err := f.lookupLocalDoHHost(t.Context(), "provider.example.", servers[:2]); err == nil {
		t.Fatal("recursive base DNS accepted")
	}
}

func TestLocalDoHRouteTLSAndRedirect(t *testing.T) {
	const endpoint = "https://example.com/secret-profile"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://other.example/leak")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	ip := netip.MustParseAddr("192.0.2.100")
	defer publicdns.RegisterTestDoHEndpoint(ip, endpoint)()
	dials := 0
	dialer := &tsdial.Dialer{
		UseNetstackForIP: func(got netip.Addr) bool { return got == ip },
		NetstackDialTCP: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			dials++
			if dst != netip.AddrPortFrom(ip, 443) {
				t.Errorf("wrong routed target: %v", dst)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		},
		NetstackDialUDP: func(context.Context, netip.AddrPort) (net.Conn, error) {
			t.Fatal("plaintext/UDP fallback")
			return nil, nil
		},
	}
	f := &forwarder{logf: t.Logf, dialer: dialer}
	client, err := f.getLocalDoHClient(&dnstype.Resolver{Addr: endpoint, LocalOverride: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	// Default trust must reject an untrusted provider certificate.
	if _, err := client.Post(endpoint, dohType, strings.NewReader("query")); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs = pool
	client.CloseIdleConnections()
	client.Transport = transport
	response, err := client.Post(endpoint, dohType, strings.NewReader("query"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatal("redirect followed")
	}
	if dials != 2 {
		t.Fatalf("route-aware dial count %d; want 2", dials)
	}
	f.setRoutes(nil, false)
	if len(f.dohClient) != 0 {
		t.Fatal("local client survives route reconfiguration")
	}
}

// Explicit opt-in: sends only example.com to public resolvers, with no account ID.
// This is host transport evidence, not Android VPN or exit-node evidence.
func TestLocalDoHLive(t *testing.T) {
	if os.Getenv("TS_TEST_LOCAL_DOH_LIVE") != "1" {
		t.Skip("live provider test requires explicit opt-in")
	}
	monitor, err := netmon.New(eventbustest.NewBus(t), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	dialer := &tsdial.Dialer{Logf: t.Logf}
	dialer.SetNetMon(monitor)
	defer dialer.Close()
	f := &forwarder{logf: t.Logf, dialer: dialer, netMon: monitor}
	defer func() {
		for _, c := range f.dohClient {
			c.CloseIdleConnections()
		}
	}()
	query := dns.Message{Header: dns.Header{ID: 42, RecursionDesired: true}, Questions: []dns.Question{{Name: dns.MustNewName("example.com."), Type: dns.TypeA, Class: dns.ClassINET}}}
	packet, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"https://freedns.controld.com/p0", "https://cloudflare-dns.com/dns-query", "https://doh.opendns.com/dns-query"} {
		t.Run(endpoint, func(t *testing.T) {
			response, err := f.send(t.Context(), &forwardQuery{packet: packet, family: "udp"}, resolverAndDelay{name: &dnstype.Resolver{Addr: endpoint, LocalOverride: true, LocalBootstrapResolvers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}})
			if err != nil {
				t.Fatal(err)
			}
			var answer dns.Message
			if err := answer.Unpack(response); err != nil {
				t.Fatal(err)
			}
			if !answer.Response || answer.RCode != dns.RCodeSuccess || len(answer.Answers) == 0 {
				t.Fatal("no successful DNS answer")
			}
		})
	}
}
