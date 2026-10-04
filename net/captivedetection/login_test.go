// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"tailscale.com/tailcfg"
)

func TestLoginProbeDoesNotTreatOutageAsPortal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     int
		location string
		want     LoginStatus
	}{
		{"portal", 302, "https://eu.network-auth.com/login?token=private", LoginCaptive},
		{"relative", 302, "/login", LoginCaptive},
		{"healthy", 204, "", LoginValidated},
		{"error", 503, "", LoginUnknown},
		{"authentication", 407, "", LoginUnknown},
		{"empty-page", 200, "", LoginUnknown},
		{"no-location", 302, "", LoginUnknown},
		{"credentials", 302, "http://user:password@portal.example/login", LoginUnknown},
		{"unsafe-scheme", 302, "file:///login", LoginUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			followed := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/generate_204" {
					followed = true
				}
				w.Header().Set("Location", tc.location)
				w.WriteHeader(tc.code)
			}))
			defer s.Close()
			u, _ := url.Parse(s.URL + "/generate_204")
			d := NewDetector(t.Logf)
			got := d.probeLoginEndpoint(context.Background(), 0, Endpoint{URL: u, StatusCode: 204})
			if got != tc.want {
				t.Fatalf("status=%v, want %v", got, tc.want)
			}
			if followed {
				t.Fatal("probe followed login redirect")
			}
		})
	}
}

func TestLoginProbeRedirectOutageAndValidationSequence(t *testing.T) {
	var mode atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 0:
			http.Redirect(w, r, "https://eu.network-auth.com/splash/test", 302)
		case 1:
			w.WriteHeader(503)
		case 2:
			w.Header().Set("X-Tailscale-Response", "response "+r.Header.Get("X-Tailscale-Challenge"))
			w.WriteHeader(204)
		}
	})
	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}}
	for _, address := range []string{"127.0.0.1:0", "127.0.0.2:0"} {
		s := httptest.NewUnstartedServer(handler)
		l, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		s.Listener = l
		s.Start()
		t.Cleanup(s.Close)
		dm.Regions[1].Nodes = append(dm.Regions[1].Nodes, &tailcfg.DERPNode{IPv4: strings.TrimPrefix(s.URL, "http://"), CanPort80: true})
	}
	d := NewDetector(t.Logf)
	for _, tc := range []struct {
		mode int32
		want LoginStatus
	}{{0, LoginCaptive}, {1, LoginUnknown}, {2, LoginValidated}} {
		mode.Store(tc.mode)
		if got := d.ProbeLogin(context.Background(), 0, dm); got != tc.want {
			t.Fatalf("mode %d: got %v want %v", tc.mode, got, tc.want)
		}
	}
	// A single whitelisted endpoint cannot restore login mode.
	dm.Regions[1].Nodes = dm.Regions[1].Nodes[:1]
	if got := d.ProbeLogin(context.Background(), 0, dm); got != LoginUnknown {
		t.Fatalf("one whitelisted endpoint=%v", got)
	}
}

func TestLoginProbeRequiresPositiveValidation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	u, _ := url.Parse(s.URL)
	d := NewDetector(t.Logf)
	e := Endpoint{URL: u, StatusCode: 204, SupportsTailscaleChallenge: true}
	if got := d.probeLoginEndpoint(context.Background(), 0, e); got != LoginUnknown {
		t.Fatalf("missing challenge=%v", got)
	}
	s.Close()
	if got := d.probeLoginEndpoint(context.Background(), 0, e); got != LoginUnknown {
		t.Fatalf("unreachable=%v", got)
	}
}
