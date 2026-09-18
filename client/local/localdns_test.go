// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package local

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tstest/nettest"
)

func TestLocalDNSStatusAndEdit(t *testing.T) {
	nw := nettest.GetNetwork(t)
	var edits []ipn.LocalDNSUpdate
	ts := nettest.NewHTTPServer(nw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/local-dns" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
		case http.MethodPatch:
			var update ipn.LocalDNSUpdate
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				t.Fatal(err)
			}
			edits = append(edits, update)
		default:
			t.Fatalf("unexpected method %q", r.Method)
		}
		json.NewEncoder(w).Encode(ipn.LocalDNSStatus{
			ProfileID:  "profile-1",
			Configured: true,
			Endpoint:   "https://resolver.example/dns-query",
			Applied:    true,
			Reason:     "Applied; provider reachability not verified",
		})
	}))
	defer ts.Close()

	lc := &Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nw.Dial(ctx, network, ts.Listener.Addr().String())
	}}
	status, err := lc.LocalDNSStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Applied || status.ProfileID != "profile-1" {
		t.Fatalf("unexpected status: %+v", status)
	}

	update := ipn.LocalDNSUpdate{
		ProfileID: "profile-1",
		Enabled:   true,
		Endpoint:  "https://resolver.example/dns-query",
	}
	status, err = lc.EditLocalDNS(context.Background(), update)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Applied {
		t.Fatalf("edit status not applied: %+v", status)
	}
	if len(edits) != 1 || edits[0] != update {
		t.Fatalf("edits = %+v, want %+v", edits, update)
	}
}

func TestLocalDNSUnsupportedDaemon(t *testing.T) {
	nw := nettest.GetNetwork(t)
	ts := nettest.NewHTTPServer(nw, http.NotFoundHandler())
	defer ts.Close()
	lc := &Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nw.Dial(ctx, network, ts.Listener.Addr().String())
	}}

	_, err := lc.LocalDNSStatus(context.Background())
	if !errors.Is(err, ErrLocalDNSUnsupported) {
		t.Fatalf("error = %v, want ErrLocalDNSUnsupported", err)
	}
}
