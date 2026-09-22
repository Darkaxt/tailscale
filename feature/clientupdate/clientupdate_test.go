// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package clientupdate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/localapi"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
)

func TestDoTailDNSSelfUpdateUsesTailDNSProvider(t *testing.T) {
	for _, tt := range []struct {
		name       string
		startError error
		wantStatus ipnstate.SelfUpdateStatus
	}{
		{name: "installer started", wantStatus: ipnstate.UpdateFinished},
		{name: "provider failure", startError: errors.New("provider failed"), wantStatus: ipnstate.UpdateFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			ext := &extension{lastSelfUpdateState: ipnstate.UpdateFinished}
			ext.doTailDNSSelfUpdate(func(context.Context, logger.Logf) error {
				called = true
				return tt.startError
			})
			if !called {
				t.Fatal("TailDNS update provider was not called")
			}
			progress := ext.GetSelfUpdateProgress()
			if len(progress) == 0 || progress[len(progress)-1].Status != tt.wantStatus {
				t.Fatalf("progress = %#v, want final status %v", progress, tt.wantStatus)
			}
		})
	}
}

// TestServeUpdateInstallRequiresWrite verifies that the update/install
// localapi handler denies requests from clients without write permission,
// i.e. non-root, non-operator local users.
func TestServeUpdateInstallRequiresWrite(t *testing.T) {
	h := &localapi.Handler{PermitWrite: false}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(httpm.POST, "/localapi/v0/update/install", nil)
	serveUpdateInstall(h, rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
