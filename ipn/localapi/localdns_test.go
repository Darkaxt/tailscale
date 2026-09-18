// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalDNSStatusAccess(t *testing.T) {
	serve, ok := handler["local-dns"]
	if !ok {
		t.Fatal("local DNS effective-state endpoint missing")
	}
	w := httptest.NewRecorder()
	serve(&Handler{}, w, httptest.NewRequest(http.MethodGet, "/localapi/v0/local-dns", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("unprivileged read status: %d", w.Code)
	}
	w = httptest.NewRecorder()
	serve(&Handler{PermitRead: true}, w, httptest.NewRequest(http.MethodPatch, "/localapi/v0/local-dns", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("read-only mutation status: %d", w.Code)
	}
	w = httptest.NewRecorder()
	serve(&Handler{PermitRead: true}, w, httptest.NewRequest(http.MethodPost, "/localapi/v0/local-dns", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("mutation status: %d", w.Code)
	}
}
