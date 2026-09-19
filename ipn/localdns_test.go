// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalDNSPrefsRoundTrip(t *testing.T) {
	var edit MaskedPrefs
	if err := json.Unmarshal([]byte(`{"LocalDNSOverride":true,"LocalDNSOverrideSet":true,"LocalDNSResolver":"https://dns.controld.com/private-id","LocalDNSResolverSet":true}`), &edit); err != nil {
		t.Fatal(err)
	}
	p := new(Prefs)
	p.ApplyEdits(&edit)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"LocalDNSResolver":"https://dns.controld.com/private-id"`) {
		t.Error("selected resolver did not survive masked preference update and serialization")
	}
	if strings.Contains(edit.Pretty(), "private-id") {
		t.Error("masked preference diagnostics expose resolver identifier")
	}
	if p.Equals(new(Prefs)) {
		t.Error("local resolver change is ignored by equality")
	}
}
