// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import "testing"

func TestAndroidDNSProvider(t *testing.T) {
	for _, tt := range []struct{ host, want string }{
		{"AbCd1234.DNS.CONTROLD.COM.", "https://dns.controld.com/abcd1234"},
		{"abcd1234-name-goes-here.dns.controld.com", "https://dns.controld.com/abcd1234/name-goes-here"},
		{"", ""}, {"dns.example", ""}, {"id.dns.controld.com.evil.test", ""},
		{"extra.id.dns.controld.com", ""}, {"id-.dns.controld.com", ""},
		{"-name.dns.controld.com", ""}, {"id_name.dns.controld.com", ""},
		{" id.dns.controld.com", ""}, {"id.dns.controld.com..", ""},
	} {
		got, err := AndroidDNSProvider(tt.host)
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Errorf("provider mapping mismatch for test input: got %q, error %v", got, err)
		}
	}
}
