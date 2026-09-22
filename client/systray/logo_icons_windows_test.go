// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package systray

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestWindowsStateIcons(t *testing.T) {
	tests := []struct {
		name string
		logo tsLogo
		hash string
	}{
		{"connected", connected, "ff50f828c12888c395e5877ee0630a2997d9853ea7a469d4b8440e5f1347a6a1"},
		{"disconnected", disconnected, "0272907ee1116d31f9a13475206fbe71ac75133f544ebfe70b746e1e8f2ceed9"},
		{"exit-node-online", exitNodeOnline, "632a55977494b2a4804c65bb106d418cfc721f6f6e79902a5530120b9e7533bf"},
		{"exit-node-offline", exitNodeOffline, "ac41bba90d263f1dc440bcc08d6823615ca65cb3d5b9bd471fe2d840585dc15f"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.logo.render().Bytes()
			if len(got) < 6 || binary.LittleEndian.Uint32(got[:4]) != 0x00010000 {
				t.Fatal("rendered icon does not have a valid ICO header")
			}
			if count := binary.LittleEndian.Uint16(got[4:6]); count != 6 {
				t.Fatalf("ICO image count = %d, want 6", count)
			}
			if hash := fmt.Sprintf("%x", sha256.Sum256(got)); hash != test.hash {
				t.Fatalf("icon hash = %s, want %s", hash, test.hash)
			}
		})
	}
}
