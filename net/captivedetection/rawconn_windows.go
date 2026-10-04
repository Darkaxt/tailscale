// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"math/bits"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
)

// IP_UNICAST_IF requires a network-byte-order index; IPV6_UNICAST_IF takes
// host byte order. Respect the socket family used by the existing detector too.
func setSocketInterfaceIndex(c syscall.RawConn, ifIndex int, network string, _ logger.Logf) error {
	if ifIndex == 0 {
		return nil
	}
	var sockErr error
	err := c.Control(func(fd uintptr) {
		protocol, value := windows.IPPROTO_IP, int(bits.ReverseBytes32(uint32(ifIndex)))
		if strings.HasSuffix(network, "6") {
			protocol, value = windows.IPPROTO_IPV6, ifIndex
		}
		sockErr = windows.SetsockoptInt(windows.Handle(fd), protocol, 31, value)
	})
	if err != nil {
		return err
	}
	return sockErr
}
