// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLoginProbeSocketBoundToInterface(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) { testWindowsLoginProbeSocket(t, family) })
	}
}

func testWindowsLoginProbeSocket(t *testing.T, family string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			index = i.Index
			break
		}
	}
	if index == 0 {
		t.Fatal("Windows loopback interface missing")
	}
	addr, protocol := "127.0.0.1:0", windows.IPPROTO_IP
	if family == "tcp6" {
		addr, protocol = "[::1]:0", windows.IPPROTO_IPV6
	}
	listener, err := net.Listen(family, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	got := -1
	dialer := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		if err := setSocketInterfaceIndex(c, index, family, t.Logf); err != nil {
			return err
		}
		var sockErr error
		err := c.Control(func(fd uintptr) { got, sockErr = windows.GetsockoptInt(windows.Handle(fd), protocol, 31) })
		if err != nil {
			return err
		}
		return sockErr
	}}
	conn, err := dialer.DialContext(context.Background(), family, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// Winsock takes network byte order on set, but returns the index in host
	// byte order on get (IP_UNICAST_IF documentation).
	if got != index {
		t.Fatalf("socket binding=%x, index=%d", got, index)
	}
}
