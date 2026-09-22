// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package systray

var (
	windowsConnectedIcon       []byte
	windowsDisconnectedIcon    []byte
	windowsExitNodeOnlineIcon  []byte
	windowsExitNodeOfflineIcon []byte
)
