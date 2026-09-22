// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package systray

import _ "embed"

var (
	//go:embed icons/windows/connected.ico
	windowsConnectedIcon []byte

	//go:embed icons/windows/disconnected.ico
	windowsDisconnectedIcon []byte

	//go:embed icons/windows/exit-node-online.ico
	windowsExitNodeOnlineIcon []byte

	//go:embed icons/windows/exit-node-offline.ico
	windowsExitNodeOfflineIcon []byte
)
