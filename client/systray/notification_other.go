// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !windows && (cgo || !darwin)

package systray

func (menu *Menu) sendNotification(title, content string) {}
