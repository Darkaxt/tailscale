// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && (cgo || !darwin)

package systray

func (menu *Menu) sendNotification(title, content string) {}
