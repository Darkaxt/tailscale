// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package systray

import (
	"log"
	"time"

	dbus "github.com/godbus/dbus/v5"
)

// sendNotification sends a Linux desktop notification with the given title
// and content. Other platforms keep address-copy behavior without attempting
// to contact a D-Bus session that does not exist.
func (menu *Menu) sendNotification(title, content string) {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Printf("dbus: %v", err)
		return
	}
	timeout := 3 * time.Second
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	call := obj.Call("org.freedesktop.Notifications.Notify", 0, menu.productName(), uint32(0),
		menu.notificationIcon.Name(), title, content, []string{}, map[string]dbus.Variant{}, int32(timeout.Milliseconds()))
	if call.Err != nil {
		log.Printf("dbus: %v", call.Err)
	}
}
