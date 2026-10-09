// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"fmt"
	"log"
	"os"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	notificationUser32     = windows.NewLazySystemDLL("user32.dll")
	notificationFindWindow = notificationUser32.NewProc("FindWindowExW")
	notificationWindowPID  = notificationUser32.NewProc("GetWindowThreadProcessId")
	notificationShell      = windows.NewLazySystemDLL("shell32.dll").NewProc("Shell_NotifyIconW")
)

// Native NOTIFYICONDATAW uses a single DWORD union for timeout/version.
type windowsNotification struct {
	Size                uint32
	Window              windows.Handle
	ID, Flags, Callback uint32
	Icon                windows.Handle
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	TimeoutOrVersion    uint32
	Title               [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         windows.Handle
}

func notificationText(dst []uint16, src string) {
	// Keep room for NUL and never split a UTF-16 surrogate pair.
	for _, r := range src {
		if r == 0 {
			r = ' '
		}
		u := utf16.Encode([]rune{r})
		if len(u) >= len(dst) {
			break
		}
		copy(dst, u)
		dst = dst[len(u):]
	}
}

func showWindowsNotification(title, content string) error {
	// fyne.io/systray v1.12.2 owns SystrayClass/uID 100 but exposes no
	// notification API. Find only this process's existing window; never create
	// another tray icon or modify another process's icon. Covered by versioned tests.
	class, _ := windows.UTF16PtrFromString("SystrayClass")
	var window uintptr
	for {
		window, _, _ = notificationFindWindow.Call(0, window, uintptr(unsafe.Pointer(class)), 0)
		if window == 0 {
			return fmt.Errorf("TailDNS notification window not found")
		}
		var pid uint32
		notificationWindowPID.Call(window, uintptr(unsafe.Pointer(&pid)))
		if pid == uint32(os.Getpid()) {
			break
		}
	}
	n := windowsNotification{Window: windows.Handle(window), ID: 100, Flags: 0x10, InfoFlags: 0x01 | 0x80}
	n.Size = uint32(unsafe.Sizeof(n))
	notificationText(n.Title[:], title)
	notificationText(n.Info[:], content)
	ok, _, err := notificationShell.Call(1, uintptr(unsafe.Pointer(&n))) // NIM_MODIFY, NIF_INFO
	if ok == 0 {
		return fmt.Errorf("Shell_NotifyIconW rejected notification: %v", err)
	}
	return nil
}

func (menu *Menu) sendNotification(title, content string) {
	if err := showWindowsNotification(title, content); err != nil {
		log.Printf("Windows notification: %v", err)
	} else {
		log.Printf("Windows notification submitted: %s", title)
	}
}
