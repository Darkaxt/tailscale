// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command taildns-ipn is the independently implemented TailDNS Windows tray
// client. It controls the daemon through the authenticated local API and keeps
// the interactive IPN-bus connection alive.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
	"tailscale.com/client/local"
	"tailscale.com/client/systray"
	"tailscale.com/util/winutil"
)

const childArg = "--taildns-tray-child"

func main() {
	configureLog()
	if len(os.Args) == 2 && os.Args[1] == childArg {
		(&systray.Menu{ProductName: "TailDNS"}).Run(&local.Client{})
		return
	}

	mutex, err := winutil.CreateAppMutex("TailDNS.Tray.Supervisor")
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return
	}
	if err != nil {
		log.Printf("creating per-session tray mutex: %v", err)
		return
	}
	defer windows.CloseHandle(mutex)

	exe, err := os.Executable()
	if err != nil {
		log.Printf("locating TailDNS tray executable: %v", err)
		return
	}
	err = runSupervisor(func() (childProcess, error) {
		cmd := exec.Command(exe, childArg)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return cmd, nil
	}, 3)
	if err != nil {
		log.Print(err)
	}
}

func configureLog() {
	dir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	dir = filepath.Join(dir, "TailDNS")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "taildns-ipn.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.SetPrefix(fmt.Sprintf("pid=%d ", os.Getpid()))
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
}
