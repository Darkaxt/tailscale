// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "fmt"

type childProcess interface {
	Wait() error
}

type childStarter func() (childProcess, error)

func runSupervisor(start childStarter, maxRestarts int) error {
	for abnormalExits := 0; ; abnormalExits++ {
		child, err := start()
		if err != nil {
			return fmt.Errorf("starting TailDNS tray child: %w", err)
		}
		if err := child.Wait(); err == nil {
			return nil
		} else if abnormalExits >= maxRestarts {
			return fmt.Errorf("TailDNS tray child failed after %d restarts: %w", maxRestarts, err)
		}
	}
}
