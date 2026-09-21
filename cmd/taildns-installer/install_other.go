// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import "errors"

func platformInstall(string, releaseManifest, string) (installResult, error) {
	return installResult{}, errors.New("TailDNS installer supports only Windows")
}

func platformRollback() (installResult, error) {
	return installResult{}, errors.New("TailDNS installer supports only Windows")
}

func platformStatus() (installResult, error) {
	return installResult{}, errors.New("TailDNS installer supports only Windows")
}
