// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows || ts_omit_captiveportal

package ipnlocal

func (b *LocalBackend) startWindowsCaptivePortalLocked()      {}
func (b *LocalBackend) syncWindowsCaptiveNetworkLocked() bool { return false }
