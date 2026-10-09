// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && (cgo || !darwin)

package systray

import "context"

func (*Menu) startTaildrop()                  {}
func (*Menu) stopTaildrop()                   {}
func (*Menu) requestTaildrop(bool)            {}
func (*Menu) addTaildropMenu(context.Context) {}
