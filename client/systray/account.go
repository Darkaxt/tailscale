// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"fmt"
)

type accountAction string

const (
	accountAdd    accountAction = "add"
	accountLogout accountAction = "logout"
)

type accountClient interface {
	SwitchToEmptyProfile(context.Context) error
	StartLoginInteractive(context.Context) error
	Logout(context.Context) error
}

func applyAccountAction(ctx context.Context, client accountClient, action accountAction) error {
	switch action {
	case accountAdd:
		if err := client.SwitchToEmptyProfile(ctx); err != nil {
			return err
		}
		return client.StartLoginInteractive(ctx)
	case accountLogout:
		return client.Logout(ctx)
	default:
		return fmt.Errorf("unknown account action %q", action)
	}
}
