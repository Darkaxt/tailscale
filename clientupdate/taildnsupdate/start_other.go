// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package taildnsupdate

import (
	"context"
	"errors"

	"tailscale.com/types/logger"
)

func StartLatest(context.Context, logger.Logf) error {
	return errors.New("TailDNS updater is available only on Windows")
}
