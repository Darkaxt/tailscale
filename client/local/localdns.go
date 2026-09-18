// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"tailscale.com/ipn"
)

// ErrLocalDNSUnsupported reports that the connected daemon does not expose the
// TailDNS local-resolver API. Callers must not present a mutation as successful
// after receiving this error.
var ErrLocalDNSUnsupported = errors.New("connected daemon does not support TailDNS local DNS")

// LocalDNSStatus returns the current profile's configured and effective local
// DNS override state.
func (lc *Client) LocalDNSStatus(ctx context.Context) (*ipn.LocalDNSStatus, error) {
	body, err := lc.get200(ctx, "/localapi/v0/local-dns")
	if err != nil {
		return nil, localDNSError(err)
	}
	return decodeLocalDNSStatus(body)
}

// EditLocalDNS applies a profile-pinned local DNS update and returns the
// resulting effective state.
func (lc *Client) EditLocalDNS(ctx context.Context, update ipn.LocalDNSUpdate) (*ipn.LocalDNSStatus, error) {
	body, err := lc.send(ctx, http.MethodPatch, "/localapi/v0/local-dns", http.StatusOK, jsonBody(update))
	if err != nil {
		return nil, localDNSError(err)
	}
	return decodeLocalDNSStatus(body)
}

func decodeLocalDNSStatus(body []byte) (*ipn.LocalDNSStatus, error) {
	var status ipn.LocalDNSStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("invalid local DNS status JSON: %w", err)
	}
	return &status, nil
}

func localDNSError(err error) error {
	var statusErr httpStatusError
	if errors.As(err, &statusErr) && statusErr.HTTPStatus == http.StatusNotFound {
		return fmt.Errorf("%w: %v", ErrLocalDNSUnsupported, err)
	}
	return err
}
