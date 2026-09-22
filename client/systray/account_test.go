// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"testing"
)

type recordingAccountClient struct {
	emptyProfiles int
	logins        int
	logouts       int
}

func (r *recordingAccountClient) SwitchToEmptyProfile(context.Context) error {
	r.emptyProfiles++
	return nil
}
func (r *recordingAccountClient) StartLoginInteractive(context.Context) error { r.logins++; return nil }
func (r *recordingAccountClient) Logout(context.Context) error                { r.logouts++; return nil }

func TestApplyAccountActionAddAccountStartsFreshInteractiveLogin(t *testing.T) {
	c := new(recordingAccountClient)
	if err := applyAccountAction(context.Background(), c, accountAdd); err != nil {
		t.Fatal(err)
	}
	if c.emptyProfiles != 1 || c.logins != 1 || c.logouts != 0 {
		t.Fatalf("calls = empty:%d login:%d logout:%d", c.emptyProfiles, c.logins, c.logouts)
	}
}

func TestApplyAccountActionLogout(t *testing.T) {
	c := new(recordingAccountClient)
	if err := applyAccountAction(context.Background(), c, accountLogout); err != nil {
		t.Fatal(err)
	}
	if c.emptyProfiles != 0 || c.logins != 0 || c.logouts != 1 {
		t.Fatalf("calls = empty:%d login:%d logout:%d", c.emptyProfiles, c.logins, c.logouts)
	}
}
