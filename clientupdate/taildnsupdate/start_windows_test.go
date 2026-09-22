// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildnsupdate

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestInstallerCreationFlagsSurviveServiceShutdown(t *testing.T) {
	for name, flag := range map[string]uint32{
		"break away from service job": windows.CREATE_BREAKAWAY_FROM_JOB,
		"detached process":            windows.DETACHED_PROCESS,
		"new process group":           windows.CREATE_NEW_PROCESS_GROUP,
	} {
		if installerCreationFlags&flag == 0 {
			t.Errorf("installer creation flags omit %s", name)
		}
	}
}
