// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildnsupdate

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

const latestReleaseAPI = "https://api.github.com/repos/Darkaxt/tailscale/releases/latest"

const installerCreationFlags uint32 = windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS | windows.CREATE_BREAKAWAY_FROM_JOB

func StartLatest(ctx context.Context, logf logger.Logf) error {
	key := PublicKey()
	if key == "" {
		return fmt.Errorf("TailDNS update public key is unavailable")
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return fmt.Errorf("ProgramData is unavailable")
	}
	payload := filepath.Join(programData, "TailDNS", "updates", "candidate")
	manifest, err := PrepareLatest(ctx, http.DefaultClient, latestReleaseAPI, payload, version.Long(), key)
	if err != nil {
		return err
	}
	installer := filepath.Join(payload, "taildns-installer.exe")
	cmd := exec.Command(installer, "-action", "update", "-payload", payload)
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: installerCreationFlags}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting TailDNS %s+%d updater: %w", manifest.UpstreamVersion, manifest.Sequence, err)
	}
	logf("TailDNS update: started %s+%d installer", manifest.UpstreamVersion, manifest.Sequence)
	return nil
}
