// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/util/cmpver"
	"tailscale.com/util/winutil"
)

const (
	serviceName  = "Tailscale"
	recordName   = "deployment-v4.json"
	runKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName = "TailDNS"
)

var replaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

type installPaths struct {
	InstallDir      string
	Daemon          string
	CLI             string
	Resolver        string
	GUI             string
	Tray            string
	Wintun          string
	OfficialStartup string
	State           string
	ProgramData     string
	Record          string
}

type statusJSON struct {
	BackendState string `json:"BackendState"`
	HaveNodeKey  bool   `json:"HaveNodeKey"`
	Self         struct {
		ID           string   `json:"ID"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		Online       bool     `json:"Online"`
	} `json:"Self"`
}

type prefsJSON struct {
	AutoUpdate struct {
		Check bool `json:"Check"`
		Apply bool `json:"Apply"`
	} `json:"AutoUpdate"`
}

type versionJSON struct {
	Short     string `json:"short"`
	Long      string `json:"long"`
	GitCommit string `json:"gitCommit"`
}

func platformInstall(payloadDir string, manifest releaseManifest, dnsEndpoint string) (result installResult, retErr error) {
	if err := expectedRuntime(); err != nil {
		return result, err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return result, errors.New("installation requires an elevated Administrator process")
	}

	manager, service, config, err := openService()
	if err != nil {
		return result, err
	}
	defer manager.Disconnect()
	defer service.Close()

	paths, err := resolveInstallPaths(config.BinaryPathName)
	if err != nil {
		return result, err
	}
	if err := validateInstalledBaseline(paths); err != nil {
		return result, err
	}
	baseline, err := readIdentity(paths.CLI)
	if err != nil {
		return result, err
	}
	prefs, err := readPrefs(paths.CLI)
	if err != nil {
		return result, err
	}

	record, err := createDeploymentRecord(paths, config.BinaryPathName, payloadDir, manifest, baseline, prefs)
	if err != nil {
		return result, err
	}
	if err := writeRecord(paths.Record, record); err != nil {
		return result, err
	}

	activationStarted := false
	defer func() {
		if retErr == nil || !activationStarted {
			return
		}
		if rollbackErr := restoreRecord(service, paths, record); rollbackErr != nil {
			retErr = fmt.Errorf("%w; automatic rollback also failed: %v", retErr, rollbackErr)
			return
		}
		if removeErr := os.Remove(paths.Record); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			retErr = fmt.Errorf("%w; original installation was restored but the active deployment record could not be removed: %v", retErr, removeErr)
			return
		}
		result.RolledBack = true
	}()
	activationStarted = true
	if err := setAutoUpdate(paths.CLI, prefs.AutoUpdate.Check, false); err != nil {
		return result, fmt.Errorf("disabling official automatic updates: %w", err)
	}

	if err := stopService(service, paths.Daemon); err != nil {
		return result, err
	}
	for sourceName, destination := range map[string]string{
		"taildnsd.exe":    paths.Daemon,
		"tailscale.exe":   paths.CLI,
		"taildns.exe":     paths.Resolver,
		"taildns-ipn.exe": paths.Tray,
	} {
		if err := replaceFromPayload(filepath.Join(payloadDir, sourceName), destination); err != nil {
			return result, err
		}
	}
	if err := startService(service); err != nil {
		return result, err
	}
	if err := waitBackend(paths.CLI); err != nil {
		return result, err
	}
	if err := verifyInstalledVersion(paths, manifest); err != nil {
		return result, err
	}
	after, err := readIdentity(paths.CLI)
	if err != nil {
		return result, err
	}
	if err := verifyIdentityContinuity(baseline, after); err != nil {
		return result, err
	}
	if err := verifyPreservedComponents(paths, record.PreservedComponentHash); err != nil {
		return result, err
	}
	if dnsEndpoint != "" {
		if err := setResolver(paths.Resolver, dnsEndpoint); err != nil {
			return result, err
		}
	}
	if err := verifyDNS(after); err != nil {
		return result, err
	}
	if err := activateTray(paths, record.Startup); err != nil {
		return result, err
	}
	if running, err := processPathRunning(paths.Tray); err != nil || !running {
		if err != nil {
			return result, fmt.Errorf("verifying TailDNS tray process: %w", err)
		}
		return result, errors.New("TailDNS tray process did not remain running after activation")
	}
	after, err = readIdentity(paths.CLI)
	if err != nil {
		return result, err
	}
	if err := verifyIdentityContinuity(baseline, after); err != nil {
		return result, err
	}

	return installResult{
		Action:             "installed",
		Version:            manifest.version(),
		ServicePath:        config.BinaryPathName,
		Identity:           after,
		ResolverConfigured: dnsEndpoint != "",
	}, nil
}

func platformUpdate(payloadDir string, manifest releaseManifest) (result installResult, retErr error) {
	if err := expectedRuntime(); err != nil {
		return result, err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return result, errors.New("update requires an elevated Administrator process")
	}
	manager, service, config, err := openService()
	if err != nil {
		return result, err
	}
	defer manager.Disconnect()
	defer service.Close()
	paths, err := resolveInstallPaths(config.BinaryPathName)
	if err != nil {
		return result, err
	}
	active, err := readRecord(paths.Record)
	if err != nil {
		return result, err
	}
	if err := validateUpdateTransition(active, manifest); err != nil {
		return result, err
	}
	before, err := readIdentity(paths.CLI)
	if err != nil {
		return result, err
	}
	prefs, err := readPrefs(paths.CLI)
	if err != nil {
		return result, err
	}
	rollback, err := createDeploymentRecord(paths, config.BinaryPathName, payloadDir, manifest, before, prefs)
	if err != nil {
		return result, err
	}
	activationStarted := false
	defer func() {
		if retErr == nil || !activationStarted {
			return
		}
		if rollbackErr := restoreRecord(service, paths, rollback); rollbackErr != nil {
			retErr = fmt.Errorf("%w; automatic update rollback also failed: %v", retErr, rollbackErr)
			return
		}
		result.RolledBack = true
	}()
	activationStarted = true
	if err := terminateProcessesByPath(paths.Tray); err != nil {
		return result, fmt.Errorf("stopping TailDNS tray for update: %w", err)
	}
	if err := stopService(service, paths.Daemon); err != nil {
		return result, err
	}
	for sourceName, destination := range map[string]string{
		"taildnsd.exe": paths.Daemon, "tailscale.exe": paths.CLI,
		"taildns.exe": paths.Resolver, "taildns-ipn.exe": paths.Tray,
	} {
		if err := replaceFromPayload(filepath.Join(payloadDir, sourceName), destination); err != nil {
			return result, err
		}
	}
	if err := startService(service); err != nil {
		return result, err
	}
	if err := waitBackend(paths.CLI); err != nil {
		return result, err
	}
	if err := verifyInstalledVersion(paths, manifest); err != nil {
		return result, err
	}
	after, err := readIdentity(paths.CLI)
	if err != nil {
		return result, err
	}
	if err := verifyIdentityContinuity(before, after); err != nil {
		return result, err
	}
	if err := verifyPreservedComponents(paths, active.PreservedComponentHash); err != nil {
		return result, err
	}
	if err := verifyDNS(after); err != nil {
		return result, err
	}
	if err := activateTray(paths, rollback.Startup); err != nil {
		return result, err
	}
	if err := verifyActiveStartup(paths, active.Startup); err != nil {
		return result, err
	}
	active.Version = manifest.version()
	active.UpstreamVersion = manifest.UpstreamVersion
	active.Sequence = manifest.Sequence
	active.CoreCommit = manifest.CoreCommit
	for name, file := range active.Files {
		file.InstalledHash = rollback.Files[name].InstalledHash
		active.Files[name] = file
	}
	if err := writeRecord(paths.Record, active); err != nil {
		return result, err
	}
	return installResult{Action: "updated", Version: manifest.version(), ServicePath: config.BinaryPathName, Identity: after}, nil
}

func validateUpdateTransition(active deploymentRecord, manifest releaseManifest) error {
	if active.SchemaVersion != 4 || active.Sequence == 0 {
		return errors.New("active TailDNS deployment record is invalid")
	}
	baseComparison := cmpver.Compare(manifest.UpstreamVersion, active.UpstreamVersion)
	if baseComparison < 0 || (baseComparison == 0 && manifest.Sequence <= active.Sequence) {
		return errors.New("TailDNS update is not newer than the active deployment")
	}
	return nil
}

func platformRollback() (installResult, error) {
	if err := expectedRuntime(); err != nil {
		return installResult{}, err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return installResult{}, errors.New("rollback requires an elevated Administrator process")
	}
	manager, service, config, err := openService()
	if err != nil {
		return installResult{}, err
	}
	defer manager.Disconnect()
	defer service.Close()
	paths, err := resolveInstallPaths(config.BinaryPathName)
	if err != nil {
		return installResult{}, err
	}
	record, err := readRecord(paths.Record)
	if err != nil {
		return installResult{}, err
	}
	if config.BinaryPathName != record.ServicePath {
		return installResult{}, errors.New("service image path differs from the deployment record")
	}
	if err := restoreRecord(service, paths, record); err != nil {
		return installResult{}, err
	}
	after, err := readIdentity(paths.CLI)
	if err != nil {
		return installResult{}, err
	}
	if err := verifyIdentityContinuity(record.BaselineIdentity, after); err != nil {
		return installResult{}, err
	}
	if err := os.Remove(paths.Record); err != nil && !errors.Is(err, os.ErrNotExist) {
		return installResult{}, fmt.Errorf("removing active deployment record after rollback: %w", err)
	}
	return installResult{Action: "rolledBack", Version: record.Version, ServicePath: record.ServicePath, Identity: after, RolledBack: true}, nil
}

func platformStatus() (installResult, error) {
	manager, service, config, err := openService()
	if err != nil {
		return installResult{}, err
	}
	defer manager.Disconnect()
	defer service.Close()
	paths, err := resolveInstallPaths(config.BinaryPathName)
	if err != nil {
		return installResult{}, err
	}
	record, err := readRecord(paths.Record)
	if err != nil {
		return installResult{}, err
	}
	identity, err := readIdentity(paths.CLI)
	if err != nil {
		return installResult{}, err
	}
	if err := verifyIdentityContinuity(record.BaselineIdentity, identity); err != nil {
		return installResult{}, err
	}
	for name, file := range record.Files {
		if got, err := hashFile(file.Path); err != nil || !strings.EqualFold(got, file.InstalledHash) {
			return installResult{}, fmt.Errorf("installed %s does not match deployment record", name)
		}
	}
	if err := verifyPreservedComponents(paths, record.PreservedComponentHash); err != nil {
		return installResult{}, err
	}
	manifest := releaseManifest{UpstreamVersion: record.UpstreamVersion, Sequence: record.Sequence, CoreCommit: record.CoreCommit}
	if err := verifyInstalledVersion(paths, manifest); err != nil {
		return installResult{}, err
	}
	if err := verifyActiveStartup(paths, record.Startup); err != nil {
		return installResult{}, err
	}
	return installResult{Action: "status", Version: record.Version, ServicePath: record.ServicePath, Identity: identity}, nil
}

func openService() (*mgr.Mgr, *mgr.Service, mgr.Config, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, mgr.Config{}, fmt.Errorf("connecting to Service Control Manager: %w", err)
	}
	service, err := manager.OpenService(serviceName)
	if err != nil {
		manager.Disconnect()
		return nil, nil, mgr.Config{}, fmt.Errorf("opening %s service: %w", serviceName, err)
	}
	config, err := service.Config()
	if err != nil {
		service.Close()
		manager.Disconnect()
		return nil, nil, mgr.Config{}, fmt.Errorf("reading %s service configuration: %w", serviceName, err)
	}
	return manager, service, config, nil
}

func resolveInstallPaths(servicePath string) (installPaths, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return installPaths{}, errors.New("ProgramData is unavailable")
	}
	executable, err := executableFromServicePath(servicePath)
	if err != nil {
		return installPaths{}, err
	}
	if !strings.EqualFold(filepath.Base(executable), "tailscaled.exe") {
		return installPaths{}, fmt.Errorf("unexpected Tailscale service executable %q", executable)
	}
	dir := filepath.Dir(executable)
	return installPaths{
		InstallDir:      dir,
		Daemon:          executable,
		CLI:             filepath.Join(dir, "tailscale.exe"),
		Resolver:        filepath.Join(dir, "taildns.exe"),
		GUI:             filepath.Join(dir, "tailscale-ipn.exe"),
		Tray:            filepath.Join(dir, "taildns-ipn.exe"),
		Wintun:          filepath.Join(dir, "wintun.dll"),
		OfficialStartup: filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "Tailscale.lnk"),
		State:           filepath.Join(programData, "Tailscale", "server-state.conf"),
		ProgramData:     filepath.Join(programData, "TailDNS"),
		Record:          filepath.Join(programData, "TailDNS", recordName),
	}, nil
}

func executableFromServicePath(servicePath string) (string, error) {
	trimmed := strings.TrimSpace(servicePath)
	if strings.HasPrefix(trimmed, `"`) {
		end := strings.Index(trimmed[1:], `"`)
		if end < 0 {
			return "", errors.New("unterminated quoted service path")
		}
		return trimmed[1 : end+1], nil
	}
	if index := strings.IndexAny(trimmed, " \t"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if trimmed == "" {
		return "", errors.New("empty service path")
	}
	return trimmed, nil
}

func validateInstalledBaseline(paths installPaths) error {
	for _, required := range []string{paths.Daemon, paths.CLI, paths.Wintun, paths.State} {
		info, err := os.Stat(required)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("required existing installation file is unavailable: %s", required)
		}
	}
	var version versionJSON
	if err := commandJSON(paths.CLI, &version, "version", "--json"); err != nil {
		return err
	}
	if err := validateBaselineVersion(version); err != nil {
		return err
	}
	if _, err := os.Stat(paths.Record); err == nil {
		return errors.New("this installation is already managed by TailDNS; use the TailDNS updater for subsequent releases")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking existing TailDNS deployment record: %w", err)
	}
	legacyRecord := filepath.Join(paths.ProgramData, "deployment-v3.json")
	if _, err := os.Stat(legacyRecord); err == nil {
		return errors.New("a legacy TailDNS deployment is active; roll it back with its original installer before installing this release")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking legacy TailDNS deployment record: %w", err)
	}
	return nil
}

func validateBaselineVersion(version versionJSON) error {
	if !upstreamVersionRE.MatchString(version.Short) || version.Long == "" || !commitRE.MatchString(version.GitCommit) {
		return errors.New("installed Tailscale has no verifiable core identity")
	}
	return nil
}

func tailDNSRunCommand(executable string) string {
	return `"` + strings.ReplaceAll(executable, `"`, `\"`) + `"`
}

func createDeploymentRecord(paths installPaths, servicePath, payloadDir string, manifest releaseManifest, baseline machineIdentity, prefs prefsJSON) (deploymentRecord, error) {
	recovery := filepath.Join(paths.ProgramData, "rollback", manifest.version())
	if err := os.MkdirAll(recovery, 0o700); err != nil {
		return deploymentRecord{}, err
	}
	record := deploymentRecord{
		SchemaVersion:          4,
		InstalledAtUTC:         time.Now().UTC().Format(time.RFC3339Nano),
		Version:                manifest.version(),
		UpstreamVersion:        manifest.UpstreamVersion,
		Sequence:               manifest.Sequence,
		CoreCommit:             manifest.CoreCommit,
		ServicePath:            servicePath,
		Files:                  map[string]fileRecord{},
		PreservedComponentHash: map[string]string{},
		OriginalUpdateCheck:    prefs.AutoUpdate.Check,
		OriginalUpdateApply:    prefs.AutoUpdate.Apply,
		BaselineIdentity:       baseline,
	}
	for source, destination := range map[string]string{
		"taildnsd.exe":    paths.Daemon,
		"tailscale.exe":   paths.CLI,
		"taildns.exe":     paths.Resolver,
		"taildns-ipn.exe": paths.Tray,
	} {
		installedHash, err := hashFile(filepath.Join(payloadDir, source))
		if err != nil {
			return deploymentRecord{}, err
		}
		file := fileRecord{Path: destination, InstalledHash: installedHash}
		if info, err := os.Stat(destination); err == nil && info.Mode().IsRegular() {
			file.Existed = true
			file.OriginalHash, err = hashFile(destination)
			if err != nil {
				return deploymentRecord{}, err
			}
			file.OriginalPath = filepath.Join(recovery, filepath.Base(destination))
			if err := copyVerified(destination, file.OriginalPath, file.OriginalHash); err != nil {
				return deploymentRecord{}, err
			}
		}
		record.Files[source] = file
	}
	for name, path := range map[string]string{"tailscale-ipn.exe": paths.GUI, "wintun.dll": paths.Wintun} {
		hash, err := hashFile(path)
		if name == "tailscale-ipn.exe" && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return deploymentRecord{}, err
		}
		record.PreservedComponentHash[name] = hash
	}
	startup, err := captureStartupRecord(paths, recovery)
	if err != nil {
		return deploymentRecord{}, err
	}
	record.Startup = startup
	return record, nil
}

func captureStartupRecord(paths installPaths, recovery string) (startupRecord, error) {
	record := startupRecord{
		OfficialLink:    fileRecord{Path: paths.OfficialStartup},
		TailDNSRunValue: registryValueRecord{Path: runKeyPath, Name: runValueName},
	}
	running, err := processPathRunning(paths.GUI)
	if err != nil {
		return startupRecord{}, fmt.Errorf("checking official GUI process: %w", err)
	}
	record.OfficialGUIRunning = running

	if info, err := os.Stat(paths.OfficialStartup); err == nil && info.Mode().IsRegular() {
		record.OfficialLink.Existed = true
		record.OfficialLink.OriginalHash, err = hashFile(paths.OfficialStartup)
		if err != nil {
			return startupRecord{}, err
		}
		record.OfficialLink.OriginalPath = filepath.Join(recovery, "Tailscale.lnk")
		if err := copyVerified(paths.OfficialStartup, record.OfficialLink.OriginalPath, record.OfficialLink.OriginalHash); err != nil {
			return startupRecord{}, err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return startupRecord{}, fmt.Errorf("inspecting official GUI startup link: %w", err)
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return startupRecord{}, fmt.Errorf("opening machine startup registry: %w", err)
	}
	defer key.Close()
	value, kind, err := key.GetStringValue(runValueName)
	if err == nil {
		record.TailDNSRunValue.Existed = true
		record.TailDNSRunValue.Value = value
		record.TailDNSRunValue.Kind = kind
	} else if !errors.Is(err, registry.ErrNotExist) {
		return startupRecord{}, fmt.Errorf("reading existing TailDNS startup value: %w", err)
	}
	return record, nil
}

func activateTray(paths installPaths, record startupRecord) error {
	if err := terminateProcessesByPath(paths.GUI); err != nil {
		return fmt.Errorf("stopping official GUI: %w", err)
	}
	if record.OfficialLink.Existed {
		got, err := hashFile(record.OfficialLink.Path)
		if err != nil || !strings.EqualFold(got, record.OfficialLink.OriginalHash) {
			return errors.New("official GUI startup link changed after the deployment record was created")
		}
		if err := os.Remove(record.OfficialLink.Path); err != nil {
			return fmt.Errorf("disabling official GUI startup: %w", err)
		}
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening machine startup registry: %w", err)
	}
	if err := key.SetStringValue(runValueName, tailDNSRunCommand(paths.Tray)); err != nil {
		key.Close()
		return fmt.Errorf("registering TailDNS tray startup: %w", err)
	}
	key.Close()
	if err := winutil.StartProcessAsCurrentGUIUser(paths.Tray, nil); err != nil {
		return fmt.Errorf("starting TailDNS tray for the interactive user: %w", err)
	}
	return nil
}

func restoreStartup(paths installPaths, record startupRecord) error {
	if err := terminateProcessesByPath(paths.Tray); err != nil {
		return fmt.Errorf("stopping TailDNS tray: %w", err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening machine startup registry: %w", err)
	}
	current, _, currentErr := key.GetStringValue(runValueName)
	currentIsOriginal := record.TailDNSRunValue.Existed && current == record.TailDNSRunValue.Value
	if currentErr == nil && current != tailDNSRunCommand(paths.Tray) && !currentIsOriginal {
		key.Close()
		return errors.New("refusing to overwrite a changed TailDNS startup value")
	}
	if currentErr != nil && !errors.Is(currentErr, registry.ErrNotExist) {
		key.Close()
		return fmt.Errorf("reading TailDNS startup value: %w", currentErr)
	}
	if record.TailDNSRunValue.Existed {
		if record.TailDNSRunValue.Kind == registry.EXPAND_SZ {
			err = key.SetExpandStringValue(runValueName, record.TailDNSRunValue.Value)
		} else {
			err = key.SetStringValue(runValueName, record.TailDNSRunValue.Value)
		}
	} else if currentErr == nil {
		err = key.DeleteValue(runValueName)
	}
	key.Close()
	if err != nil {
		return fmt.Errorf("restoring TailDNS startup value: %w", err)
	}
	if record.OfficialLink.Existed {
		if got, err := hashFile(record.OfficialLink.OriginalPath); err != nil || !strings.EqualFold(got, record.OfficialLink.OriginalHash) {
			return errors.New("official GUI startup-link backup is unavailable or corrupt")
		}
		if got, err := hashFile(record.OfficialLink.Path); err == nil && !strings.EqualFold(got, record.OfficialLink.OriginalHash) {
			return errors.New("refusing to overwrite a changed official GUI startup link")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := copyVerified(record.OfficialLink.OriginalPath, record.OfficialLink.Path, record.OfficialLink.OriginalHash); err != nil {
			return err
		}
	}
	if record.OfficialGUIRunning {
		if err := winutil.StartProcessAsCurrentGUIUser(paths.GUI, nil); err != nil {
			return fmt.Errorf("restarting official GUI after rollback: %w", err)
		}
	}
	return nil
}

func verifyActiveStartup(paths installPaths, record startupRecord) error {
	if record.OfficialLink.Existed {
		if _, err := os.Stat(record.OfficialLink.Path); err == nil {
			return errors.New("official GUI startup link is active during TailDNS deployment")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(runValueName)
	if err != nil {
		return err
	}
	if value != tailDNSRunCommand(paths.Tray) {
		return errors.New("TailDNS tray startup value does not target the installed tray")
	}
	running, err := processPathRunning(paths.Tray)
	if err != nil {
		return err
	}
	if !running {
		return errors.New("TailDNS tray is not running for the interactive user")
	}
	return nil
}

func processHandlesByPath(executable string) ([]windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	wanted, err := filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	var handles []windows.Handle
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err := windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		process, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if openErr != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_PATH)
		size := uint32(len(buf))
		queryErr := windows.QueryFullProcessImageName(process, 0, &buf[0], &size)
		if queryErr != nil || !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buf[:size])), filepath.Clean(wanted)) {
			windows.CloseHandle(process)
			continue
		}
		handles = append(handles, process)
	}
	return handles, nil
}

func processPathRunning(executable string) (bool, error) {
	handles, err := processHandlesByPath(executable)
	if err != nil {
		return false, err
	}
	for _, handle := range handles {
		windows.CloseHandle(handle)
	}
	return len(handles) != 0, nil
}

func terminateProcessesByPath(executable string) error {
	handles, err := processHandlesByPath(executable)
	if err != nil {
		return err
	}
	defer func() {
		for _, handle := range handles {
			windows.CloseHandle(handle)
		}
	}()
	for _, handle := range handles {
		if err := windows.TerminateProcess(handle, 0); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
	}
	for _, handle := range handles {
		if _, err := windows.WaitForSingleObject(handle, windows.INFINITE); err != nil {
			return err
		}
	}
	return nil
}

func restoreRecord(service *mgr.Service, paths installPaths, record deploymentRecord) error {
	if err := terminateProcessesByPath(paths.Tray); err != nil {
		return fmt.Errorf("stopping TailDNS tray before rollback: %w", err)
	}
	if err := stopService(service, paths.Daemon); err != nil {
		return err
	}
	for name, file := range record.Files {
		if file.Existed {
			if got, err := hashFile(file.OriginalPath); err != nil || !strings.EqualFold(got, file.OriginalHash) {
				return fmt.Errorf("original %s backup is unavailable or corrupt", name)
			}
			if err := replaceFromPayload(file.OriginalPath, file.Path); err != nil {
				return err
			}
		} else if err := removeKnownInstalled(file); err != nil {
			return err
		}
	}
	if err := startService(service); err != nil {
		return err
	}
	if err := waitBackend(paths.CLI); err != nil {
		return err
	}
	if err := setAutoUpdate(paths.CLI, record.OriginalUpdateCheck, record.OriginalUpdateApply); err != nil {
		return err
	}
	return restoreStartup(paths, record.Startup)
}

func removeKnownInstalled(file fileRecord) error {
	hash, err := hashFile(file.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.EqualFold(hash, file.InstalledHash) {
		return fmt.Errorf("refusing to remove changed task-owned file %s", file.Path)
	}
	return os.Remove(file.Path)
}

func stopService(service *mgr.Service, daemonPath string) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		if _, err := service.Control(svc.Stop); err != nil && status.State != svc.StopPending {
			return fmt.Errorf("stopping Tailscale service: %w", err)
		}
		if err := waitServiceState(service, svc.Stopped); err != nil {
			return err
		}
	}
	if err := terminateProcessesByPath(daemonPath); err != nil {
		return fmt.Errorf("stopping remaining Tailscale daemon processes: %w", err)
	}
	return nil
}

func startService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	if err := service.Start(); err != nil && status.State != svc.StartPending {
		return fmt.Errorf("starting Tailscale service: %w", err)
	}
	return waitServiceState(service, svc.Running)
}

func waitServiceState(service *mgr.Service, wanted svc.State) error {
	var lastCheckpoint uint32
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		if status.State == svc.Stopped && wanted != svc.Stopped {
			return fmt.Errorf("Tailscale service stopped with code %d", status.Win32ExitCode)
		}
		wait := time.Duration(status.WaitHint/10) * time.Millisecond
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		if wait > 2*time.Second {
			wait = 2 * time.Second
		}
		if status.CheckPoint != 0 {
			lastCheckpoint = status.CheckPoint
		}
		_ = lastCheckpoint
		time.Sleep(wait)
	}
}

func replaceFromPayload(source, destination string) error {
	staged := destination + ".taildns-staged"
	if err := copyFile(source, staged); err != nil {
		return err
	}
	if info, err := os.Stat(destination); err == nil && info.Mode().IsRegular() {
		if err := replaceFile(staged, destination); err != nil {
			_ = os.Remove(staged)
			return err
		}
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(staged)
		return err
	}
	return moveFile(staged, destination)
}

func replaceFile(source, destination string) error {
	dst, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	r1, _, callErr := replaceFileW.Call(uintptr(unsafe.Pointer(dst)), uintptr(unsafe.Pointer(src)), 0, 1, 0, 0)
	if r1 == 0 {
		return fmt.Errorf("atomically replacing %s: %w", destination, callErr)
	}
	return nil
}

func moveFile(source, destination string) error {
	src, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func copyVerified(source, destination, expectedHash string) error {
	if got, err := hashFile(destination); err == nil && strings.EqualFold(got, expectedHash) {
		return nil
	}
	if err := copyFile(source, destination); err != nil {
		return err
	}
	got, err := hashFile(destination)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, expectedHash) {
		return fmt.Errorf("backup hash mismatch for %s", destination)
	}
	return nil
}

func copyFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeRecord(path string, record deploymentRecord) error {
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if containsFold(string(raw), "PrivateNodeKey") || containsFold(string(raw), "NetworkLockKey") || containsFold(string(raw), "server-state") {
		return errors.New("deployment record contains prohibited private-state material")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	staged := path + ".new"
	if err := os.WriteFile(staged, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return moveFile(staged, path)
}

func readRecord(path string) (deploymentRecord, error) {
	var record deploymentRecord
	raw, err := os.ReadFile(path)
	if err != nil {
		return record, fmt.Errorf("reading deployment record: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return record, err
	}
	if record.SchemaVersion != 4 || record.ServicePath == "" || len(record.Files) != 4 {
		return record, errors.New("unsupported or incomplete deployment record")
	}
	return record, nil
}

func commandJSON(cli string, target any, args ...string) error {
	output, err := exec.Command(cli, args...).Output()
	if err != nil {
		return fmt.Errorf("running %s %s: %w", cli, strings.Join(args, " "), err)
	}
	if err := json.Unmarshal(output, target); err != nil {
		return fmt.Errorf("parsing %s %s output: %w", cli, strings.Join(args, " "), err)
	}
	return nil
}

func readPrefs(cli string) (prefsJSON, error) {
	var prefs prefsJSON
	err := commandJSON(cli, &prefs, "debug", "prefs")
	return prefs, err
}

var lockKeyRE = regexp.MustCompile(`This node's tailnet-lock key:\s*(tlpub:[0-9a-f]+)`)

func readIdentity(cli string) (machineIdentity, error) {
	var status statusJSON
	if err := commandJSON(cli, &status, "status", "--json"); err != nil {
		return machineIdentity{}, err
	}
	if status.BackendState != "Running" || !status.HaveNodeKey || !status.Self.Online || status.Self.ID == "" || status.Self.DNSName == "" {
		return machineIdentity{}, errors.New("Tailscale backend is not authenticated and running")
	}
	output, err := exec.Command(cli, "lock", "status").CombinedOutput()
	if err != nil {
		return machineIdentity{}, fmt.Errorf("reading Tailnet Lock status: %w", err)
	}
	if !bytesContains(output, []byte("Tailnet Lock is ENABLED")) || !bytesContains(output, []byte("This node is accessible under Tailnet Lock")) {
		return machineIdentity{}, errors.New("node is not accessible under Tailnet Lock")
	}
	match := lockKeyRE.FindSubmatch(output)
	if len(match) != 2 {
		return machineIdentity{}, errors.New("Tailnet Lock signing-key identity is unavailable")
	}
	return machineIdentity{NodeID: status.Self.ID, TailscaleIPs: status.Self.TailscaleIPs, TailnetLockKey: string(match[1]), DNSName: status.Self.DNSName}, nil
}

func bytesContains(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}

func setAutoUpdate(cli string, check, apply bool) error {
	cmd := exec.Command(cli, "set", fmt.Sprintf("--update-check=%t", check), fmt.Sprintf("--auto-update=%t", apply))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("updating automatic-update preferences: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitBackend(cli string) error {
	cmd := exec.Command(cli, "wait", "--timeout=0s")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("waiting for Tailscale backend: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func verifyInstalledVersion(paths installPaths, manifest releaseManifest) error {
	var version versionJSON
	if err := commandJSON(paths.CLI, &version, "version", "--json"); err != nil {
		return err
	}
	expectedLong := fmt.Sprintf("%s-taildns.%d", manifest.UpstreamVersion, manifest.Sequence)
	if version.Short != manifest.UpstreamVersion || version.Long != expectedLong || version.GitCommit != manifest.CoreCommit {
		return fmt.Errorf("installed CLI reports incompatible version %q (%q)", version.Short, version.Long)
	}
	output, err := exec.Command(paths.Daemon, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reading installed daemon version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	daemonVersion := string(output)
	for _, required := range []string{
		expectedLong,
		"tailscale commit: " + manifest.CoreCommit,
		"long version: " + expectedLong,
	} {
		if !strings.Contains(daemonVersion, required) {
			return fmt.Errorf("installed daemon version does not contain %q", required)
		}
	}
	return nil
}

func verifyPreservedComponents(paths installPaths, expected map[string]string) error {
	pathsByName := map[string]string{"tailscale-ipn.exe": paths.GUI, "wintun.dll": paths.Wintun}
	for name, expectedHash := range expected {
		path, ok := pathsByName[name]
		if !ok {
			return fmt.Errorf("deployment record contains unknown preserved component %s", name)
		}
		actual, err := hashFile(path)
		if err != nil {
			return err
		}
		if !strings.EqualFold(actual, expectedHash) {
			return fmt.Errorf("preserved component %s changed", name)
		}
	}
	return nil
}

func setResolver(resolver, endpoint string) error {
	if !strings.HasPrefix(endpoint, "https://") {
		return errors.New("DNS endpoint must be an HTTPS URL")
	}
	if output, err := exec.Command(resolver, "set", endpoint).CombinedOutput(); err != nil {
		return fmt.Errorf("configuring TailDNS resolver: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var status struct {
		Configured bool   `json:"Configured"`
		Applied    bool   `json:"Applied"`
		Endpoint   string `json:"Endpoint"`
		Reason     string `json:"Reason"`
	}
	if err := commandJSON(resolver, &status, "--json", "status"); err != nil {
		return err
	}
	if !status.Configured || !status.Applied || status.Endpoint != endpoint {
		return fmt.Errorf("resolver was not confirmed applied: %s", status.Reason)
	}
	return nil
}

func verifyDNS(identity machineIdentity) error {
	public, err := net.DefaultResolver.LookupHost(context.Background(), "example.com")
	if err != nil || len(public) == 0 {
		return fmt.Errorf("public DNS verification failed: %w", err)
	}
	if identity.DNSName == "" || len(identity.TailscaleIPs) == 0 {
		return errors.New("MagicDNS verification has no expected name or tailnet address")
	}
	magic, err := net.DefaultResolver.LookupHost(context.Background(), strings.TrimSuffix(identity.DNSName, "."))
	if err != nil || len(magic) == 0 {
		return fmt.Errorf("MagicDNS verification failed for %s: %w", identity.DNSName, err)
	}
	expected := make(map[string]bool, len(identity.TailscaleIPs))
	for _, address := range identity.TailscaleIPs {
		if parsed := net.ParseIP(address); parsed != nil {
			expected[parsed.String()] = true
		}
	}
	for _, address := range magic {
		if parsed := net.ParseIP(address); parsed != nil && expected[parsed.String()] {
			return nil
		}
	}
	return fmt.Errorf("MagicDNS answer for %s does not contain a preserved tailnet address", identity.DNSName)
}
