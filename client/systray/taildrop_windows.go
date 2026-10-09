// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/util/quarantine"
)

type taildropClient interface {
	WaitingFiles(context.Context) ([]apitype.WaitingFile, error)
	GetWaitingFile(context.Context, string) (io.ReadCloser, int64, error)
	DeleteWaitingFile(context.Context, string) error
}

// Resolve this at each batch: Downloads can be redirected while the tray runs.
func taildropDownloadsDirectory() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Downloads, windows.KF_FLAG_DEFAULT)
}

func validTaildropName(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	// Reject reserved basenames even with extensions, independently of OS
	// long-path/device-name handling (IsLocal alone permits some on newer Windows).
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return false
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		if len([]rune(base)) == 4 && strings.Contains("123456789¹²³", base[3:]) {
			return false
		}
	}
	return filepath.IsLocal(name) && filepath.Base(name) == name &&
		!strings.ContainsAny(name, `<>:"/\|?*`+"\x00") &&
		!strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ") &&
		!strings.ContainsFunc(name, func(r rune) bool { return r < 32 })
}

// receiveTaildropFile returns the saved path even if subsequent inbox ack fails.
// Only the owned staging file is removed on error; a published file is never removed.
func receiveTaildropFile(ctx context.Context, c interface {
	GetWaitingFile(context.Context, string) (io.ReadCloser, int64, error)
	DeleteWaitingFile(context.Context, string) error
}, wf apitype.WaitingFile, dir string) (saved string, err error) {
	if !validTaildropName(wf.Name) || wf.Size < 0 || wf.Size == math.MaxInt64 {
		return "", errors.New("unsafe Taildrop filename or size")
	}
	rc, size, err := c.GetWaitingFile(ctx, wf.Name)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	if size != wf.Size {
		return "", errors.New("inbox size changed; file retained")
	}
	f, err := os.CreateTemp(dir, ".taildns-receive-*")
	if err != nil {
		return "", err
	}
	stage := f.Name()
	defer func() { f.Close(); os.Remove(stage) }()
	if err = quarantine.SetOnFile(f); err != nil {
		return "", fmt.Errorf("quarantine: %w", err)
	}
	n, err := io.Copy(f, io.LimitReader(rc, size+1))
	if err != nil {
		return "", err
	}
	if n != size {
		return "", fmt.Errorf("incomplete Taildrop copy: got %d bytes, want %d", n, size)
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	from, err := windows.UTF16PtrFromString(stage)
	if err != nil {
		return "", err
	}
	ext := filepath.Ext(wf.Name)
	for i := 0; ; i++ {
		name := wf.Name
		if i > 0 {
			name = fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(wf.Name, ext), i, ext)
		}
		target := filepath.Join(dir, name)
		to, e := windows.UTF16PtrFromString(target)
		if e != nil {
			return "", e
		}
		// No REPLACE_EXISTING: an existing file, directory, link or ADS is never overwritten.
		e = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
		if e == nil {
			saved = target
			break
		}
		if _, statErr := os.Lstat(target); statErr == nil {
			continue
		}
		return "", fmt.Errorf("publish Taildrop file: %w", e)
	}
	if err = c.DeleteWaitingFile(ctx, wf.Name); err != nil {
		return saved, fmt.Errorf("saved file; inbox acknowledgement failed: %w", err)
	}
	return saved, nil
}

type taildropReceiver struct {
	client    taildropClient
	directory func() (string, error)
	notify    func(string, string)
	failed    map[apitype.WaitingFile]bool
	blocked   bool // inbox/destination failure: wait for explicit retry or reconnect
}

func (r *taildropReceiver) receive(ctx context.Context, retry bool) {
	if r.blocked && !retry {
		return
	}
	if retry || r.failed == nil {
		r.failed = make(map[apitype.WaitingFile]bool)
		r.blocked = false
	}
	files, err := r.client.WaitingFiles(ctx)
	if err != nil {
		r.blocked = true
		if ctx.Err() == nil {
			r.notify("Taildrop receive failed", "Cannot read the inbox. Use Taildrop > Receive pending files to retry.")
			log.Printf("Taildrop inbox: %v", err)
		}
		return
	}
	if len(files) == 0 {
		clear(r.failed)
		return
	}
	dir, err := r.directory()
	if err != nil {
		r.blocked = true
		r.notify("Taildrop receive failed", "Cannot locate Downloads. Files remain in the inbox.")
		log.Printf("Taildrop Downloads: %v", err)
		return
	}
	for _, wf := range files {
		if ctx.Err() != nil {
			return
		}
		if r.failed[wf] {
			continue
		}
		saved, err := receiveTaildropFile(ctx, r.client, wf, dir)
		if saved != "" {
			log.Printf("Taildrop saved: %s (%d bytes)", saved, wf.Size)
			if ctx.Err() == nil {
				r.notify("Taildrop file received", saved)
			}
		}
		if err != nil {
			r.failed[wf] = true
			log.Printf("Taildrop receive %q: %v", wf.Name, err)
			if ctx.Err() == nil {
				r.notify("Taildrop receive needs attention", wf.Name+": "+err.Error()+". Use Taildrop > Receive pending files to retry.")
			}
		}
	}
	// Forget failures once that inbox item disappears (e.g. handled by the CLI).
	for old := range r.failed {
		found := false
		for _, wf := range files {
			if wf == old {
				found = true
				break
			}
		}
		if !found {
			delete(r.failed, old)
		}
	}
}

func (menu *Menu) requestTaildrop(retry bool) {
	if retry {
		menu.taildropRetry.Store(true)
	}
	select {
	case menu.taildropCh <- struct{}{}:
	default:
	}
}

func (menu *Menu) startTaildrop() {
	menu.taildropDone = make(chan struct{})
	go func() {
		defer close(menu.taildropDone)
		r := taildropReceiver{client: menu.lc, directory: taildropDownloadsDirectory, notify: menu.sendNotification}
		for {
			select {
			case <-menu.bgCtx.Done():
				return
			case <-menu.taildropCh:
				r.receive(menu.bgCtx, menu.taildropRetry.Swap(false))
			}
		}
	}()
	menu.requestTaildrop(true)
}

func (menu *Menu) stopTaildrop() {
	if menu.taildropDone != nil {
		<-menu.taildropDone
	}
}

func (menu *Menu) addTaildropMenu(ctx context.Context) {
	item := systray.AddMenuItem("Taildrop", "Received files are saved in Downloads")
	open := item.AddSubMenuItem("Open Downloads", "")
	onClick(ctx, open, func(context.Context) {
		dir, err := taildropDownloadsDirectory()
		if err == nil {
			p, e := windows.UTF16PtrFromString(dir)
			err = e
			if e == nil {
				err = windows.ShellExecute(0, nil, p, nil, nil, windows.SW_SHOWNORMAL)
			}
		}
		if err != nil {
			menu.sendNotification("Cannot open Downloads", err.Error())
		}
	})
	receive := item.AddSubMenuItem("Receive pending files", "Retry files retained after a receive error")
	onClick(ctx, receive, func(context.Context) { menu.requestTaildrop(true) })
}
