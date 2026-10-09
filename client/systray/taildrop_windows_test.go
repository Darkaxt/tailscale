// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package systray

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/types/empty"
)

type testTaildropClient struct {
	body         string
	size         int64
	readErr      bool
	deleteErr    bool
	deletes      int
	beforeDelete func()
	files        []apitype.WaitingFile
	gets         int
}

func (c *testTaildropClient) WaitingFiles(context.Context) ([]apitype.WaitingFile, error) {
	return c.files, nil
}

func (c *testTaildropClient) GetWaitingFile(context.Context, string) (io.ReadCloser, int64, error) {
	c.gets++
	if c.readErr {
		return nil, 0, errors.New("read denied")
	}
	return io.NopCloser(strings.NewReader(c.body)), c.size, nil
}
func (c *testTaildropClient) DeleteWaitingFile(context.Context, string) error {
	if c.beforeDelete != nil {
		c.beforeDelete()
	}
	c.deletes++
	if c.deleteErr {
		return errors.New("ack denied")
	}
	c.files = nil
	return nil
}

func TestTaildropReceivePublishesQuarantinedFileBeforeAck(t *testing.T) {
	dir := t.TempDir()
	c := &testTaildropClient{body: "photo", size: 5}
	c.beforeDelete = func() {
		b, err := os.ReadFile(filepath.Join(dir, "photo.jpg"))
		if err != nil || string(b) != "photo" {
			t.Fatalf("ack before publication: %q %v", b, err)
		}
		b, err = os.ReadFile(filepath.Join(dir, "photo.jpg:Zone.Identifier"))
		if err != nil || !strings.Contains(string(b), "ZoneId=3") {
			t.Fatalf("missing quarantine: %q %v", b, err)
		}
	}
	got, err := receiveTaildropFile(context.Background(), c, apitype.WaitingFile{Name: "photo.jpg", Size: 5}, dir)
	if err != nil || got != filepath.Join(dir, "photo.jpg") || c.deletes != 1 {
		t.Fatalf("got=%q err=%v deletes=%d", got, err, c.deletes)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("staging leaked: %v", files)
	}
}

func TestTaildropReceiveNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"photo.jpg", "photo (1).jpg"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := &testTaildropClient{body: "new", size: 3}
	got, err := receiveTaildropFile(context.Background(), c, apitype.WaitingFile{Name: "photo.jpg", Size: 3}, dir)
	if err != nil || filepath.Base(got) != "photo (2).jpg" {
		t.Fatalf("%q %v", got, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "photo.jpg"))
	if string(b) != "original" {
		t.Fatal("overwrote original")
	}
}

func TestTaildropReceiveFailurePreservesInbox(t *testing.T) {
	for _, tt := range []struct {
		name    string
		c       testTaildropClient
		listed  int64
		missing bool
	}{
		{"short body", testTaildropClient{body: "abc", size: 5}, 5, false},
		{"long body", testTaildropClient{body: "abcdef", size: 5}, 5, false},
		{"changed size", testTaildropClient{body: "abc", size: 3}, 4, false},
		{"read denied", testTaildropClient{readErr: true}, 3, false},
		{"missing folder", testTaildropClient{body: "abc", size: 3}, 3, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := dir
			if tt.missing {
				target = filepath.Join(dir, "missing")
			}
			_, err := receiveTaildropFile(context.Background(), &tt.c, apitype.WaitingFile{Name: "photo.jpg", Size: tt.listed}, target)
			if err == nil || tt.c.deletes != 0 {
				t.Fatalf("err=%v deletes=%d", err, tt.c.deletes)
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 {
				t.Fatalf("partial output leaked: %v", files)
			}
		})
	}
}

func TestTaildropAckFailureKeepsPublishedFile(t *testing.T) {
	dir := t.TempDir()
	c := &testTaildropClient{body: "photo", size: 5, deleteErr: true}
	got, err := receiveTaildropFile(context.Background(), c, apitype.WaitingFile{Name: "photo.jpg", Size: 5}, dir)
	if err == nil || got == "" {
		t.Fatalf("%q %v", got, err)
	}
	b, e := os.ReadFile(got)
	if e != nil || string(b) != "photo" {
		t.Fatalf("lost published file: %v", e)
	}
}

func TestTaildropRejectsUnsafeWindowsNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../outside", `..\outside`, `C:\outside`, "a:stream", "NUL", "con.txt", "COM1.jpg", "LPT².txt", "CONIN$", "con .jpg", "a.", "a ", "a/b", "a\x00b", "a?b"} {
		t.Run(name, func(t *testing.T) {
			c := &testTaildropClient{body: "x", size: 1}
			dir := t.TempDir()
			if _, err := receiveTaildropFile(context.Background(), c, apitype.WaitingFile{Name: name, Size: 1}, dir); err == nil {
				t.Fatal("accepted unsafe name")
			}
			if c.deletes != 0 {
				t.Fatal("deleted rejected file")
			}
			if c.gets != 0 {
				t.Fatal("unsafe name reached LocalAPI")
			}
		})
	}
}

func taildropHTTPClient(s *httptest.Server) *local.Client {
	return &local.Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(s.URL, "http://"))
	}}
}

func TestTaildropLocalAPIToDownloads(t *testing.T) {
	dir := t.TempDir()
	name := "photo #1.jpg"
	deleted := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/localapi/v0/files/" && r.Method == "GET":
			json.NewEncoder(w).Encode([]apitype.WaitingFile{{Name: name, Size: 5}})
		case r.URL.Path == "/localapi/v0/files/"+name && r.Method == "GET":
			w.Header().Set("Content-Length", "5")
			io.WriteString(w, "photo")
		case r.URL.Path == "/localapi/v0/files/"+name && r.Method == "DELETE":
			if b, e := os.ReadFile(filepath.Join(dir, name)); e != nil || string(b) != "photo" {
				t.Error("LocalAPI ack before complete file")
			}
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", 400)
		}
	}))
	defer s.Close()
	var notices []string
	receiver := taildropReceiver{client: taildropHTTPClient(s), directory: func() (string, error) { return dir, nil }, notify: func(title, body string) { notices = append(notices, body) }}
	receiver.receive(context.Background(), true)
	if !deleted || len(notices) != 1 || notices[0] != filepath.Join(dir, name) {
		t.Fatalf("deleted=%v notices=%v", deleted, notices)
	}
}

func TestTaildropIPNReconnectAndArrivalTrigger(t *testing.T) {
	arrival := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/localapi/v0/watch-ipn-bus") {
			http.Error(w, "unexpected route", 400)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-arrival:
		case <-r.Context().Done():
			return
		}
		json.NewEncoder(w).Encode(ipn.Notify{FilesWaiting: &empty.Message{}})
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Menu{lc: taildropHTTPClient(s), bgCtx: ctx, taildropCh: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { done <- m.watchIPNBusInner() }()
	<-m.taildropCh
	if !m.taildropRetry.Swap(false) {
		t.Fatal("reconnect did not recover pending files")
	}
	close(arrival)
	<-m.taildropCh
	if m.taildropRetry.Load() {
		t.Fatal("arrival must not reset failures")
	}
	cancel()
	<-done
}

func TestTaildropKnownFolder(t *testing.T) {
	dir, err := taildropDownloadsDirectory()
	if err != nil || !filepath.IsAbs(dir) {
		t.Fatalf("%q %v", dir, err)
	}
}

func TestTaildropReceiverPendingStartupRepeatedEventAndRetry(t *testing.T) {
	dir := t.TempDir()
	c := &testTaildropClient{body: "photo", size: 5, files: []apitype.WaitingFile{{Name: "photo.jpg", Size: 5}}, readErr: true}
	var notices []string
	r := taildropReceiver{client: c, directory: func() (string, error) { return dir, nil }, notify: func(title, body string) { notices = append(notices, title) }}
	r.receive(context.Background(), true)
	r.receive(context.Background(), false)
	if c.gets != 1 || len(notices) != 1 {
		t.Fatalf("repeated failed attempt: gets=%d notices=%v", c.gets, notices)
	}
	c.readErr = false
	r.receive(context.Background(), true)
	r.receive(context.Background(), false)
	if c.deletes != 1 || c.gets != 2 || len(notices) != 2 || notices[1] != "Taildrop file received" {
		t.Fatalf("gets=%d deletes=%d notices=%v", c.gets, c.deletes, notices)
	}
}

func TestTaildropRequestsCoalesceWithoutLosingExplicitRetry(t *testing.T) {
	m := &Menu{taildropCh: make(chan struct{}, 1)}
	m.requestTaildrop(false)
	m.requestTaildrop(true)
	m.requestTaildrop(false)
	if len(m.taildropCh) != 1 || !m.taildropRetry.Swap(false) {
		t.Fatal("lost retry while event was pending")
	}
}

func TestWindowsNotificationNativeLayoutAndText(t *testing.T) {
	if runtime.GOARCH == "amd64" && unsafe.Sizeof(windowsNotification{}) != 976 {
		t.Fatalf("invalid NOTIFYICONDATAW size %d", unsafe.Sizeof(windowsNotification{}))
	}
	var dst [6]uint16
	notificationText(dst[:], "abc😀x")
	if got := string(utf16.Decode(dst[:5])); got != "abc😀" || dst[5] != 0 {
		t.Fatalf("bad termination/truncation: %q %v", got, dst)
	}
	var short [5]uint16
	notificationText(short[:], "abc😀")
	if string(utf16.Decode(short[:3])) != "abc" || short[3] != 0 {
		t.Fatalf("split surrogate: %v", short)
	}
}

func TestTaildropWorkerShutdownCancelsLocalAPIRead(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/localapi/v0/files/" {
			json.NewEncoder(w).Encode([]apitype.WaitingFile{{Name: "photo.jpg", Size: 5}})
			return
		}
		close(started)
		<-r.Context().Done()
	}))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Menu{lc: taildropHTTPClient(s), bgCtx: ctx, taildropCh: make(chan struct{}, 1)}
	m.startTaildrop()
	<-started
	cancel()
	m.stopTaildrop()
}

func TestTaildropCanceledCopyIsNotPublished(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	c := &testTaildropClient{body: "photo", size: 5}
	if _, err := receiveTaildropFile(ctx, c, apitype.WaitingFile{Name: "photo.jpg", Size: 5}, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 || c.deletes != 0 {
		t.Fatal("canceled copy was published/acknowledged")
	}
}
