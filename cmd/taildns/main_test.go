// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

type fakeLocalDNSClient struct {
	status *ipn.LocalDNSStatus
	err    error
	edits  []ipn.LocalDNSUpdate
}

func (f *fakeLocalDNSClient) LocalDNSStatus(context.Context) (*ipn.LocalDNSStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	copy := *f.status
	return &copy, nil
}

func (f *fakeLocalDNSClient) EditLocalDNS(_ context.Context, update ipn.LocalDNSUpdate) (*ipn.LocalDNSStatus, error) {
	f.edits = append(f.edits, update)
	if f.err != nil {
		return nil, f.err
	}
	copy := *f.status
	copy.Configured = update.Enabled
	copy.Endpoint = update.Endpoint
	copy.ManualEndpoint = update.Endpoint
	copy.FollowAndroid = update.FollowAndroid
	copy.Applied = update.Enabled
	if update.Enabled {
		copy.Reason = "Applied; provider reachability not verified"
	} else {
		copy.Reason = "Using Tailscale DNS selection"
	}
	f.status = &copy
	return &copy, nil
}

func TestRunStatus(t *testing.T) {
	fake := &fakeLocalDNSClient{status: &ipn.LocalDNSStatus{
		ProfileID: "profile-1", Configured: true,
		Endpoint: "https://resolver.example/dns-query", Applied: true,
		Reason: "Applied; provider reachability not verified",
	}}
	var out bytes.Buffer
	err := runCLI(context.Background(), []string{"status"}, &out, &bytes.Buffer{}, func(string) localDNSClient { return fake })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TailDNS", "Configured: yes", "Applied: yes", "https://resolver.example/dns-query"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunSetAndClear(t *testing.T) {
	fake := &fakeLocalDNSClient{status: &ipn.LocalDNSStatus{ProfileID: "profile-1"}}
	newClient := func(string) localDNSClient { return fake }
	var out bytes.Buffer
	endpoint := "https://resolver.example/dns-query"
	if err := runCLI(context.Background(), []string{"set", endpoint}, &out, &bytes.Buffer{}, newClient); err != nil {
		t.Fatal(err)
	}
	if len(fake.edits) != 1 || fake.edits[0] != (ipn.LocalDNSUpdate{ProfileID: "profile-1", Enabled: true, Endpoint: endpoint}) {
		t.Fatalf("set edits = %+v", fake.edits)
	}
	if err := runCLI(context.Background(), []string{"clear"}, &out, &bytes.Buffer{}, newClient); err != nil {
		t.Fatal(err)
	}
	if len(fake.edits) != 2 || fake.edits[1] != (ipn.LocalDNSUpdate{ProfileID: "profile-1"}) {
		t.Fatalf("clear edits = %+v", fake.edits)
	}
}

func TestRunRejectsInvalidEndpointBeforeWrite(t *testing.T) {
	fake := &fakeLocalDNSClient{status: &ipn.LocalDNSStatus{ProfileID: "profile-1"}}
	err := runCLI(context.Background(), []string{"set", "http://resolver.example/dns-query"}, &bytes.Buffer{}, &bytes.Buffer{}, func(string) localDNSClient { return fake })
	if err == nil || len(fake.edits) != 0 {
		t.Fatalf("error = %v, edits = %+v", err, fake.edits)
	}
}

func TestRunRejectsUnmodifiedDaemon(t *testing.T) {
	fake := &fakeLocalDNSClient{err: local.ErrLocalDNSUnsupported}
	var out bytes.Buffer
	err := runCLI(context.Background(), []string{"set", "https://resolver.example/dns-query"}, &out, &bytes.Buffer{}, func(string) localDNSClient { return fake })
	if !errors.Is(err, local.ErrLocalDNSUnsupported) || !strings.Contains(err.Error(), "incompatible daemon") {
		t.Fatalf("error = %v", err)
	}
	if out.Len() != 0 || len(fake.edits) != 0 {
		t.Fatalf("unsupported daemon reported output %q or edits %+v", out.String(), fake.edits)
	}
}
