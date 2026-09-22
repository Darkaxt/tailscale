// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"testing"
)

type fakeChild struct {
	err error
}

func (c fakeChild) Wait() error { return c.err }

func TestSupervisorStopsAfterExplicitTrayExit(t *testing.T) {
	starts := 0
	err := runSupervisor(func() (childProcess, error) {
		starts++
		return fakeChild{}, nil
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("starts = %d, want 1", starts)
	}
}

func TestSupervisorRestartsAbnormalTrayExit(t *testing.T) {
	starts := 0
	err := runSupervisor(func() (childProcess, error) {
		starts++
		if starts == 1 {
			return fakeChild{err: errors.New("crash")}, nil
		}
		return fakeChild{}, nil
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if starts != 2 {
		t.Fatalf("starts = %d, want 2", starts)
	}
}

func TestSupervisorBoundsAbnormalRestartLoop(t *testing.T) {
	starts := 0
	err := runSupervisor(func() (childProcess, error) {
		starts++
		return fakeChild{err: errors.New("crash")}, nil
	}, 3)
	if err == nil {
		t.Fatal("runSupervisor unexpectedly accepted a persistent crash loop")
	}
	if starts != 4 {
		t.Fatalf("starts = %d, want initial start plus 3 restarts", starts)
	}
}
