// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command taildns is the independently branded local-resolver frontend for the
// TailDNS fork daemon. It does not contain or reuse the proprietary Tailscale
// Windows GUI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

type localDNSClient interface {
	LocalDNSStatus(context.Context) (*ipn.LocalDNSStatus, error)
	EditLocalDNS(context.Context, ipn.LocalDNSUpdate) (*ipn.LocalDNSStatus, error)
}

func main() {
	if err := runCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr, func(socket string) localDNSClient {
		return &local.Client{Socket: socket, UseSocketOnly: socket != ""}
	}); err != nil {
		fmt.Fprintln(os.Stderr, "taildns:", err)
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer, newClient func(string) localDNSClient) error {
	fs := flag.NewFlagSet("taildns", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "", "alternate TailDNS daemon socket or named pipe")
	jsonOutput := fs.Bool("json", false, "print status as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: taildns [--socket PATH] [--json] status")
		fmt.Fprintln(stderr, "       taildns [--socket PATH] set HTTPS_ENDPOINT")
		fmt.Fprintln(stderr, "       taildns [--socket PATH] clear")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		fs.Usage()
		return errors.New("missing command")
	}
	lc := newClient(*socket)

	switch command[0] {
	case "status":
		if len(command) != 1 {
			return errors.New("status takes no arguments")
		}
		status, err := lc.LocalDNSStatus(ctx)
		if err != nil {
			return describeLocalDNSError(err)
		}
		return printStatus(stdout, status, *jsonOutput)

	case "set":
		if len(command) != 2 {
			return errors.New("set requires exactly one HTTPS endpoint")
		}
		if err := ipn.ValidateLocalDNSResolver(command[1]); err != nil {
			return err
		}
		current, err := lc.LocalDNSStatus(ctx)
		if err != nil {
			return describeLocalDNSError(err)
		}
		if current.ProfileID == "" {
			return errors.New("daemon has no active profile")
		}
		updated, err := lc.EditLocalDNS(ctx, ipn.LocalDNSUpdate{
			ProfileID: current.ProfileID,
			Enabled:   true,
			Endpoint:  command[1],
		})
		if err != nil {
			return describeLocalDNSError(err)
		}
		if !updated.Configured || updated.Endpoint != command[1] {
			return errors.New("daemon did not confirm the requested resolver")
		}
		if !updated.Applied {
			return fmt.Errorf("resolver saved but not applied: %s", updated.Reason)
		}
		return printStatus(stdout, updated, *jsonOutput)

	case "clear":
		if len(command) != 1 {
			return errors.New("clear takes no arguments")
		}
		current, err := lc.LocalDNSStatus(ctx)
		if err != nil {
			return describeLocalDNSError(err)
		}
		if current.ProfileID == "" {
			return errors.New("daemon has no active profile")
		}
		updated, err := lc.EditLocalDNS(ctx, ipn.LocalDNSUpdate{ProfileID: current.ProfileID})
		if err != nil {
			return describeLocalDNSError(err)
		}
		if updated.Configured || updated.Endpoint != "" {
			return errors.New("daemon did not confirm resolver removal")
		}
		return printStatus(stdout, updated, *jsonOutput)

	default:
		return fmt.Errorf("unknown command %q", command[0])
	}
}

func describeLocalDNSError(err error) error {
	if errors.Is(err, local.ErrLocalDNSUnsupported) {
		return fmt.Errorf("incompatible daemon: TailDNS local DNS API is unavailable; no change was made: %w", err)
	}
	return err
}

func printStatus(w io.Writer, status *ipn.LocalDNSStatus, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	}
	yesNo := func(value bool) string {
		if value {
			return "yes"
		}
		return "no"
	}
	fmt.Fprintln(w, "TailDNS local DNS")
	fmt.Fprintf(w, "Profile: %s\n", status.ProfileID)
	fmt.Fprintf(w, "Configured: %s\n", yesNo(status.Configured))
	fmt.Fprintf(w, "Applied: %s\n", yesNo(status.Applied))
	if status.Endpoint != "" {
		fmt.Fprintf(w, "Endpoint: %s\n", status.Endpoint)
	}
	fmt.Fprintf(w, "State: %s\n", strings.TrimSpace(status.Reason))
	return nil
}
