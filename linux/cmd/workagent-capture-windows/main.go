//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/wincapture"
)

type commandOptions struct {
	spec, legacySnapshot, migrationReport, specOutput string
	destination, captureID, confirm                   string
	check, capture, initSpec, verifyFinalDelta        bool
	windowsFrozen                                     bool
}

func parseArguments(arguments []string) (commandOptions, error) {
	var options commandOptions
	flags := flag.NewFlagSet("workagent-capture-windows", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.spec, "spec", "", "absolute path to the root-owned 0600 private capture spec")
	flags.BoolVar(&options.check, "check", false, "run a read-only rehearsal; never publish a final snapshot")
	flags.BoolVar(&options.capture, "capture", false, "stream and atomically publish a frozen final snapshot")
	flags.BoolVar(&options.verifyFinalDelta, "verify-final-delta", false, "compare a completed capture with two frozen, read-only Windows inventories")
	flags.BoolVar(&options.initSpec, "init-spec", false, "create a private spec from a protected legacy snapshot and completed migration report")
	flags.StringVar(&options.legacySnapshot, "legacy-snapshot", "", "absolute root-owned 0700 protected legacy snapshot used only by --init-spec")
	flags.StringVar(&options.migrationReport, "migration-report", "", "absolute root-owned 0600 completed migration report used only by --init-spec")
	flags.StringVar(&options.specOutput, "spec-output", "", "absolute private spec path used only by --init-spec; exact-content retries converge")
	flags.StringVar(&options.destination, "destination", "", "absolute final snapshot path; basename must equal capture ID")
	flags.StringVar(&options.captureID, "capture-id", "", "unique immutable capture ID")
	flags.StringVar(&options.confirm, "confirm", "", "exact mode-specific confirmation token")
	flags.BoolVar(&options.windowsFrozen, "windows-frozen", false, "declare that an operator has externally frozen all Windows writers")
	if err := flags.Parse(arguments); err != nil {
		return commandOptions{}, fmt.Errorf("invalid arguments")
	}
	selected := 0
	for _, value := range []bool{options.check, options.capture, options.initSpec, options.verifyFinalDelta} {
		if value {
			selected++
		}
	}
	if flags.NArg() != 0 || selected != 1 {
		return commandOptions{}, fmt.Errorf("choose exactly one of --init-spec, --check, --capture, or --verify-final-delta")
	}
	if options.initSpec {
		if options.spec != "" || options.destination != "" || options.captureID != "" || options.confirm != "" || options.windowsFrozen {
			return commandOptions{}, fmt.Errorf("--init-spec accepts only --legacy-snapshot, --migration-report, and --spec-output")
		}
		if options.legacySnapshot == "" || options.migrationReport == "" || options.specOutput == "" {
			return commandOptions{}, fmt.Errorf("--init-spec requires --legacy-snapshot, --migration-report, and --spec-output")
		}
	} else if options.check {
		if options.legacySnapshot != "" || options.migrationReport != "" || options.specOutput != "" || options.destination != "" || options.captureID != "" || options.confirm != "" || options.windowsFrozen {
			return commandOptions{}, fmt.Errorf("rehearsal accepts only --spec and --check")
		}
		if options.spec == "" {
			return commandOptions{}, fmt.Errorf("rehearsal requires --spec")
		}
	} else if options.legacySnapshot != "" || options.migrationReport != "" || options.specOutput != "" {
		return commandOptions{}, fmt.Errorf("capture and final-delta modes do not accept spec-initialization inputs")
	} else if options.capture && (options.spec == "" || options.destination == "" || options.captureID == "" || !options.windowsFrozen || options.confirm != "FINAL-WINDOWS-CAPTURE:"+options.captureID) {
		return commandOptions{}, fmt.Errorf("--capture requires --spec, --destination, --capture-id, --windows-frozen, and the exact capture confirmation")
	} else if options.verifyFinalDelta && (options.spec == "" || options.destination == "" || options.captureID == "" || !options.windowsFrozen || options.confirm != "FINAL-WINDOWS-DELTA:"+options.captureID) {
		return commandOptions{}, fmt.Errorf("--verify-final-delta requires --spec, --destination, --capture-id, --windows-frozen, and the exact final-delta confirmation")
	}
	return options, nil
}

func main() {
	options, parseErr := parseArguments(os.Args[1:])
	if parseErr != nil {
		fmt.Fprintln(os.Stderr, "workagent-capture-windows:", parseErr)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if options.initSpec {
		report, err := wincapture.InitializeSpec(ctx, wincapture.InitSpecOptions{LegacySnapshot: options.legacySnapshot, MigrationReport: options.migrationReport, Output: options.specOutput})
		if err != nil {
			fmt.Fprintln(os.Stderr, "workagent-capture-windows:", err)
			os.Exit(1)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, "workagent-capture-windows: encode redacted init report")
			os.Exit(1)
		}
		return
	}
	var report wincapture.Report
	var err error
	switch {
	case options.check:
		report, err = wincapture.Check(ctx, wincapture.CheckOptions{SpecPath: options.spec})
	case options.capture:
		report, err = wincapture.Capture(ctx, wincapture.CaptureOptions{
			SpecPath: options.spec, Destination: options.destination, CaptureID: options.captureID, Confirm: options.confirm, WindowsFrozen: options.windowsFrozen,
		})
	case options.verifyFinalDelta:
		report, err = wincapture.VerifyFinalDelta(ctx, wincapture.FinalDeltaOptions{
			SpecPath: options.spec, Destination: options.destination, CaptureID: options.captureID, Confirm: options.confirm, WindowsFrozen: options.windowsFrozen,
		})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "workagent-capture-windows:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "workagent-capture-windows: encode redacted report")
		os.Exit(1)
	}
}
