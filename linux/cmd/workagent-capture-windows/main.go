//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/wincapture"
)

func main() {
	flags := flag.NewFlagSet("workagent-capture-windows", flag.ExitOnError)
	spec := flags.String("spec", "", "absolute path to the root-owned 0600 private capture spec")
	check := flags.Bool("check", false, "run a read-only rehearsal; never publish a final snapshot")
	capture := flags.Bool("capture", false, "stream and atomically publish a frozen final snapshot")
	initSpec := flags.Bool("init-spec", false, "create a private spec from a protected legacy snapshot and completed migration report")
	legacySnapshot := flags.String("legacy-snapshot", "", "absolute root-owned 0700 protected legacy snapshot used only by --init-spec")
	migrationReport := flags.String("migration-report", "", "absolute root-owned 0600 completed migration report used only by --init-spec")
	specOutput := flags.String("spec-output", "", "absolute private spec path used only by --init-spec; exact-content retries converge")
	destination := flags.String("destination", "", "absolute final snapshot path; basename must equal capture ID")
	captureID := flags.String("capture-id", "", "unique immutable capture ID")
	confirm := flags.String("confirm", "", "exact FINAL-WINDOWS-CAPTURE:<capture-id> confirmation token")
	windowsFrozen := flags.Bool("windows-frozen", false, "declare that an operator has externally frozen all Windows writers")
	flags.Parse(os.Args[1:])
	selected := 0
	for _, value := range []bool{*check, *capture, *initSpec} {
		if value {
			selected++
		}
	}
	if flags.NArg() != 0 || selected != 1 {
		fmt.Fprintln(os.Stderr, "workagent-capture-windows: choose exactly one of --init-spec, --check, or --capture")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *initSpec {
		if *spec != "" || *destination != "" || *captureID != "" || *confirm != "" || *windowsFrozen || *check || *capture {
			fmt.Fprintln(os.Stderr, "workagent-capture-windows: --init-spec accepts only --legacy-snapshot, --migration-report, and --spec-output")
			os.Exit(2)
		}
		report, err := wincapture.InitializeSpec(ctx, wincapture.InitSpecOptions{LegacySnapshot: *legacySnapshot, MigrationReport: *migrationReport, Output: *specOutput})
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
	if *check {
		if *legacySnapshot != "" || *migrationReport != "" || *specOutput != "" {
			fmt.Fprintln(os.Stderr, "workagent-capture-windows: --check does not accept spec-initialization inputs")
			os.Exit(2)
		}
		if *destination != "" || *captureID != "" || *confirm != "" || *windowsFrozen {
			fmt.Fprintln(os.Stderr, "workagent-capture-windows: rehearsal accepts only --spec and --check")
			os.Exit(2)
		}
		report, err = wincapture.Check(ctx, wincapture.CheckOptions{SpecPath: *spec})
	} else {
		if *legacySnapshot != "" || *migrationReport != "" || *specOutput != "" {
			fmt.Fprintln(os.Stderr, "workagent-capture-windows: --capture does not accept spec-initialization inputs")
			os.Exit(2)
		}
		report, err = wincapture.Capture(ctx, wincapture.CaptureOptions{
			SpecPath: *spec, Destination: *destination, CaptureID: *captureID, Confirm: *confirm, WindowsFrozen: *windowsFrozen,
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
