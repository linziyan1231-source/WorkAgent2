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
	"path/filepath"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

func main() {
	options, err := parseArguments(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "workagent-migrate-windows:", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := winmigration.Migrate(ctx, options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "workagent-migrate-windows:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "workagent-migrate-windows: encode report")
		os.Exit(1)
	}
}

func parseArguments(arguments []string) (winmigration.Options, error) {
	flags := flag.NewFlagSet("workagent-migrate-windows", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	snapshotRoot := flags.String("snapshot-root", "", "absolute path to the completed frozen Windows capture")
	captureSpec := flags.String("capture-spec", "", "absolute path to the private frozen-capture spec")
	stagingDir := flags.String("staging-dir", "", "absolute path for the offline Linux staging output")
	tenantDataRoot := flags.String("tenant-data-root", "/srv/workagent/users", "future production tenant-data root used in rewritten records")
	externalWorkspaceManifest := flags.String("external-workspace-manifest", "", "required fixed <snapshot-root>/external-workspaces.json captured manifest")
	dryRun := flags.Bool("dry-run", false, "validate inputs and emit a plan without writing staging output")
	if err := flags.Parse(arguments); err != nil {
		return winmigration.Options{}, err
	}
	if flags.NArg() != 0 {
		return winmigration.Options{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	for _, required := range []struct{ name, value string }{
		{"--snapshot-root", *snapshotRoot},
		{"--capture-spec", *captureSpec},
		{"--staging-dir", *stagingDir},
		{"--external-workspace-manifest", *externalWorkspaceManifest},
	} {
		if required.value == "" {
			return winmigration.Options{}, fmt.Errorf("%s is required", required.name)
		}
	}
	if *externalWorkspaceManifest != filepath.Join(*snapshotRoot, "external-workspaces.json") {
		return winmigration.Options{}, fmt.Errorf("--external-workspace-manifest must be exactly <snapshot-root>/external-workspaces.json")
	}
	return winmigration.Options{
		SnapshotRoot: *snapshotRoot, CaptureSpec: *captureSpec, StagingDir: *stagingDir, TenantDataRoot: *tenantDataRoot,
		ExternalWorkspaceManifest: *externalWorkspaceManifest, DryRun: *dryRun,
	}, nil
}
