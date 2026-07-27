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

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

func main() {
	flags := flag.NewFlagSet("workagent-migrate-windows", flag.ExitOnError)
	snapshotRoot := flags.String("snapshot-root", "", "absolute path to the read-only Windows snapshot")
	stagingDir := flags.String("staging-dir", "", "absolute path for the offline Linux staging output")
	tenantDataRoot := flags.String("tenant-data-root", "/srv/workagent/users", "future production tenant-data root used in rewritten records")
	externalWorkspaceManifest := flags.String("external-workspace-manifest", "", "absolute path to a private external-workspace manifest inside the snapshot")
	dryRun := flags.Bool("dry-run", false, "validate inputs and emit a plan without writing staging output")
	flags.Parse(os.Args[1:])
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, err := winmigration.Migrate(ctx, winmigration.Options{
		SnapshotRoot: *snapshotRoot, StagingDir: *stagingDir, TenantDataRoot: *tenantDataRoot, ExternalWorkspaceManifest: *externalWorkspaceManifest, DryRun: *dryRun,
	})
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
