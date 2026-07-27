package winmigration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Migrate(ctx context.Context, options Options) (Report, error) {
	plan, err := buildPlan(ctx, options)
	if err != nil {
		return Report{}, err
	}
	defer plan.cleanup()
	if options.DryRun {
		return plan.report, nil
	}
	if _, err := os.Lstat(plan.options.StagingDir); err == nil {
		return verifyExistingStage(ctx, plan)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Report{}, fmt.Errorf("inspect staging destination: %w", err)
	}
	parent := filepath.Dir(plan.options.StagingDir)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return Report{}, errors.New("staging parent must be an existing real directory")
	}
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(plan.options.StagingDir)+".partial-")
	if err != nil {
		return Report{}, fmt.Errorf("create private migration staging directory: %w", err)
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return Report{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	for _, relative := range []string{"portal", "tenants", "backups", "backups/tenants", "backups/cliproxy", "backups/external", "cutover"} {
		if err := os.Mkdir(filepath.Join(temporary, filepath.FromSlash(relative)), 0o700); err != nil {
			return Report{}, err
		}
	}
	snapshotFD, err := openSnapshotRoot(plan.options.SnapshotRoot)
	if err != nil {
		return Report{}, err
	}
	defer closeFD(snapshotFD)
	portalSource := plan.portalSource
	if err := verifyPortalSourceSet(snapshotFD, portalSource); err != nil {
		return Report{}, err
	}
	for _, file := range []struct {
		relative string
		name     string
		hash     string
	}{
		{sourcePortalRelative, "portal.windows.db", portalSource.databaseSHA256},
		{sourcePortalWALRelative, "portal.windows.db-wal", portalSource.walSHA256},
		{sourcePortalSHMRelative, "portal.windows.db-shm", portalSource.shmSHA256},
	} {
		if err := copySecureSnapshotFile(snapshotFD, file.relative, filepath.Join(temporary, "backups", file.name), file.hash); err != nil {
			return Report{}, fmt.Errorf("archive Windows Portal %s: %w", file.name, err)
		}
	}
	if err := verifyPortalSourceSet(snapshotFD, portalSource); err != nil {
		return Report{}, err
	}
	if err := copySecureSnapshotFile(snapshotFD, legacyCPAStateRelative, filepath.Join(temporary, "backups", "cliproxy", "cpa-key-policy-state.windows.json"), plan.cpaStateSHA256); err != nil {
		return Report{}, fmt.Errorf("archive legacy CLIProxy policy state: %w", err)
	}
	if plan.options.ExternalWorkspaceManifest != "" {
		manifestRelative, err := snapshotRelativePath(plan.options.SnapshotRoot, plan.options.ExternalWorkspaceManifest)
		if err != nil {
			return Report{}, err
		}
		if err := copySecureSnapshotFile(snapshotFD, manifestRelative, filepath.Join(temporary, "backups", "external", "external-workspaces.windows.json"), plan.externalManifestSHA256); err != nil {
			return Report{}, fmt.Errorf("archive external workspace manifest: %w", err)
		}
	}
	if err := migratePortalDatabase(ctx, plan, filepath.Join(temporary, "portal")); err != nil {
		return Report{}, err
	}
	if err := verifyPortalSourceSet(snapshotFD, portalSource); err != nil {
		return Report{}, err
	}
	for index := range plan.tenants {
		tenant := &plan.tenants[index]
		fresh, err := inventoryTree(ctx, snapshotFD, tenant.sourceRelative)
		if err != nil || fresh.hash != tenant.report.SourceTreeSHA256 {
			return Report{}, fmt.Errorf("tenant source %q changed after planning", tenant.report.SourceDirectory)
		}
		destination := filepath.Join(temporary, "tenants", tenant.report.TenantID)
		if err := copyTenantTree(ctx, snapshotFD, *tenant, destination); err != nil {
			return Report{}, fmt.Errorf("copy tenant %q: %w", tenant.report.SourceDirectory, err)
		}
		for _, workspace := range tenant.externalWorkspaces {
			freshExternal, err := inventoryTree(ctx, snapshotFD, workspace.sourceRelative)
			if err != nil || freshExternal.hash != workspace.report.SourceTreeSHA256 {
				return Report{}, fmt.Errorf("external workspace capture for %q changed after planning", tenant.report.SourceDirectory)
			}
			if err := copyExternalWorkspace(ctx, snapshotFD, destination, workspace); err != nil {
				return Report{}, fmt.Errorf("copy external workspace for %q: %w", tenant.report.SourceDirectory, err)
			}
			freshExternal, err = inventoryTree(ctx, snapshotFD, workspace.sourceRelative)
			if err != nil || freshExternal.hash != workspace.report.SourceTreeSHA256 {
				return Report{}, fmt.Errorf("external workspace capture for %q changed during copy", tenant.report.SourceDirectory)
			}
		}
		backupDirectory := filepath.Join(temporary, "backups", "tenants", tenant.report.TenantID)
		if err := os.Mkdir(backupDirectory, 0o700); err != nil {
			return Report{}, err
		}
		databasePath := filepath.Join(destination, "data", "aionui-backend.db")
		if err := copyLocalRegularFile(databasePath, filepath.Join(backupDirectory, "aionui-backend.db.windows.bak")); err != nil {
			return Report{}, fmt.Errorf("back up tenant database: %w", err)
		}
		if err := invalidateLegacyModelState(destination, *tenant); err != nil {
			return Report{}, fmt.Errorf("invalidate legacy model state for %q: %w", tenant.report.SourceDirectory, err)
		}
		rewrites, err := rewriteAionDatabase(ctx, databasePath, pathIdentityForTenant(*tenant))
		if err != nil {
			return Report{}, fmt.Errorf("rewrite tenant database for %q: %w", tenant.report.SourceDirectory, err)
		}
		if rewrites != tenant.report.PathRewrites {
			return Report{}, fmt.Errorf("tenant database for %q changed after planning", tenant.report.SourceDirectory)
		}
		if err := verifyTenantOutput(ctx, destination, *tenant); err != nil {
			return Report{}, err
		}
		fresh, err = inventoryTree(ctx, snapshotFD, tenant.sourceRelative)
		if err != nil || fresh.hash != tenant.report.SourceTreeSHA256 {
			return Report{}, fmt.Errorf("tenant source %q changed during copy", tenant.report.SourceDirectory)
		}
	}
	if err := writeCutoverPlan(filepath.Join(temporary, "cutover", "cliproxy-quota-overrides.json"), plan); err != nil {
		return Report{}, err
	}
	if err := verifyPortalSourceSet(snapshotFD, portalSource); err != nil {
		return Report{}, err
	}
	outputFingerprint, err := hashStagedPayload(temporary)
	if err != nil {
		return Report{}, err
	}
	plan.report.Status = "complete"
	plan.report.OutputFingerprint = outputFingerprint
	if err := writePrivateJSON(filepath.Join(temporary, "report.json"), plan.report); err != nil {
		return Report{}, err
	}
	if err := syncDirectoryTree(temporary); err != nil {
		return Report{}, err
	}
	if err := os.Rename(temporary, plan.options.StagingDir); err != nil {
		return Report{}, fmt.Errorf("publish completed staging tree: %w", err)
	}
	published = true
	if err := syncDirectory(parent); err != nil {
		return Report{}, err
	}
	return plan.report, nil
}

func writeCutoverPlan(target string, plan *migrationPlan) error {
	payload := struct {
		SchemaVersion     int                    `json:"schema_version"`
		SourceFingerprint string                 `json:"source_fingerprint"`
		ApplyAfter        string                 `json:"apply_after"`
		KeyPolicy         string                 `json:"key_policy"`
		Overrides         []plannedQuotaOverride `json:"overrides"`
	}{
		SchemaVersion: 1, SourceFingerprint: plan.report.SourceFingerprint,
		ApplyAfter: "Portal has provisioned and verified both deterministic Linux tenant keys",
		KeyPolicy:  "patch only quota limits and transfer the archived usage window to each matching new_key_id; never restore legacy key hashes or plaintext",
		Overrides:  plan.quotaOverrides,
	}
	return writePrivateJSON(target, payload)
}

func writePrivateJSON(target string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return writePrivateFileAtomic(target, payload)
}
