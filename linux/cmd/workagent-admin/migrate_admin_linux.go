package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

// migrateAdministrator is the one-time Linux bridge from the historical
// tenant-bound administrator to the Portal-only administrator used by the
// browser account manager. The verified backup is the recovery point; the old
// data root and runtime account are retained as an offline retirement hold.
func migrateAdministrator(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("migrate-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	backupConfigPath := flags.String("backup-config", "/etc/workagent/backup.json", "backup configuration")
	archivePath := flags.String("backup-archive", "", "verified pre-migration backup archive")
	receiptPath := flags.String("backup-receipt", "", "verified pre-migration backup receipt")
	username := flags.String("username", "admin", "existing administrator username")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("usage: workagent-admin migrate-admin [--config <path>] [--backup-config <path>] --backup-archive <path> --backup-receipt <path> [--username <name>]")
	}
	if os.Geteuid() != 0 {
		return errors.New("Portal administrator migration must run as root")
	}
	if *archivePath == "" || *receiptPath == "" {
		return errors.New("administrator migration requires --backup-archive and --backup-receipt")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	activation, err := acquireCleanTenantActivationMutation(ctx)
	if err != nil {
		return fmt.Errorf("acquire administrator migration activation lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	fixed, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire administrator migration control snapshot: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, fixed.Close()) }()

	portal, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	if err := admin.VerifyPortalFiles(portal, *configPath); err != nil {
		return err
	}
	backupConfig, err := backup.LoadConfig(*backupConfigPath)
	if err != nil {
		return err
	}
	key, err := backup.LoadKey(backupConfig.EncryptionKey, true)
	if err != nil {
		return err
	}
	manifest, verifyErr := backup.VerifyFiles(*archivePath, *receiptPath, key, true)
	clear(key)
	if verifyErr != nil {
		return fmt.Errorf("administrator migration backup gate failed: %w", verifyErr)
	}
	now := time.Now().UTC()
	if manifest.CreatedAt.Before(now.Add(-4*time.Hour)) || manifest.CreatedAt.After(now.Add(5*time.Minute)) {
		return errors.New("administrator migration backup is stale")
	}
	contract, err := backup.BuildActivationBackupContract(*configPath, backupConfig)
	if err != nil {
		return err
	}
	if err := backup.ValidateActivationBackupManifest(manifest, contract); err != nil {
		return fmt.Errorf("administrator migration backup is not a complete recovery point: %w", err)
	}

	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
	legacy, err := data.UserByUsername(ctx, *username)
	if err != nil {
		return err
	}
	if !legacy.Admin {
		return errors.New("selected Portal user is not the administrator")
	}
	if store.IsPortalOnlyAdministrator(legacy) {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"migrated": false, "already_portal_only": true, "username": legacy.Username})
	}
	if filepath.IsAbs(legacy.TenantID) || filepath.Base(legacy.TenantID) != legacy.TenantID {
		return errors.New("legacy administrator tenant identity is invalid")
	}
	tenantConfigPath := filepath.Join(portal.Paths.TenantConfigs, legacy.TenantID+".json")
	retirementRoot := filepath.Join(filepath.Dir(portal.Paths.TenantConfigs), "retired-tenants")
	retiredConfigPath := filepath.Join(retirementRoot, legacy.TenantID+".json")
	if err := prepareRetirementRoot(retirementRoot); err != nil {
		return err
	}
	_, liveErr := os.Lstat(tenantConfigPath)
	_, retiredErr := os.Lstat(retiredConfigPath)
	switch {
	case liveErr == nil && errors.Is(retiredErr, os.ErrNotExist):
		if err := applyUserEnabledState(ctx, portal, data, legacy.Username, false, systemdctl.Default()); err != nil {
			return fmt.Errorf("disable legacy administrator tenant: %w", err)
		}
		tenant, loadErr := config.LoadTenant(tenantConfigPath)
		if loadErr != nil {
			return loadErr
		}
		if tenant.TenantID != legacy.TenantID || tenant.RuntimeUser != legacy.RuntimeUser || tenant.DataRoot != legacy.DataRoot {
			return errors.New("legacy administrator tenant configuration does not match the Portal identity")
		}
		if err := admin.VerifyTenantConfigPath(portal, tenant, tenantConfigPath); err != nil {
			return err
		}
		if err := os.Rename(tenantConfigPath, retiredConfigPath); err != nil {
			return fmt.Errorf("archive legacy administrator tenant configuration: %w", err)
		}
		if err := errors.Join(fsutil.SyncDirectory(portal.Paths.TenantConfigs), fsutil.SyncDirectory(retirementRoot)); err != nil {
			return fmt.Errorf("commit legacy administrator tenant retirement: %w", err)
		}
	case errors.Is(liveErr, os.ErrNotExist) && retiredErr == nil:
		// The prior attempt crossed the durable retirement rename. That rename is
		// reachable only after the crash-safe disable transaction has converged.
		if legacy.Enabled {
			return errors.New("retired administrator tenant is still enabled")
		}
		retiredTenant, loadErr := config.LoadTenant(retiredConfigPath)
		if loadErr != nil {
			return loadErr
		}
		if retiredTenant.TenantID != legacy.TenantID || retiredTenant.RuntimeUser != legacy.RuntimeUser || retiredTenant.DataRoot != legacy.DataRoot {
			return errors.New("retired administrator tenant configuration does not match the Portal identity")
		}
	case liveErr != nil && !errors.Is(liveErr, os.ErrNotExist):
		return liveErr
	case retiredErr != nil && !errors.Is(retiredErr, os.ErrNotExist):
		return retiredErr
	default:
		return errors.New("legacy administrator retirement paths are ambiguous")
	}

	previous, current, err := data.ConvertAdministratorToPortalOnly(ctx, legacy.Username, now)
	if err != nil {
		return err
	}
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data); err != nil {
		return fmt.Errorf("administrator migration left an invalid tenant catalog: %w", err)
	}
	if err := data.Audit(ctx, store.AuditEvent{Action: "admin.identity.migrate", Outcome: "success", Username: current.Username, TenantID: previous.TenantID, RemoteIP: "local-admin", Details: map[string]any{"portal_only": true, "retired_config": retiredConfigPath, "backup_id": manifest.BackupID}}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"migrated": true, "username": current.Username, "retired_tenant_id": previous.TenantID,
		"retired_config": retiredConfigPath, "retained_data_root": previous.DataRoot, "backup_id": manifest.BackupID,
	})
}

func prepareRetirementRoot(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create retired tenant configuration directory: %w", err)
		}
		return fsutil.SyncDirectory(filepath.Dir(path))
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("retired tenant configuration directory is unsafe")
	}
	return nil
}
