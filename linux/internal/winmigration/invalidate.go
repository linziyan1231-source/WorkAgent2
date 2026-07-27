package winmigration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func invalidateLegacyModelState(tenantRoot string, tenant plannedTenant) error {
	for _, item := range []struct {
		relative string
		required bool
	}{
		{"config/model-bootstrap-v1.applied.json", true},
		{"credentials/model-bootstrap-v1.pending.json", tenant.report.ModelInvalidation.PendingBundles > 0},
		{"config/codex/auth.json", true},
	} {
		path := filepath.Join(tenantRoot, filepath.FromSlash(item.relative))
		if err := removePrivateRegularFile(path, item.required); err != nil {
			return err
		}
	}
	codexPath := filepath.Join(tenantRoot, "config", "codex", "config.toml")
	if changed, err := rewriteSanitizedConfig(codexPath, sanitizeCodexConfig); err != nil {
		return err
	} else if changed != tenant.report.ModelInvalidation.CodexManagedSettings {
		return errors.New("Codex managed settings changed after planning")
	}
	kimiChanged := 0
	for _, relative := range []string{"home/.kimi-code/config.toml", "home/.kimi/config.toml"} {
		path := filepath.Join(tenantRoot, filepath.FromSlash(relative))
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		changed, err := rewriteSanitizedConfig(path, sanitizeKimiConfig)
		if err != nil {
			return err
		}
		if changed > 0 {
			kimiChanged++
		}
	}
	if kimiChanged != tenant.report.ModelInvalidation.KimiManagedConfigs {
		return errors.New("Kimi managed configuration changed after planning")
	}
	return nil
}

func rewriteSanitizedConfig(path string, sanitizer func([]byte) ([]byte, int, error)) (int, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return 0, errors.New("managed CLI configuration is not a bounded regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	defer clear(payload)
	sanitized, changed, err := sanitizer(payload)
	if err != nil {
		return 0, err
	}
	defer clear(sanitized)
	if changed == 0 && bytes.Equal(payload, sanitized) {
		return 0, nil
	}
	if err := writePrivateFileAtomic(path, sanitized); err != nil {
		return 0, err
	}
	return changed, nil
}

func removePrivateRegularFile(path string, required bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("managed credential path is missing or unsafe")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func verifyTenantOutput(ctx context.Context, tenantRoot string, tenant plannedTenant) error {
	for _, relative := range []string{"config/model-bootstrap-v1.applied.json", "credentials/model-bootstrap-v1.pending.json", "config/codex/auth.json"} {
		if _, err := os.Lstat(filepath.Join(tenantRoot, filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("invalidated managed state remains at %s", relative)
		}
	}
	for _, relative := range []string{"home/.kimi-code/config.toml", "home/.kimi/config.toml"} {
		path := filepath.Join(tenantRoot, filepath.FromSlash(relative))
		payload, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		_, found, extractErr := extractManagedKimiKey(payload)
		clear(payload)
		if extractErr != nil || found {
			return errors.New("legacy managed Kimi provider remains after sanitization")
		}
	}
	databasePath := filepath.Join(tenantRoot, "data", "aionui-backend.db")
	database, err := openReadOnlySQLite(databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return err
	}
	var managed int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM providers WHERE id IN (?,?)`, "managed-cliproxy-chatgpt", "managed-cliproxy-kimi").Scan(&managed); err != nil || managed != 0 {
		return errors.New("legacy managed Aion providers remain after sanitization")
	}
	return verifyOutputSymlinks(tenantRoot)
}

func verifyOutputSymlinks(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return nil
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithin(root, target) {
			return errors.New("staged tenant contains an escaping or dangling symbolic link")
		}
		return nil
	})
}

func writePrivateFileAtomic(target string, payload []byte) error {
	parent := filepath.Dir(target)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private file parent is unsafe")
	}
	temporary, err := os.CreateTemp(parent, ".migration-write-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	return syncDirectory(parent)
}
