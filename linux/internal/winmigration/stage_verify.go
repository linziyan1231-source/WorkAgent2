package winmigration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func verifyExistingStage(ctx context.Context, plan *migrationPlan) (Report, error) {
	info, err := os.Lstat(plan.options.StagingDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return Report{}, errors.New("existing staging destination is not a private real directory")
	}
	reportPath := filepath.Join(plan.options.StagingDir, "report.json")
	file, err := os.Open(reportPath)
	if err != nil {
		return Report{}, errors.New("existing staging destination is incomplete")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 2*1024*1024))
	decoder.DisallowUnknownFields()
	var report Report
	decodeErr := decoder.Decode(&report)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := file.Close()
	if decodeErr != nil || !errors.Is(trailingErr, io.EOF) || closeErr != nil || report.SchemaVersion != ReportSchemaVersion || report.Status != "complete" || report.SourceFingerprint != plan.report.SourceFingerprint || report.TenantDataRoot != plan.report.TenantDataRoot || report.OutputFingerprint == "" {
		return Report{}, errors.New("existing staging destination does not match this migration plan")
	}
	for _, backup := range []struct {
		name     string
		minimum  int64
		maximum  int64
		expected string
	}{
		{"portal.windows.db", 1, maximumPortalDatabaseBytes, plan.portalSource.databaseSHA256},
		{"portal.windows.db-wal", 0, maximumPortalWALBytes, plan.portalSource.walSHA256},
		{"portal.windows.db-shm", 0, maximumPortalSHMBytes, plan.portalSource.shmSHA256},
	} {
		path := filepath.Join(plan.options.StagingDir, "backups", backup.name)
		info, statErr := os.Lstat(path)
		digest, hashErr := hashLocalRegularFile(path)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < backup.minimum || info.Size() > backup.maximum || hashErr != nil || digest != backup.expected {
			return Report{}, errors.New("existing staging Portal DB/WAL/SHM archive does not match its source")
		}
	}
	fingerprint, err := hashStagedPayload(plan.options.StagingDir)
	if err != nil || fingerprint != report.OutputFingerprint {
		return Report{}, errors.New("existing staging payload failed its integrity fingerprint")
	}
	if err := verifyStagedPortal(ctx, filepath.Join(plan.options.StagingDir, "portal", "portal.db"), plan.report.Portal); err != nil {
		return Report{}, err
	}
	for _, tenant := range plan.tenants {
		tenantRoot := filepath.Join(plan.options.StagingDir, "tenants", tenant.report.TenantID)
		if err := verifyTenantOutput(ctx, tenantRoot, tenant); err != nil {
			return Report{}, err
		}
		for _, workspace := range tenant.externalWorkspaces {
			destination := filepath.Join(tenantRoot, filepath.FromSlash(workspace.destinationRelative))
			if err := verifyCopiedExternalWorkspace(destination, workspace); err != nil {
				return Report{}, err
			}
		}
	}
	return report, nil
}

func hashStagedPayload(stage string) (string, error) {
	var entries []treeEntry
	for _, rootName := range []string{"backups", "cutover", "portal", "tenants"} {
		root := filepath.Join(stage, rootName)
		if err := filepath.WalkDir(root, func(fullPath string, directoryEntry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(stage, fullPath)
			if err != nil {
				return err
			}
			info, err := os.Lstat(fullPath)
			if err != nil {
				return err
			}
			entry := treeEntry{Path: filepath.ToSlash(relative), Mode: uint32(info.Mode().Perm()), Size: info.Size()}
			switch {
			case info.IsDir():
				entry.Kind = 'd'
				if info.Mode().Perm()&0o077 != 0 {
					return fmt.Errorf("staged directory %q is not private", relative)
				}
			case info.Mode().IsRegular():
				entry.Kind = 'f'
				if info.Mode().Perm()&0o077 != 0 {
					return fmt.Errorf("staged file %q is not private", relative)
				}
				digest, err := hashLocalRegularFile(fullPath)
				if err != nil {
					return err
				}
				entry.SHA256 = digest
			case info.Mode()&os.ModeSymlink != 0:
				entry.Kind = 'l'
				target, err := os.Readlink(fullPath)
				if err != nil {
					return err
				}
				entry.LinkTarget = filepath.ToSlash(target)
			default:
				return fmt.Errorf("staged entry %q has an unsafe file type", relative)
			}
			entries = append(entries, entry)
			return nil
		}); err != nil {
			return "", err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return hashEntries(entries), nil
}

func hashLocalRegularFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("staged hash target is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
