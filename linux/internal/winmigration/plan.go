package winmigration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/wincapture"
	_ "modernc.org/sqlite"
)

var migrationCaptureIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{7,79}$`)

type completedCaptureVerifier func(wincapture.CompletedCaptureOptions) (wincapture.CompletedCaptureBinding, error)

func buildPlan(ctx context.Context, options Options) (*migrationPlan, error) {
	options, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if err := validateSnapshotRootMetadata(options.SnapshotRoot); err != nil {
		return nil, err
	}
	verifier := options.verifyCompletedCapture
	if verifier == nil {
		verifier = wincapture.VerifyCompletedCapture
	}
	capture, err := verifyMigrationCapture(options, verifier)
	if err != nil {
		return nil, err
	}
	snapshotFD, err := openSnapshotRoot(options.SnapshotRoot)
	if err != nil {
		return nil, err
	}
	defer closeFD(snapshotFD)
	portalSource, err := inspectPortalSourceSet(snapshotFD)
	if err != nil {
		return nil, err
	}
	portalWorkRoot, portalPath, err := preparePortalWorkingCopy(snapshotFD, portalSource)
	if err != nil {
		return nil, err
	}
	keepPortalWorkRoot := false
	defer func() {
		if !keepPortalWorkRoot {
			cleanupPortalWorkRoot(portalWorkRoot)
		}
	}()
	users, portalReport, err := readPortalPlan(ctx, portalPath)
	if err != nil {
		return nil, err
	}
	if err := verifyPortalSourceSet(snapshotFD, portalSource); err != nil {
		return nil, err
	}
	cpaStateHash, _, err := hashSecureFile(snapshotFD, legacyCPAStateRelative)
	if err != nil {
		return nil, fmt.Errorf("inspect legacy CLIProxy policy state: %w", err)
	}
	cpaPayload, err := readSecureFile(snapshotFD, legacyCPAStateRelative, 8*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("read legacy CLIProxy policy state: %w", err)
	}
	legacyPolicy, err := readLegacyPolicyState(cpaPayload)
	clear(cpaPayload)
	if err != nil {
		return nil, err
	}
	externalBySID, externalManifestHash, err := loadExternalWorkspaceManifest(snapshotFD, options)
	if err != nil {
		return nil, err
	}
	rawNames, err := secureDirectoryNames(snapshotFD, "tenants/raw")
	if err != nil {
		return nil, err
	}
	nameByFold := make(map[string]string, len(rawNames))
	for _, name := range rawNames {
		folded := strings.ToLower(name)
		if previous, exists := nameByFold[folded]; exists && previous != name {
			return nil, errors.New("tenant source directories collide under Windows case-folding rules")
		}
		nameByFold[folded] = name
	}
	usedDirectories := make(map[string]bool, len(users))
	plan := &migrationPlan{
		options: options, portalPath: portalPath, portalWorkRoot: portalWorkRoot, portalSource: portalSource,
		cpaStatePath: filepath.Join(options.SnapshotRoot, filepath.FromSlash(legacyCPAStateRelative)), cpaStateSHA256: cpaStateHash,
		externalManifestSHA256: externalManifestHash, users: users,
	}
	for _, user := range users {
		windowsLeaf, err := windowsAccountLeaf(user.WindowsUsername)
		if err != nil {
			return nil, fmt.Errorf("Portal user %d has an invalid Windows account name", user.ID)
		}
		candidates := []string{user.WindowsSID, windowsLeaf, user.Username}
		matches := make(map[string]bool)
		for _, candidate := range candidates {
			if !safeSingleName(candidate) {
				continue
			}
			if actual, exists := nameByFold[strings.ToLower(candidate)]; exists {
				matches[actual] = true
			}
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("Portal user %d must map to exactly one tenant source directory", user.ID)
		}
		var sourceDirectory string
		for candidate := range matches {
			sourceDirectory = candidate
		}
		if usedDirectories[sourceDirectory] {
			return nil, errors.New("multiple Portal users map to the same tenant source directory")
		}
		usedDirectories[sourceDirectory] = true
		sourceRelative := path.Join("tenants/raw", sourceDirectory, "AionUiPortal")
		inventory, err := inventoryTree(ctx, snapshotFD, sourceRelative)
		if err != nil {
			return nil, fmt.Errorf("inventory tenant source %q: %w", sourceDirectory, err)
		}
		if !inventoryHasFile(inventory.entries, "data/aionui-backend.db") {
			return nil, fmt.Errorf("tenant source %q is missing data/aionui-backend.db", sourceDirectory)
		}
		tenantID, runtimeUser, dataRoot, projectID, err := deriveIdentity(user.WindowsSID, options.TenantDataRoot)
		if err != nil {
			return nil, fmt.Errorf("derive identity for Portal user %d: %w", user.ID, err)
		}
		tenant := plannedTenant{
			user: user, sourceRelative: sourceRelative, windowsLeaf: windowsLeaf, entries: inventory.entries,
			report: TenantReport{
				Username: user.Username, WindowsSID: user.WindowsSID, SourceDirectory: sourceDirectory,
				TenantID: tenantID, RuntimeUser: runtimeUser, DataRoot: dataRoot, ProjectID: projectID,
				DiskHardLimitBytes: TenantDiskLimitBytes, Files: inventory.files, Directories: inventory.directories,
				Symlinks: inventory.symlinks, Bytes: inventory.bytes, SourceTreeSHA256: inventory.hash,
				SkippedTransientFiles: inventory.skipped,
			},
		}
		if err := planExternalWorkspaces(ctx, snapshotFD, &tenant, externalBySID[user.WindowsSID]); err != nil {
			return nil, fmt.Errorf("validate external workspace capture for %q: %w", sourceDirectory, err)
		}
		delete(externalBySID, user.WindowsSID)
		identity := pathIdentityForTenant(tenant)
		aionPath := filepath.Join(options.SnapshotRoot, filepath.FromSlash(path.Join(sourceRelative, "data/aionui-backend.db")))
		rewrites, err := inspectAionDatabase(ctx, aionPath, identity)
		if err != nil {
			return nil, fmt.Errorf("inspect tenant database for %q: %w", sourceDirectory, err)
		}
		databaseHash, _, err := hashSecureFile(snapshotFD, path.Join(sourceRelative, "data/aionui-backend.db"))
		if err != nil || databaseHash != inventoryFileHash(inventory.entries, "data/aionui-backend.db") {
			return nil, fmt.Errorf("tenant database for %q changed while it was being planned", sourceDirectory)
		}
		if rewrites.UnmappedExternalWindowsPaths != 0 {
			return nil, fmt.Errorf("tenant database for %q contains %d Windows path(s) outside the tenant root without an exact external-workspace mapping", sourceDirectory, rewrites.UnmappedExternalWindowsPaths)
		}
		tenant.report.PathRewrites = rewrites
		if err := validatePlannedSymlinks(tenant); err != nil {
			return nil, fmt.Errorf("validate tenant links for %q: %w", sourceDirectory, err)
		}
		overrides, err := legacyPolicy.inspectTenant(snapshotFD, &tenant)
		if err != nil {
			return nil, fmt.Errorf("validate managed model state for %q: %w", sourceDirectory, err)
		}
		plan.quotaOverrides = append(plan.quotaOverrides, overrides...)
		plan.tenants = append(plan.tenants, tenant)
	}
	if len(usedDirectories) != len(rawNames) {
		return nil, errors.New("tenant snapshot contains a directory not owned by a Portal user")
	}
	if len(externalBySID) != 0 {
		return nil, errors.New("external workspace manifest references a Windows SID that is not present in Portal")
	}
	sort.Slice(plan.tenants, func(i, j int) bool { return plan.tenants[i].user.ID < plan.tenants[j].user.ID })
	if err := validateIdentityCollisions(plan.tenants); err != nil {
		return nil, err
	}
	if err := legacyPolicy.validateAllKeysMapped(); err != nil {
		return nil, err
	}
	cpaHashAfter, _, err := hashSecureFile(snapshotFD, legacyCPAStateRelative)
	if err != nil || cpaHashAfter != cpaStateHash {
		return nil, errors.New("legacy CLIProxy policy state changed while it was being planned")
	}
	if options.ExternalWorkspaceManifest != "" {
		manifestRelative, err := snapshotRelativePath(options.SnapshotRoot, options.ExternalWorkspaceManifest)
		if err != nil {
			return nil, err
		}
		manifestHashAfter, _, err := hashSecureFile(snapshotFD, manifestRelative)
		if err != nil || manifestHashAfter != externalManifestHash {
			return nil, errors.New("external workspace manifest changed while it was being planned")
		}
	}
	if err := verifyPortalSourceSet(snapshotFD, portalSource); err != nil {
		return nil, err
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion, Status: "planned",
		CaptureID: capture.CaptureID, CaptureSpecSHA256: capture.SpecSHA256, CaptureManifestSHA256: capture.CaptureManifestSHA256, CaptureCompletedAt: capture.CompletedAt,
		SourcePortalSHA256: portalSource.databaseSHA256, SourcePortalWALSHA256: portalSource.walSHA256, SourcePortalSHMSHA256: portalSource.shmSHA256,
		SourceCPAStateSHA256: cpaStateHash, SourceExternalManifestSHA256: externalManifestHash,
		TenantDataRoot: options.TenantDataRoot, Portal: portalReport,
		SessionsPolicy:    "all Windows Portal sessions are intentionally invalidated; destination portal_sessions is empty",
		OAuthStatesPolicy: "all in-flight Windows OAuth states are intentionally invalidated; destination oauth_states is empty",
		PublicationPolicy: "output is an offline staging tree and must be reviewed before a separate privileged deployment",
		LegacyKeyPolicy:   "legacy tenant key material and bindings are intentionally invalidated; Portal must provision tenant-bound Linux keys before use",
		LegacyUsagePolicy: "legacy quota limits and usage windows are retained only in the protected cutover override plan for explicit post-provision application",
	}
	for _, tenant := range plan.tenants {
		report.Tenants = append(report.Tenants, tenant.report)
	}
	report.SourceFingerprint, err = sourceFingerprint(report)
	if err != nil {
		return nil, err
	}
	if err := ValidateReportSourceFingerprint(report); err != nil {
		return nil, err
	}
	plan.report = report
	keepPortalWorkRoot = true
	return plan, nil
}

func verifyMigrationCapture(options Options, verifier completedCaptureVerifier) (wincapture.CompletedCaptureBinding, error) {
	if verifier == nil {
		return wincapture.CompletedCaptureBinding{}, errors.New("completed capture verifier is unavailable")
	}
	captureID := filepath.Base(options.SnapshotRoot)
	binding, err := verifier(wincapture.CompletedCaptureOptions{
		SpecPath: options.CaptureSpec, Destination: options.SnapshotRoot, CaptureID: captureID,
	})
	if err != nil {
		return wincapture.CompletedCaptureBinding{}, fmt.Errorf("verify completed frozen Windows capture: %w", err)
	}
	if binding.SchemaVersion != 1 || binding.CaptureID != captureID || !migrationCaptureIDPattern.MatchString(binding.CaptureID) ||
		!publicationFingerprintPattern.MatchString(binding.SpecSHA256) || !publicationFingerprintPattern.MatchString(binding.CaptureManifestSHA256) ||
		binding.CompletedAt.IsZero() || binding.CompletedAt.Location() != time.UTC {
		return wincapture.CompletedCaptureBinding{}, errors.New("completed frozen Windows capture returned an invalid binding")
	}
	return binding, nil
}

func sourceFingerprint(report Report) (string, error) {
	type fingerprint struct {
		SchemaVersion                int
		CaptureID                    string
		CaptureSpecSHA256            string
		CaptureManifestSHA256        string
		CaptureCompletedAt           time.Time
		SourcePortalSHA256           string
		SourcePortalWALSHA256        string
		SourcePortalSHMSHA256        string
		SourceCPAStateSHA256         string
		SourceExternalManifestSHA256 string
		TenantDataRoot               string
		Portal                       PortalReport
		Tenants                      []TenantReport
	}
	payload, err := json.Marshal(fingerprint{
		SchemaVersion:                report.SchemaVersion,
		CaptureID:                    report.CaptureID,
		CaptureSpecSHA256:            report.CaptureSpecSHA256,
		CaptureManifestSHA256:        report.CaptureManifestSHA256,
		CaptureCompletedAt:           report.CaptureCompletedAt,
		SourcePortalSHA256:           report.SourcePortalSHA256,
		SourcePortalWALSHA256:        report.SourcePortalWALSHA256,
		SourcePortalSHMSHA256:        report.SourcePortalSHMSHA256,
		SourceCPAStateSHA256:         report.SourceCPAStateSHA256,
		SourceExternalManifestSHA256: report.SourceExternalManifestSHA256,
		TenantDataRoot:               report.TenantDataRoot,
		Portal:                       report.Portal,
		Tenants:                      report.Tenants,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateReportSourceFingerprint rejects legacy or detached migration
// reports and proves that every frozen-capture binding and source digest is
// covered by the report's canonical source fingerprint.
func ValidateReportSourceFingerprint(report Report) error {
	if report.SchemaVersion != ReportSchemaVersion || !migrationCaptureIDPattern.MatchString(report.CaptureID) ||
		!publicationFingerprintPattern.MatchString(report.CaptureSpecSHA256) || !publicationFingerprintPattern.MatchString(report.CaptureManifestSHA256) ||
		report.CaptureCompletedAt.IsZero() || report.CaptureCompletedAt.Location() != time.UTC ||
		!publicationFingerprintPattern.MatchString(report.SourcePortalSHA256) || !publicationFingerprintPattern.MatchString(report.SourcePortalWALSHA256) ||
		!publicationFingerprintPattern.MatchString(report.SourcePortalSHMSHA256) || !publicationFingerprintPattern.MatchString(report.SourceCPAStateSHA256) ||
		!publicationFingerprintPattern.MatchString(report.SourceExternalManifestSHA256) || !publicationFingerprintPattern.MatchString(report.SourceFingerprint) {
		return errors.New("migration report frozen-capture binding or source hash is invalid")
	}
	externalWorkspaces := 0
	for _, tenant := range report.Tenants {
		if !publicationFingerprintPattern.MatchString(tenant.SourceTreeSHA256) {
			return errors.New("migration report tenant source hash is invalid")
		}
		for _, workspace := range tenant.ExternalWorkspaces {
			externalWorkspaces++
			if !publicationFingerprintPattern.MatchString(workspace.SourcePathSHA256) || !publicationFingerprintPattern.MatchString(workspace.SourceTreeSHA256) {
				return errors.New("migration report external workspace source hash is invalid")
			}
		}
	}
	if externalWorkspaces == 0 {
		return errors.New("migration report is detached from the required external workspace capture")
	}
	recomputed, err := sourceFingerprint(report)
	if err != nil || recomputed != report.SourceFingerprint {
		return errors.New("migration report source fingerprint is not canonical")
	}
	return nil
}

func inventoryHasFile(entries []treeEntry, target string) bool {
	return inventoryFileHash(entries, target) != ""
}

func inventoryFileHash(entries []treeEntry, target string) string {
	for _, entry := range entries {
		if entry.Path == target && entry.Kind == 'f' {
			return entry.SHA256
		}
	}
	return ""
}

func safeSingleName(value string) bool {
	return value != "" && value != "." && value != ".." && fs.ValidPath(value) && !strings.ContainsAny(value, "/\\\x00")
}

func windowsAccountLeaf(value string) (string, error) {
	value = strings.TrimSpace(value)
	if index := strings.LastIndexAny(value, `/\\`); index >= 0 {
		value = value[index+1:]
	}
	if !safeSingleName(value) {
		return "", errors.New("invalid Windows account leaf")
	}
	return value, nil
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unixClose(fd)
	}
}
