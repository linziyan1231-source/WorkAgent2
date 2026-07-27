//go:build linux

package winmigration

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	publicationMaxReportBytes = 8 * 1024 * 1024
	publicationMaxTenants     = 1000
)

var publicationFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PublicationTreeSummary is a content/type/mode inventory of the exact tenant
// payload that a privileged publisher is allowed to copy. Ownership and
// filesystem-specific directory sizes are deliberately excluded so the same
// payload can be verified after activation under its dedicated Linux UID.
type PublicationTreeSummary struct {
	SHA256      string `json:"sha256"`
	Files       int    `json:"files"`
	Directories int    `json:"directories"`
	Symlinks    int    `json:"symlinks"`
	Bytes       int64  `json:"bytes"`
}

// PublicationTenant binds one verified report identity to its exact staged
// payload. It contains no plaintext key, password, session, or OAuth material.
type PublicationTenant struct {
	Report  TenantReport           `json:"report"`
	Payload PublicationTreeSummary `json:"payload"`
}

// PublicationStage is returned only after the complete, private staging tree,
// report, Portal database, tenant databases, identities and payload hashes all
// pass the publication contract.
type PublicationStage struct {
	Report       Report                       `json:"report"`
	PortalSHA256 string                       `json:"portal_sha256"`
	Tenants      map[string]PublicationTenant `json:"tenants"`
}

// VerifyActivatedPortal performs the complete schema, integrity, identity,
// content, ownership and mode readback required after an atomic publication.
func VerifyActivatedPortal(ctx context.Context, databasePath string, report Report, expectedSHA256 string, expectedUID, expectedGID uint32) error {
	info, err := os.Lstat(databasePath)
	if err != nil {
		return errors.New("published Portal database is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return errors.New("published Portal database ownership or mode is invalid")
	}
	digest, err := hashLocalRegularFile(databasePath)
	if err != nil || digest != expectedSHA256 {
		return errors.New("published Portal database content hash is invalid")
	}
	if err := verifyStagedPortal(ctx, databasePath, report.Portal); err != nil {
		return err
	}
	return verifyPublicationPortalIdentities(ctx, databasePath, report)
}

// VerifyActivatedTenant performs a descriptor-confined content/type/mode and
// ownership readback. The publisher-created .runtime.lock is validated but is
// not part of the staged payload digest.
func VerifyActivatedTenant(ctx context.Context, tenantRoot string, tenant TenantReport, expected PublicationTreeSummary, expectedUID, expectedGID uint32) error {
	info, err := os.Lstat(tenantRoot)
	if err != nil {
		return errors.New("published tenant root is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return errors.New("published tenant root ownership or mode is invalid")
	}
	rootFD, err := unix.Open(tenantRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	if err := validatePublicationOwnership(rootFD, "", uint64(stat.Dev), expectedUID, expectedGID); err != nil {
		return err
	}
	entries, summary, err := inventoryPublicationTreeFD(ctx, rootFD, uint64(stat.Dev))
	if err != nil {
		return err
	}
	filtered := entries[:0]
	lockFound := false
	for _, entry := range entries {
		if entry.Path == ".runtime.lock" {
			if entry.Kind != 'f' || entry.Mode != 0o600 || entry.Size != 0 {
				return errors.New("published tenant runtime lock is invalid")
			}
			lockFound = true
			continue
		}
		filtered = append(filtered, entry)
	}
	if !lockFound {
		return errors.New("published tenant runtime lock is missing")
	}
	summary = summarizePublicationEntries(filtered)
	if summary != expected {
		return errors.New("published tenant payload does not match its staged content hash and counts")
	}
	if err := validatePublicationLinks(filtered); err != nil {
		return err
	}
	if err := verifyTenantOutput(ctx, tenantRoot, plannedTenant{report: tenant}); err != nil {
		return err
	}
	return nil
}

type publicationEntry struct {
	Path       string
	Kind       byte
	Mode       uint32
	Size       int64
	SHA256     string
	LinkTarget string
}

// VerifyPublicationStage is the canonical boundary between the offline
// Windows migration and a privileged Linux publisher. expectedUID is zero in
// production; tests may pass their own non-zero effective UID while exercising
// the identical descriptor-relative validation.
func VerifyPublicationStage(ctx context.Context, stage, expectedSourceFingerprint, expectedOutputFingerprint string, expectedUID uint32) (PublicationStage, error) {
	if stage == "" || !filepath.IsAbs(stage) || filepath.Clean(stage) != stage || stage == string(filepath.Separator) {
		return PublicationStage{}, errors.New("publication stage path must be clean and absolute")
	}
	if !publicationFingerprintPattern.MatchString(expectedSourceFingerprint) || !publicationFingerprintPattern.MatchString(expectedOutputFingerprint) {
		return PublicationStage{}, errors.New("expected migration fingerprints must be lowercase SHA-256 values")
	}
	rootFD, rootStat, err := openPrivatePublicationRoot(stage, expectedUID)
	if err != nil {
		return PublicationStage{}, err
	}
	defer unix.Close(rootFD)
	if err := validatePublicationTopLevel(rootFD); err != nil {
		return PublicationStage{}, err
	}
	reportPayload, err := readPrivatePublicationFile(rootFD, "report.json", expectedUID, publicationMaxReportBytes)
	if err != nil {
		return PublicationStage{}, fmt.Errorf("read completed migration report: %w", err)
	}
	defer clear(reportPayload)
	var report Report
	decoder := json.NewDecoder(strings.NewReader(string(reportPayload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return PublicationStage{}, errors.New("completed migration report is invalid")
	}
	if err := validatePublicationReport(report, expectedSourceFingerprint, expectedOutputFingerprint); err != nil {
		return PublicationStage{}, err
	}
	for _, backup := range []struct {
		relative string
		minimum  int64
		maximum  int64
		expected string
	}{
		{"backups/portal.windows.db", 1, maximumPortalDatabaseBytes, report.SourcePortalSHA256},
		{"backups/portal.windows.db-wal", 0, maximumPortalWALBytes, report.SourcePortalWALSHA256},
		{"backups/portal.windows.db-shm", 0, maximumPortalSHMBytes, report.SourcePortalSHMSHA256},
	} {
		digest, err := hashPublicationRegularRange(rootFD, backup.relative, uint64(rootStat.Dev), backup.minimum, backup.maximum)
		if err != nil || digest != backup.expected {
			return PublicationStage{}, errors.New("archived Windows Portal DB/WAL/SHM set does not match the migration report")
		}
	}
	payloadFingerprint, err := hashPublicationPayload(rootFD, uint64(rootStat.Dev))
	if err != nil {
		return PublicationStage{}, err
	}
	if payloadFingerprint != report.OutputFingerprint {
		return PublicationStage{}, errors.New("staging payload does not match the expected output fingerprint")
	}
	portalPath := filepath.Join(stage, "portal", "portal.db")
	portalSHA, err := hashPublicationRegular(rootFD, "portal/portal.db", uint64(rootStat.Dev), 4*1024*1024*1024)
	if err != nil {
		return PublicationStage{}, fmt.Errorf("verify staged Portal database file: %w", err)
	}
	if err := verifyStagedPortal(ctx, portalPath, report.Portal); err != nil {
		return PublicationStage{}, fmt.Errorf("verify staged Portal database: %w", err)
	}
	if err := verifyPublicationPortalIdentities(ctx, portalPath, report); err != nil {
		return PublicationStage{}, err
	}
	result := PublicationStage{Report: report, PortalSHA256: portalSHA, Tenants: make(map[string]PublicationTenant, len(report.Tenants))}
	for _, tenant := range report.Tenants {
		relative := path.Join("tenants", tenant.TenantID)
		entries, summary, err := inventoryPublicationTree(ctx, rootFD, relative, uint64(rootStat.Dev))
		if err != nil {
			return PublicationStage{}, fmt.Errorf("verify staged tenant payload: %w", err)
		}
		if err := validatePublicationLinks(entries); err != nil {
			return PublicationStage{}, fmt.Errorf("verify staged tenant links: %w", err)
		}
		if err := validatePublicationExternalWorkspaces(entries, tenant.ExternalWorkspaces); err != nil {
			return PublicationStage{}, err
		}
		tenantRoot := filepath.Join(stage, "tenants", tenant.TenantID)
		if err := verifyTenantOutput(ctx, tenantRoot, plannedTenant{report: tenant}); err != nil {
			return PublicationStage{}, fmt.Errorf("verify sanitized staged tenant: %w", err)
		}
		result.Tenants[tenant.TenantID] = PublicationTenant{Report: tenant, Payload: summary}
	}
	// Re-read the report and payload from the already-open stage after all
	// SQLite and tree checks. A root-controlled mutation cannot silently bridge
	// the long verification window.
	reportAfter, err := readPrivatePublicationFile(rootFD, "report.json", expectedUID, publicationMaxReportBytes)
	if err != nil || !bytesEqual(reportPayload, reportAfter) {
		clear(reportAfter)
		return PublicationStage{}, errors.New("migration report changed during publication verification")
	}
	clear(reportAfter)
	fingerprintAfter, err := hashPublicationPayload(rootFD, uint64(rootStat.Dev))
	if err != nil || fingerprintAfter != payloadFingerprint {
		return PublicationStage{}, errors.New("staging payload changed during publication verification")
	}
	return result, nil
}

func openPrivatePublicationRoot(stage string, expectedUID uint32) (int, unix.Stat_t, error) {
	info, err := os.Lstat(stage)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return -1, unix.Stat_t{}, errors.New("publication stage must be a real private 0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Gid != expectedUID {
		return -1, unix.Stat_t{}, errors.New("publication stage ownership is invalid")
	}
	fd, err := unix.Open(stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, fmt.Errorf("open publication stage: %w", err)
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Dev != uint64(stat.Dev) || opened.Ino != stat.Ino || opened.Uid != expectedUID || os.FileMode(opened.Mode).Perm() != 0o700 {
		unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("publication stage changed while it was opened")
	}
	return fd, opened, nil
}

func validatePublicationTopLevel(rootFD int) error {
	duplicate, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	root := os.NewFile(uintptr(duplicate), "publication-stage")
	entries, readErr := root.ReadDir(-1)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	wanted := map[string]byte{"backups": 'd', "cutover": 'd', "portal": 'd', "tenants": 'd', "report.json": 'f'}
	if len(entries) != len(wanted) {
		return errors.New("publication stage contains an unexpected top-level entry")
	}
	for _, entry := range entries {
		kind, ok := wanted[entry.Name()]
		if !ok {
			return errors.New("publication stage contains an unexpected top-level entry")
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(rootFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if (kind == 'd' && stat.Mode&unix.S_IFMT != unix.S_IFDIR) || (kind == 'f' && stat.Mode&unix.S_IFMT != unix.S_IFREG) {
			return errors.New("publication stage top-level layout is invalid")
		}
	}
	portal, err := openPublicationAt(rootFD, "portal", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(portal)
	duplicate, err = unix.Dup(portal)
	if err != nil {
		return errors.New("inspect staged Portal directory")
	}
	file := os.NewFile(uintptr(duplicate), "publication-portal")
	portalEntries, readErr := file.ReadDir(-1)
	closeErr = file.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	allowed := map[string]bool{"portal.db": true, "audit.jsonl": true}
	if len(portalEntries) != len(allowed) {
		return errors.New("staged Portal directory contains a non-publication artifact")
	}
	for _, entry := range portalEntries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return errors.New("staged Portal directory contains a non-publication artifact")
		}
	}
	return nil
}

func readPrivatePublicationFile(rootFD int, relative string, expectedUID uint32, maximum int64) ([]byte, error) {
	fd, err := openPublicationAt(rootFD, relative, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "publication-private-file")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("create publication file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("publication file is not a bounded private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Gid != expectedUID {
		return nil, errors.New("publication file ownership is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		clear(payload)
		return nil, errors.New("publication file exceeds its read boundary")
	}
	return payload, nil
}

func openPublicationAt(rootFD int, relative string, flags int, mode os.FileMode) (int, error) {
	if relative == "" || relative == "." || path.IsAbs(relative) || !fs.ValidPath(relative) {
		return -1, errors.New("publication-relative path is invalid")
	}
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode.Perm()),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return -1, fmt.Errorf("securely open publication path: %w", err)
	}
	return fd, nil
}

func validatePublicationReport(report Report, expectedSource, expectedOutput string) error {
	if report.SchemaVersion != ReportSchemaVersion || report.Status != "complete" || report.SourceFingerprint != expectedSource || report.OutputFingerprint != expectedOutput || report.TenantDataRoot != "/srv/workagent/users" {
		return errors.New("migration report does not match the explicit production publication contract")
	}
	if report.Portal.Users < 1 || report.Portal.Users > publicationMaxTenants || report.Portal.Users != len(report.Tenants) || report.Portal.AuditEvents < 0 || report.Portal.LoginLimits < 0 || report.Portal.ProLimits < 0 || report.Portal.ProUsage < 0 || report.Portal.ProEvents < 0 || report.Portal.InvalidatedSessions < 0 || report.Portal.InvalidatedOAuthStates < 0 {
		return errors.New("migration report Portal counts are invalid")
	}
	if report.SessionsPolicy != "all Windows Portal sessions are intentionally invalidated; destination portal_sessions is empty" ||
		report.OAuthStatesPolicy != "all in-flight Windows OAuth states are intentionally invalidated; destination oauth_states is empty" ||
		report.PublicationPolicy != "output is an offline staging tree and must be reviewed before a separate privileged deployment" ||
		report.LegacyKeyPolicy != "legacy tenant key material and bindings are intentionally invalidated; Portal must provision tenant-bound Linux keys before use" ||
		report.LegacyUsagePolicy != "legacy quota limits and usage windows are retained only in the protected cutover override plan for explicit post-provision application" {
		return errors.New("migration report security policies are invalid")
	}
	if !publicationFingerprintPattern.MatchString(report.SourcePortalSHA256) || !publicationFingerprintPattern.MatchString(report.SourcePortalWALSHA256) || !publicationFingerprintPattern.MatchString(report.SourcePortalSHMSHA256) || !publicationFingerprintPattern.MatchString(report.SourceCPAStateSHA256) || (report.SourceExternalManifestSHA256 != "" && !publicationFingerprintPattern.MatchString(report.SourceExternalManifestSHA256)) {
		return errors.New("migration report source hashes are invalid")
	}
	recomputed, err := sourceFingerprint(report)
	if err != nil || recomputed != report.SourceFingerprint {
		return errors.New("migration report source fingerprint is not canonical")
	}
	seenTenant := make(map[string]bool, len(report.Tenants))
	seenRuntime := make(map[string]bool, len(report.Tenants))
	seenRoot := make(map[string]bool, len(report.Tenants))
	seenProject := make(map[uint32]bool, len(report.Tenants))
	seenUsername := make(map[string]bool, len(report.Tenants))
	for _, tenant := range report.Tenants {
		parsed, parseErr := uuid.Parse(tenant.TenantID)
		derivedID, derivedRuntime, derivedRoot, derivedProject, deriveErr := deriveIdentity(tenant.WindowsSID, report.TenantDataRoot)
		usernameKey := strings.ToLower(strings.TrimSpace(tenant.Username))
		if parseErr != nil || parsed.String() != tenant.TenantID || deriveErr != nil || tenant.TenantID != derivedID || tenant.RuntimeUser != derivedRuntime || tenant.DataRoot != derivedRoot || tenant.ProjectID != derivedProject ||
			tenant.DiskHardLimitBytes != TenantDiskLimitBytes || strings.TrimSpace(tenant.Username) == "" || strings.ContainsAny(tenant.Username, "\r\n\x00") || !safeSingleName(tenant.SourceDirectory) ||
			tenant.Files < 1 || tenant.Directories < 1 || tenant.Symlinks < 0 || tenant.Bytes < 1 || uint64(tenant.Bytes) > tenant.DiskHardLimitBytes || !publicationFingerprintPattern.MatchString(tenant.SourceTreeSHA256) ||
			seenTenant[tenant.TenantID] || seenRuntime[tenant.RuntimeUser] || seenRoot[tenant.DataRoot] || seenProject[tenant.ProjectID] || seenUsername[usernameKey] {
			return errors.New("migration report contains an invalid or duplicate tenant identity")
		}
		if tenant.PathRewrites.UnmappedExternalWindowsPaths != 0 || tenant.PathRewrites.Total() < 0 || tenant.ModelInvalidation.AppliedMarkers < 0 || tenant.ModelInvalidation.PendingBundles < 0 || tenant.ModelInvalidation.CodexManagedAuthFiles < 0 || tenant.ModelInvalidation.CodexManagedSettings < 0 || tenant.ModelInvalidation.KimiManagedConfigs < 0 {
			return errors.New("migration report contains invalid tenant rewrite or invalidation counts")
		}
		if len(tenant.QuotaOverrides) != 2 {
			return errors.New("migration report tenant quota summaries are incomplete")
		}
		providers := map[string]bool{}
		for _, quota := range tenant.QuotaOverrides {
			if (quota.Provider != "codex" && quota.Provider != "kimi") || quota.NewKeyID == "" || quota.DailyLimitUSD == "" || quota.WeeklyLimitUSD == "" || providers[quota.Provider] {
				return errors.New("migration report tenant quota summaries are invalid")
			}
			providers[quota.Provider] = true
		}
		for _, workspace := range tenant.ExternalWorkspaces {
			if !publicationFingerprintPattern.MatchString(workspace.SourcePathSHA256) || !publicationFingerprintPattern.MatchString(workspace.SourceTreeSHA256) || !fs.ValidPath(workspace.DestinationRelative) || !strings.HasPrefix(workspace.DestinationRelative, "workspace/") || workspace.Files < 0 || workspace.Directories < 0 || workspace.Bytes < 0 {
				return errors.New("migration report external workspace summary is invalid")
			}
		}
		seenTenant[tenant.TenantID], seenRuntime[tenant.RuntimeUser], seenRoot[tenant.DataRoot], seenProject[tenant.ProjectID], seenUsername[usernameKey] = true, true, true, true, true
	}
	return nil
}

func hashPublicationPayload(rootFD int, rootDevice uint64) (string, error) {
	var entries []treeEntry
	for _, rootName := range []string{"backups", "cutover", "portal", "tenants"} {
		fd, err := openPublicationAt(rootFD, rootName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return "", err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			unix.Close(fd)
			return "", err
		}
		if uint64(stat.Dev) != rootDevice || stat.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(stat.Mode).Perm()&0o077 != 0 {
			unix.Close(fd)
			return "", errors.New("staging payload root is unsafe")
		}
		entries = append(entries, treeEntry{Path: rootName, Kind: 'd', Mode: uint32(os.FileMode(stat.Mode).Perm()), Size: stat.Size})
		if err := scanFingerprintDirectory(fd, rootName, rootDevice, &entries); err != nil {
			unix.Close(fd)
			return "", err
		}
		unix.Close(fd)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return hashEntries(entries), nil
}

func scanFingerprintDirectory(directoryFD int, relative string, rootDevice uint64, result *[]treeEntry) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "publication-fingerprint-directory")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return errors.New("staging payload entry name is invalid")
		}
		entryPath := path.Join(relative, name)
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		item := treeEntry{Path: entryPath, Mode: uint32(os.FileMode(stat.Mode).Perm()), Size: stat.Size}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if uint64(stat.Dev) != rootDevice || os.FileMode(stat.Mode).Perm()&0o077 != 0 {
				return errors.New("staging payload directory is unsafe")
			}
			item.Kind = 'd'
			child, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
			if err != nil {
				return err
			}
			*result = append(*result, item)
			err = scanFingerprintDirectory(child, entryPath, rootDevice, result)
			unix.Close(child)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			if uint64(stat.Dev) != rootDevice || os.FileMode(stat.Mode).Perm()&0o077 != 0 {
				return errors.New("staging payload file is unsafe")
			}
			item.Kind = 'f'
			fd, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
			if err != nil {
				return err
			}
			item.SHA256, err = hashPublicationFD(fd, stat)
			if err != nil {
				return err
			}
			*result = append(*result, item)
		case unix.S_IFLNK:
			item.Kind = 'l'
			buffer := make([]byte, 32*1024)
			length, err := unix.Readlinkat(directoryFD, name, buffer)
			if err != nil || length == len(buffer) {
				return errors.New("read staging payload symbolic link")
			}
			item.LinkTarget = string(buffer[:length])
			*result = append(*result, item)
		default:
			return errors.New("staging payload contains a special file")
		}
	}
	return nil
}

func hashPublicationRegular(rootFD int, relative string, rootDevice uint64, maximum int64) (string, error) {
	return hashPublicationRegularRange(rootFD, relative, rootDevice, 1, maximum)
}

func hashPublicationRegularRange(rootFD int, relative string, rootDevice uint64, minimum, maximum int64) (string, error) {
	if minimum < 0 || maximum < minimum {
		return "", errors.New("publication file size boundary is invalid")
	}
	fd, err := openPublicationAt(rootFD, relative, unix.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Dev) != rootDevice || stat.Size < minimum || stat.Size > maximum || os.FileMode(stat.Mode).Perm() != 0o600 {
		unix.Close(fd)
		return "", errors.New("publication source is not a bounded private regular file")
	}
	return hashPublicationFD(fd, stat)
}

func hashPublicationFD(fd int, before unix.Stat_t) (string, error) {
	file := os.NewFile(uintptr(fd), "publication-hash-file")
	if file == nil {
		unix.Close(fd)
		return "", errors.New("create publication hash handle")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(digest, file)
	var after unix.Stat_t
	statErr := unix.Fstat(int(file.Fd()), &after)
	closeErr := file.Close()
	if copyErr != nil || statErr != nil || closeErr != nil || written != before.Size || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim {
		return "", errors.New("publication source changed while it was hashed")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func inventoryPublicationTree(ctx context.Context, rootFD int, relative string, rootDevice uint64) ([]publicationEntry, PublicationTreeSummary, error) {
	fd, err := openPublicationAt(rootFD, relative, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, PublicationTreeSummary{}, err
	}
	defer unix.Close(fd)
	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(rootStat.Dev) != rootDevice || os.FileMode(rootStat.Mode).Perm() != 0o700 {
		return nil, PublicationTreeSummary{}, errors.New("staged tenant root is unsafe")
	}
	return inventoryPublicationTreeFD(ctx, fd, rootDevice)
}

func inventoryPublicationTreeFD(ctx context.Context, fd int, rootDevice uint64) ([]publicationEntry, PublicationTreeSummary, error) {
	var entries []publicationEntry
	if err := scanPublicationTree(ctx, fd, "", rootDevice, &entries); err != nil {
		return nil, PublicationTreeSummary{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	summary := summarizePublicationEntries(entries)
	return entries, summary, nil
}

func summarizePublicationEntries(entries []publicationEntry) PublicationTreeSummary {
	summary := PublicationTreeSummary{}
	digest := sha256.New()
	for _, entry := range entries {
		writePublicationField(digest, entry.Path)
		digest.Write([]byte{entry.Kind})
		var number [8]byte
		binary.BigEndian.PutUint64(number[:], uint64(entry.Mode))
		digest.Write(number[:])
		binary.BigEndian.PutUint64(number[:], uint64(entry.Size))
		digest.Write(number[:])
		writePublicationField(digest, entry.SHA256)
		writePublicationField(digest, entry.LinkTarget)
		switch entry.Kind {
		case 'd':
			summary.Directories++
		case 'f':
			summary.Files++
			summary.Bytes += entry.Size
		case 'l':
			summary.Symlinks++
		}
	}
	summary.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return summary
}

func validatePublicationOwnership(directoryFD int, relative string, rootDevice uint64, expectedUID, expectedGID uint32) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "published-tenant-ownership")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if uint64(stat.Dev) != rootDevice || stat.Uid != expectedUID || stat.Gid != expectedGID {
			return errors.New("published tenant entry ownership or filesystem is invalid")
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := unix.Openat2(directoryFD, entry.Name(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
			if err != nil {
				return err
			}
			childRelative := entry.Name()
			if relative != "" {
				childRelative = path.Join(relative, entry.Name())
			}
			err = validatePublicationOwnership(child, childRelative, rootDevice, expectedUID, expectedGID)
			unix.Close(child)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func scanPublicationTree(ctx context.Context, directoryFD int, relative string, rootDevice uint64, result *[]publicationEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "publication-tenant-directory")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return errors.New("tenant payload entry name is invalid")
		}
		entryPath := name
		if relative != "" {
			entryPath = path.Join(relative, name)
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		item := publicationEntry{Path: entryPath}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if uint64(stat.Dev) != rootDevice || os.FileMode(stat.Mode).Perm() != 0o700 {
				return errors.New("tenant payload directory is not private")
			}
			item.Kind, item.Mode = 'd', 0o700
			*result = append(*result, item)
			child, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
			if err != nil {
				return err
			}
			err = scanPublicationTree(ctx, child, entryPath, rootDevice, result)
			unix.Close(child)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			mode := os.FileMode(stat.Mode).Perm()
			if uint64(stat.Dev) != rootDevice || (mode != 0o600 && mode != 0o700) || stat.Size < 0 || stat.Size > int64(TenantDiskLimitBytes) {
				return errors.New("tenant payload regular file metadata is unsafe")
			}
			item.Kind, item.Mode, item.Size = 'f', uint32(mode), stat.Size
			fd, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
			if err != nil {
				return err
			}
			item.SHA256, err = hashPublicationFD(fd, stat)
			if err != nil {
				return err
			}
			*result = append(*result, item)
		case unix.S_IFLNK:
			buffer := make([]byte, 32*1024)
			length, err := unix.Readlinkat(directoryFD, name, buffer)
			if err != nil || length == 0 || length == len(buffer) {
				return errors.New("tenant payload symbolic link is invalid")
			}
			item.Kind, item.LinkTarget = 'l', string(buffer[:length])
			*result = append(*result, item)
		default:
			return errors.New("tenant payload contains a device, FIFO, socket, or other special file")
		}
	}
	return nil
}

func validatePublicationLinks(entries []publicationEntry) error {
	byPath := make(map[string]publicationEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	for _, entry := range entries {
		if entry.Kind != 'l' {
			continue
		}
		target := filepath.ToSlash(entry.LinkTarget)
		if path.IsAbs(target) || strings.ContainsRune(target, '\x00') || strings.Contains(target, `\`) || path.Clean(target) != target {
			return errors.New("tenant symbolic link target is not a canonical relative path")
		}
		resolved := path.Clean(path.Join(path.Dir(entry.Path), target))
		if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
			return errors.New("tenant symbolic link escapes its tenant root")
		}
		destination, ok := byPath[resolved]
		if !ok || destination.Kind == 'l' {
			return errors.New("tenant symbolic link is dangling or chained")
		}
	}
	return nil
}

func validatePublicationExternalWorkspaces(entries []publicationEntry, workspaces []ExternalWorkspaceReport) error {
	byPath := make(map[string]publicationEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	seen := make(map[string]bool, len(workspaces))
	for _, workspace := range workspaces {
		if seen[workspace.DestinationRelative] {
			return errors.New("migration report reuses an external workspace destination")
		}
		seen[workspace.DestinationRelative] = true
		root, ok := byPath[workspace.DestinationRelative]
		if !ok || root.Kind != 'd' {
			return errors.New("staged tenant is missing a reported external workspace")
		}
		files, directories, bytes := 0, 0, int64(0)
		prefix := workspace.DestinationRelative + "/"
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Path, prefix) {
				continue
			}
			switch entry.Kind {
			case 'd':
				directories++
			case 'f':
				files++
				bytes += entry.Size
			case 'l':
				return errors.New("reported external workspace contains a symbolic link")
			}
		}
		if files != workspace.Files || directories != workspace.Directories || bytes != workspace.Bytes {
			return errors.New("reported external workspace counts do not match the staged payload")
		}
	}
	return nil
}

func verifyPublicationPortalIdentities(ctx context.Context, databasePath string, report Report) error {
	database, err := openReadOnlySQLite(databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	rows, err := database.QueryContext(ctx, `SELECT username,tenant_id,runtime_user,data_root FROM portal_users ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type identity struct{ username, runtime, root string }
	actual := make(map[string]identity, len(report.Tenants))
	for rows.Next() {
		var username, tenantID, runtimeUser, dataRoot string
		if err := rows.Scan(&username, &tenantID, &runtimeUser, &dataRoot); err != nil {
			return err
		}
		if _, duplicate := actual[tenantID]; duplicate {
			return errors.New("staged Portal contains a duplicate tenant identity")
		}
		actual[tenantID] = identity{username: username, runtime: runtimeUser, root: dataRoot}
	}
	if err := rows.Err(); err != nil || len(actual) != len(report.Tenants) {
		return errors.New("staged Portal identity count does not match the migration report")
	}
	for _, tenant := range report.Tenants {
		value, ok := actual[tenant.TenantID]
		if !ok || value.username != tenant.Username || value.runtime != tenant.RuntimeUser || value.root != tenant.DataRoot {
			return errors.New("staged Portal identity does not match the migration report")
		}
	}
	return nil
}

func writePublicationField(digest hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	digest.Write(length[:])
	digest.Write([]byte(value))
}

func bytesEqual(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	var difference byte
	for index := range first {
		difference |= first[index] ^ second[index]
	}
	return difference == 0
}
