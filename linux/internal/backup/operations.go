package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"

	_ "modernc.org/sqlite"
)

const ReceiptSchemaVersion = 1

var archiveNamePattern = regexp.MustCompile(`^workagent-[0-9]{8}T[0-9]{6}Z-[0-9a-f-]{36}\.wab$`)

type Receipt struct {
	SchemaVersion   int              `json:"schema_version"`
	BackupID        string           `json:"backup_id"`
	CreatedAt       time.Time        `json:"created_at"`
	ArchiveName     string           `json:"archive_name"`
	ArchiveSHA256   string           `json:"archive_sha256"`
	ArchiveSize     int64            `json:"archive_size"`
	PortalConfig    string           `json:"portal_config"`
	ReleasePointers []ReleasePointer `json:"release_pointers"`
}

type Snapshot struct {
	PortalConfig    string
	Sources         []Source
	ReleasePointers []ReleasePointer
	catalogGuard    io.Closer
	locks           []io.Closer
}

type snapshotCatalogAcquire func(context.Context) (io.Closer, error)

func beginCatalogLockedSnapshot(ctx context.Context, portalConfigPath string, acquire snapshotCatalogAcquire) (*Snapshot, error) {
	if ctx == nil || acquire == nil {
		return nil, errors.New("backup catalog snapshot guard is unavailable")
	}
	guard, err := acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire backup catalog lifecycle lock: %w", err)
	}
	if guard == nil || (reflect.ValueOf(guard).Kind() == reflect.Pointer && reflect.ValueOf(guard).IsNil()) {
		return nil, errors.New("backup catalog lifecycle lock acquisition returned no guard")
	}
	return &Snapshot{PortalConfig: portalConfigPath, catalogGuard: guard, locks: []io.Closer{guard}}, nil
}

func acquireProductionSnapshotCatalog(ctx context.Context) (io.Closer, error) {
	return lifecyclelock.AcquireCatalogShared(ctx)
}

type Created struct {
	Manifest       Manifest `json:"manifest"`
	Receipt        Receipt  `json:"receipt"`
	LocalArchive   string   `json:"local_archive"`
	LocalReceipt   string   `json:"local_receipt"`
	OffHostArchive string   `json:"off_host_archive"`
	OffHostReceipt string   `json:"off_host_receipt"`
}

func VerifyEnvironment(configuration Config, requireRootOwner bool) error {
	if err := configuration.Validate(); err != nil {
		return err
	}
	for _, directory := range []string{configuration.LocalDirectory, configuration.OffHostDirectory} {
		if err := verifyBackupDirectory(directory); err != nil {
			return err
		}
	}
	localInfo, err := os.Stat(configuration.LocalDirectory)
	if err != nil {
		return err
	}
	offHostInfo, err := os.Stat(configuration.OffHostDirectory)
	if err != nil {
		return err
	}
	localStat, localOK := localInfo.Sys().(*syscall.Stat_t)
	offHostStat, offHostOK := offHostInfo.Sys().(*syscall.Stat_t)
	if !localOK || !offHostOK || localStat.Dev == offHostStat.Dev {
		return errors.New("off-host backup directory must be on a different filesystem from local backups")
	}
	if err := verifyRemoteMount(configuration.OffHostDirectory); err != nil {
		return err
	}
	guard, err := openBackupDirectoryGuard(configuration.OffHostDirectory)
	if err != nil {
		return fmt.Errorf("verify off-host mount identity support: %w", err)
	}
	if err := guard.verifyCurrent(); err != nil {
		_ = guard.Close()
		return fmt.Errorf("verify stable off-host mount identity: %w", err)
	}
	if err := guard.Close(); err != nil {
		return errors.New("close off-host mount identity guard")
	}
	key, err := LoadKey(configuration.EncryptionKey, requireRootOwner)
	if err != nil {
		return err
	}
	clear(key)
	metricsParent := filepath.Dir(configuration.MetricsFile)
	info, err := os.Lstat(metricsParent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("backup metrics directory is missing or unsafe")
	}
	for _, source := range configuration.AdditionalSources {
		info, err := os.Lstat(source.Path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("additional backup source is missing or unsafe: %s", source.Name)
		}
	}
	return nil
}

func DiscoverSnapshot(portalConfigPath string, backupConfig Config) (*Snapshot, error) {
	if err := backupConfig.Validate(); err != nil {
		return nil, err
	}
	// This shared guard is the outermost snapshot lock. It is acquired before
	// any production configuration is read and remains in Snapshot.locks until
	// Create has archived and authenticated every source. Tenant configuration
	// publication takes the same inode exclusively, so discovery and archive
	// can never span two catalog generations even outside the systemd wrapper.
	snapshot, err := beginCatalogLockedSnapshot(context.Background(), portalConfigPath, acquireProductionSnapshotCatalog)
	if err != nil {
		return nil, err
	}
	keepLocks := false
	defer func() {
		if !keepLocks {
			_ = snapshot.Close()
		}
	}()
	portal, err := config.LoadPortal(portalConfigPath)
	if err != nil {
		return nil, err
	}
	if err := portal.ValidateProductionLayout(portalConfigPath); err != nil {
		return nil, fmt.Errorf("backup production layout: %w", err)
	}
	if err := admin.VerifyPortalFiles(portal, portalConfigPath); err != nil {
		return nil, fmt.Errorf("backup Portal file protection: %w", err)
	}
	for path, account := range map[string]string{
		"/etc/workagent/chatforward.env":   "workagent-chatforward",
		"/etc/workagent/notification.json": "workagent-notification",
	} {
		if err := verifyServiceRecoveryFile(path, account); err != nil {
			return nil, fmt.Errorf("backup service configuration %s: %w", path, err)
		}
	}
	tenantEntries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return nil, fmt.Errorf("read tenant configurations: %w", err)
	}
	tenantConfigs := make([]config.Tenant, 0)
	for _, entry := range tenantEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, errors.New("tenant backup configuration directory contains an unexpected entry")
		}
		path := filepath.Join(portal.Paths.TenantConfigs, entry.Name())
		tenant, err := config.LoadTenant(path)
		if err != nil {
			return nil, fmt.Errorf("load tenant backup source %s: %w", entry.Name(), err)
		}
		if entry.Name() != tenant.TenantID+".json" || tenant.DataRoot != filepath.Join(portal.Paths.TenantData, tenant.TenantID) {
			return nil, errors.New("tenant backup source does not match its canonical identity")
		}
		if err := admin.VerifyTenantConfigPath(portal, tenant, path); err != nil {
			return nil, fmt.Errorf("tenant backup configuration protection %s: %w", entry.Name(), err)
		}
		tenantConfigs = append(tenantConfigs, tenant)
	}
	if len(tenantConfigs) == 0 {
		return nil, errors.New("no tenant configuration is available for backup")
	}
	sort.Slice(tenantConfigs, func(i, j int) bool { return tenantConfigs[i].TenantID < tenantConfigs[j].TenantID })

	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil || portalAccount.Username != portal.RuntimeUser || portalAccount.HomeDir != portal.Paths.PortalState {
		return nil, errors.New("Portal dedicated account is unavailable or noncanonical")
	}
	portalUID, portalUIDErr := strconv.ParseUint(portalAccount.Uid, 10, 32)
	portalGID, portalGIDErr := strconv.ParseUint(portalAccount.Gid, 10, 32)
	if portalUIDErr != nil || portalGIDErr != nil || portalUID == 0 || portalGID == 0 {
		return nil, errors.New("Portal dedicated account identity is invalid")
	}
	type lockTarget struct {
		path string
		uid  uint32
		gid  uint32
	}
	lockTargets := []lockTarget{{
		path: filepath.Join(portal.Paths.PortalState, ".runtime.lock"),
		uid:  uint32(portalUID),
		gid:  uint32(portalGID),
	}}
	for _, tenant := range tenantConfigs {
		account, err := user.Lookup(tenant.RuntimeUser)
		if err != nil || account.Username != tenant.RuntimeUser || account.HomeDir != tenant.DataRoot {
			return nil, fmt.Errorf("tenant %s dedicated account is unavailable or noncanonical", tenant.TenantID)
		}
		uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
		gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
		if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
			return nil, fmt.Errorf("tenant %s dedicated account identity is invalid", tenant.TenantID)
		}
		lockTargets = append(lockTargets, lockTarget{path: filepath.Join(tenant.DataRoot, ".runtime.lock"), uid: uint32(uid), gid: uint32(gid)})
	}
	for _, target := range lockTargets {
		lock, err := servicelock.AcquireExclusiveExisting(target.path, target.uid)
		if err != nil {
			return nil, fmt.Errorf("quiescence check for %s: %w", filepath.Dir(target.path), err)
		}
		snapshot.locks = append(snapshot.locks, lock)
		if err := verifyBackupStateRoot(filepath.Dir(target.path), target.uid, target.gid); err != nil {
			return nil, err
		}
	}
	pointerPaths := map[string]bool{portal.Renderer.PointerFile: true}
	for _, tenant := range tenantConfigs {
		pointerPaths[tenant.Release.PointerFile] = true
	}
	sortedPointerPaths := make([]string, 0, len(pointerPaths))
	for path := range pointerPaths {
		sortedPointerPaths = append(sortedPointerPaths, path)
	}
	sort.Strings(sortedPointerPaths)
	for _, path := range sortedPointerPaths {
		lock, err := acquireReleasePointerSnapshotLock(path)
		if err != nil {
			return nil, fmt.Errorf("lock release pointer %s for backup: %w", path, err)
		}
		snapshot.locks = append(snapshot.locks, lock)
	}
	rendererIndex := filepath.ToSlash(filepath.Join(portal.Renderer.RelativeRoot, "index.html"))
	if _, err := release.ResolveActive(
		portal.Renderer.ReleasesRoot,
		portal.Renderer.PointerFile,
		release.ResolveOptions{
			Scope: portal.Renderer.Scope, RequiredPaths: []string{rendererIndex}, RequireRootOwner: true,
		},
	); err != nil {
		return nil, fmt.Errorf("Renderer current release is not recoverable: %w", err)
	}
	if err := verifyRecoveredPreviousRelease(
		portal.Renderer.ReleasesRoot,
		portal.Renderer.PointerFile,
		portal.Renderer.Scope,
		[]string{rendererIndex},
		nil,
	); err != nil {
		return nil, fmt.Errorf("Renderer previous release is not recoverable: %w", err)
	}
	for _, tenant := range tenantConfigs {
		if _, err := admin.VerifyTenantHost(portal, tenant); err != nil {
			return nil, fmt.Errorf("tenant %s is not recoverable: %w", tenant.TenantID, err)
		}
		required := append([]string(nil), tenant.Backend.RequiredReleaseFiles...)
		requiredExecutables := []string{tenant.Backend.Executable}
		if tenant.Backend.Migration.Enabled {
			requiredExecutables = append(requiredExecutables, tenant.Backend.Migration.Executable)
		}
		if tenant.Backend.AgentCLI.BinDirectory != "" {
			requiredExecutables = append(requiredExecutables, tenant.Backend.AgentCLI.CodexExecutable, tenant.Backend.AgentCLI.KimiExecutable, tenant.Backend.AgentCLI.PythonExecutable)
		}
		if err := verifyRecoveredPreviousRelease(
			tenant.Release.ReleasesRoot,
			tenant.Release.PointerFile,
			tenant.Release.Scope,
			required,
			requiredExecutables,
		); err != nil {
			return nil, fmt.Errorf("tenant %s previous release is not recoverable: %w", tenant.TenantID, err)
		}
	}
	proxyLock, err := cliproxy.AcquireProductionMigrationLock()
	if err != nil {
		return nil, fmt.Errorf("CLIProxy policy-state quiescence: %w", err)
	}
	snapshot.locks = append(snapshot.locks, proxyLock)
	proxyAccount, err := user.Lookup("cliproxyapi")
	if err != nil {
		return nil, errors.New("CLIProxy dedicated account is unavailable")
	}
	proxyUID, uidErr := strconv.ParseUint(proxyAccount.Uid, 10, 32)
	proxyGID, gidErr := strconv.ParseUint(proxyAccount.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || proxyUID == 0 || proxyGID == 0 {
		return nil, errors.New("CLIProxy dedicated account identity is invalid")
	}
	if err := cliproxy.VerifyProductionPolicyState(portal.CLIProxy.PolicyStateFile, uint32(proxyUID), uint32(proxyGID)); err != nil {
		return nil, fmt.Errorf("CLIProxy policy state is not backup-safe: %w", err)
	}

	snapshot.Sources = append(snapshot.Sources,
		Source{Name: "configuration", Path: filepath.Dir(portalConfigPath)},
		Source{Name: "portal-state", Path: portal.Paths.PortalState},
		Source{Name: "cliproxy-policy-state", Path: portal.CLIProxy.PolicyStateFile},
	)
	if err := verifyProtectedRecoveryFile(portal.Renderer.PointerFile, 0o644); err != nil {
		return nil, fmt.Errorf("Renderer release pointer is not backup-safe: %w", err)
	}
	snapshot.Sources = append(snapshot.Sources, Source{Name: "release-pointer-renderer", Path: portal.Renderer.PointerFile})
	pointerSources := map[string]bool{portal.Renderer.PointerFile: true}
	for _, tenant := range tenantConfigs {
		snapshot.Sources = append(snapshot.Sources, Source{Name: "tenant-" + tenant.TenantID, Path: tenant.DataRoot})
		identityPath := filepath.Join("/etc/systemd/system", "workagent-userhost@"+tenant.TenantID+".service.d", "identity.conf")
		if err := verifyProtectedRecoveryFile(identityPath, 0o644); err != nil {
			return nil, fmt.Errorf("tenant %s systemd identity is not backup-safe: %w", tenant.TenantID, err)
		}
		snapshot.Sources = append(snapshot.Sources, Source{Name: "systemd-identity-" + tenant.TenantID, Path: identityPath})
		if !pointerSources[tenant.Release.PointerFile] {
			if err := verifyProtectedRecoveryFile(tenant.Release.PointerFile, 0o644); err != nil {
				return nil, fmt.Errorf("tenant release pointer is not backup-safe: %w", err)
			}
			snapshot.Sources = append(snapshot.Sources, Source{Name: "release-pointer-" + tenant.TenantID, Path: tenant.Release.PointerFile})
			pointerSources[tenant.Release.PointerFile] = true
		}
	}
	snapshot.Sources = append(snapshot.Sources, backupConfig.AdditionalSources...)
	if err := validateSources(snapshot.Sources); err != nil {
		return nil, err
	}
	for _, source := range snapshot.Sources {
		if source.Path == config.CLIProxyAuthDirectory || pathWithin(source.Path, config.CLIProxyAuthDirectory) || pathWithin(config.CLIProxyAuthDirectory, source.Path) {
			return nil, errors.New("CLIProxy provider OAuth material must not be included in application backups")
		}
		for _, destination := range []string{backupConfig.LocalDirectory, backupConfig.OffHostDirectory} {
			if source.Path == destination || pathWithin(source.Path, destination) || pathWithin(destination, source.Path) {
				return nil, errors.New("backup destination and source paths must not overlap")
			}
		}
		if pathsOverlap(source.Path, backupConfig.EncryptionKey) {
			return nil, errors.New("backup encryption key must remain outside all backup sources")
		}
	}

	pointers := make(map[string]ReleasePointer)
	rendererPointer, err := release.LoadProtectedPointer(portal.Renderer.PointerFile, true)
	if err != nil || rendererPointer.Scope != portal.Renderer.Scope {
		return nil, fmt.Errorf("read Renderer release pointer: %w", err)
	}
	pointers[portal.Renderer.PointerFile] = ReleasePointer{
		Path: portal.Renderer.PointerFile, Scope: rendererPointer.Scope, Current: rendererPointer.Current,
		Previous: rendererPointer.Previous, Activated: rendererPointer.ActivatedAt.UTC().Format(time.RFC3339Nano),
	}
	for _, tenant := range tenantConfigs {
		pointer, err := release.LoadProtectedPointer(tenant.Release.PointerFile, true)
		if err != nil {
			return nil, fmt.Errorf("read tenant release pointer: %w", err)
		}
		if pointer.Scope != tenant.Release.Scope {
			return nil, errors.New("tenant release pointer scope mismatch")
		}
		pointers[tenant.Release.PointerFile] = ReleasePointer{Path: tenant.Release.PointerFile, Scope: pointer.Scope, Current: pointer.Current, Previous: pointer.Previous, Activated: pointer.ActivatedAt.UTC().Format(time.RFC3339Nano)}
	}
	for _, pointer := range pointers {
		snapshot.ReleasePointers = append(snapshot.ReleasePointers, pointer)
	}
	sort.Slice(snapshot.ReleasePointers, func(i, j int) bool { return snapshot.ReleasePointers[i].Path < snapshot.ReleasePointers[j].Path })

	if err := checkSQLite(portal.DatabasePath()); err != nil {
		return nil, fmt.Errorf("Portal database is not backup-safe: %w", err)
	}
	for _, tenant := range tenantConfigs {
		if tenant.Backend.InternalAuth.Enabled {
			if err := checkSQLite(tenant.Backend.InternalAuth.DatabasePath); err != nil {
				return nil, fmt.Errorf("tenant %s database is not backup-safe: %w", tenant.TenantID, err)
			}
		}
	}
	keepLocks = true
	return snapshot, nil
}

// BuildActivationBackupContract derives the exact authenticated source and
// release-pointer set that a pre-upgrade backup must contain. It deliberately
// performs no quiescing; callers combine it with the release/config lifecycle
// lock before authorizing a pointer change.
func BuildActivationBackupContract(portalConfigPath string, backupConfig Config) (CreateInput, error) {
	if err := backupConfig.Validate(); err != nil {
		return CreateInput{}, err
	}
	portal, err := config.LoadPortal(portalConfigPath)
	if err != nil {
		return CreateInput{}, err
	}
	if err := portal.ValidateProductionLayout(portalConfigPath); err != nil {
		return CreateInput{}, fmt.Errorf("activation backup production layout: %w", err)
	}
	if err := admin.VerifyPortalFiles(portal, portalConfigPath); err != nil {
		return CreateInput{}, fmt.Errorf("activation backup Portal file protection: %w", err)
	}
	entries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return CreateInput{}, err
	}
	tenants := make([]config.Tenant, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return CreateInput{}, errors.New("activation backup tenant configuration directory contains an unexpected entry")
		}
		path := filepath.Join(portal.Paths.TenantConfigs, entry.Name())
		tenant, err := config.LoadTenant(path)
		if err != nil || entry.Name() != tenant.TenantID+".json" {
			return CreateInput{}, errors.New("activation backup tenant configuration set is invalid")
		}
		if err := admin.ValidateTenantBinding(portal, tenant); err != nil {
			return CreateInput{}, fmt.Errorf("activation backup tenant %s binding: %w", tenant.TenantID, err)
		}
		if err := admin.VerifyTenantConfigPath(portal, tenant, path); err != nil {
			return CreateInput{}, fmt.Errorf("activation backup tenant %s config protection: %w", tenant.TenantID, err)
		}
		tenants = append(tenants, tenant)
	}
	if len(tenants) == 0 {
		return CreateInput{}, errors.New("activation backup contract contains no tenant")
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].TenantID < tenants[j].TenantID })

	contract := CreateInput{PortalConfig: portalConfigPath}
	contract.Sources = append(contract.Sources,
		Source{Name: "configuration", Path: filepath.Dir(portalConfigPath)},
		Source{Name: "portal-state", Path: portal.Paths.PortalState},
		Source{Name: "cliproxy-policy-state", Path: portal.CLIProxy.PolicyStateFile},
		Source{Name: "release-pointer-renderer", Path: portal.Renderer.PointerFile},
	)
	pointerSources := map[string]bool{portal.Renderer.PointerFile: true}
	for _, tenant := range tenants {
		identityPath := filepath.Join("/etc/systemd/system", "workagent-userhost@"+tenant.TenantID+".service.d", "identity.conf")
		contract.Sources = append(contract.Sources,
			Source{Name: "tenant-" + tenant.TenantID, Path: tenant.DataRoot},
			Source{Name: "systemd-identity-" + tenant.TenantID, Path: identityPath},
		)
		if !pointerSources[tenant.Release.PointerFile] {
			contract.Sources = append(contract.Sources, Source{Name: "release-pointer-" + tenant.TenantID, Path: tenant.Release.PointerFile})
			pointerSources[tenant.Release.PointerFile] = true
		}
	}
	contract.Sources = append(contract.Sources, backupConfig.AdditionalSources...)
	if err := validateSources(contract.Sources); err != nil {
		return CreateInput{}, err
	}
	sort.Slice(contract.Sources, func(i, j int) bool { return contract.Sources[i].Path < contract.Sources[j].Path })

	pointers := make(map[string]ReleasePointer, len(pointerSources))
	addPointer := func(path, scope string) error {
		pointer, err := release.LoadProtectedPointer(path, true)
		if err != nil || pointer.Scope != scope {
			return fmt.Errorf("activation backup release pointer %s is invalid: %w", path, err)
		}
		pointers[path] = ReleasePointer{Path: path, Scope: pointer.Scope, Current: pointer.Current, Previous: pointer.Previous, Activated: pointer.ActivatedAt.UTC().Format(time.RFC3339Nano)}
		return nil
	}
	if err := addPointer(portal.Renderer.PointerFile, portal.Renderer.Scope); err != nil {
		return CreateInput{}, err
	}
	for _, tenant := range tenants {
		if _, exists := pointers[tenant.Release.PointerFile]; !exists {
			if err := addPointer(tenant.Release.PointerFile, tenant.Release.Scope); err != nil {
				return CreateInput{}, err
			}
		}
	}
	for _, pointer := range pointers {
		contract.ReleasePointers = append(contract.ReleasePointers, pointer)
	}
	sort.Slice(contract.ReleasePointers, func(i, j int) bool { return contract.ReleasePointers[i].Path < contract.ReleasePointers[j].Path })
	return contract, nil
}

func ValidateActivationBackupManifest(manifest Manifest, contract CreateInput) error {
	if !cleanAbsolute(contract.PortalConfig) || manifest.PortalConfig != contract.PortalConfig || len(contract.Sources) == 0 || len(contract.ReleasePointers) == 0 {
		return errors.New("activation backup manifest does not match the protected Portal identity")
	}
	expectedSources := append([]Source(nil), contract.Sources...)
	actualSources := append([]Source(nil), manifest.Sources...)
	sort.Slice(expectedSources, func(i, j int) bool { return expectedSources[i].Path < expectedSources[j].Path })
	sort.Slice(actualSources, func(i, j int) bool { return actualSources[i].Path < actualSources[j].Path })
	if len(actualSources) != len(expectedSources) {
		return errors.New("activation backup manifest source set is incomplete or contains extras")
	}
	for index := range expectedSources {
		if actualSources[index] != expectedSources[index] {
			return errors.New("activation backup manifest source set does not match the current recovery contract")
		}
	}
	expectedPointers := append([]ReleasePointer(nil), contract.ReleasePointers...)
	actualPointers := append([]ReleasePointer(nil), manifest.ReleasePointers...)
	sort.Slice(expectedPointers, func(i, j int) bool { return expectedPointers[i].Path < expectedPointers[j].Path })
	sort.Slice(actualPointers, func(i, j int) bool { return actualPointers[i].Path < actualPointers[j].Path })
	if !equalReleasePointers(expectedPointers, actualPointers) {
		return errors.New("activation backup manifest release-pointer set does not match the current channel state")
	}
	entryPaths := make(map[string]bool, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		entryPaths[entry.Path] = true
	}
	for _, source := range expectedSources {
		rootEntry := "rootfs" + filepath.ToSlash(source.Path)
		if !entryPaths[rootEntry] {
			return fmt.Errorf("activation backup manifest omits source root %s", source.Name)
		}
	}
	return nil
}

func verifyProtectedRecoveryFile(path string, maximumMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&^maximumMode != 0 || info.Size() <= 0 || info.Size() > 1024*1024 {
		return errors.New("recovery file must be a protected root-owned regular file")
	}
	return nil
}

func verifyBackupStateRoot(root string, uid, gid uint32) error {
	if !cleanAbsolute(root) || uid == 0 || gid == 0 {
		return errors.New("backup state-root identity is invalid")
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("backup state root is missing or unsafe: %s", root)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("backup state root ownership is invalid: %s", root)
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open backup state root %s: %w", root, err)
	}
	defer unix.Close(rootFD)
	var opened unix.Stat_t
	if err := unix.Fstat(rootFD, &opened); err != nil || opened.Dev != uint64(stat.Dev) || opened.Ino != stat.Ino ||
		opened.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(opened.Mode).Perm() != 0o700 || opened.Uid != uid || opened.Gid != gid {
		return fmt.Errorf("backup state root changed while it was opened: %s", root)
	}
	var lockStat unix.Stat_t
	if err := unix.Fstatat(rootFD, ".runtime.lock", &lockStat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		lockStat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(lockStat.Mode).Perm() != 0o600 || lockStat.Uid != uid || lockStat.Gid != gid {
		return fmt.Errorf("backup runtime lock is missing or unsafe: %s", root)
	}
	return nil
}

// acquireReleasePointerSnapshotLock holds the same inode lock used by release
// activation for the lifetime of a snapshot. This makes pointer bytes and the
// signed current/previous release verification one coherent backup epoch.
func acquireReleasePointerSnapshotLock(pointerPath string) (io.Closer, error) {
	if !cleanAbsolute(pointerPath) || filepath.Base(pointerPath) != "current.json" {
		return nil, errors.New("release pointer snapshot-lock path is invalid")
	}
	parent := filepath.Dir(pointerPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("release pointer snapshot-lock parent is unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return nil, errors.New("release pointer snapshot-lock parent ownership is unsafe")
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("open release pointer snapshot-lock parent")
	}
	defer unix.Close(parentFD)
	var openedParent unix.Stat_t
	if err := unix.Fstat(parentFD, &openedParent); err != nil || openedParent.Dev != uint64(parentStat.Dev) || openedParent.Ino != parentStat.Ino ||
		openedParent.Mode&unix.S_IFMT != unix.S_IFDIR || openedParent.Uid != 0 || openedParent.Gid != 0 || os.FileMode(openedParent.Mode).Perm()&0o022 != 0 {
		return nil, errors.New("release pointer snapshot-lock parent changed")
	}
	base := filepath.Base(pointerPath) + ".lock"
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("open existing release pointer snapshot lock")
	}
	file := os.NewFile(uintptr(fd), pointerPath+".lock")
	fail := func(err error) (io.Closer, error) {
		_ = file.Close()
		return nil, err
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(fd, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		os.FileMode(lockStat.Mode).Perm() != 0o600 || lockStat.Uid != 0 || lockStat.Gid != 0 {
		return fail(errors.New("release pointer snapshot lock is unsafe"))
	}
	if err := verifyRecoveryDestinationName(parentFD, base, lockStat); err != nil {
		return fail(errors.New("release pointer snapshot lock pathname changed"))
	}
	if err := unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return fail(errors.New("release activation is in progress"))
		}
		return fail(errors.New("acquire release pointer snapshot lock"))
	}
	if err := verifyRecoveryDestinationName(parentFD, base, lockStat); err != nil {
		return fail(errors.New("release pointer snapshot lock changed after acquisition"))
	}
	return file, nil
}

func verifyServiceRecoveryFile(path, accountName string) error {
	if !strings.HasPrefix(path, "/etc/workagent/") || filepath.Clean(path) != path || accountName == "" {
		return errors.New("service recovery file input is invalid")
	}
	account, err := user.Lookup(accountName)
	if err != nil {
		return errors.New("dedicated service account is unavailable")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return errors.New("dedicated service group is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || info.Size() <= 0 || info.Size() > 1024*1024 {
		return errors.New("service recovery file is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != uint32(gid) {
		return errors.New("service recovery file ownership does not match its dedicated group")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return errors.New("dedicated service configuration parent is missing")
	}
	parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	if !parentOK || parentStat.Uid != 0 || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() ||
		parentInfo.Mode().Perm()&0o022 != 0 || parentInfo.Mode().Perm()&0o001 == 0 {
		return errors.New("dedicated service cannot safely traverse its configuration parent")
	}
	return nil
}

func verifyRemoteMount(path string) error {
	payload, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("inspect off-host mount: %w", err)
	}
	filesystem, source, found := mountForPath(string(payload), path)
	if !found {
		return errors.New("off-host backup directory is not covered by a mounted filesystem")
	}
	remote := filesystem == "nfs" || filesystem == "nfs4" || filesystem == "cifs" || filesystem == "smb3" || filesystem == "ceph" || filesystem == "9p" || strings.HasPrefix(filesystem, "fuse.sshfs") || strings.HasPrefix(filesystem, "fuse.rclone") || strings.HasPrefix(filesystem, "fuse.s3fs")
	if !remote {
		return fmt.Errorf("off-host backup filesystem %s (%s) is not an approved remote filesystem", filesystem, source)
	}
	return nil
}

func mountForPath(mountInfo, target string) (string, string, bool) {
	target = filepath.Clean(target)
	bestLength := -1
	var bestFilesystem, bestSource string
	for _, line := range strings.Split(mountInfo, "\n") {
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+2 >= len(fields) {
			continue
		}
		mountPoint := strings.ReplaceAll(fields[4], `\040`, " ")
		if target != mountPoint && !pathWithin(mountPoint, target) {
			continue
		}
		if len(mountPoint) > bestLength {
			bestLength = len(mountPoint)
			bestFilesystem, bestSource = fields[separator+1], fields[separator+2]
		}
	}
	return bestFilesystem, bestSource, bestLength >= 0
}

func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	var first error
	for index := len(s.locks) - 1; index >= 0; index-- {
		if err := s.locks[index].Close(); err != nil && first == nil {
			first = err
		}
	}
	s.locks = nil
	s.catalogGuard = nil
	return first
}

func Create(snapshot *Snapshot, configuration Config, key []byte, now time.Time) (Created, error) {
	if snapshot == nil || snapshot.catalogGuard == nil || len(snapshot.locks) == 0 || len(key) != keySize {
		return Created{}, errors.New("a locked snapshot and encryption key are required")
	}
	// Do not rely on a caller having run a preflight at some earlier point.
	// A backup can spend minutes archiving tenant trees, during which a remote
	// mount may disappear and expose its local mount-point directory. Re-prove
	// the complete production environment here and again around the off-host
	// write so that such a fallback can never be reported as a remote backup.
	if err := VerifyEnvironment(configuration, true); err != nil {
		return Created{}, fmt.Errorf("verify backup environment at creation boundary: %w", err)
	}
	offHostGuard, err := openBackupDirectoryGuard(configuration.OffHostDirectory)
	if err != nil {
		return Created{}, fmt.Errorf("pin off-host backup mount: %w", err)
	}
	defer offHostGuard.Close()
	if err := revalidateOffHostEnvironment(configuration, offHostGuard); err != nil {
		return Created{}, fmt.Errorf("revalidate pinned off-host backup environment: %w", err)
	}
	temporary, err := os.CreateTemp(configuration.LocalDirectory, ".workagent-backup-*.partial")
	if err != nil {
		return Created{}, err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o400); err != nil {
		return Created{}, err
	}
	hash := sha256.New()
	manifest, err := CreateArchive(io.MultiWriter(temporary, hash), key, CreateInput{PortalConfig: snapshot.PortalConfig, Sources: snapshot.Sources, ReleasePointers: snapshot.ReleasePointers, Now: now})
	if err != nil {
		return Created{}, err
	}
	// Release activation uses an independent protected pointer lock. Re-read
	// every pointer after archiving so an activation concurrent with this
	// snapshot can never bind archived pointer bytes to stale manifest evidence.
	if err := verifyReleasePointersOnDisk(snapshot.ReleasePointers); err != nil {
		return Created{}, fmt.Errorf("release pointer changed during backup: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return Created{}, err
	}
	if err := temporary.Close(); err != nil {
		return Created{}, err
	}
	archiveName := ArchiveName(manifest)
	localArchive := filepath.Join(configuration.LocalDirectory, archiveName)
	if _, err := os.Lstat(localArchive); err == nil {
		return Created{}, errors.New("backup archive already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Created{}, err
	}
	if err := renameNoReplace(temporaryPath, localArchive); err != nil {
		return Created{}, err
	}
	committed = true
	if err := syncDirectory(configuration.LocalDirectory); err != nil {
		return Created{}, err
	}
	archiveInfo, err := os.Stat(localArchive)
	if err != nil {
		return Created{}, err
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, BackupID: manifest.BackupID, CreatedAt: manifest.CreatedAt, ArchiveName: archiveName, ArchiveSHA256: hex.EncodeToString(hash.Sum(nil)), ArchiveSize: archiveInfo.Size(), PortalConfig: manifest.PortalConfig, ReleasePointers: manifest.ReleasePointers}
	localReceipt := localArchive + ".receipt.json"
	if err := writeReceipt(localReceipt, receipt); err != nil {
		return Created{}, err
	}
	if _, err := VerifyFiles(localArchive, localReceipt, key, true); err != nil {
		return Created{}, fmt.Errorf("new backup failed its read-after-write verification: %w", err)
	}
	if err := revalidateOffHostEnvironment(configuration, offHostGuard); err != nil {
		return Created{}, fmt.Errorf("revalidate off-host backup environment before copy: %w", err)
	}
	offHostArchive := filepath.Join(configuration.OffHostDirectory, archiveName)
	offHostReceipt := offHostArchive + ".receipt.json"
	pinnedOffHostArchive, err := offHostGuard.pinnedPath(archiveName)
	if err != nil {
		return Created{}, err
	}
	pinnedOffHostReceipt, err := offHostGuard.pinnedPath(archiveName + ".receipt.json")
	if err != nil {
		return Created{}, err
	}
	if err := copyFileAtomic(localArchive, pinnedOffHostArchive, receipt.ArchiveSHA256, 0o400); err != nil {
		return Created{}, fmt.Errorf("write off-host backup: %w", err)
	}
	if err := copyFileAtomic(localReceipt, pinnedOffHostReceipt, "", 0o400); err != nil {
		return Created{}, fmt.Errorf("write off-host backup receipt: %w", err)
	}
	if _, err := VerifyFiles(pinnedOffHostArchive, pinnedOffHostReceipt, key, true); err != nil {
		return Created{}, fmt.Errorf("off-host backup failed verification: %w", err)
	}
	if err := revalidateOffHostEnvironment(configuration, offHostGuard); err != nil {
		return Created{}, fmt.Errorf("revalidate off-host backup environment after copy: %w", err)
	}
	// Verify through the configured pathname as well as the pinned descriptor.
	// The checks are sandwiched by mount-identity validation so a detached or
	// replacement mount cannot be reported as the destination we wrote.
	if _, err := VerifyFiles(offHostArchive, offHostReceipt, key, true); err != nil {
		return Created{}, fmt.Errorf("off-host backup pathname failed verification: %w", err)
	}
	if err := offHostGuard.verifyCurrent(); err != nil {
		return Created{}, fmt.Errorf("revalidate off-host mount after pathname verification: %w", err)
	}
	if err := enforceRetention(configuration.LocalDirectory, configuration.RetentionCount, archiveName); err != nil {
		return Created{}, err
	}
	if err := revalidateOffHostEnvironment(configuration, offHostGuard); err != nil {
		return Created{}, fmt.Errorf("revalidate off-host backup environment before retention: %w", err)
	}
	pinnedOffHostDirectory, err := offHostGuard.pinnedPath("")
	if err != nil {
		return Created{}, err
	}
	if err := enforceRetention(pinnedOffHostDirectory, configuration.RetentionCount, archiveName); err != nil {
		return Created{}, err
	}
	if err := revalidateOffHostEnvironment(configuration, offHostGuard); err != nil {
		return Created{}, fmt.Errorf("revalidate off-host backup environment after retention: %w", err)
	}
	if _, err := VerifyFiles(offHostArchive, offHostReceipt, key, true); err != nil {
		return Created{}, fmt.Errorf("retained off-host backup failed final verification: %w", err)
	}
	if err := offHostGuard.verifyCurrent(); err != nil {
		return Created{}, fmt.Errorf("revalidate off-host mount after final verification: %w", err)
	}
	metricPayload := []byte(fmt.Sprintf("# TYPE workagent_backup_last_success_timestamp_seconds gauge\nworkagent_backup_last_success_timestamp_seconds %.0f\n# TYPE workagent_backup_last_archive_bytes gauge\nworkagent_backup_last_archive_bytes %d\n", float64(manifest.CreatedAt.Unix()), receipt.ArchiveSize))
	if err := atomicWrite(configuration.MetricsFile, metricPayload, 0o644); err != nil {
		return Created{}, fmt.Errorf("write backup success metric: %w", err)
	}
	return Created{Manifest: manifest, Receipt: receipt, LocalArchive: localArchive, LocalReceipt: localReceipt, OffHostArchive: offHostArchive, OffHostReceipt: offHostReceipt}, nil
}

func revalidateOffHostEnvironment(configuration Config, guard *backupDirectoryGuard) error {
	if err := VerifyEnvironment(configuration, true); err != nil {
		return err
	}
	return guard.verifyCurrent()
}

func VerifyFiles(archivePath, receiptPath string, key []byte, requireRootOwner bool) (Manifest, error) {
	receipt, err := LoadReceipt(receiptPath, requireRootOwner)
	if err != nil {
		return Manifest{}, err
	}
	archive, archiveStat, err := openProtectedArchive(archivePath, receipt, requireRootOwner)
	if err != nil {
		return Manifest{}, err
	}
	defer archive.Close()
	hash := sha256.New()
	manifest, err := VerifyArchive(io.TeeReader(archive, hash), key)
	if err != nil {
		return Manifest{}, err
	}
	if err := verifyOpenedBackupFile(archive, archivePath, archiveStat); err != nil {
		return Manifest{}, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != receipt.ArchiveSHA256 || manifest.BackupID != receipt.BackupID || manifest.CreatedAt != receipt.CreatedAt || manifest.PortalConfig != receipt.PortalConfig || !equalReleasePointers(manifest.ReleasePointers, receipt.ReleasePointers) {
		return Manifest{}, errors.New("backup receipt does not match the archive")
	}
	return manifest, nil
}

func RestoreFiles(archivePath, receiptPath string, key []byte, target string, requireRootOwner bool) (Manifest, error) {
	verified, err := VerifyFiles(archivePath, receiptPath, key, requireRootOwner)
	if err != nil {
		return Manifest{}, err
	}
	receipt, err := LoadReceipt(receiptPath, requireRootOwner)
	if err != nil {
		return Manifest{}, err
	}
	archive, archiveStat, err := openProtectedArchive(archivePath, receipt, requireRootOwner)
	if err != nil {
		return Manifest{}, err
	}
	defer archive.Close()
	hash := sha256.New()
	manifest, err := RestoreArchive(io.TeeReader(archive, hash), key, target)
	if err != nil {
		return Manifest{}, err
	}
	if err := verifyOpenedBackupFile(archive, archivePath, archiveStat); err != nil {
		return Manifest{}, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != receipt.ArchiveSHA256 || manifest.BackupID != receipt.BackupID || manifest.BackupID != verified.BackupID {
		return Manifest{}, errors.New("restored backup does not match its receipt")
	}
	return manifest, nil
}

func LoadReceipt(path string, requireRootOwner bool) (Receipt, error) {
	if !cleanAbsolute(path) {
		return Receipt{}, errors.New("backup receipt path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4*1024*1024 || info.Mode().Perm()&0o022 != 0 {
		return Receipt{}, errors.New("backup receipt is missing or unsafe")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return Receipt{}, errors.New("backup receipt is not owned by root")
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Receipt{}, err
	}
	before, err := file.Stat()
	beforeStat, beforeOK := fileSyscallStat(before)
	infoStat, infoOK := fileSyscallStat(info)
	if err != nil || !beforeOK || !infoOK || !sameArchivedStat(infoStat, beforeStat) {
		file.Close()
		return Receipt{}, errors.New("backup receipt changed while it was opened")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 4*1024*1024+1))
	verifyErr := verifyOpenedBackupFile(file, path, *beforeStat)
	closeErr := file.Close()
	if readErr != nil || len(payload) > 4*1024*1024 || verifyErr != nil || closeErr != nil {
		return Receipt{}, errors.New("backup receipt changed while it was read")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, errors.New("backup receipt is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("backup receipt contains trailing data")
	}
	if receipt.SchemaVersion != ReceiptSchemaVersion || receipt.BackupID == "" || !archiveNamePattern.MatchString(receipt.ArchiveName) || len(receipt.ArchiveSHA256) != 64 || receipt.ArchiveSize <= int64(headerSize) || receipt.CreatedAt.IsZero() || !cleanAbsolute(receipt.PortalConfig) {
		return Receipt{}, errors.New("backup receipt metadata is invalid")
	}
	if _, err := hex.DecodeString(receipt.ArchiveSHA256); err != nil || strings.ToLower(receipt.ArchiveSHA256) != receipt.ArchiveSHA256 {
		return Receipt{}, errors.New("backup receipt hash is invalid")
	}
	return receipt, nil
}

func writeReceipt(path string, receipt Receipt) error {
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteNoReplace(path, append(payload, '\n'), 0o400)
}

func openProtectedArchive(path string, receipt Receipt, requireRootOwner bool) (*os.File, syscall.Stat_t, error) {
	if !cleanAbsolute(path) || filepath.Base(path) != receipt.ArchiveName {
		return nil, syscall.Stat_t{}, errors.New("backup archive path does not match its receipt")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != receipt.ArchiveSize || info.Mode().Perm()&0o022 != 0 {
		return nil, syscall.Stat_t{}, errors.New("backup archive is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, syscall.Stat_t{}, errors.New("backup archive metadata is unavailable")
	}
	if requireRootOwner {
		if stat.Uid != 0 {
			return nil, syscall.Stat_t{}, errors.New("backup archive is not owned by root")
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	opened, err := file.Stat()
	openedStat, openedOK := fileSyscallStat(opened)
	if err != nil || !openedOK || !sameArchivedStat(stat, openedStat) {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("backup archive changed while it was opened")
	}
	return file, *openedStat, nil
}

func verifyOpenedBackupFile(file *os.File, path string, before syscall.Stat_t) error {
	if file == nil || !cleanAbsolute(path) {
		return errors.New("protected backup file verification input is invalid")
	}
	after, err := file.Stat()
	afterStat, afterOK := fileSyscallStat(after)
	named, namedErr := os.Lstat(path)
	namedStat, namedOK := fileSyscallStat(named)
	if err != nil || !afterOK || namedErr != nil || !namedOK || !sameArchivedStat(&before, afterStat) || !sameArchivedStat(&before, namedStat) {
		return errors.New("protected backup file changed while it was read")
	}
	return nil
}

func verifyBackupDirectory(path string) error {
	if !cleanAbsolute(path) {
		return errors.New("backup directory path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("backup directory is missing or unsafe: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("backup directory is not owned by root: %s", path)
	}
	return nil
}

func copyFileAtomic(source, destination, expectedHash string, mode os.FileMode) error {
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("refusing to overwrite an existing off-host backup")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	parent := filepath.Dir(destination)
	temporary, err := os.CreateTemp(parent, ".workagent-copy-*.partial")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(temporary, hash), input); err != nil {
		temporary.Close()
		return err
	}
	if expectedHash != "" && hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		temporary.Close()
		return errors.New("backup changed while it was copied")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := renameNoReplace(temporaryPath, destination); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func enforceRetention(directory string, keep int, protectedArchive string) error {
	if keep < 1 || !archiveNamePattern.MatchString(protectedArchive) {
		return errors.New("retention protection input is invalid")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var archives []string
	archiveEntries := make(map[string]bool)
	receiptEntries := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if archiveNamePattern.MatchString(name) {
			archiveEntries[name] = true
		}
		const receiptSuffix = ".receipt.json"
		if strings.HasSuffix(name, receiptSuffix) {
			archiveName := strings.TrimSuffix(name, receiptSuffix)
			if archiveNamePattern.MatchString(archiveName) {
				receiptEntries[archiveName] = true
			}
		}
	}
	for name := range archiveEntries {
		if !receiptEntries[name] {
			return errors.New("retention encountered an incomplete backup pair")
		}
	}
	for name := range receiptEntries {
		if !archiveEntries[name] {
			return errors.New("retention encountered an incomplete backup pair")
		}
	}
	for name := range archiveEntries {
		archivePath := filepath.Join(directory, name)
		receiptPath := archivePath + ".receipt.json"
		if err := verifyRetentionFile(archivePath); err != nil {
			return err
		}
		if err := verifyRetentionFile(receiptPath); err != nil {
			return err
		}
		archives = append(archives, name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(archives)))
	protectedFound := false
	for _, name := range archives {
		if name == protectedArchive {
			protectedFound = true
			break
		}
	}
	if !protectedFound {
		return errors.New("new backup is missing before retention")
	}
	if len(archives) <= keep {
		return syncDirectory(directory)
	}
	retained := make(map[string]bool, keep)
	retained[protectedArchive] = true
	for _, name := range archives {
		if name == protectedArchive {
			continue
		}
		if len(retained) < keep {
			retained[name] = true
		}
	}
	for _, name := range archives {
		if retained[name] {
			continue
		}
		archivePath := filepath.Join(directory, name)
		receiptPath := archivePath + ".receipt.json"
		for _, path := range []string{receiptPath, archivePath} {
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("retention encountered an unsafe backup entry")
			}
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return syncDirectory(directory)
}

func verifyRetentionFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("retention encountered an unsafe backup entry")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("retention encountered an unsafe backup entry")
	}
	return nil
}

func ValidateRestoredTree(target string, manifest Manifest) error {
	if !cleanAbsolute(target) || manifest.BackupID == "" {
		return errors.New("restored-tree validation input is invalid")
	}
	translate := func(original string) (string, error) {
		if !cleanAbsolute(original) {
			return "", errors.New("restored path is invalid")
		}
		return restorePath(target, "rootfs/"+strings.TrimPrefix(filepath.ToSlash(original), "/"))
	}
	portalPath, err := translate(manifest.PortalConfig)
	if err != nil {
		return err
	}
	portal, err := config.LoadPortal(portalPath)
	if err != nil {
		return fmt.Errorf("load restored Portal configuration: %w", err)
	}
	if err := portal.ValidateProductionLayout(manifest.PortalConfig); err != nil {
		return fmt.Errorf("validate restored production layout: %w", err)
	}
	portalDatabase, err := translate(portal.DatabasePath())
	if err != nil {
		return err
	}
	if err := checkSQLite(portalDatabase); err != nil {
		return fmt.Errorf("validate restored Portal database: %w", err)
	}
	tenantConfigRoot, err := translate(portal.Paths.TenantConfigs)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(tenantConfigRoot)
	if err != nil {
		return err
	}
	tenants := make([]config.Tenant, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("restored tenant configuration directory contains an unexpected entry")
		}
		tenant, err := config.LoadTenant(filepath.Join(tenantConfigRoot, entry.Name()))
		if err != nil {
			return err
		}
		if entry.Name() != tenant.TenantID+".json" {
			return errors.New("restored tenant configuration filename is invalid")
		}
		tenants = append(tenants, tenant)
	}
	if len(tenants) == 0 {
		return errors.New("restored tree contains no tenant")
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].TenantID < tenants[j].TenantID })
	canonicalPointerSources := canonicalReleasePointerSources(tenants)
	sources := make(map[string]string, len(manifest.Sources))
	for _, source := range manifest.Sources {
		sources[source.Name] = source.Path
	}
	if sources["configuration"] != filepath.Dir(manifest.PortalConfig) || sources["portal-state"] != portal.Paths.PortalState ||
		sources["cliproxy-policy-state"] != portal.CLIProxy.PolicyStateFile || sources["release-pointer-renderer"] != portal.Renderer.PointerFile {
		return errors.New("restored tree is missing a canonical application-state source")
	}
	policyPath, err := translate(portal.CLIProxy.PolicyStateFile)
	if err != nil {
		return err
	}
	policyInfo, err := os.Lstat(policyPath)
	if err != nil || policyInfo.Mode()&os.ModeSymlink != 0 || !policyInfo.Mode().IsRegular() || policyInfo.Mode().Perm() != 0o600 || policyInfo.Size() <= 0 || policyInfo.Size() > 64*1024*1024 {
		return errors.New("restored CLIProxy policy state is missing or unsafe")
	}
	policyFile, err := os.OpenFile(policyPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open restored CLIProxy policy state")
	}
	policyPayload, readErr := io.ReadAll(io.LimitReader(policyFile, 64*1024*1024+1))
	closeErr := policyFile.Close()
	if readErr != nil || closeErr != nil || len(policyPayload) > 64*1024*1024 {
		clear(policyPayload)
		return errors.New("read restored CLIProxy policy state")
	}
	if err := cliproxy.ValidatePolicyStatePayload(policyPayload); err != nil {
		clear(policyPayload)
		return fmt.Errorf("validate restored CLIProxy policy state: %w", err)
	}
	clear(policyPayload)
	actualPointers := make(map[string]ReleasePointer)
	rendererPointerPath, err := translate(portal.Renderer.PointerFile)
	if err != nil {
		return err
	}
	rendererPointer, err := release.LoadProtectedPointer(rendererPointerPath, true)
	if err != nil || rendererPointer.Scope != portal.Renderer.Scope {
		return fmt.Errorf("restored Renderer release pointer is invalid: %w", err)
	}
	actualPointers[portal.Renderer.PointerFile] = ReleasePointer{
		Path: portal.Renderer.PointerFile, Scope: rendererPointer.Scope, Current: rendererPointer.Current,
		Previous: rendererPointer.Previous, Activated: rendererPointer.ActivatedAt.UTC().Format(time.RFC3339Nano),
	}
	for _, tenant := range tenants {
		identityOriginal := filepath.Join("/etc/systemd/system", "workagent-userhost@"+tenant.TenantID+".service.d", "identity.conf")
		if sources["tenant-"+tenant.TenantID] != tenant.DataRoot || sources["systemd-identity-"+tenant.TenantID] != identityOriginal {
			return errors.New("restored tree is missing canonical tenant recovery evidence")
		}
		// Multiple tenants intentionally share one immutable runtime channel.
		// The source path is therefore archived once (under the first sorted
		// tenant's source name), while every tenant must still bind to that exact
		// authenticated pointer path.
		canonicalName, found := canonicalPointerSources[tenant.Release.PointerFile]
		pointerCovered := found && sources[canonicalName] == tenant.Release.PointerFile
		if tenant.Release.PointerFile == portal.Renderer.PointerFile {
			pointerCovered = sources["release-pointer-renderer"] == tenant.Release.PointerFile
		}
		if !pointerCovered {
			return errors.New("restored tree is missing the canonical shared release pointer")
		}
		identityPath, err := translate(identityOriginal)
		if err != nil {
			return err
		}
		identity, err := os.ReadFile(identityPath)
		if err != nil || string(identity) != "[Service]\nUser="+tenant.RuntimeUser+"\nGroup="+tenant.RuntimeUser+"\n" {
			return errors.New("restored tenant systemd identity is invalid")
		}
		pointerPath, err := translate(tenant.Release.PointerFile)
		if err != nil {
			return err
		}
		pointer, err := release.LoadProtectedPointer(pointerPath, true)
		if err != nil || pointer.Scope != tenant.Release.Scope {
			return fmt.Errorf("restored tenant release pointer is invalid: %w", err)
		}
		actualPointers[tenant.Release.PointerFile] = ReleasePointer{
			Path: tenant.Release.PointerFile, Scope: pointer.Scope, Current: pointer.Current,
			Previous: pointer.Previous, Activated: pointer.ActivatedAt.UTC().Format(time.RFC3339Nano),
		}
		dataRoot, err := translate(tenant.DataRoot)
		if err != nil {
			return err
		}
		info, err := os.Lstat(dataRoot)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			return errors.New("restored tenant data root is missing or unsafe")
		}
		if tenant.Backend.InternalAuth.Enabled {
			databasePath, err := translate(tenant.Backend.InternalAuth.DatabasePath)
			if err != nil {
				return err
			}
			if err := checkSQLite(databasePath); err != nil {
				return fmt.Errorf("validate restored tenant database: %w", err)
			}
		}
	}
	actualPointerList := make([]ReleasePointer, 0, len(actualPointers))
	for _, pointer := range actualPointers {
		actualPointerList = append(actualPointerList, pointer)
	}
	sort.Slice(actualPointerList, func(i, j int) bool { return actualPointerList[i].Path < actualPointerList[j].Path })
	if !equalReleasePointers(actualPointerList, manifest.ReleasePointers) {
		return errors.New("restored release pointers do not match authenticated manifest evidence")
	}
	return nil
}

// canonicalReleasePointerSources mirrors snapshot discovery: tenant configs
// are sorted and the first tenant bound to each shared channel names the one
// archived pointer source. This avoids overlapping source paths while keeping
// source naming deterministic across backup and recovery.
func canonicalReleasePointerSources(tenants []config.Tenant) map[string]string {
	result := make(map[string]string)
	for _, tenant := range tenants {
		if _, exists := result[tenant.Release.PointerFile]; !exists {
			result[tenant.Release.PointerFile] = "release-pointer-" + tenant.TenantID
		}
	}
	return result
}

func verifyReleasePointersOnDisk(expected []ReleasePointer) error {
	if len(expected) == 0 {
		return errors.New("release pointer evidence is missing")
	}
	actual := make([]ReleasePointer, 0, len(expected))
	seen := make(map[string]bool, len(expected))
	for _, evidence := range expected {
		if seen[evidence.Path] {
			return errors.New("release pointer evidence contains a duplicate path")
		}
		seen[evidence.Path] = true
		pointer, err := release.LoadProtectedPointer(evidence.Path, true)
		if err != nil {
			return err
		}
		actual = append(actual, ReleasePointer{
			Path: evidence.Path, Scope: pointer.Scope, Current: pointer.Current,
			Previous: pointer.Previous, Activated: pointer.ActivatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	sort.Slice(actual, func(i, j int) bool { return actual[i].Path < actual[j].Path })
	expectedCopy := append([]ReleasePointer(nil), expected...)
	sort.Slice(expectedCopy, func(i, j int) bool { return expectedCopy[i].Path < expectedCopy[j].Path })
	if !equalReleasePointers(actual, expectedCopy) {
		return errors.New("release pointer evidence no longer matches protected files")
	}
	return nil
}

func renameNoReplace(source, destination string) error {
	if !cleanAbsolute(source) || !cleanAbsolute(destination) {
		return errors.New("no-replace publication path is invalid")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("refusing to overwrite existing state")
		}
		return fmt.Errorf("publish without replacement: %w", err)
	}
	return nil
}

func checkSQLite(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("SQLite database is missing or unsafe")
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(1000)")
	if err != nil {
		return err
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var result string
	if err := database.QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return errors.New("SQLite quick_check did not return ok")
	}
	return nil
}

func equalReleasePointers(first, second []ReleasePointer) bool {
	firstPayload, _ := json.Marshal(first)
	secondPayload, _ := json.Marshal(second)
	return string(firstPayload) == string(secondPayload)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
