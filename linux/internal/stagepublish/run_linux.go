//go:build linux

package stagepublish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/tenantprovision"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

func Run(ctx context.Context, options Options) (Result, error) {
	return (&runner{env: productionEnvironment{}, layout: productionLayout(), verifyStage: winmigration.VerifyPublicationStage, production: true}).run(ctx, options)
}

func (r *runner) run(ctx context.Context, options Options) (Result, error) {
	if r == nil || r.env == nil || r.verifyStage == nil {
		return Result{}, errors.New("publication runtime is unavailable")
	}
	if err := options.validate(); err != nil {
		return Result{}, err
	}
	if r.production && r.env.EffectiveUID() != 0 {
		return Result{}, errors.New("migration stage publication must run as root")
	}
	verified, err := r.verifyStage(ctx, options.Stage, options.ExpectedSourceFingerprint, options.ExpectedOutputFingerprint, r.env.EffectiveUID())
	if err != nil {
		return Result{}, err
	}
	portal, err := r.env.LoadPortal(r.layout.portalConfig)
	if err != nil {
		return Result{}, err
	}
	if r.production {
		if err := portal.ValidateProductionLayout(r.layout.portalConfig); err != nil {
			return Result{}, err
		}
		if portal.Paths.PortalState != filepath.Dir(r.layout.portalDatabase) || portal.Paths.TenantData != r.layout.tenantRoot || portal.Paths.TenantConfigs != r.layout.tenantConfigs {
			return Result{}, errors.New("Portal configuration does not match the fixed publication layout")
		}
	}
	if err := r.env.VerifyPortalFiles(portal, r.layout.portalConfig); err != nil {
		return Result{}, err
	}
	host, err := r.env.InspectHost(portal)
	if err != nil {
		return Result{}, err
	}
	if !host.Ready || host.Filesystem != "xfs" || host.MountPoint != portal.Paths.TenantData || !host.ProjectQuota {
		return Result{}, errors.New("tenant publication requires the exact XFS prjquota production mount")
	}
	portalAccount, err := r.env.PortalAccount(portal)
	if err != nil {
		return Result{}, err
	}
	portalParent, err := openRealDirectory(filepath.Dir(r.layout.portalDatabase), portalAccount.UID, portalAccount.GID, 0o700)
	if err != nil {
		return Result{}, fmt.Errorf("Portal state root: %w", err)
	}
	defer portalParent.Close()
	tenantParent, err := openRealDirectory(r.layout.tenantRoot, 0, 0, 0o711)
	if err != nil {
		return Result{}, fmt.Errorf("tenant publication root: %w", err)
	}
	defer tenantParent.Close()
	if err := validateFreeSpace(r.layout.tenantRoot, verified); err != nil {
		return Result{}, err
	}
	tenants, err := buildTenantConfigs(portal, portalAccount.UID, verified)
	if err != nil {
		return Result{}, err
	}
	if err := r.validateTenantConfigNamespace(tenants, portalAccount.GID); err != nil {
		return Result{}, err
	}
	journalReady, err := ensureProtectedDirectory(r.layout.journalRoot, r.env.EffectiveUID(), options.Apply)
	if err != nil {
		return Result{}, err
	}
	quotaReady, err := ensureProtectedDirectory(r.layout.quotaBackupDir, r.env.EffectiveUID(), options.Apply)
	if err != nil {
		return Result{}, err
	}
	rollbackReady, err := ensureProtectedDirectory(r.layout.rollbackRoot, r.env.EffectiveUID(), options.Apply)
	if err != nil {
		return Result{}, err
	}
	if options.Apply && (!journalReady || !quotaReady || !rollbackReady) {
		// Re-open after creation to turn the return value into a verified state.
		journalReady, err = ensureProtectedDirectory(r.layout.journalRoot, r.env.EffectiveUID(), false)
		if err != nil {
			return Result{}, err
		}
		quotaReady, err = ensureProtectedDirectory(r.layout.quotaBackupDir, r.env.EffectiveUID(), false)
		if err != nil {
			return Result{}, err
		}
		rollbackReady, err = ensureProtectedDirectory(r.layout.rollbackRoot, r.env.EffectiveUID(), false)
		if err != nil {
			return Result{}, err
		}
	}
	if options.Apply && (!journalReady || !quotaReady || !rollbackReady) {
		return Result{}, errors.New("protected migration publication directories were not durably created")
	}
	existingJournal, journalExists, err := loadJournal(r.layout.journalPath, r.env.EffectiveUID())
	if err != nil {
		return Result{}, err
	}
	if journalExists {
		if err := existingJournal.validateAgainst(options, verified, r.layout); err != nil {
			return Result{}, err
		}
	}
	if err := validatePublicationNamespace(portalParent, tenantParent, filepath.Base(r.layout.portalDatabase), verified, existingJournal, journalExists); err != nil {
		return Result{}, err
	}
	if err := r.requireAllServicesStopped(ctx, verified); err != nil {
		return Result{}, err
	}
	cliproxyLock, err := r.env.AcquireCLIProxyLock(r.layout.cliproxyLock)
	if err != nil {
		return Result{}, err
	}
	defer cliproxyLock.Close()
	if err := r.requireAllServicesStopped(ctx, verified); err != nil {
		return Result{}, err
	}
	if options.Check {
		if err := r.checkExistingAccountsAndConfigs(ctx, portal, tenants); err != nil {
			return Result{}, err
		}
		if journalExists {
			if err := r.checkJournalArtifacts(ctx, options.Stage, portalParent, tenantParent, portalAccount, tenants, verified, existingJournal); err != nil {
				return Result{}, err
			}
		}
		if err := checkPortalRuntimeLock(filepath.Join(filepath.Dir(r.layout.portalDatabase), ".runtime.lock"), portalAccount.UID); err != nil {
			return Result{}, err
		}
		return buildResult(verified, existingJournal, journalExists, r.layout, false, journalReady && quotaReady && rollbackReady), nil
	}
	value := existingJournal
	resumed := journalExists
	if !journalExists {
		value = newJournal(options, verified, r.layout, r.env.Now())
		if err := writeJournal(r.layout.journalPath, &value, r.env.EffectiveUID(), r.env.Now()); err != nil {
			return Result{}, err
		}
	}
	portalRuntimeLock, err := servicelock.AcquireExclusive(filepath.Join(filepath.Dir(r.layout.portalDatabase), ".runtime.lock"), portalAccount.UID, portalAccount.GID)
	if err != nil {
		return Result{}, fmt.Errorf("acquire Portal publication lock: %w", err)
	}
	defer portalRuntimeLock.Close()
	if err := r.requireAllServicesStopped(ctx, verified); err != nil {
		return Result{}, err
	}
	accounts, err := r.ensureAccountsAndConfigs(ctx, portal, tenants, &value)
	if err != nil {
		return Result{}, err
	}
	if err := r.env.EnsureCapacity(ctx, "/run/workagent/capacity", portal.Runtime.MaxConcurrentInstances); err != nil {
		return Result{}, err
	}
	if err := r.env.Systemd().Action(ctx, "daemon-reload"); err != nil {
		return Result{}, err
	}
	for _, tenant := range tenants {
		if err := r.env.VerifyTenantConfig(ctx, portal, tenant); err != nil {
			return Result{}, err
		}
	}
	tenantLocks := make([]io.Closer, 0, len(value.Tenants))
	defer func() {
		for index := len(tenantLocks) - 1; index >= 0; index-- {
			_ = tenantLocks[index].Close()
		}
	}()
	for index := range value.Tenants {
		item := &value.Tenants[index]
		account := accounts[item.TenantID]
		item.UID, item.GID = account.UID, account.GID
		finalExists, err := pathExistsAt(tenantParent, item.TenantID)
		if err != nil {
			return Result{}, err
		}
		lockRoot := filepath.Join(r.layout.tenantRoot, item.TenantID)
		if !finalExists {
			temporaryPath, created, err := prepareTenantTemporary(tenantParent, *item)
			if err != nil {
				return Result{}, err
			}
			if err := convergeTenantQuota(
				created,
				func() error {
					_, err := r.env.VerifyQuota(temporaryPath, item.ProjectID, item.HardLimitBytes)
					return err
				},
				func() (bool, error) { return directoryPathEmpty(temporaryPath) },
				func() error {
					_, err := r.env.AssignQuota(temporaryPath, item.ProjectID, item.HardLimitBytes)
					return err
				},
			); err != nil {
				return Result{}, err
			}
			lockRoot = temporaryPath
		} else if _, err := r.env.VerifyQuota(lockRoot, item.ProjectID, item.HardLimitBytes); err != nil {
			return Result{}, err
		}
		lock, err := servicelock.AcquireExclusive(filepath.Join(lockRoot, ".runtime.lock"), item.UID, item.GID)
		if err != nil {
			return Result{}, err
		}
		tenantLocks = append(tenantLocks, lock)
	}
	value.Status = "provisioned"
	if err := writeJournal(r.layout.journalPath, &value, r.env.EffectiveUID(), r.env.Now()); err != nil {
		return Result{}, err
	}
	for index := range value.Tenants {
		item := &value.Tenants[index]
		finalPath := filepath.Join(r.layout.tenantRoot, item.TenantID)
		finalExists, err := pathExistsAt(tenantParent, item.TenantID)
		if err != nil {
			return Result{}, err
		}
		if finalExists {
			temporaryExists, err := pathExistsAt(tenantParent, item.Temporary)
			if err != nil || temporaryExists {
				return Result{}, errors.New("published tenant and its temporary sibling both exist")
			}
			if err := winmigration.VerifyActivatedTenant(ctx, finalPath, verified.Tenants[item.TenantID].Report, item.Payload, item.UID, item.GID); err != nil {
				return Result{}, err
			}
			item.State = "published"
			continue
		}
		if err := copyTenantTree(ctx, options.Stage, tenantParent, *item); err != nil {
			return Result{}, err
		}
		temporaryPath := filepath.Join(r.layout.tenantRoot, item.Temporary)
		if err := winmigration.VerifyActivatedTenant(ctx, temporaryPath, verified.Tenants[item.TenantID].Report, item.Payload, item.UID, item.GID); err != nil {
			return Result{}, err
		}
		item.State = "ready"
		value.Status = "publishing"
		if err := writeJournal(r.layout.journalPath, &value, r.env.EffectiveUID(), r.env.Now()); err != nil {
			return Result{}, err
		}
		if err := r.requireAllServicesStopped(ctx, verified); err != nil {
			return Result{}, err
		}
		if err := publishNoReplace(tenantParent, item.Temporary, item.TenantID); err != nil {
			return Result{}, err
		}
		if err := winmigration.VerifyActivatedTenant(ctx, finalPath, verified.Tenants[item.TenantID].Report, item.Payload, item.UID, item.GID); err != nil {
			return Result{}, err
		}
		item.State = "published"
		if err := writeJournal(r.layout.journalPath, &value, r.env.EffectiveUID(), r.env.Now()); err != nil {
			return Result{}, err
		}
	}
	verifiedAfterCopy, err := r.verifyStage(ctx, options.Stage, options.ExpectedSourceFingerprint, options.ExpectedOutputFingerprint, r.env.EffectiveUID())
	if err != nil || verifiedAfterCopy.PortalSHA256 != verified.PortalSHA256 {
		return Result{}, errors.New("staging tree changed before Portal publication")
	}
	portalFinalExists, err := pathExistsAt(portalParent, filepath.Base(r.layout.portalDatabase))
	if err != nil {
		return Result{}, err
	}
	if portalFinalExists {
		temporaryExists, err := pathExistsAt(portalParent, value.PortalTemporary)
		if err != nil || temporaryExists {
			return Result{}, errors.New("published Portal database and its temporary sibling both exist")
		}
		if err := winmigration.VerifyActivatedPortal(ctx, r.layout.portalDatabase, verified.Report, verified.PortalSHA256, portalAccount.UID, portalAccount.GID); err != nil {
			return Result{}, err
		}
		value.PortalState = "published"
	} else {
		if err := copyPortalDatabase(options.Stage, portalParent, value.PortalTemporary, portalAccount.UID, portalAccount.GID, verified.PortalSHA256); err != nil {
			return Result{}, err
		}
		temporaryPath := filepath.Join(filepath.Dir(r.layout.portalDatabase), value.PortalTemporary)
		if err := winmigration.VerifyActivatedPortal(ctx, temporaryPath, verified.Report, verified.PortalSHA256, portalAccount.UID, portalAccount.GID); err != nil {
			return Result{}, err
		}
		if err := r.requireAllServicesStopped(ctx, verified); err != nil {
			return Result{}, err
		}
		if err := publishNoReplace(portalParent, value.PortalTemporary, filepath.Base(r.layout.portalDatabase)); err != nil {
			return Result{}, err
		}
		if err := winmigration.VerifyActivatedPortal(ctx, r.layout.portalDatabase, verified.Report, verified.PortalSHA256, portalAccount.UID, portalAccount.GID); err != nil {
			return Result{}, err
		}
		value.PortalState = "published"
	}
	if err := r.fullReadback(ctx, portal, tenants, accounts, verified); err != nil {
		return Result{}, err
	}
	if err := r.requireAllServicesStopped(ctx, verified); err != nil {
		return Result{}, errors.New("a WorkAgent unit did not remain stopped through publication")
	}
	value.Status = "complete"
	if err := writeJournal(r.layout.journalPath, &value, r.env.EffectiveUID(), r.env.Now()); err != nil {
		return Result{}, err
	}
	return buildResult(verified, value, resumed, r.layout, true, true), nil
}

func buildTenantConfigs(portal config.Portal, portalUID uint32, verified winmigration.PublicationStage) ([]config.Tenant, error) {
	result := make([]config.Tenant, 0, len(verified.Report.Tenants))
	for _, report := range verified.Report.Tenants {
		tenant, err := tenantprovision.BuildConfig(portal, portalUID, tenantprovision.Identity{
			TenantID: report.TenantID, RuntimeUser: report.RuntimeUser, ProjectID: report.ProjectID, DiskHardLimitBytes: report.DiskHardLimitBytes,
		}, config.DefaultResourceLimits())
		if err != nil || tenant.DataRoot != report.DataRoot {
			return nil, errors.New("migration report tenant does not map to the canonical runtime configuration")
		}
		result = append(result, tenant)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TenantID < result[j].TenantID })
	return result, nil
}

func validateFreeSpace(path string, verified winmigration.PublicationStage) error {
	var total uint64
	for _, tenant := range verified.Tenants {
		if tenant.Payload.Bytes < 0 || uint64(tenant.Payload.Bytes) > tenant.Report.DiskHardLimitBytes {
			return errors.New("staged tenant payload exceeds its 20 GiB hard quota")
		}
		if uint64(tenant.Payload.Bytes) > math.MaxUint64-total {
			return errors.New("staged tenant byte total overflows")
		}
		total += uint64(tenant.Payload.Bytes)
	}
	const publicationReserve = uint64(32 * 1024 * 1024 * 1024)
	if total > math.MaxUint64-publicationReserve {
		return errors.New("staged tenant byte total overflows reserve calculation")
	}
	var stat unixStatfs
	if err := statFS(path, &stat); err != nil {
		return err
	}
	if stat.Bsize <= 0 || stat.Bavail > math.MaxUint64/uint64(stat.Bsize) || stat.Bavail*uint64(stat.Bsize) < total+publicationReserve {
		return errors.New("tenant XFS mount lacks staged bytes plus the publication reserve")
	}
	return nil
}

type unixStatfs = syscall.Statfs_t

func statFS(path string, destination *unixStatfs) error { return syscall.Statfs(path, destination) }

func directoryPathEmpty(path string) (bool, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer file.Close()
	return directoryFDEmpty(int(file.Fd()))
}

// convergeTenantQuota closes both initialization crash windows. A newly
// created/adopted empty directory always receives its quota. On resume, a
// directory whose chown completed before quota assignment may receive the
// quota only while it is still empty; any populated directory with a missing
// or conflicting quota fails closed.
func convergeTenantQuota(created bool, verify func() error, empty func() (bool, error), assign func() error) error {
	if verify == nil || empty == nil || assign == nil {
		return errors.New("tenant quota convergence callbacks are unavailable")
	}
	if created {
		return assign()
	}
	verifyErr := verify()
	if verifyErr == nil {
		return nil
	}
	isEmpty, emptyErr := empty()
	if emptyErr != nil {
		return errors.Join(verifyErr, emptyErr)
	}
	if !isEmpty {
		return verifyErr
	}
	return assign()
}

func (r *runner) validateTenantConfigNamespace(tenants []config.Tenant, portalGID uint32) error {
	info, err := os.Lstat(r.layout.tenantConfigs)
	stat, ok := fileStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o750 || stat.Uid != 0 || stat.Gid != portalGID {
		return errors.New("tenant configuration root is unsafe")
	}
	wanted := make(map[string]bool, len(tenants))
	for _, tenant := range tenants {
		wanted[tenant.TenantID+".json"] = true
	}
	entries, err := os.ReadDir(r.layout.tenantConfigs)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("tenant configuration root contains an identity outside this migration report")
		}
	}
	return r.validateTenantDropInNamespace(wanted)
}

func (r *runner) validateTenantDropInNamespace(wantedConfigs map[string]bool) error {
	info, err := os.Lstat(r.layout.systemdRoot)
	stat, ok := fileStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 {
		return errors.New("systemd configuration root is unsafe")
	}
	entries, err := os.ReadDir(r.layout.systemdRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		const prefix = "workagent-userhost@"
		if !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".d") {
			continue
		}
		const suffix = ".service.d"
		if !strings.HasSuffix(entry.Name(), suffix) {
			return errors.New("systemd root contains an unexpected UserHost instance drop-in")
		}
		identity := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), prefix), suffix)
		if identity == "" {
			return errors.New("systemd root contains a template-wide UserHost drop-in")
		}
		if !wantedConfigs[identity+".json"] || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("systemd root contains a tenant identity outside this migration report")
		}
		directory := filepath.Join(r.layout.systemdRoot, entry.Name())
		directoryInfo, err := os.Lstat(directory)
		directoryStat, typed := fileStat(directoryInfo)
		if err != nil || !typed || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o022 != 0 || directoryStat.Uid != 0 || directoryStat.Gid != 0 {
			return errors.New("tenant systemd drop-in directory is unsafe")
		}
		children, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, child := range children {
			if (child.Name() != "identity.conf" && child.Name() != "resources.conf") || child.IsDir() || child.Type()&os.ModeSymlink != 0 {
				return errors.New("tenant systemd drop-in directory contains an unexpected override")
			}
		}
	}
	return nil
}

func validatePublicationNamespace(portalParent, tenantParent *os.File, portalDatabaseName string, verified winmigration.PublicationStage, value journal, journalExists bool) error {
	allowedTenant := make(map[string]bool, len(verified.Report.Tenants)*2)
	for _, tenant := range verified.Report.Tenants {
		allowedTenant[tenant.TenantID] = journalExists
	}
	if journalExists {
		for _, tenant := range value.Tenants {
			allowedTenant[tenant.Temporary] = true
		}
	}
	entries, err := tenantParent.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !allowedTenant[entry.Name()] {
			return errors.New("tenant production root contains data outside the matching publication journal")
		}
	}
	portalAllowed := map[string]bool{".runtime.lock": true}
	if journalExists {
		portalAllowed[portalDatabaseName] = true
		portalAllowed[value.PortalTemporary] = true
		portalAllowed["audit.jsonl"] = true
	}
	portalEntries, err := portalParent.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range portalEntries {
		if !portalAllowed[entry.Name()] {
			return errors.New("Portal production root contains data outside the matching publication journal")
		}
	}
	return nil
}

func (r *runner) requireAllServicesStopped(ctx context.Context, verified winmigration.PublicationStage) error {
	discovered, err := r.env.ListUserHostUnits(ctx)
	if err != nil {
		return err
	}
	return requireUnitsStopped(ctx, r.env.Systemd(), verified, discovered)
}

func requireUnitsStopped(ctx context.Context, controller systemdctl.Controller, verified winmigration.PublicationStage, discovered []string) error {
	if controller == nil {
		return errors.New("systemd controller is required for publication")
	}
	units := []string{
		"caddy.service", "workagent-portal.service", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", "workagent-chatforward-browser.service",
		"workagent-backup.service", "workagent-backup.timer", "workagent-healthcheck.service", "workagent-healthcheck.timer",
	}
	for _, tenant := range verified.Report.Tenants {
		units = append(units, "workagent-userhost@"+tenant.TenantID+".service", "workagent-userhost@"+tenant.TenantID+".socket")
	}
	units = append(units, discovered...)
	sort.Strings(units)
	previous := ""
	for _, unit := range units {
		if unit == previous {
			continue
		}
		previous = unit
		properties, err := controller.Properties(ctx, unit, "LoadState", "ActiveState", "SubState", "MainPID", "ControlPID")
		if err != nil {
			return fmt.Errorf("inspect required stopped unit: %w", err)
		}
		mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 64)
		controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 64)
		if properties["LoadState"] != "loaded" || properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" || mainErr != nil || controlErr != nil || mainPID != 0 || controlPID != 0 {
			return errors.New("every WorkAgent service, socket, timer, Caddy and CLIProxy unit must be loaded and explicitly inactive/dead with zero PIDs")
		}
	}
	return nil
}

func checkPortalRuntimeLock(path string, expectedUID uint32) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	lock, err := servicelock.AcquireExclusiveExisting(path, expectedUID)
	if err != nil {
		return err
	}
	return lock.Close()
}

func (r *runner) checkExistingAccountsAndConfigs(ctx context.Context, portal config.Portal, tenants []config.Tenant) error {
	for _, tenant := range tenants {
		_, found, err := r.env.InspectTenantAccount(tenant)
		if err != nil {
			return err
		}
		path := filepath.Join(r.layout.tenantConfigs, tenant.TenantID+".json")
		_, configErr := os.Lstat(path)
		if configErr == nil {
			if !found {
				return errors.New("tenant configuration exists without its dedicated runtime account")
			}
			if err := r.env.VerifyTenantConfig(ctx, portal, tenant); err != nil {
				return err
			}
		} else if !errors.Is(configErr, os.ErrNotExist) {
			return configErr
		}
	}
	return nil
}

func (r *runner) checkJournalArtifacts(ctx context.Context, stage string, portalParent, tenantParent *os.File, portalAccount accountIdentity, tenants []config.Tenant, verified winmigration.PublicationStage, value journal) error {
	configs := make(map[string]config.Tenant, len(tenants))
	for _, tenant := range tenants {
		configs[tenant.TenantID] = tenant
	}
	// The journal identities, not filenames or directory ownership alone, bind
	// a resumable artifact to the dedicated locked runtime account.
	for _, item := range value.Tenants {
		publication, ok := verified.Tenants[item.TenantID]
		if !ok {
			return errors.New("publication journal references an unknown tenant")
		}
		tenantConfig, ok := configs[item.TenantID]
		if !ok {
			return errors.New("publication journal references a tenant without canonical configuration")
		}
		account, found, err := r.env.InspectTenantAccount(tenantConfig)
		if err != nil {
			return err
		}
		if item.UID != 0 && (!found || account.UID != item.UID || account.GID != item.GID) {
			return errors.New("publication journal tenant account identity changed")
		}
		finalExists, err := pathExistsAt(tenantParent, item.TenantID)
		if err != nil {
			return err
		}
		temporaryExists, err := pathExistsAt(tenantParent, item.Temporary)
		if err != nil {
			return err
		}
		if finalExists && temporaryExists {
			return errors.New("published tenant and its temporary sibling both exist")
		}
		if (finalExists || temporaryExists) && (item.UID == 0 || item.GID == 0 || !found) {
			return errors.New("journal-bound tenant artifact lacks its dedicated runtime identity")
		}
		artifactPath := ""
		if finalExists {
			artifactPath = filepath.Join(r.layout.tenantRoot, item.TenantID)
		} else if temporaryExists {
			artifactPath = filepath.Join(r.layout.tenantRoot, item.Temporary)
		}
		if artifactPath != "" {
			if _, err := r.env.VerifyQuota(artifactPath, item.ProjectID, item.HardLimitBytes); err != nil {
				return err
			}
		}
		if finalExists {
			if err := winmigration.VerifyActivatedTenant(ctx, artifactPath, publication.Report, item.Payload, item.UID, item.GID); err != nil {
				return err
			}
		} else if temporaryExists && item.State == "ready" {
			if err := winmigration.VerifyActivatedTenant(ctx, artifactPath, publication.Report, item.Payload, item.UID, item.GID); err != nil {
				return err
			}
		} else if temporaryExists {
			directory, err := openRealDirectory(artifactPath, item.UID, item.GID, 0o700)
			if err != nil {
				return errors.New("interrupted tenant temporary root is unsafe")
			}
			if err := directory.Close(); err != nil {
				return err
			}
		} else if item.State != "pending" {
			return errors.New("publication journal tenant artifact is missing")
		}
	}
	portalFinal := filepath.Base(r.layout.portalDatabase)
	finalExists, err := pathExistsAt(portalParent, portalFinal)
	if err != nil {
		return err
	}
	temporaryExists, err := pathExistsAt(portalParent, value.PortalTemporary)
	if err != nil {
		return err
	}
	if finalExists && temporaryExists {
		return errors.New("published Portal database and its temporary sibling both exist")
	}
	if finalExists {
		return winmigration.VerifyActivatedPortal(ctx, r.layout.portalDatabase, verified.Report, verified.PortalSHA256, portalAccount.UID, portalAccount.GID)
	}
	if temporaryExists {
		return verifyPortalPartial(stage, portalParent, value.PortalTemporary, portalAccount.UID, portalAccount.GID, verified.PortalSHA256)
	}
	if value.PortalState != "pending" {
		return errors.New("publication journal Portal artifact is missing")
	}
	return nil
}

func (r *runner) ensureAccountsAndConfigs(ctx context.Context, portal config.Portal, tenants []config.Tenant, value *journal) (map[string]accountIdentity, error) {
	accounts := make(map[string]accountIdentity, len(tenants))
	byID := make(map[string]*journalTenant, len(value.Tenants))
	for index := range value.Tenants {
		byID[value.Tenants[index].TenantID] = &value.Tenants[index]
	}
	for _, tenant := range tenants {
		account, err := r.env.EnsureTenantAccount(ctx, tenant)
		if err != nil {
			return nil, err
		}
		if account.UID == 0 || account.GID == 0 {
			return nil, errors.New("tenant dedicated runtime identity is invalid")
		}
		item := byID[tenant.TenantID]
		if item.UID != 0 && (item.UID != account.UID || item.GID != account.GID) {
			return nil, errors.New("tenant runtime UID/GID changed across publication resume")
		}
		item.UID, item.GID = account.UID, account.GID
		accounts[tenant.TenantID] = account
		if err := writeJournal(r.layout.journalPath, value, r.env.EffectiveUID(), r.env.Now()); err != nil {
			return nil, err
		}
	}
	for _, tenant := range tenants {
		if err := r.env.EnsureTenantConfig(ctx, portal, tenant); err != nil {
			return nil, err
		}
	}
	return accounts, nil
}

func (r *runner) fullReadback(ctx context.Context, portal config.Portal, tenants []config.Tenant, accounts map[string]accountIdentity, verified winmigration.PublicationStage) error {
	portalAccount, err := r.env.PortalAccount(portal)
	if err != nil {
		return err
	}
	if err := winmigration.VerifyActivatedPortal(ctx, r.layout.portalDatabase, verified.Report, verified.PortalSHA256, portalAccount.UID, portalAccount.GID); err != nil {
		return err
	}
	for _, tenant := range tenants {
		account, found, err := r.env.InspectTenantAccount(tenant)
		if err != nil || !found || account != accounts[tenant.TenantID] {
			return errors.New("tenant runtime account failed final readback")
		}
		if err := r.env.VerifyTenantConfig(ctx, portal, tenant); err != nil {
			return err
		}
		if _, err := r.env.VerifyQuota(tenant.DataRoot, tenant.Capacity.ProjectID, tenant.Capacity.DiskHardLimitBytes); err != nil {
			return err
		}
		publication := verified.Tenants[tenant.TenantID]
		if err := winmigration.VerifyActivatedTenant(ctx, tenant.DataRoot, publication.Report, publication.Payload, account.UID, account.GID); err != nil {
			return err
		}
	}
	return nil
}

func buildResult(verified winmigration.PublicationStage, value journal, resumed bool, paths layout, published, quotaReady bool) Result {
	result := Result{
		Ready: true, Published: published || value.Status == "complete", Resumed: resumed, Tenants: len(verified.Report.Tenants),
		SourceFingerprint: verified.Report.SourceFingerprint, OutputFingerprint: verified.Report.OutputFingerprint,
		JournalPath: paths.journalPath, RollbackDestination: filepath.Join(paths.rollbackRoot, verified.Report.SourceFingerprint), QuotaBackupDirectoryReady: quotaReady,
	}
	for _, tenant := range verified.Tenants {
		result.Files += tenant.Payload.Files
		result.Bytes += tenant.Payload.Bytes
	}
	return result
}
