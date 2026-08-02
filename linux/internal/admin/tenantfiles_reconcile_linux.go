package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	tenantDropInPrefix = "workagent-userhost@"
	tenantDropInSuffix = ".service.d"
)

type TenantFileReconcileResult struct {
	PendingJournals int `json:"pending_journals"`
	VerifiedTenants int `json:"verified_tenants"`
	LoadedUnits     int `json:"loaded_units"`
}

type tenantFileJournalCandidate struct {
	TenantID string
	Path     string
}

// ReconcileTenantFiles is the root-only boot boundary. It is the deliberate
// activation-lock exception: cold-start orchestrators may synchronously wait
// for this service while retaining A_EX, so taking A_EX here would deadlock.
// It owns C_EX, then pins the control channel with SH, and authenticates the
// running reconciler against that signed release before it reads the Portal
// catalog. It replays every durable file and activation journal, reloads
// systemd once, and verifies every final tenant config plus every discovered
// loaded instance before releasing either lock.
// External activation writers always take A_EX before C_SH/C_EX and never
// retain C while waiting for this systemd job, preserving the global order.
func ReconcileTenantFiles(ctx context.Context, portalConfigPath string, controller systemdctl.Controller, authenticateRunningControl func() error) (TenantFileReconcileResult, error) {
	return reconcileTenantFilesWithAuthentication(
		ctx,
		portalConfigPath,
		controller,
		func(ctx context.Context) (io.Closer, error) {
			return lifecyclelock.AcquireCatalogExclusiveFixedConsumer(ctx, "/opt/workagent/control")
		},
		authenticateRunningControl,
	)
}

func reconcileTenantFilesWithAuthentication(
	ctx context.Context,
	portalConfigPath string,
	controller systemdctl.Controller,
	acquire tenantFileCatalogAcquire,
	authenticateRunningControl func() error,
) (TenantFileReconcileResult, error) {
	var result TenantFileReconcileResult
	if ctx == nil || acquire == nil || authenticateRunningControl == nil {
		return result, errors.New("authenticated tenant file reconciliation boundary is unavailable")
	}
	err := withTenantFileCatalogTransaction(ctx, acquire, func(transaction *TenantFileCatalogTransaction) error {
		if err := authenticateRunningControl(); err != nil {
			return fmt.Errorf("authenticate running tenant file reconciler under catalog/control locks: %w", err)
		}
		portal, err := config.LoadPortal(portalConfigPath)
		if err != nil {
			return err
		}
		if err := portal.ValidateProductionLayout(portalConfigPath); err != nil {
			return err
		}
		if err := VerifyPortalFiles(portal, portalConfigPath); err != nil {
			return fmt.Errorf("verify Portal files before tenant transaction reconciliation: %w", err)
		}
		result, err = transaction.reconcileTenantFiles(ctx, portal, tenantProductionSystemdRoot, controller, true)
		return err
	})
	return result, err
}

// ReconcilePendingTenantFiles converges any durable global or per-tenant
// intent while the caller retains this transaction's C_EX capability. A clean
// catalog is a no-op: it does not reload systemd or require a non-empty tenant
// set. This lets migration and recovery close an earlier crash before their
// first namespace scan or copy.
func (transaction *TenantFileCatalogTransaction) ReconcilePendingTenantFiles(ctx context.Context, portal config.Portal, controller systemdctl.Controller) (bool, error) {
	if controller == nil {
		value := systemdctl.Default()
		controller = value
	}
	result, err := transaction.reconcileTenantFiles(ctx, portal, tenantProductionSystemdRoot, controller, false)
	return result.PendingJournals != 0, err
}

func (transaction *TenantFileCatalogTransaction) reconcileTenantFiles(ctx context.Context, portal config.Portal, systemdRoot string, controller systemdctl.Controller, alwaysFinalize bool) (TenantFileReconcileResult, error) {
	if err := transaction.requireActive(); err != nil {
		return TenantFileReconcileResult{}, err
	}
	if ctx == nil || controller == nil {
		return TenantFileReconcileResult{}, errors.New("tenant file reconciliation runtime is unavailable")
	}
	pendingCount := 0
	if exists, err := tenantPathExists(tenantFileBatchJournalPath(portal) + ".tmp"); err != nil {
		return TenantFileReconcileResult{}, err
	} else if exists {
		return TenantFileReconcileResult{}, errors.New("tenant batch transaction has an unbound journal temporary")
	}
	batchPending := false
	var batchJournal tenantFileBatchJournal
	if batch, exists, err := loadTenantFileBatchJournal(portal, systemdRoot); err != nil {
		return TenantFileReconcileResult{}, fmt.Errorf("load pending tenant batch transaction: %w", err)
	} else if exists {
		if err := reconcileTenantFileBatch(ctx, portal, systemdRoot, batch); err != nil {
			return TenantFileReconcileResult{}, fmt.Errorf("replay pending tenant batch transaction: %w", err)
		}
		batchPending = true
		batchJournal = batch
		pendingCount++
	}
	candidates, err := discoverTenantFileJournalCandidates(systemdRoot, portal.Paths.TenantConfigs)
	if err != nil {
		return TenantFileReconcileResult{}, err
	}
	for _, candidate := range candidates {
		publication, err := tenantFilePublicationFromJournal(portal, systemdRoot, candidate)
		if err != nil {
			return TenantFileReconcileResult{}, fmt.Errorf("load pending tenant transaction %s: %w", candidate.TenantID, err)
		}
		if err := publishPreparedTenantFiles(ctx, publication); err != nil {
			return TenantFileReconcileResult{}, fmt.Errorf("replay pending tenant transaction %s: %w", candidate.TenantID, err)
		}
	}
	if !alwaysFinalize && !batchPending && len(candidates) == 0 {
		return TenantFileReconcileResult{}, nil
	}
	var expectedBatch *tenantFileBatchJournal
	if batchPending {
		expectedBatch = &batchJournal
	}
	tenants, loaded, err := finalizeTenantFileCatalog(ctx, portal, systemdRoot, controller, expectedBatch)
	if err != nil {
		return TenantFileReconcileResult{}, err
	}
	if alwaysFinalize {
		if err := verifyOfflinePortalIdentityCatalog(ctx, portal, tenants, controller); err != nil {
			return TenantFileReconcileResult{}, fmt.Errorf("verify Portal database against the reconciled tenant catalog: %w", err)
		}
	}
	if batchPending {
		if err := removeTenantFileBatchJournal(portal, systemdRoot, batchJournal); err != nil {
			return TenantFileReconcileResult{}, fmt.Errorf("commit verified tenant batch reconciliation: %w", err)
		}
	}
	return TenantFileReconcileResult{PendingJournals: pendingCount + len(candidates), VerifiedTenants: len(tenants), LoadedUnits: loaded}, nil
}

// verifyOfflinePortalIdentityCatalog is the boot activation boundary. A_EX
// and then C_EX are already held by the caller; it next takes the existing
// Portal runtime lock exclusively, inspects a WAL-aware private copy without
// creating live state, and requires exact bidirectional config/database
// identity equality before replaying any durable activation decision.
func verifyOfflinePortalIdentityCatalog(ctx context.Context, portal config.Portal, tenants []config.Tenant, controller systemdctl.Controller) (resultErr error) {
	if ctx == nil || len(tenants) == 0 || controller == nil {
		return errors.New("offline Portal identity catalog verification input is invalid")
	}
	account, err := user.Lookup(portal.RuntimeUser)
	if err != nil || account.Username != portal.RuntimeUser {
		return errors.New("Portal runtime account is unavailable for offline identity verification")
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return errors.New("Portal runtime identity is invalid for offline identity verification")
	}
	lockPath := filepath.Join(filepath.Dir(portal.DatabasePath()), ".runtime.lock")
	runtimeLock, err := servicelock.AcquireExclusiveExistingIdentity(lockPath, uint32(uid), uint32(gid))
	if err != nil {
		return fmt.Errorf("acquire stopped Portal runtime identity lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, runtimeLock.Close()) }()
	identities, err := store.InspectPortalIdentitiesOffline(ctx, portal.DatabasePath(), uint32(uid), uint32(gid))
	if err != nil {
		return err
	}
	return reconcileOfflineTenantActivationCatalog(ctx, tenants, identities, controller, ReplayTenantActivation)
}

type tenantActivationReplay func(context.Context, []store.PortalUserIdentity, systemdctl.Controller) error

func reconcileOfflineTenantActivationCatalog(ctx context.Context, tenants []config.Tenant, identities []store.PortalUserIdentity, controller systemdctl.Controller, replay tenantActivationReplay) error {
	if ctx == nil || controller == nil || replay == nil {
		return errors.New("offline tenant activation reconciliation is unavailable")
	}
	if err := VerifyTenantIdentityCatalog(tenants, identities); err != nil {
		return err
	}
	if err := replay(ctx, identities, controller); err != nil {
		return fmt.Errorf("replay durable tenant activation transaction: %w", err)
	}
	// Replay is a no-op when no journal exists, so retain the unconditional
	// full-catalog proof that made this service the boot readiness boundary.
	return VerifyTenantActivationCatalog(ctx, identities, controller)
}

// AssertTenantFileCatalogClean rejects every exact reserved transaction name.
// Callers must hold C_SH (or C_EX) for the entire subsequent activation so a
// writer cannot create a new marker between this proof and systemd execution.
func AssertTenantFileCatalogClean(portal config.Portal) error {
	return assertTenantFileCatalogClean(portal, tenantProductionSystemdRoot)
}

// AssertRuntimeTenantFileCatalogClean is the least-privilege startup form for
// a dedicated tenant process. The process has traversal rights, but cannot
// enumerate the Portal-owned config directory, so it proves absence of the
// exact global names and the exact reserved names for its own tenant.
func AssertRuntimeTenantFileCatalogClean(tenant config.Tenant, configPath string) error {
	if !canonicalTenantFileID(tenant.TenantID) || !cleanTenantFilePath(configPath) ||
		filepath.Base(configPath) != tenant.TenantID+".json" {
		return errors.New("runtime tenant catalog path is invalid")
	}
	configRoot := filepath.Dir(configPath)
	dropInRoot := filepath.Join(tenantProductionSystemdRoot, tenantDropInPrefix+tenant.TenantID+tenantDropInSuffix)
	reserved := []string{
		filepath.Join(configRoot, tenantFileBatchJournalName),
		filepath.Join(configRoot, tenantFileBatchJournalName+".tmp"),
		configPath + ".workagent-stage",
		filepath.Join(dropInRoot, ".workagent-tenant-files.transaction.json"),
		filepath.Join(dropInRoot, ".workagent-tenant-files.transaction.json.tmp"),
		filepath.Join(dropInRoot, "identity.conf.workagent-stage"),
		filepath.Join(dropInRoot, "resources.conf.workagent-stage"),
	}
	for _, path := range reserved {
		exists, err := tenantPathExists(path)
		if err != nil {
			return fmt.Errorf("inspect runtime tenant transaction marker %s: %w", filepath.Base(path), err)
		}
		if exists {
			return fmt.Errorf("runtime tenant catalog has pending reserved path %s", filepath.Base(path))
		}
	}
	return nil
}

func assertTenantFileCatalogClean(portal config.Portal, systemdRoot string) error {
	for _, path := range []string{tenantFileBatchJournalPath(portal), tenantFileBatchJournalPath(portal) + ".tmp"} {
		exists, err := tenantPathExists(path)
		if err != nil {
			return fmt.Errorf("inspect tenant catalog transaction marker: %w", err)
		}
		if exists {
			return errors.New("tenant configuration catalog has a pending global transaction")
		}
	}
	candidates, err := discoverTenantFileJournalCandidates(systemdRoot, portal.Paths.TenantConfigs)
	if err != nil {
		return fmt.Errorf("inspect tenant catalog transaction namespace: %w", err)
	}
	if len(candidates) != 0 {
		return errors.New("tenant configuration catalog has a pending per-tenant transaction")
	}
	return nil
}

func finalizeTenantFileCatalog(ctx context.Context, portal config.Portal, systemdRoot string, controller systemdctl.Controller, expectedBatch *tenantFileBatchJournal) ([]config.Tenant, int, error) {
	return finalizeTenantFileCatalogWithHook(ctx, portal, systemdRoot, controller, expectedBatch, nil)
}

func finalizeTenantFileCatalogWithHook(ctx context.Context, portal config.Portal, systemdRoot string, controller systemdctl.Controller, expectedBatch *tenantFileBatchJournal, hook tenantFileFaultHook) ([]config.Tenant, int, error) {
	if !cleanTenantFilePath(systemdRoot) {
		return nil, 0, errors.New("tenant catalog finalization systemd root is invalid")
	}
	tenants, err := loadFinalTenantFileCatalog(portal, expectedBatch)
	if err != nil {
		return nil, 0, err
	}
	if len(tenants) == 0 {
		return nil, 0, errors.New("tenant configuration catalog is empty")
	}
	if err := verifyTenantDropInNamespace(systemdRoot, tenants); err != nil {
		return nil, 0, err
	}
	if err := verifyTenantAlternateSystemdNamespaces(systemdRoot); err != nil {
		return nil, 0, err
	}
	// This is unconditional. It closes both the journal-unlink/reload crash
	// window and the batch files-complete/reload crash window.
	if err := tenantFileHook(hook, "batch-before-daemon-reload"); err != nil {
		return nil, 0, err
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return nil, 0, fmt.Errorf("reload systemd after tenant transaction reconciliation: %w", err)
	}
	if err := tenantFileHook(hook, "batch-daemon-reloaded"); err != nil {
		return nil, 0, err
	}
	for _, tenant := range tenants {
		if err := VerifyTenantService(ctx, portal, tenant, ServiceVerificationOptions{SystemdRoot: systemdRoot, Controller: controller}); err != nil {
			return nil, 0, fmt.Errorf("verify reconciled tenant service %s: %w", tenant.TenantID, err)
		}
		if err := tenantFileHook(hook, "batch-tenant-verified:"+tenant.TenantID); err != nil {
			return nil, 0, err
		}
	}
	if err := tenantFileHook(hook, "batch-before-exact-unit-catalog"); err != nil {
		return nil, 0, err
	}
	loaded, err := verifyLoadedTenantUnitCatalog(ctx, controller, tenants)
	if err != nil {
		return nil, 0, err
	}
	if err := tenantFileHook(hook, "batch-exact-unit-catalog-verified"); err != nil {
		return nil, 0, err
	}
	return tenants, loaded, nil
}

func verifyTenantDropInNamespace(systemdRoot string, tenants []config.Tenant) error {
	if err := validateTenantFileDirectoryAncestry(systemdRoot, systemdRoot); err != nil {
		return fmt.Errorf("validate tenant systemd namespace root: %w", err)
	}
	expected := make(map[string]config.Tenant, len(tenants))
	for _, tenant := range tenants {
		expected[tenantDropInPrefix+tenant.TenantID+tenantDropInSuffix] = tenant
	}
	entries, err := os.ReadDir(systemdRoot)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(expected))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, tenantDropInPrefix) {
			continue
		}
		// The package-owned templates are the only top-level names outside the
		// authenticated per-tenant service drop-in set. In particular, reject
		// exact-instance service/socket fragments and dependency directories:
		// systemd gives them precedence over the template while their loaded
		// unit name still looks like an expected tenant instance.
		if name == tenantDropInPrefix+".service" || name == tenantDropInPrefix+".socket" {
			continue
		}
		tenant, expectedDirectory := expected[name]
		if !expectedDirectory || seen[name] {
			return fmt.Errorf("tenant systemd namespace contains an unauthenticated top-level entry %q", name)
		}
		path := filepath.Join(systemdRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o755 || stat.Uid != 0 || stat.Gid != 0 {
			return fmt.Errorf("tenant systemd drop-in directory is unsafe: %s", name)
		}
		children, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		childSeen := map[string]bool{}
		for _, child := range children {
			childName := child.Name()
			if childName != "identity.conf" && childName != "resources.conf" {
				return fmt.Errorf("tenant systemd drop-in directory %s contains unexpected child %q", name, childName)
			}
			if childSeen[childName] {
				return fmt.Errorf("tenant systemd drop-in directory %s contains an invalid child %q", name, childName)
			}
			intended := ResourceDropInPayload(tenant.Limits)
			if childName == "identity.conf" {
				intended = []byte("[Service]\nUser=" + tenant.RuntimeUser + "\nGroup=" + tenant.RuntimeUser + "\n")
			}
			state, payload, err := inspectTenantFile(filepath.Join(path, childName), tenantFileMaximumSize)
			if err != nil {
				return fmt.Errorf("tenant systemd drop-in child %s/%s is not the exact protected generated file: %w", name, childName, err)
			}
			if state != desiredTenantFileJournalState(intended, 0o644, 0, 0) || !bytes.Equal(payload, intended) {
				return fmt.Errorf("tenant systemd drop-in child %s/%s differs from the frozen generated file", name, childName)
			}
			childSeen[childName] = true
		}
		if len(childSeen) != 2 || !childSeen["identity.conf"] || !childSeen["resources.conf"] {
			return fmt.Errorf("tenant systemd drop-in directory %s does not contain the exact generated pair", name)
		}
		seen[name] = true
	}
	if len(seen) != len(expected) {
		return errors.New("tenant systemd drop-in directory set differs from the authenticated tenant catalog")
	}
	return nil
}

type tenantSystemdSearchRoot struct {
	path           string
	allowTemplates bool
}

// verifyTenantAlternateSystemdNamespaces closes override and dependency edges
// outside /etc/systemd/system. FragmentPath/DropInPaths readback below proves
// the selected source, while this pre-reload scan also rejects .wants,
// .requires and similar top-level instance dependency directories that do not
// appear in either source property.
func verifyTenantAlternateSystemdNamespaces(systemdRoot string) error {
	if systemdRoot != tenantProductionSystemdRoot {
		return nil
	}
	return verifyTenantSystemdOverrideRoots([]tenantSystemdSearchRoot{
		{path: "/etc/systemd/system.control"},
		{path: "/run/systemd/system.control"},
		{path: "/run/systemd/transient"},
		{path: "/run/systemd/generator.early"},
		{path: "/etc/systemd/system.attached"},
		{path: "/run/systemd/system"},
		{path: "/run/systemd/system.attached"},
		{path: "/run/systemd/generator"},
		{path: "/usr/local/lib/systemd/system", allowTemplates: true},
		{path: "/usr/lib/systemd/system", allowTemplates: true},
		{path: "/run/systemd/generator.late"},
	})
}

func verifyTenantSystemdOverrideRoots(roots []tenantSystemdSearchRoot) error {
	for _, root := range roots {
		fd, err := openTenantProtectedRoot(root.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("open alternate systemd unit namespace %s: %w", root.path, err)
		}
		directory := os.NewFile(uintptr(fd), root.path)
		if directory == nil {
			_ = syscall.Close(fd)
			return fmt.Errorf("adopt alternate systemd unit namespace %s", root.path)
		}
		entries, readErr := directory.ReadDir(-1)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			return fmt.Errorf("enumerate alternate systemd unit namespace %s: %w", root.path, errors.Join(readErr, closeErr))
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, tenantDropInPrefix) {
				continue
			}
			if root.allowTemplates && (name == tenantDropInPrefix+".service" || name == tenantDropInPrefix+".socket") {
				continue
			}
			return fmt.Errorf("alternate systemd unit namespace %s contains unauthenticated tenant entry %q", root.path, name)
		}
	}
	return nil
}

func discoverTenantFileJournalCandidates(systemdRoot, tenantConfigRoot string) ([]tenantFileJournalCandidate, error) {
	for _, root := range []string{systemdRoot, tenantConfigRoot} {
		if err := validateTenantFileDirectoryAncestry(root, root); err != nil {
			return nil, fmt.Errorf("validate tenant transaction enumeration root %s: %w", root, err)
		}
	}
	entries, err := os.ReadDir(systemdRoot)
	if err != nil {
		return nil, err
	}
	pending := make(map[string]tenantFileJournalCandidate)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, tenantDropInPrefix) || !strings.HasSuffix(name, tenantDropInSuffix) {
			continue
		}
		tenantID := strings.TrimSuffix(strings.TrimPrefix(name, tenantDropInPrefix), tenantDropInSuffix)
		if !canonicalTenantFileID(tenantID) {
			return nil, fmt.Errorf("tenant systemd drop-in namespace contains invalid instance %q", name)
		}
		directory := filepath.Join(systemdRoot, name)
		info, err := os.Lstat(directory)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("tenant systemd drop-in directory is unsafe: %s", name)
		}
		children, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		reserved := make(map[string]bool)
		for _, child := range children {
			switch child.Name() {
			case ".workagent-tenant-files.transaction.json", ".workagent-tenant-files.transaction.json.tmp", "identity.conf.workagent-stage", "resources.conf.workagent-stage":
				reserved[child.Name()] = true
			}
		}
		journal := reserved[".workagent-tenant-files.transaction.json"]
		if reserved[".workagent-tenant-files.transaction.json.tmp"] {
			return nil, fmt.Errorf("tenant %s has an unbound or conflicting journal temporary", tenantID)
		}
		if !journal && (reserved["identity.conf.workagent-stage"] || reserved["resources.conf.workagent-stage"]) {
			return nil, fmt.Errorf("tenant %s has an unbound reserved systemd stage", tenantID)
		}
		if journal {
			pending[tenantID] = tenantFileJournalCandidate{TenantID: tenantID, Path: filepath.Join(directory, ".workagent-tenant-files.transaction.json")}
		}
	}
	configEntries, err := os.ReadDir(tenantConfigRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range configEntries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json.workagent-stage") {
			continue
		}
		tenantID := strings.TrimSuffix(name, ".json.workagent-stage")
		if !canonicalTenantFileID(tenantID) || pending[tenantID].TenantID == "" {
			return nil, fmt.Errorf("tenant configuration root contains an unbound reserved stage %q", name)
		}
	}
	result := make([]tenantFileJournalCandidate, 0, len(pending))
	for _, candidate := range pending {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TenantID < result[j].TenantID })
	return result, nil
}

func tenantFilePublicationFromJournal(portal config.Portal, systemdRoot string, candidate tenantFileJournalCandidate) (tenantFilePublication, error) {
	state, payload, err := inspectTenantFile(candidate.Path, tenantJournalMaximumSize)
	if err != nil {
		return tenantFilePublication{}, err
	}
	if !state.Exists || state.Mode != 0o600 || state.UID != 0 || state.GID != 0 || state.ACLSHA256 != "" {
		return tenantFilePublication{}, errors.New("pending tenant transaction journal metadata is unsafe")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var journal tenantFileJournal
	if err := decoder.Decode(&journal); err != nil {
		return tenantFilePublication{}, errors.New("pending tenant transaction journal is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return tenantFilePublication{}, errors.New("pending tenant transaction journal contains trailing data")
	}
	if journal.SchemaVersion != tenantFileJournalSchema || journal.TenantID != candidate.TenantID || len(journal.Entries) != 3 || journal.Entries[2].Name != tenantFileConfig {
		return tenantFilePublication{}, errors.New("pending tenant transaction journal identity is invalid")
	}
	tenant, err := decodeTenantFileConfigPayload(journal.Entries[2].Payload)
	if err != nil || tenant.TenantID != candidate.TenantID {
		return tenantFilePublication{}, errors.New("pending tenant transaction config payload is invalid")
	}
	publication, err := prepareTenantFilePublication(portal, tenant, systemdRoot)
	if err != nil {
		return tenantFilePublication{}, err
	}
	if publication.plan.JournalPath != candidate.Path {
		return tenantFilePublication{}, errors.New("pending tenant transaction journal path is not canonical")
	}
	if _, err := loadTenantFileJournal(candidate.Path, publication.plan); err != nil {
		return tenantFilePublication{}, err
	}
	return publication, nil
}

func loadFinalTenantFileCatalog(portal config.Portal, expectedBatch *tenantFileBatchJournal) ([]config.Tenant, error) {
	entries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return nil, err
	}
	tenants := make([]config.Tenant, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	markerSeen := false
	for _, entry := range entries {
		name := entry.Name()
		if name == tenantFileBatchJournalName {
			if expectedBatch == nil || entry.IsDir() {
				return nil, errors.New("tenant configuration directory contains an unauthenticated global transaction marker")
			}
			actual, exists, err := loadTenantFileBatchJournal(portal, expectedBatch.SystemdRoot)
			if err != nil || !exists || !sameTenantFileBatchJournal(actual, *expectedBatch) {
				return nil, errors.New("tenant configuration global transaction marker differs from the authenticated finalization scope")
			}
			markerSeen = true
			continue
		}
		if entry.IsDir() || filepath.Ext(name) != ".json" {
			return nil, fmt.Errorf("tenant configuration directory contains unexpected entry %q", name)
		}
		tenantID := strings.TrimSuffix(name, ".json")
		if !canonicalTenantFileID(tenantID) || seen[tenantID] {
			return nil, errors.New("tenant configuration namespace is invalid")
		}
		path := filepath.Join(portal.Paths.TenantConfigs, name)
		state, payload, err := inspectTenantFile(path, tenantFileMaximumSize)
		if err != nil || !state.Exists {
			return nil, fmt.Errorf("inspect tenant configuration %s: %w", name, err)
		}
		tenant, err := decodeTenantFileConfigPayload(payload)
		if err != nil || tenant.TenantID != tenantID {
			return nil, fmt.Errorf("tenant configuration %s is invalid", name)
		}
		if err := ValidateTenantBinding(portal, tenant); err != nil {
			return nil, fmt.Errorf("tenant configuration %s binding: %w", name, err)
		}
		if err := VerifyTenantConfigPath(portal, tenant, path); err != nil {
			return nil, fmt.Errorf("tenant configuration %s protection: %w", name, err)
		}
		seen[tenantID] = true
		tenants = append(tenants, tenant)
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].TenantID < tenants[j].TenantID })
	if expectedBatch != nil {
		if !markerSeen || len(tenants) != len(expectedBatch.Members) {
			return nil, errors.New("final tenant catalog does not have the exact authenticated batch identity set")
		}
		for index, member := range expectedBatch.Members {
			if tenants[index].TenantID != member.Tenant.TenantID || !sameCanonicalTenantConfig(tenants[index], member.Tenant) {
				return nil, errors.New("final tenant catalog differs from the authenticated batch generation")
			}
		}
	}
	return tenants, nil
}

func sameCanonicalTenantConfig(left, right config.Tenant) bool {
	leftPayload, leftErr := json.Marshal(left)
	rightPayload, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}

// CanonicalTenantConfigEqual compares the durable JSON meaning of two tenant
// values. Empty non-nil containers omitted by JSON are intentionally equal to
// their decoded nil representation.
func CanonicalTenantConfigEqual(left, right config.Tenant) bool {
	return sameCanonicalTenantConfig(left, right)
}

func decodeTenantFileConfigPayload(payload []byte) (config.Tenant, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var tenant config.Tenant
	if err := decoder.Decode(&tenant); err != nil {
		return config.Tenant{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return config.Tenant{}, errors.New("tenant configuration payload contains trailing data")
	}
	if err := tenant.Validate(); err != nil {
		return config.Tenant{}, err
	}
	return tenant, nil
}

func verifyLoadedTenantUnitCatalog(ctx context.Context, controller systemdctl.Controller, tenants []config.Tenant) (int, error) {
	lister, ok := controller.(systemdctl.UnitLister)
	if !ok {
		return 0, errors.New("tenant file reconciliation cannot enumerate loaded tenant units")
	}
	expected := make(map[string]bool, len(tenants)*2)
	for _, tenant := range tenants {
		expected[tenantDropInPrefix+tenant.TenantID+".service"] = true
		expected[tenantDropInPrefix+tenant.TenantID+".socket"] = true
	}
	for unit := range expected {
		properties, err := controller.Properties(ctx, unit, "LoadState")
		if err != nil || properties["LoadState"] != "loaded" {
			return 0, fmt.Errorf("load expected tenant unit %s before exact enumeration: %w", unit, err)
		}
	}
	units, err := lister.ListUnits(ctx, "workagent-userhost@*.service", "workagent-userhost@*.socket")
	if err != nil {
		return 0, fmt.Errorf("enumerate loaded tenant units after reconciliation: %w", err)
	}
	// systemd only keeps instances in memory after their first start job; a
	// freshly provisioned but never-started tenant is absent from this list.
	// The loadability of every expected unit was proved above, so the
	// enumeration only has to reject loaded units without protected
	// configuration.
	seen := make(map[string]bool, len(units))
	for _, unit := range units {
		if seen[unit] {
			return 0, errors.New("loaded tenant unit enumeration contains a duplicate")
		}
		seen[unit] = true
		if _, ok := tenantIDFromLoadedUnit(unit); !ok || !expected[unit] {
			return 0, fmt.Errorf("loaded tenant unit %s has no protected tenant configuration", unit)
		}
	}
	return len(units), nil
}

func tenantIDFromLoadedUnit(unit string) (string, bool) {
	if !strings.HasPrefix(unit, tenantDropInPrefix) {
		return "", false
	}
	value := strings.TrimPrefix(unit, tenantDropInPrefix)
	for _, suffix := range []string{".service", ".socket"} {
		if strings.HasSuffix(value, suffix) {
			tenantID := strings.TrimSuffix(value, suffix)
			return tenantID, canonicalTenantFileID(tenantID)
		}
	}
	return "", false
}

func canonicalTenantFileID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
