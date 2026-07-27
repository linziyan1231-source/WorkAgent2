package backup

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	BlankHostConfirmation        = "INSTALL-RESTORED-WORKAGENT"
	maxRecoveredPolicyStateBytes = 64 * 1024 * 1024
)

type InstallOptions struct {
	Confirmation string
	Controller   systemdctl.Controller
}

type Installed struct {
	TenantCount               int      `json:"tenant_count"`
	EnabledSockets            []string `json:"enabled_sockets"`
	CLIProxyStarted           bool     `json:"cli_proxy_started"`
	NotificationStarted       bool     `json:"notification_started"`
	ChatForwardStarted        bool     `json:"chatforward_started"`
	ChatForwardBrowserStarted bool     `json:"chatforward_browser_started"`
	PortalStarted             bool     `json:"portal_started"`
}

// InstallRestoredTree installs a freshly verified restore staging tree onto a
// blank, package-prepared host. Existing non-matching files are never
// overwritten. Matching partial results are accepted so an interrupted blank-
// host recovery can be resumed safely.
func InstallRestoredTree(ctx context.Context, target string, manifest Manifest, options InstallOptions) (Installed, error) {
	if os.Geteuid() != 0 {
		return Installed{}, errors.New("blank-host recovery must run as root")
	}
	if options.Confirmation != BlankHostConfirmation {
		return Installed{}, fmt.Errorf("blank-host recovery requires --confirm %s", BlankHostConfirmation)
	}
	controller := options.Controller
	if controller == nil {
		value := systemdctl.Default()
		controller = value
	}
	installLock, err := acquireRecoveryInstallLock(recoveryInstallLockPath)
	if err != nil {
		return Installed{}, err
	}
	defer installLock.Close()
	// A SIGKILL after activation begins leaves a durable, unit-restricted
	// journal. Reconcile it before inspecting or mutating a new restore tree so
	// no previous partial activation can overlap this installation.
	if err := rollbackRecoveryActivation(controller, recoveryActivationJournalPath); err != nil {
		return Installed{}, fmt.Errorf("recover interrupted blank-host activation: %w", err)
	}
	if err := VerifyRestoredFiles(target, manifest, true); err != nil {
		return Installed{}, fmt.Errorf("verify authenticated restore contents before installation: %w", err)
	}
	if err := ValidateRestoredTree(target, manifest); err != nil {
		return Installed{}, err
	}
	translate := func(original string) string {
		return filepath.Join(target, strings.TrimPrefix(filepath.Clean(original), string(filepath.Separator)))
	}
	portal, err := config.LoadPortal(translate(manifest.PortalConfig))
	if err != nil {
		return Installed{}, err
	}
	if err := portal.ValidateProductionLayout(manifest.PortalConfig); err != nil {
		return Installed{}, err
	}
	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return Installed{}, errors.New("the WorkAgent package must create the Portal account before recovery")
	}
	portalUID, uidErr := strconv.ParseUint(portalAccount.Uid, 10, 32)
	portalGID, gidErr := strconv.ParseUint(portalAccount.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || portalUID == 0 || portalGID == 0 {
		return Installed{}, errors.New("the package-created Portal account is invalid")
	}
	proxyAccount, err := user.Lookup("cliproxyapi")
	if err != nil || proxyAccount.Username != "cliproxyapi" || proxyAccount.HomeDir != "/var/lib/cliproxyapi" {
		return Installed{}, errors.New("the WorkAgent package must create the canonical CLIProxy account before recovery")
	}
	proxyUID, proxyUIDErr := strconv.ParseUint(proxyAccount.Uid, 10, 32)
	proxyGID, proxyGIDErr := strconv.ParseUint(proxyAccount.Gid, 10, 32)
	if proxyUIDErr != nil || proxyGIDErr != nil || proxyUID == 0 || proxyGID == 0 {
		return Installed{}, errors.New("the package-created CLIProxy account is invalid")
	}
	tenantEntries, err := os.ReadDir(translate(portal.Paths.TenantConfigs))
	if err != nil {
		return Installed{}, err
	}
	var tenants []config.Tenant
	for _, entry := range tenantEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		tenant, err := config.LoadTenant(filepath.Join(translate(portal.Paths.TenantConfigs), entry.Name()))
		if err != nil || entry.Name() != tenant.TenantID+".json" {
			return Installed{}, errors.New("restored tenant configuration set is invalid")
		}
		tenants = append(tenants, tenant)
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].TenantID < tenants[j].TenantID })
	if len(tenants) == 0 {
		return Installed{}, errors.New("restored tree contains no tenant")
	}
	allowedSources := map[string]string{
		"configuration":            "/etc/workagent",
		"portal-state":             portal.Paths.PortalState,
		"cliproxy-policy-state":    portal.CLIProxy.PolicyStateFile,
		"release-pointer-renderer": portal.Renderer.PointerFile,
	}
	for _, tenant := range tenants {
		allowedSources["tenant-"+tenant.TenantID] = tenant.DataRoot
		allowedSources["systemd-identity-"+tenant.TenantID] = filepath.Join("/etc/systemd/system", "workagent-userhost@"+tenant.TenantID+".service.d", "identity.conf")
	}
	for path, name := range canonicalReleasePointerSources(tenants) {
		allowedSources[name] = path
	}
	for _, source := range manifest.Sources {
		if !eligibleForBlankHostInstall(source, allowedSources) {
			return Installed{}, fmt.Errorf("backup source %s is not eligible for automatic blank-host installation", source.Name)
		}
	}
	cutoverBlockedUnits := []string{
		"caddy.service",
		"workagent-backup.service",
		"workagent-backup.timer",
		"workagent-healthcheck.service",
		"workagent-healthcheck.timer",
	}
	units := []string{
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
	}
	units = append(units, cutoverBlockedUnits...)
	disabledUnitFiles := []string{
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
		"caddy.service",
		"workagent-backup.timer",
		"workagent-healthcheck.timer",
	}
	staticUnitFiles := []string{
		"workagent-backup.service",
		"workagent-healthcheck.service",
	}
	for _, tenant := range tenants {
		units = append(units, "workagent-userhost@"+tenant.TenantID+".socket", "workagent-userhost@"+tenant.TenantID+".service")
		disabledUnitFiles = append(disabledUnitFiles, "workagent-userhost@"+tenant.TenantID+".socket")
		staticUnitFiles = append(staticUnitFiles, "workagent-userhost@"+tenant.TenantID+".service")
	}
	if err := requireRecoveryUnitsStopped(ctx, controller, units); err != nil {
		return Installed{}, err
	}
	if err := requireRecoveryUnitFileState(ctx, controller, disabledUnitFiles, "disabled"); err != nil {
		return Installed{}, fmt.Errorf("blank-host recovery requires every future entrypoint to be disabled: %w", err)
	}
	if err := requireRecoveryUnitFileState(ctx, controller, staticUnitFiles, "static"); err != nil {
		return Installed{}, fmt.Errorf("blank-host recovery package unit topology is invalid: %w", err)
	}
	// Properties above forces every expected template instance to be loaded;
	// the list readback can now require exact equality rather than merely
	// rejecting foreign instances.
	if err := requireExactRecoveryTenantUnits(ctx, controller, tenants); err != nil {
		return Installed{}, err
	}
	if err := requireRecoveryUnitRunning(ctx, controller, "mihomo.service"); err != nil {
		return Installed{}, fmt.Errorf("blank-host recovery egress prerequisite: %w", err)
	}
	proxyLock, err := cliproxy.AcquireProductionMigrationLock()
	if err != nil {
		return Installed{}, fmt.Errorf("lock CLIProxy policy state for recovery: %w", err)
	}
	defer func() {
		if proxyLock != nil {
			_ = proxyLock.Close()
		}
	}()
	stagedPortalInfo, err := os.Lstat(translate(portal.Paths.PortalState))
	productionPortalInfo, productionPortalErr := os.Lstat(portal.Paths.PortalState)
	if err != nil || productionPortalErr != nil {
		return Installed{}, errors.New("restored or package-prepared Portal state root is missing")
	}
	stagedPortalStat, stagedPortalOK := stagedPortalInfo.Sys().(*syscall.Stat_t)
	productionPortalStat, productionPortalOK := productionPortalInfo.Sys().(*syscall.Stat_t)
	if !stagedPortalOK || stagedPortalInfo.Mode()&os.ModeSymlink != 0 || !stagedPortalInfo.IsDir() || stagedPortalInfo.Mode().Perm() != 0o700 ||
		!productionPortalOK || productionPortalInfo.Mode()&os.ModeSymlink != 0 || !productionPortalInfo.IsDir() || productionPortalInfo.Mode().Perm() != 0o700 {
		return Installed{}, errors.New("restored or package-prepared Portal state root is unsafe")
	}
	packagePortalIdentity := recoveredIdentity{uid: uint32(portalUID), gid: uint32(portalGID)}
	stagedPortalIdentity := recoveredIdentity{uid: stagedPortalStat.Uid, gid: stagedPortalStat.Gid}
	currentPortalIdentity := recoveredIdentity{uid: productionPortalStat.Uid, gid: productionPortalStat.Gid}
	if stagedPortalIdentity.uid == 0 || stagedPortalIdentity.gid == 0 || currentPortalIdentity.uid == 0 || currentPortalIdentity.gid == 0 {
		return Installed{}, errors.New("restored Portal state ownership evidence is invalid")
	}
	if currentPortalIdentity != packagePortalIdentity && currentPortalIdentity != stagedPortalIdentity {
		return Installed{}, errors.New("partially restored Portal state ownership is not resumable")
	}
	portalLock, err := acquireRecoveredPortalLock(
		filepath.Join(portal.Paths.PortalState, ".runtime.lock"),
		[]recoveredIdentity{packagePortalIdentity, stagedPortalIdentity},
	)
	if err != nil {
		return Installed{}, fmt.Errorf("lock Portal state for recovery: %w", err)
	}
	defer portalLock.Close()
	if err := requireRecoveryUnitsStopped(ctx, controller, units); err != nil {
		return Installed{}, err
	}
	for _, tenant := range tenants {
		if tenant.Capacity.MaxInstances != portal.Runtime.MaxConcurrentInstances {
			return Installed{}, errors.New("restored tenant capacity does not match the Portal policy")
		}
		if err := admin.EnsureCapacitySlots(ctx, tenant.Capacity.SlotDirectory, tenant.Capacity.MaxInstances); err != nil {
			return Installed{}, fmt.Errorf("restore capacity slots: %w", err)
		}
	}
	restoredIdentities := make(map[string]recoveredIdentity, len(tenants))
	for _, tenant := range tenants {
		dataInfo, err := os.Lstat(translate(tenant.DataRoot))
		if err != nil {
			return Installed{}, err
		}
		stat, ok := dataInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid == 0 || stat.Gid == 0 {
			return Installed{}, errors.New("restored tenant ownership evidence is invalid")
		}
		if err := ensureRecoveredRuntimeAccount(ctx, tenant, stat.Uid, stat.Gid); err != nil {
			return Installed{}, fmt.Errorf("restore tenant account %s: %w", tenant.RuntimeUser, err)
		}
		restoredIdentities[tenant.TenantID] = recoveredIdentity{uid: stat.Uid, gid: stat.Gid}
	}
	tenantLocks := make([]io.Closer, 0, len(tenants))
	defer func() {
		for index := len(tenantLocks) - 1; index >= 0; index-- {
			_ = tenantLocks[index].Close()
		}
	}()
	for _, tenant := range tenants {
		identity := restoredIdentities[tenant.TenantID]
		if err := prepareRecoveredTenantRoot(tenant, identity.uid, identity.gid); err != nil {
			return Installed{}, fmt.Errorf("prepare restored tenant root %s: %w", tenant.TenantID, err)
		}
		lock, err := servicelock.AcquireExclusive(filepath.Join(tenant.DataRoot, ".runtime.lock"), identity.uid, identity.gid)
		if err != nil {
			return Installed{}, fmt.Errorf("lock restored tenant root %s: %w", tenant.TenantID, err)
		}
		tenantLocks = append(tenantLocks, lock)
	}
	if err := requireRecoveryUnitsStopped(ctx, controller, units); err != nil {
		return Installed{}, err
	}
	for _, source := range manifest.Sources {
		staged := translate(source.Path)
		if err := copyRecoveredPath(staged, source.Path); err != nil {
			return Installed{}, fmt.Errorf("install restored source %s: %w", source.Name, err)
		}
	}
	stagedPortalConfigInfo, err := os.Lstat(translate(manifest.PortalConfig))
	if err != nil {
		return Installed{}, errors.New("restored Portal configuration ownership evidence is missing")
	}
	stagedPortalConfigStat, ok := stagedPortalConfigInfo.Sys().(*syscall.Stat_t)
	if !ok || stagedPortalConfigInfo.Mode()&os.ModeSymlink != 0 || !stagedPortalConfigInfo.Mode().IsRegular() || stagedPortalConfigStat.Uid != 0 || stagedPortalConfigStat.Gid == 0 {
		return Installed{}, errors.New("restored Portal configuration ownership evidence is invalid")
	}
	configurationGroups := map[uint32]uint32{}
	if err := addRecoveredGroupMapping(configurationGroups, stagedPortalConfigStat.Gid, uint32(portalGID)); err != nil {
		return Installed{}, err
	}
	for path, accountName := range map[string]string{
		"/etc/workagent/chatforward.env":   "workagent-chatforward",
		"/etc/workagent/notification.json": "workagent-notification",
	} {
		stagedInfo, err := os.Lstat(translate(path))
		if err != nil || stagedInfo.Mode()&os.ModeSymlink != 0 || !stagedInfo.Mode().IsRegular() || stagedInfo.Mode().Perm() != 0o640 {
			return Installed{}, fmt.Errorf("restored %s configuration ownership evidence is invalid", accountName)
		}
		stagedStat, ok := stagedInfo.Sys().(*syscall.Stat_t)
		if !ok || stagedStat.Uid != 0 || stagedStat.Gid == 0 {
			return Installed{}, fmt.Errorf("restored %s configuration ownership is invalid", accountName)
		}
		account, err := user.Lookup(accountName)
		if err != nil {
			return Installed{}, fmt.Errorf("the WorkAgent package must create %s before recovery", accountName)
		}
		packageGID, err := strconv.ParseUint(account.Gid, 10, 32)
		if err != nil || packageGID == 0 {
			return Installed{}, fmt.Errorf("the package-created %s group is invalid", accountName)
		}
		if err := addRecoveredGroupMapping(configurationGroups, stagedStat.Gid, uint32(packageGID)); err != nil {
			return Installed{}, err
		}
	}
	if err := normalizeRecoveredPortalConfiguration(filepath.Dir(manifest.PortalConfig), configurationGroups); err != nil {
		return Installed{}, fmt.Errorf("normalize restored Portal configuration tree: %w", err)
	}
	if err := chownRecoveredTree(portal.Paths.PortalState, int(portalUID), int(portalGID)); err != nil {
		return Installed{}, fmt.Errorf("normalize restored Portal state ownership: %w", err)
	}
	for path, accountName := range map[string]string{
		"/etc/workagent/chatforward.env":   "workagent-chatforward",
		"/etc/workagent/notification.json": "workagent-notification",
	} {
		if err := verifyServiceRecoveryFile(path, accountName); err != nil {
			return Installed{}, fmt.Errorf("verify restored %s configuration: %w", accountName, err)
		}
	}
	policyParentInfo, err := os.Lstat(filepath.Dir(portal.CLIProxy.PolicyStateFile))
	if err != nil {
		return Installed{}, errors.New("package-prepared CLIProxy policy directory is missing")
	}
	policyParentStat, policyParentOK := policyParentInfo.Sys().(*syscall.Stat_t)
	if !policyParentOK || policyParentInfo.Mode()&os.ModeSymlink != 0 || !policyParentInfo.IsDir() || policyParentInfo.Mode().Perm() != 0o700 ||
		policyParentStat.Uid != uint32(proxyUID) || policyParentStat.Gid != uint32(proxyGID) {
		return Installed{}, errors.New("package-prepared CLIProxy policy directory is unsafe")
	}
	if err := normalizeRecoveredPolicyState(portal.CLIProxy.PolicyStateFile, uint32(proxyUID), uint32(proxyGID)); err != nil {
		return Installed{}, fmt.Errorf("normalize restored CLIProxy policy state: %w", err)
	}
	if err := cliproxy.VerifyProductionPolicyState(portal.CLIProxy.PolicyStateFile, uint32(proxyUID), uint32(proxyGID)); err != nil {
		return Installed{}, fmt.Errorf("verify restored CLIProxy policy state: %w", err)
	}
	for index, tenant := range tenants {
		installed, err := config.LoadTenant(filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json"))
		if err != nil {
			return Installed{}, err
		}
		installed.PortalUID = uint32(portalUID)
		if err := admin.WriteTenantFiles(ctx, portal, installed); err != nil {
			return Installed{}, fmt.Errorf("rebuild tenant configuration ACL and service metadata: %w", err)
		}
		if installed.Capacity.ProjectID != 0 {
			if _, err := hostcheck.VerifyTenantQuota(installed.DataRoot, installed.Capacity.ProjectID, installed.Capacity.DiskHardLimitBytes); err != nil {
				return Installed{}, fmt.Errorf("verify restored tenant project quota: %w", err)
			}
		}
		tenants[index] = installed
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return Installed{}, err
	}
	installedPortal, err := config.LoadPortal(manifest.PortalConfig)
	if err != nil {
		return Installed{}, err
	}
	if err := admin.VerifyPortalFiles(installedPortal, manifest.PortalConfig); err != nil {
		return Installed{}, fmt.Errorf("verify restored Portal configuration protection: %w", err)
	}
	rendererIndex := filepath.ToSlash(filepath.Join(installedPortal.Renderer.RelativeRoot, "index.html"))
	if _, err := release.ResolveActive(
		installedPortal.Renderer.ReleasesRoot,
		installedPortal.Renderer.PointerFile,
		installedPortal.Renderer.PublicKeyFile,
		release.ResolveOptions{
			Scope: installedPortal.Renderer.Scope, RequiredPaths: []string{rendererIndex}, RequireRootOwner: true,
			RequiredComponents: release.RequiredComponentsForScope(installedPortal.Renderer.Scope),
		},
	); err != nil {
		return Installed{}, fmt.Errorf("verify restored signed Renderer release: %w", err)
	}
	if err := verifyRecoveredPreviousRelease(
		installedPortal.Renderer.ReleasesRoot,
		installedPortal.Renderer.PointerFile,
		installedPortal.Renderer.PublicKeyFile,
		installedPortal.Renderer.Scope,
		[]string{rendererIndex},
	); err != nil {
		return Installed{}, fmt.Errorf("verify restored previous Renderer release: %w", err)
	}
	data, err := store.Open(installedPortal.DatabasePath(), installedPortal.AuditPath())
	if err != nil {
		return Installed{}, err
	}
	users, listErr := data.ListUsers(ctx)
	closeErr := data.Close()
	if listErr != nil || closeErr != nil {
		return Installed{}, errors.Join(listErr, closeErr)
	}
	enabledTenants := make(map[string]bool)
	for _, value := range users {
		enabledTenants[value.TenantID] = value.Enabled
	}
	result := Installed{TenantCount: len(tenants)}
	enabledSocketUnits := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		if _, err := admin.VerifyTenantHost(installedPortal, tenant); err != nil {
			return Installed{}, fmt.Errorf("verify restored tenant %s: %w", tenant.TenantID, err)
		}
		required := []string{tenant.Backend.Executable}
		required = append(required, tenant.Backend.RequiredReleaseFiles...)
		if tenant.Backend.Migration.Enabled {
			required = append(required, tenant.Backend.Migration.Executable)
		}
		if tenant.Backend.AgentCLI.BinDirectory != "" {
			required = append(required, tenant.Backend.AgentCLI.CodexExecutable, tenant.Backend.AgentCLI.KimiExecutable, tenant.Backend.AgentCLI.PythonExecutable)
		}
		if err := verifyRecoveredPreviousRelease(
			tenant.Release.ReleasesRoot, tenant.Release.PointerFile, tenant.Release.PublicKeyFile, tenant.Release.Scope, required,
		); err != nil {
			return Installed{}, fmt.Errorf("verify restored previous tenant release %s: %w", tenant.TenantID, err)
		}
		if err := admin.VerifyTenantService(ctx, installedPortal, tenant, admin.ServiceVerificationOptions{Controller: controller}); err != nil {
			return Installed{}, fmt.Errorf("verify restored tenant service %s: %w", tenant.TenantID, err)
		}
		if enabledTenants[tenant.TenantID] {
			enabledSocketUnits = append(enabledSocketUnits, "workagent-userhost@"+tenant.TenantID+".socket")
		}
	}
	// Everything above is a validation or an inactive-state installation. Only
	// now release the exclusive lock and begin activation. A failed activation
	// is stopped in reverse order and remains safely resumable.
	if err := requireRecoveryUnitsStopped(ctx, controller, units); err != nil {
		return Installed{}, errors.New("a WorkAgent unit did not remain stopped through blank-host recovery")
	}
	if err := requireRecoveryUnitFileState(ctx, controller, disabledUnitFiles, "disabled"); err != nil {
		return Installed{}, fmt.Errorf("a recovery entrypoint became enabled before activation: %w", err)
	}
	if err := requireRecoveryUnitFileState(ctx, controller, staticUnitFiles, "static"); err != nil {
		return Installed{}, fmt.Errorf("the package unit topology changed before activation: %w", err)
	}
	if err := requireExactRecoveryTenantUnits(ctx, controller, tenants); err != nil {
		return Installed{}, fmt.Errorf("the loaded tenant-unit set changed through blank-host recovery: %w", err)
	}
	if err := requireRecoveryUnitRunning(ctx, controller, "mihomo.service"); err != nil {
		return Installed{}, fmt.Errorf("blank-host recovery egress prerequisite changed: %w", err)
	}
	activationUnits := []string{"cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service"}
	activationUnits = append(activationUnits, enabledSocketUnits...)
	activationUnits = append(activationUnits, "workagent-chatforward-browser.service", "workagent-portal.service")
	activationJournal, err := activationJournalForUnits(activationUnits)
	if err != nil {
		return Installed{}, err
	}
	if err := writeRecoveryActivationJournal(recoveryActivationJournalPath, activationJournal); err != nil {
		return Installed{}, fmt.Errorf("record blank-host activation recovery: %w", err)
	}
	failActivation := func(cause error) (Installed, error) {
		rollbackErr := rollbackKnownRecoveryActivation(controller, activationJournal, recoveryActivationJournalPath)
		return Installed{}, errors.Join(cause, rollbackErr)
	}
	for index := len(tenantLocks) - 1; index >= 0; index-- {
		if err := tenantLocks[index].Close(); err != nil {
			return failActivation(errors.New("release tenant recovery lock"))
		}
	}
	tenantLocks = nil
	if err := portalLock.Close(); err != nil {
		return failActivation(errors.New("release Portal recovery lock"))
	}
	if err := proxyLock.Close(); err != nil {
		return failActivation(errors.New("release CLIProxy recovery lock"))
	}
	proxyLock = nil
	for _, unit := range activationUnits {
		if err := controller.Action(ctx, "start", unit); err != nil {
			return failActivation(fmt.Errorf("start restored unit %s: %w", unit, err))
		}
		if !strings.HasSuffix(unit, ".socket") {
			if err := requireRecoveryUnitRunning(ctx, controller, unit); err != nil {
				return failActivation(err)
			}
		}
		if unit == "cliproxyapi.service" {
			result.CLIProxyStarted = true
		} else if unit == "workagent-notification.service" {
			result.NotificationStarted = true
		} else if unit == "workagent-chatforward.service" {
			result.ChatForwardStarted = true
		} else if unit == "workagent-chatforward-browser.service" {
			result.ChatForwardBrowserStarted = true
		} else if unit == "workagent-portal.service" {
			result.PortalStarted = true
		}
	}
	if err := recoverySystemdActionUnits(ctx, controller, "enable", activationUnits); err != nil {
		return failActivation(fmt.Errorf("enable restored services: %w", err))
	}
	if err := requireRecoveryUnitFileState(ctx, controller, activationUnits, "enabled"); err != nil {
		return failActivation(fmt.Errorf("prove restored service enablement: %w", err))
	}
	for _, tenant := range tenants {
		if enabledTenants[tenant.TenantID] {
			if err := admin.VerifyTenantService(ctx, installedPortal, tenant, admin.ServiceVerificationOptions{RequireReadySocket: true, Controller: controller}); err != nil {
				return failActivation(err)
			}
		}
	}
	// Re-prove every commit condition after enable. This closes the window in
	// which a core process can exit, a disabled tenant can be activated, or an
	// external edge/timer can start between its first readiness check and the
	// durable activation-journal commit.
	for _, unit := range activationUnits {
		if strings.HasSuffix(unit, ".socket") {
			continue
		}
		if err := requireRecoveryUnitRunning(ctx, controller, unit); err != nil {
			return failActivation(err)
		}
	}
	commitStoppedUnits := append([]string(nil), cutoverBlockedUnits...)
	for _, tenant := range tenants {
		if !enabledTenants[tenant.TenantID] {
			commitStoppedUnits = append(commitStoppedUnits,
				"workagent-userhost@"+tenant.TenantID+".socket",
				"workagent-userhost@"+tenant.TenantID+".service",
			)
		}
	}
	if err := requireRecoveryUnitsStopped(ctx, controller, commitStoppedUnits); err != nil {
		return failActivation(fmt.Errorf("recovery cutover blocker changed during activation: %w", err))
	}
	activationSet := make(map[string]bool, len(activationUnits))
	for _, unit := range activationUnits {
		activationSet[unit] = true
	}
	commitDisabledUnitFiles := make([]string, 0, len(disabledUnitFiles))
	for _, unit := range disabledUnitFiles {
		if !activationSet[unit] {
			commitDisabledUnitFiles = append(commitDisabledUnitFiles, unit)
		}
	}
	if err := requireRecoveryUnitFileState(ctx, controller, commitDisabledUnitFiles, "disabled"); err != nil {
		return failActivation(fmt.Errorf("recovery cutover blocker enablement changed during activation: %w", err))
	}
	if err := requireRecoveryUnitFileState(ctx, controller, staticUnitFiles, "static"); err != nil {
		return failActivation(fmt.Errorf("the package unit topology changed during activation: %w", err))
	}
	if err := requireExactRecoveryTenantUnits(ctx, controller, tenants); err != nil {
		return failActivation(fmt.Errorf("loaded tenant-unit set changed during activation: %w", err))
	}
	if err := requireRecoveryUnitRunning(ctx, controller, "mihomo.service"); err != nil {
		return failActivation(fmt.Errorf("blank-host recovery egress prerequisite changed before commit: %w", err))
	}
	if err := removeRecoveryActivationJournal(recoveryActivationJournalPath); err != nil {
		return failActivation(fmt.Errorf("commit blank-host activation journal: %w", err))
	}
	result.EnabledSockets = append(result.EnabledSockets, enabledSocketUnits...)
	return result, nil
}

func verifyRecoveredPreviousRelease(releasesRoot, pointerPath, publicKeyPath, scope string, requiredPaths []string) error {
	pointer, err := release.LoadProtectedPointer(pointerPath, true)
	if err != nil || pointer.Scope != scope {
		return errors.New("restored release pointer changed before previous-release verification")
	}
	if pointer.Previous == "" {
		return nil
	}
	root := filepath.Join(releasesRoot, pointer.Previous)
	_, err = release.Verify(root, filepath.Join(root, "manifest.json"), release.VerifyOptions{
		ExpectedReleaseID: pointer.Previous, RequiredPaths: requiredPaths, RequireRootOwner: true, RequireSignature: true,
		SignaturePath: filepath.Join(root, "manifest.sig"), PublicKeyPath: publicKeyPath,
		AllowedScopes: []string{scope}, RequiredComponents: release.RequiredComponentsForScope(scope),
	})
	return err
}

func eligibleForBlankHostInstall(source Source, allowedSources map[string]string) bool {
	expected, allowed := allowedSources[source.Name]
	return allowed && source.Path == expected
}

type recoveredIdentity struct {
	uid uint32
	gid uint32
}

func requireRecoveryUnitsStopped(ctx context.Context, controller systemdctl.Controller, units []string) error {
	if controller == nil || len(units) == 0 {
		return errors.New("blank-host recovery systemd gate is unavailable")
	}
	for _, unit := range units {
		properties, err := controller.Properties(ctx, unit, "LoadState", "ActiveState", "SubState", "MainPID", "ControlPID")
		if err != nil || properties["LoadState"] != "loaded" {
			return fmt.Errorf("package-prepared systemd unit %s is unavailable: %w", unit, err)
		}
		mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 64)
		controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 64)
		if properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" || mainErr != nil || controlErr != nil || mainPID != 0 || controlPID != 0 {
			return fmt.Errorf("blank-host recovery requires %s to be inactive/dead with no process", unit)
		}
	}
	return nil
}

// requireRecoveryUnitFileState makes boot-time behaviour part of the recovery
// transaction. An inactive but enabled socket, timer, or service could start
// after a power loss and bypass the durable activation journal. Exact readback
// is also required after enable/disable so a successful systemctl exit alone is
// never treated as durable state proof.
func requireRecoveryUnitFileState(ctx context.Context, controller systemdctl.Controller, units []string, expected string) error {
	if controller == nil || len(units) == 0 || (expected != "disabled" && expected != "enabled" && expected != "static") {
		return errors.New("blank-host recovery unit-file-state gate is unavailable")
	}
	seen := make(map[string]bool, len(units))
	for _, unit := range units {
		if seen[unit] {
			return errors.New("blank-host recovery unit-file-state gate contains a duplicate unit")
		}
		seen[unit] = true
		properties, err := controller.Properties(ctx, unit, "LoadState", "UnitFileState")
		if err != nil || properties["LoadState"] != "loaded" || properties["UnitFileState"] != expected {
			return fmt.Errorf("package-prepared systemd unit %s must have UnitFileState=%s: %w", unit, expected, err)
		}
	}
	return nil
}

func requireExactRecoveryTenantUnits(ctx context.Context, controller systemdctl.Controller, tenants []config.Tenant) error {
	lister, ok := controller.(systemdctl.UnitLister)
	if !ok || len(tenants) == 0 {
		return errors.New("blank-host recovery cannot enumerate loaded tenant units")
	}
	expected := make(map[string]bool, len(tenants)*2)
	for _, tenant := range tenants {
		expected["workagent-userhost@"+tenant.TenantID+".service"] = true
		expected["workagent-userhost@"+tenant.TenantID+".socket"] = true
	}
	loaded, err := lister.ListUnits(ctx, "workagent-userhost@*.service", "workagent-userhost@*.socket")
	if err != nil {
		return fmt.Errorf("enumerate loaded tenant units before blank-host recovery: %w", err)
	}
	seen := make(map[string]bool, len(loaded))
	for _, unit := range loaded {
		if !expected[unit] || seen[unit] {
			return fmt.Errorf("blank-host recovery found an unexpected or duplicate loaded tenant unit %s", unit)
		}
		seen[unit] = true
	}
	if len(seen) != len(expected) {
		return errors.New("blank-host recovery tenant-unit enumeration omitted an expected service or socket")
	}
	return nil
}

func requireRecoveryUnitRunning(ctx context.Context, controller systemdctl.Controller, unit string) error {
	allowed := map[string]bool{
		"mihomo.service":                        true,
		"cliproxyapi.service":                   true,
		"workagent-notification.service":        true,
		"workagent-chatforward.service":         true,
		"workagent-chatforward-browser.service": true,
		"workagent-portal.service":              true,
	}
	if controller == nil || !allowed[unit] {
		return errors.New("blank-host recovery running-state gate is unavailable")
	}
	properties, err := controller.Properties(ctx, unit, "LoadState", "ActiveState", "SubState", "MainPID", "ControlPID")
	if err != nil {
		return fmt.Errorf("inspect restored unit %s: %w", unit, err)
	}
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 64)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 64)
	if properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" || properties["SubState"] != "running" ||
		mainErr != nil || controlErr != nil || mainPID == 0 || controlPID != 0 {
		return fmt.Errorf("restored unit %s did not become active/running with one main process", unit)
	}
	return nil
}

// prepareRecoveredTenantRoot establishes the project boundary before any
// archived tenant bytes are copied. An interrupted empty root is adoptable;
// once data exists the already-assigned exact project quota is mandatory.
func prepareRecoveredTenantRoot(tenant config.Tenant, uid, gid uint32) error {
	if uid == 0 || gid == 0 || tenant.DataRoot == "" || filepath.Clean(tenant.DataRoot) != tenant.DataRoot {
		return errors.New("restored tenant root identity is invalid")
	}
	parent := filepath.Dir(tenant.DataRoot)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o711 {
		return errors.New("tenant recovery parent is missing or unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return errors.New("tenant recovery parent ownership is invalid")
	}
	info, err := os.Lstat(tenant.DataRoot)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(tenant.DataRoot, 0o700); err != nil {
			return err
		}
		if err := os.Chown(tenant.DataRoot, int(uid), int(gid)); err != nil {
			return err
		}
		if err := os.Chmod(tenant.DataRoot, 0o700); err != nil {
			return err
		}
		if err := syncDirectory(tenant.DataRoot); err != nil {
			return err
		}
		if err := syncDirectory(parent); err != nil {
			return err
		}
		info, err = os.Lstat(tenant.DataRoot)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("tenant recovery root is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("tenant recovery root ownership is unavailable")
	}
	entries, err := os.ReadDir(tenant.DataRoot)
	if err != nil {
		return err
	}
	if stat.Uid == 0 && stat.Gid == 0 && len(entries) == 0 {
		// Recover a kill between mkdir and chown. No root-owned non-empty tree is
		// ever adopted as tenant state.
		if err := os.Chown(tenant.DataRoot, int(uid), int(gid)); err != nil {
			return err
		}
		if err := syncDirectory(tenant.DataRoot); err != nil {
			return errors.New("sync adopted tenant recovery root")
		}
		if err := syncDirectory(parent); err != nil {
			return errors.New("sync adopted tenant recovery parent")
		}
		stat.Uid, stat.Gid = uid, gid
	}
	if stat.Uid != uid || stat.Gid != gid {
		return errors.New("tenant recovery root ownership conflicts with the archive identity")
	}
	if len(entries) == 0 {
		_, err = hostcheck.AssignTenantQuota(tenant.DataRoot, tenant.Capacity.ProjectID, tenant.Capacity.DiskHardLimitBytes)
	} else {
		_, err = hostcheck.VerifyTenantQuota(tenant.DataRoot, tenant.Capacity.ProjectID, tenant.Capacity.DiskHardLimitBytes)
	}
	return err
}

func normalizeRecoveredPortalConfiguration(root string, groupMappings map[uint32]uint32) error {
	if root != "/etc/workagent" || len(groupMappings) == 0 {
		return errors.New("Portal configuration group normalization input is invalid")
	}
	for archivedGID, packageGID := range groupMappings {
		if archivedGID == 0 || packageGID == 0 {
			return errors.New("Portal configuration group normalization identity is invalid")
		}
	}
	type entry struct {
		path string
		info os.FileInfo
	}
	var entries []entry
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("restored Portal configuration contains an unsupported entry")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("restored Portal configuration is not root-owned")
		}
		entries = append(entries, entry{path: path, info: info})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].path) > len(entries[j].path) })
	for _, item := range entries {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if item.info.IsDir() {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(item.path, flags, 0)
		if err != nil {
			return err
		}
		original, ok := item.info.Sys().(*syscall.Stat_t)
		var opened unix.Stat_t
		if !ok || unix.Fstat(fd, &opened) != nil || opened.Dev != uint64(original.Dev) || opened.Ino != original.Ino || opened.Uid != 0 {
			unix.Close(fd)
			return errors.New("restored Portal configuration changed during normalization")
		}
		expectedGID := opened.Gid
		if packageGID, mapped := groupMappings[opened.Gid]; mapped {
			expectedGID = packageGID
			if err := unix.Fchown(fd, 0, int(packageGID)); err != nil {
				unix.Close(fd)
				return err
			}
		}
		if err := unix.Fsync(fd); err != nil {
			unix.Close(fd)
			return err
		}
		var after unix.Stat_t
		if err := unix.Fstat(fd, &after); err != nil || after.Dev != opened.Dev || after.Ino != opened.Ino || after.Uid != 0 || after.Gid != expectedGID {
			unix.Close(fd)
			return errors.New("restored Portal configuration ownership readback failed")
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(root))
}

func addRecoveredGroupMapping(mappings map[uint32]uint32, archivedGID, packageGID uint32) error {
	if mappings == nil || archivedGID == 0 || packageGID == 0 {
		return errors.New("restored configuration group mapping is invalid")
	}
	if existing, found := mappings[archivedGID]; found && existing != packageGID {
		return errors.New("restored configuration groups cannot be mapped unambiguously on this host")
	}
	mappings[archivedGID] = packageGID
	return nil
}

func chownRecoveredTree(root string, uid, gid int) error {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restored ownership root is unsafe")
	}
	type entry struct {
		path string
		info os.FileInfo
	}
	var entries []entry
	if err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("restored Portal state contains an unsupported entry")
		}
		entries = append(entries, entry{path: path, info: info})
		return nil
	}); err != nil {
		return err
	}
	// Normalize children before the root. A kill can then leave either the old
	// or new authenticated root identity, and acquireRecoveredPortalLock accepts
	// the corresponding mixed lock-owner crash window on the next run.
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].path) > len(entries[j].path) })
	for _, item := range entries {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if item.info.IsDir() {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(item.path, flags, 0)
		if err != nil {
			return err
		}
		var opened unix.Stat_t
		original, ok := item.info.Sys().(*syscall.Stat_t)
		if !ok || unix.Fstat(fd, &opened) != nil || opened.Dev != uint64(original.Dev) || opened.Ino != original.Ino {
			unix.Close(fd)
			return errors.New("restored Portal state changed during ownership normalization")
		}
		if err := unix.Fchown(fd, uid, gid); err != nil || unix.Fsync(fd) != nil {
			unix.Close(fd)
			return errors.New("normalize restored Portal state entry")
		}
		var after unix.Stat_t
		if err := unix.Fstat(fd, &after); err != nil || after.Uid != uint32(uid) || after.Gid != uint32(gid) || after.Dev != opened.Dev || after.Ino != opened.Ino {
			unix.Close(fd)
			return errors.New("restored Portal state ownership readback failed")
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(root))
}

// acquireRecoveredPortalLock handles every authenticated crash state created
// while remapping an archived Portal UID/GID to the blank host's package UID.
// The parent and lock may independently carry either identity, but no third
// owner, symlink, unsafe mode, or active shared lock is accepted.
func acquireRecoveredPortalLock(path string, allowed []recoveredIdentity) (io.Closer, error) {
	if !cleanAbsolute(path) || filepath.Base(path) != ".runtime.lock" || len(allowed) == 0 {
		return nil, errors.New("restored Portal lock input is invalid")
	}
	owners := make(map[recoveredIdentity]bool, len(allowed))
	for _, identity := range allowed {
		if identity.uid == 0 || identity.gid == 0 {
			return nil, errors.New("restored Portal lock identity is invalid")
		}
		owners[identity] = true
	}
	parentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, errors.New("open restored Portal lock parent")
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(parent.Mode).Perm() != 0o700 ||
		!owners[recoveredIdentity{uid: parent.Uid, gid: parent.Gid}] {
		return nil, errors.New("restored Portal lock parent is unsafe")
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(parentFD, filepath.Base(path), flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parentFD, filepath.Base(path), flags, 0)
	}
	if err != nil {
		return nil, errors.New("open restored Portal runtime lock")
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(message string) (io.Closer, error) {
		file.Close()
		if created {
			_ = unix.Unlinkat(parentFD, filepath.Base(path), 0)
			_ = unix.Fsync(parentFD)
		}
		return nil, errors.New(message)
	}
	if created {
		if err := unix.Fchown(fd, int(parent.Uid), int(parent.Gid)); err != nil || unix.Fchmod(fd, 0o600) != nil || unix.Fsync(fd) != nil || unix.Fsync(parentFD) != nil {
			return fail("initialize restored Portal runtime lock")
		}
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(fd, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(lockStat.Mode).Perm() != 0o600 ||
		!owners[recoveredIdentity{uid: lockStat.Uid, gid: lockStat.Gid}] {
		return fail("restored Portal runtime lock is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), lockStat); err != nil {
		return fail("restored Portal runtime lock pathname changed")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("Portal is active; quiesce it before recovery")
		}
		return nil, errors.New("acquire restored Portal runtime lock")
	}
	return file, nil
}

func normalizeRecoveredPolicyState(path string, uid, gid uint32) error {
	if path != config.CLIProxyPolicyStateFile || uid == 0 || gid == 0 {
		return errors.New("restored CLIProxy policy-state normalization input is invalid")
	}
	parentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return errors.New("open restored CLIProxy policy-state parent")
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(parent.Mode).Perm() != 0o700 || parent.Uid != uid || parent.Gid != gid {
		return errors.New("restored CLIProxy policy-state parent changed")
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("open restored CLIProxy policy state")
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 || before.Size > maxRecoveredPolicyStateBytes {
		return errors.New("restored CLIProxy policy state is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), before); err != nil {
		return err
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil || unix.Fchmod(fd, 0o600) != nil || unix.Fsync(fd) != nil {
		return errors.New("persist restored CLIProxy policy-state metadata")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Mode&unix.S_IFMT != unix.S_IFREG ||
		after.Uid != uid || after.Gid != gid || os.FileMode(after.Mode).Perm() != 0o600 || after.Size != before.Size {
		return errors.New("restored CLIProxy policy-state metadata readback failed")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), after); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func ensureRecoveredRuntimeAccount(ctx context.Context, tenant config.Tenant, uid, gid uint32) error {
	uidText, gidText := strconv.FormatUint(uint64(uid), 10), strconv.FormatUint(uint64(gid), 10)
	if existing, err := user.LookupId(uidText); err == nil {
		if existing.Username != tenant.RuntimeUser {
			return fmt.Errorf("UID %d is already assigned to %s", uid, existing.Username)
		}
	} else {
		var unknown user.UnknownUserIdError
		if !errors.As(err, &unknown) {
			return fmt.Errorf("look up restored UID %d: %w", uid, err)
		}
	}
	if existing, err := user.LookupGroupId(gidText); err == nil {
		if existing.Name != tenant.RuntimeUser {
			return fmt.Errorf("GID %d is already assigned to %s", gid, existing.Name)
		}
	} else {
		var unknown user.UnknownGroupIdError
		if !errors.As(err, &unknown) {
			return fmt.Errorf("look up restored GID %d: %w", gid, err)
		}
	}
	if existingGroup, err := user.LookupGroup(tenant.RuntimeUser); err == nil {
		if existingGroup.Gid != gidText {
			return errors.New("existing tenant primary group does not match restored identity")
		}
	} else {
		var unknown user.UnknownGroupError
		if !errors.As(err, &unknown) {
			return err
		}
		if err := runRecoveryCommand(ctx, "groupadd", "--system", "--gid", gidText, tenant.RuntimeUser); err != nil {
			return err
		}
	}
	if existing, err := user.Lookup(tenant.RuntimeUser); err == nil {
		if existing.Uid != uidText || existing.Gid != gidText || existing.HomeDir != tenant.DataRoot {
			return errors.New("existing tenant runtime account does not match restored identity")
		}
	} else {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return err
		}
		shell := "/usr/sbin/nologin"
		if _, err := os.Stat(shell); err != nil {
			shell = "/sbin/nologin"
		}
		if err := runRecoveryCommand(ctx, "useradd", "--system", "--uid", uidText, "--gid", gidText, "--no-create-home", "--home-dir", tenant.DataRoot, "--shell", shell, tenant.RuntimeUser); err != nil {
			return err
		}
	}
	shell := "/usr/sbin/nologin"
	if _, err := os.Stat(shell); err != nil {
		shell = "/sbin/nologin"
	}
	if err := runRecoveryCommand(ctx, "usermod", "--home", tenant.DataRoot, "--shell", shell, "--append", "--groups", "workagent-slots", tenant.RuntimeUser); err != nil {
		return err
	}
	if err := runRecoveryCommand(ctx, "passwd", "--lock", tenant.RuntimeUser); err != nil {
		return err
	}
	_, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true})
	return err
}

func runRecoveryCommand(ctx context.Context, name string, arguments ...string) error {
	programs := map[string]string{
		"groupadd": "/usr/sbin/groupadd",
		"useradd":  "/usr/sbin/useradd",
		"usermod":  "/usr/sbin/usermod",
		"passwd":   "/usr/bin/passwd",
	}
	program, allowed := programs[name]
	if !allowed {
		return fmt.Errorf("unsupported recovery account command %s", name)
	}
	commandContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandContext, program, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func copyRecoveredPath(source, destination string) error {
	if !cleanAbsolute(source) || !cleanAbsolute(destination) || destination == string(filepath.Separator) {
		return errors.New("recovery copy path is invalid")
	}
	if err := ensureRecoveryParents(filepath.Dir(destination)); err != nil {
		return err
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	stat, ok := sourceInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("recovery source ownership is unavailable")
	}
	destinationInfo, destinationErr := os.Lstat(destination)
	switch {
	case sourceInfo.IsDir():
		sourceFD, err := unix.Openat2(unix.AT_FDCWD, source, &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		if err != nil {
			return errors.New("open restored source directory")
		}
		sourceDirectory := os.NewFile(uintptr(sourceFD), source)
		defer sourceDirectory.Close()
		var sourceBefore unix.Stat_t
		if err := unix.Fstat(sourceFD, &sourceBefore); err != nil || !sameRecoverySourceStat(sourceBefore, stat) || sourceBefore.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("restored source directory changed while it was opened")
		}
		if errors.Is(destinationErr, os.ErrNotExist) {
			if err := os.Mkdir(destination, 0o700); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(destination)); err != nil {
				return err
			}
		} else if destinationErr != nil || destinationInfo.Mode()&os.ModeSymlink != 0 || !destinationInfo.IsDir() {
			return errors.New("recovery destination directory conflicts with existing state")
		}
		destinationParentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(destination), &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		if err != nil {
			return errors.New("open recovery destination directory parent")
		}
		defer unix.Close(destinationParentFD)
		destinationFD, err := unix.Openat(destinationParentFD, filepath.Base(destination), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("open recovery destination directory")
		}
		destinationDirectory := os.NewFile(uintptr(destinationFD), destination)
		defer destinationDirectory.Close()
		var destinationBefore unix.Stat_t
		if err := unix.Fstat(destinationFD, &destinationBefore); err != nil || destinationBefore.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("recovery destination directory is unsafe")
		}
		if err := verifyRecoveryNamedInode(destinationParentFD, filepath.Base(destination), destinationBefore, unix.S_IFDIR); err != nil {
			return err
		}
		sourceEntries, err := sourceDirectory.ReadDir(-1)
		if err != nil {
			return err
		}
		destinationEntries, err := destinationDirectory.ReadDir(-1)
		if err != nil {
			return err
		}
		sort.Slice(sourceEntries, func(i, j int) bool { return sourceEntries[i].Name() < sourceEntries[j].Name() })
		expected := make(map[string]bool, len(sourceEntries))
		for _, entry := range sourceEntries {
			expected[entry.Name()] = true
		}
		for _, entry := range destinationEntries {
			if !expected[entry.Name()] {
				return fmt.Errorf("recovery destination contains unexpected entry %s", filepath.Join(destination, entry.Name()))
			}
		}
		for _, entry := range sourceEntries {
			if err := copyRecoveredPath(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		if err := verifyRecoveryDirectoryAfter(sourceDirectory, sourceBefore, sourceEntries); err != nil {
			return err
		}
		if _, err := destinationDirectory.Seek(0, io.SeekStart); err != nil {
			return err
		}
		destinationAfterEntries, err := destinationDirectory.ReadDir(-1)
		if err != nil || !sameRecoveryEntryNames(sourceEntries, destinationAfterEntries) {
			return errors.New("recovery destination directory changed while it was populated")
		}
		if err := unix.Fchown(destinationFD, int(stat.Uid), int(stat.Gid)); err != nil ||
			unix.Fchmod(destinationFD, uint32(sourceInfo.Mode().Perm())) != nil || unix.Fsync(destinationFD) != nil {
			return errors.New("normalize recovery destination directory")
		}
		var destinationAfter unix.Stat_t
		if err := unix.Fstat(destinationFD, &destinationAfter); err != nil || destinationAfter.Dev != destinationBefore.Dev || destinationAfter.Ino != destinationBefore.Ino ||
			destinationAfter.Mode&unix.S_IFMT != unix.S_IFDIR || destinationAfter.Uid != stat.Uid || destinationAfter.Gid != stat.Gid ||
			os.FileMode(destinationAfter.Mode).Perm() != sourceInfo.Mode().Perm() {
			return errors.New("recovery destination directory metadata readback failed")
		}
		if err := verifyRecoveryNamedInode(destinationParentFD, filepath.Base(destination), destinationAfter, unix.S_IFDIR); err != nil {
			return err
		}
		if err := unix.Fsync(destinationParentFD); err != nil {
			return err
		}
		return nil
	case sourceInfo.Mode().IsRegular():
		if destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
			return destinationErr
		}
		return copyRecoveredRegularFile(source, destination, stat, sourceInfo.Mode().Perm(), destinationErr == nil)
	case sourceInfo.Mode()&os.ModeSymlink != 0:
		sourceParentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(source), &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		if err != nil {
			return errors.New("open restored symlink source parent")
		}
		defer unix.Close(sourceParentFD)
		var sourceBefore unix.Stat_t
		if err := unix.Fstatat(sourceParentFD, filepath.Base(source), &sourceBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			sourceBefore.Mode&unix.S_IFMT != unix.S_IFLNK || !sameRecoverySourceStat(sourceBefore, stat) {
			return errors.New("restored source symlink changed while it was opened")
		}
		target, err := readlinkatBounded(sourceParentFD, filepath.Base(source))
		if err != nil {
			return err
		}
		destinationParentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(destination), &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		if err != nil {
			return errors.New("open recovery symlink destination parent")
		}
		defer unix.Close(destinationParentFD)
		if destinationErr == nil {
			existing, err := readlinkatBounded(destinationParentFD, filepath.Base(destination))
			if err != nil || existing != target {
				return errors.New("recovery destination symlink conflicts with existing state")
			}
		} else if errors.Is(destinationErr, os.ErrNotExist) {
			if err := unix.Symlinkat(target, destinationParentFD, filepath.Base(destination)); err != nil {
				if errors.Is(err, unix.EEXIST) {
					return errors.New("recovery destination symlink appeared concurrently")
				}
				return err
			}
		} else {
			return destinationErr
		}
		if err := unix.Fchownat(destinationParentFD, filepath.Base(destination), int(stat.Uid), int(stat.Gid), unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		var sourceAfter, destinationAfter unix.Stat_t
		if err := unix.Fstatat(sourceParentFD, filepath.Base(source), &sourceAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameUnixStat(sourceBefore, sourceAfter) {
			return errors.New("restored source symlink changed while it was copied")
		}
		if err := unix.Fstatat(destinationParentFD, filepath.Base(destination), &destinationAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			destinationAfter.Mode&unix.S_IFMT != unix.S_IFLNK || destinationAfter.Uid != stat.Uid || destinationAfter.Gid != stat.Gid {
			return errors.New("recovery destination symlink metadata readback failed")
		}
		readback, err := readlinkatBounded(destinationParentFD, filepath.Base(destination))
		if err != nil || readback != target {
			return errors.New("recovery destination symlink readback failed")
		}
		return unix.Fsync(destinationParentFD)
	default:
		return errors.New("recovery source contains an unsupported file type")
	}
}

func ensureRecoveryParents(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(current)); err != nil {
				return err
			}
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("recovery destination parent is unsafe: %s", current)
		}
	}
	return nil
}

func sameRecoverySourceStat(opened unix.Stat_t, expected *syscall.Stat_t) bool {
	return expected != nil && opened.Dev == uint64(expected.Dev) && opened.Ino == expected.Ino && opened.Size == expected.Size &&
		opened.Mode == expected.Mode && opened.Uid == expected.Uid && opened.Gid == expected.Gid &&
		opened.Mtim.Sec == expected.Mtim.Sec && opened.Mtim.Nsec == expected.Mtim.Nsec &&
		opened.Ctim.Sec == expected.Ctim.Sec && opened.Ctim.Nsec == expected.Ctim.Nsec
}

func sameUnixStat(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino && first.Size == second.Size && first.Mode == second.Mode &&
		first.Uid == second.Uid && first.Gid == second.Gid && first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

func verifyRecoveryNamedInode(parentFD int, base string, expected unix.Stat_t, fileType uint32) error {
	var named unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Mode&unix.S_IFMT != fileType ||
		named.Dev != expected.Dev || named.Ino != expected.Ino {
		return errors.New("recovery destination pathname changed concurrently")
	}
	return nil
}

func verifyRecoveryDirectoryAfter(directory *os.File, before unix.Stat_t, expected []os.DirEntry) error {
	if directory == nil {
		return errors.New("restored source directory descriptor is invalid")
	}
	fd := int(directory.Fd())
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameUnixStat(before, after) {
		return errors.New("restored source directory changed while it was copied")
	}
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return err
	}
	readback, err := directory.ReadDir(-1)
	if err != nil || !sameRecoveryEntryNames(expected, readback) {
		return errors.New("restored source directory entries changed while they were copied")
	}
	if err := unix.Fstat(fd, &after); err != nil || !sameUnixStat(before, after) {
		return errors.New("restored source directory changed during readback")
	}
	return nil
}

func sameRecoveryEntryNames(first, second []os.DirEntry) bool {
	if len(first) != len(second) {
		return false
	}
	firstNames := make([]string, len(first))
	secondNames := make([]string, len(second))
	for index := range first {
		firstNames[index] = first[index].Name()
	}
	for index := range second {
		secondNames[index] = second[index].Name()
	}
	sort.Strings(firstNames)
	sort.Strings(secondNames)
	return strings.Join(firstNames, "\x00") == strings.Join(secondNames, "\x00")
}

func readlinkatBounded(parentFD int, base string) (string, error) {
	buffer := make([]byte, 4097)
	count, err := unix.Readlinkat(parentFD, base, buffer)
	if err != nil || count <= 0 || count > 4096 {
		return "", errors.New("recovery symbolic-link target is invalid")
	}
	return string(buffer[:count]), nil
}

// copyRecoveredRegularFile never exposes a partially copied final pathname.
// A new file is assembled and synced as an unnamed inode on the destination
// filesystem, then linked exactly once. Existing files are accepted only
// after descriptor-relative, no-follow content and metadata verification.
func copyRecoveredRegularFile(source, destination string, expected *syscall.Stat_t, mode os.FileMode, destinationExists bool) error {
	if expected == nil || filepath.Base(destination) == "." || filepath.Base(destination) == string(filepath.Separator) {
		return errors.New("recovery regular-file metadata is invalid")
	}
	sourceFD, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	input := os.NewFile(uintptr(sourceFD), "recovery-source")
	defer input.Close()
	var before unix.Stat_t
	if err := unix.Fstat(sourceFD, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Dev != uint64(expected.Dev) || before.Ino != expected.Ino || before.Size != expected.Size ||
		before.Uid != expected.Uid || before.Gid != expected.Gid || before.Mode != expected.Mode ||
		before.Mtim.Sec != expected.Mtim.Sec || before.Mtim.Nsec != expected.Mtim.Nsec ||
		before.Ctim.Sec != expected.Ctim.Sec || before.Ctim.Nsec != expected.Ctim.Nsec ||
		os.FileMode(before.Mode).Perm() != mode.Perm() {
		return errors.New("recovery source changed while it was opened")
	}
	parentPath := filepath.Dir(destination)
	parentFD, err := unix.Openat2(unix.AT_FDCWD, parentPath, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return errors.New("open recovery destination parent")
	}
	defer unix.Close(parentFD)
	base := filepath.Base(destination)
	if destinationExists {
		destinationFD, err := unix.Openat(parentFD, base, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("open existing recovery destination")
		}
		output := os.NewFile(uintptr(destinationFD), "existing-recovery-destination")
		defer output.Close()
		var destinationBefore unix.Stat_t
		if err := unix.Fstat(destinationFD, &destinationBefore); err != nil || destinationBefore.Mode&unix.S_IFMT != unix.S_IFREG || destinationBefore.Size != before.Size {
			return errors.New("recovery destination file conflicts with existing state")
		}
		if err := verifyRecoveryDestinationName(parentFD, base, destinationBefore); err != nil {
			return err
		}
		matching, err := sameOpenFileContent(input, output)
		if err != nil || !matching {
			return errors.New("recovery destination file conflicts with existing state")
		}
		if err := verifyOpenRecoveryFileUnchanged(destinationFD, destinationBefore); err != nil {
			return err
		}
		if err := verifyRecoverySourceAfter(sourceFD, before); err != nil {
			return err
		}
		if err := unix.Fchown(destinationFD, int(expected.Uid), int(expected.Gid)); err != nil || unix.Fchmod(destinationFD, uint32(mode.Perm())) != nil || unix.Fsync(destinationFD) != nil {
			return errors.New("normalize existing recovery destination")
		}
		var destinationAfter unix.Stat_t
		if err := unix.Fstat(destinationFD, &destinationAfter); err != nil || destinationAfter.Mode&unix.S_IFMT != unix.S_IFREG || destinationAfter.Size != before.Size ||
			destinationAfter.Uid != expected.Uid || destinationAfter.Gid != expected.Gid || os.FileMode(destinationAfter.Mode).Perm() != mode.Perm() {
			return errors.New("existing recovery destination metadata readback failed")
		}
		if err := verifyRecoveryDestinationName(parentFD, base, destinationAfter); err != nil {
			return err
		}
		return unix.Fsync(parentFD)
	}
	temporaryFD, err := unix.Openat(parentFD, ".", unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("destination filesystem does not support crash-safe unnamed recovery files: %w", err)
	}
	output := os.NewFile(uintptr(temporaryFD), "unnamed-recovery-destination")
	defer output.Close()
	if err := unix.Fchown(temporaryFD, int(expected.Uid), int(expected.Gid)); err != nil || unix.Fchmod(temporaryFD, uint32(mode.Perm())) != nil {
		return errors.New("initialize unnamed recovery file")
	}
	written, copyErr := io.CopyN(output, input, before.Size)
	if copyErr != nil || written != before.Size {
		return errors.New("copy restored regular file")
	}
	if err := verifyRecoverySourceAfter(sourceFD, before); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return errors.New("sync unnamed recovery file")
	}
	var destinationAfter unix.Stat_t
	if err := unix.Fstat(temporaryFD, &destinationAfter); err != nil || destinationAfter.Mode&unix.S_IFMT != unix.S_IFREG || destinationAfter.Size != before.Size ||
		destinationAfter.Uid != expected.Uid || destinationAfter.Gid != expected.Gid || os.FileMode(destinationAfter.Mode).Perm() != mode.Perm() {
		return errors.New("unnamed recovery file metadata readback failed")
	}
	linkErr := unix.Linkat(temporaryFD, "", parentFD, base, unix.AT_EMPTY_PATH)
	if errors.Is(linkErr, unix.EPERM) {
		linkErr = unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(temporaryFD), parentFD, base, unix.AT_SYMLINK_FOLLOW)
	}
	if errors.Is(linkErr, unix.EEXIST) {
		return errors.New("recovery destination appeared concurrently")
	}
	if linkErr != nil {
		return fmt.Errorf("publish unnamed recovery file: %w", linkErr)
	}
	if err := verifyRecoveryDestinationName(parentFD, base, destinationAfter); err != nil {
		// Remove only the inode just linked by this invocation. A concurrently
		// replaced name is foreign state and is never unlinked here.
		var named unix.Stat_t
		if statErr := unix.Fstatat(parentFD, base, &named, unix.AT_SYMLINK_NOFOLLOW); statErr == nil && named.Dev == destinationAfter.Dev && named.Ino == destinationAfter.Ino {
			_ = unix.Unlinkat(parentFD, base, 0)
			_ = unix.Fsync(parentFD)
		}
		return err
	}
	return unix.Fsync(parentFD)
}

func verifyRecoveryDestinationName(parentFD int, base string, expected unix.Stat_t) error {
	return verifyRecoveryNamedInode(parentFD, base, expected, unix.S_IFREG)
}

func verifyOpenRecoveryFileUnchanged(fd int, before unix.Stat_t) error {
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
		after.Mtim != before.Mtim || after.Ctim != before.Ctim || after.Mode != before.Mode || after.Uid != before.Uid || after.Gid != before.Gid {
		return errors.New("recovery destination file changed while it was verified")
	}
	return nil
}

func sameOpenFileContent(first, second *os.File) (bool, error) {
	if _, err := first.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if _, err := second.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	firstHash, secondHash := sha256.New(), sha256.New()
	if _, err := io.Copy(firstHash, first); err != nil {
		return false, err
	}
	if _, err := io.Copy(secondHash, second); err != nil {
		return false, err
	}
	return string(firstHash.Sum(nil)) == string(secondHash.Sum(nil)), nil
}

func verifyRecoverySourceAfter(fd int, before unix.Stat_t) error {
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
		after.Mtim != before.Mtim || after.Ctim != before.Ctim || after.Mode != before.Mode || after.Uid != before.Uid || after.Gid != before.Gid {
		return errors.New("recovery source changed while it was copied")
	}
	return nil
}
