//go:build linux

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
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backupquiescence"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/coreactivation"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/edgepublication"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/serviceaction"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	coreActivationConfirmation = "ACTIVATE-WORKAGENT-CORE"
	corePortalConfigPath       = "/etc/workagent/portal.json"
	coreBackupConfigPath       = "/etc/workagent/backup.json"
	coreChatForwardManagerExec = "/usr/libexec/workagent-fixed-root-exec-v1 chatforward /opt/workagent/shared/chatforward/integration/run-server.sh /run/credentials/workagent-chatforward.service/chatforward-key"
)

var (
	corePersistentServiceUnits = []string{
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
	}
	coreTimerUnits = []string{
		"workagent-backup.timer",
		"workagent-healthcheck.timer",
	}
	coreRollbackServiceUnits = []string{
		"workagent-portal.service",
		"workagent-chatforward-browser.service",
		"workagent-chatforward.service",
		"workagent-notification.service",
		"cliproxyapi.service",
	}
	rollbackCoreCaddy           = serviceaction.RollbackPublishedCaddyFailClosed
	verifyCoreBackupEnvironment = verifyProductionCoreBackupEnvironment
	verifyCorePreflightRollback = verifyProductionCoreRollbackUnitSource
	syncCorePreflightEnablement = syncCorePersistentEnablement
	settleCoreCaddy             = serviceaction.SettleCommittedCaddyEdge
)

type coreSourceVerifier func(string, map[string]string) error
type coreEnablementSync func(bool, string, string) error

func activateCoreFleet(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("activate-core-fleet", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	confirm := flags.String("confirm", "", "exact irreversible production activation confirmation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("activate-core-fleet does not accept positional arguments")
	}
	if *confirm != coreActivationConfirmation {
		return errors.New("core fleet activation requires --confirm " + coreActivationConfirmation)
	}
	if os.Geteuid() != 0 {
		return errors.New("core fleet activation must run as root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	activation, err := lifecyclelock.AcquireActivationExclusiveForCoreReconciliation(ctx)
	if err != nil {
		return fmt.Errorf("acquire core activation lifecycle lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	controller := systemdctl.Default()
	fixed, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		// No recovery or systemd mutation is authorized until the running admin
		// inode has been bound to the current signed control release.
		return fmt.Errorf("authenticate running control before core recovery: %w", err)
	}
	defer func() {
		if fixed != nil {
			resultErr = errors.Join(resultErr, fixed.Close())
		}
	}()

	// Neither recovery protocol may mask the other. In particular, unsafe edge
	// evidence must not prevent a pending core journal from stopping the whole
	// fleet before any Portal or database input is read.
	edgeRecoveryErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return edgepublication.ReconcilePending(cleanupContext, controller, serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
	})
	coreRecoveryErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return reconcilePendingCoreActivation(cleanupContext, controller, verifyProductionCoreRollbackUnitSource)
	})
	if err := errors.Join(edgeRecoveryErr, coreRecoveryErr); err != nil {
		return fmt.Errorf("fail-close pending edge and core activation evidence: %w", err)
	}
	if err := backupquiescence.AssertClean(); err != nil {
		// The backup owner froze an exact active-unit set. Cross-protocol
		// mutation here would invalidate its resume journal and could later
		// resurrect stale intent; only backup resume may settle this state.
		return fmt.Errorf("refuse core activation while backup quiescence recovery is pending: %w", err)
	}
	if err := backup.AssertNoPendingRecoveryActivation(); err != nil {
		return fmt.Errorf("refuse core activation while blank-host recovery is pending: %w", err)
	}
	if err := admin.AssertTenantActivationClean(); err != nil {
		return fmt.Errorf("refuse core activation while tenant activation is pending: %w", err)
	}

	verifySource := func(unit string, properties map[string]string) error {
		return errors.New("core Portal source snapshot has not been loaded")
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return rejectCorePreflightFailClosed(controller, fmt.Errorf("reload systemd manager before core activation: %w", err))
	}
	if err := verifyInstalledCoreFleetHelpers(); err != nil {
		return rejectCorePreflightFailClosed(controller, fmt.Errorf("authenticate immutable core fleet helpers: %w", err))
	}
	if err := verifyCoreBackupEnvironment(); err != nil {
		return rejectCorePreflightFailClosed(controller, fmt.Errorf("verify production off-host backup environment before core activation: %w", err))
	}
	portal, err := loadCoreBootstrapPortal()
	if err != nil {
		return rejectCorePreflightFailClosed(controller, err)
	}
	verifySource = func(unit string, properties map[string]string) error {
		return verifyProductionCoreUnitSource(unit, properties, portal)
	}
	if err := verifyEveryCoreUnitSource(ctx, controller, verifySource); err != nil {
		return rejectCorePreflightFailClosed(controller, fmt.Errorf("authenticate complete manager-loaded core fleet: %w", err))
	}
	if _, _, catalogErr := loadCoreActivationCatalog(ctx); catalogErr == nil {
		if err := verifyConvergedCoreFleet(ctx, controller, portal, verifySource); err == nil {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"activated": true, "transaction": "already-converged", "persistent_units": 8, "running_services": 6, "timers": 2,
			})
		}
	}
	// A new journal may only be published from a fully fail-closed baseline.
	// Otherwise a kill before the nested edge watcher starts could leave an old
	// public Caddy generation or an internal service running indefinitely.
	if err := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return rollbackCoreFleetFailClosed(cleanupContext, controller, verifySource, syncCorePersistentEnablement)
	}); err != nil {
		return fmt.Errorf("establish fail-closed core baseline before transaction begin: %w", err)
	}
	if err := verifyCoreBackupEnvironment(); err != nil {
		return fmt.Errorf("reverify production off-host backup environment before transaction begin: %w", err)
	}
	if err := fixed.Close(); err != nil {
		return fmt.Errorf("release bootstrap control snapshot before tenant reconciliation: %w", err)
	}
	fixed = nil

	transaction, err := coreactivation.Begin()
	if err != nil {
		return fmt.Errorf("persist core activation crash evidence: %w", err)
	}
	defer func() {
		if transaction != nil {
			resultErr = errors.Join(resultErr, transaction.Close())
		}
	}()
	if err := transaction.Verify(); err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, err)
	}
	// The boot reconciler takes C_EX. No catalog/control snapshot may be held
	// while systemd waits for this target.
	if err := startAndProveFreshTenantCatalogReady(ctx, controller, verifySource, transaction.Verify); err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, fmt.Errorf("start tenant catalog readiness latch: %w", err))
	}
	if err := transaction.Verify(); err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, err)
	}
	fixed, err = acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, fmt.Errorf("reacquire authenticated control snapshot after tenant reconciliation: %w", err))
	}
	loadedPortal, identities, err := loadCoreActivationCatalog(ctx)
	if err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, err)
	}
	portal = loadedPortal
	verifySource = func(unit string, properties map[string]string) error {
		return verifyProductionCoreUnitSource(unit, properties, portal)
	}
	if err := verifyInstalledCoreFleetHelpers(); err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, err)
	}
	if err := verifyEveryCoreUnitSource(ctx, controller, verifySource); err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, fmt.Errorf("reauthenticate complete manager-loaded core fleet: %w", err))
	}
	if _, err := startStoredTenantActivationCatalog(ctx, corePortalConfigPath, portal, identities, controller); err != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, nil, portal, verifySource, fmt.Errorf("restore complete enabled tenant socket catalog: %w", err))
	}

	publication, activateErr := convergeCoreFleet(ctx, controller, portal, verifySource, transaction.Verify)
	if activateErr != nil {
		return abortCoreFleetActivation(ctx, controller, transaction, publication.transaction, portal, verifySource, activateErr)
	}
	coreCommitted, commitErr := commitCoreBeforeNestedEdge(transaction.Commit, publication.transaction.Commit)
	if !coreCommitted {
		return abortCoreFleetActivation(ctx, controller, transaction, publication.transaction, portal, verifySource, commitErr)
	}
	transaction = nil
	if commitErr != nil {
		return edgepublication.FailClosedAfterCommitError(controller, publication.transaction, commitErr, serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
	}
	if err := settleCommittedCoreCaddyFailClosed(ctx, controller, publication.generation); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"activated": true, "transaction": "committed", "persistent_units": 8, "running_services": 6, "timers": 2,
	})
}

func commitCoreBeforeNestedEdge(commitCore, commitEdge func() error) (coreCommitted bool, err error) {
	if commitCore == nil || commitEdge == nil {
		return false, errors.New("core/edge commit callbacks are unavailable")
	}
	if err := commitCore(); err != nil {
		return false, fmt.Errorf("commit core activation transaction: %w", err)
	}
	if err := commitEdge(); err != nil {
		return true, fmt.Errorf("commit nested edge publication after core commit: %w", err)
	}
	return true, nil
}

func settleCommittedCoreCaddyFailClosed(ctx context.Context, controller systemdctl.Controller, generation serviceaction.CaddyPublishingGeneration) error {
	if err := settleCoreCaddy(ctx, controller, generation); err != nil {
		rollbackErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
			return rollbackCoreCaddy(cleanupContext, controller)
		})
		return errors.Join(errors.New("core activation committed but its Caddy watcher did not settle; Caddy was failed closed"), err, rollbackErr)
	}
	return nil
}

func loadCoreActivationCatalog(ctx context.Context) (portal config.Portal, identities []store.PortalUserIdentity, resultErr error) {
	if ctx == nil {
		return config.Portal{}, nil, errors.New("core activation catalog verifier is unavailable")
	}
	loaded, err := config.LoadPortal(corePortalConfigPath)
	if err != nil {
		return config.Portal{}, nil, err
	}
	portal = loaded
	if err := portal.ValidateProductionLayout(corePortalConfigPath); err != nil {
		return config.Portal{}, nil, err
	}
	if err := admin.VerifyPortalFiles(portal, corePortalConfigPath); err != nil {
		return config.Portal{}, nil, err
	}
	if err := admin.AssertTenantFileCatalogClean(portal); err != nil {
		return config.Portal{}, nil, fmt.Errorf("refuse core activation with an uncommitted tenant file catalog: %w", err)
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return config.Portal{}, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data); err != nil {
		return config.Portal{}, nil, fmt.Errorf("verify imported Portal identity catalog: %w", err)
	}
	identities, err = portalActivationIdentities(ctx, data)
	if err != nil {
		return config.Portal{}, nil, err
	}
	return portal, identities, nil
}

func loadCoreBootstrapPortal() (config.Portal, error) {
	portal, err := config.LoadPortal(corePortalConfigPath)
	if err != nil {
		return config.Portal{}, err
	}
	if err := portal.ValidateProductionLayout(corePortalConfigPath); err != nil {
		return config.Portal{}, err
	}
	if err := admin.VerifyPortalFiles(portal, corePortalConfigPath); err != nil {
		return config.Portal{}, err
	}
	return portal, nil
}

func verifyProductionCoreBackupEnvironment() error {
	// A completely absent backup configuration means backup is deferred on
	// this host; any present configuration must verify completely.
	if _, err := os.Lstat(coreBackupConfigPath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	configuration, err := backup.LoadConfig(coreBackupConfigPath)
	if err != nil {
		return err
	}
	return backup.VerifyEnvironment(configuration, true)
}

func rejectCorePreflightFailClosed(controller systemdctl.Controller, cause error) error {
	if cause == nil {
		cause = errors.New("core activation preflight failed")
	}
	rollbackErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return rollbackCoreFleetFailClosed(cleanupContext, controller, verifyCorePreflightRollback, syncCorePreflightEnablement)
	})
	if rollbackErr != nil {
		return errors.Join(errors.New("core activation preflight failed and the fail-closed fleet baseline is ambiguous"), cause, rollbackErr)
	}
	return errors.Join(errors.New("core activation preflight failed after the complete core fleet was failed closed"), cause)
}

func startAndProveFreshTenantCatalogReady(ctx context.Context, controller systemdctl.Controller, verifySource coreSourceVerifier, verifyEvidence func() error) error {
	if ctx == nil || controller == nil || verifySource == nil || verifyEvidence == nil {
		return errors.New("tenant catalog reconciliation proof is unavailable")
	}
	const reconcileUnit = "workagent-tenant-config-reconcile.service"
	before, err := authenticateCoreUnitState(ctx, controller, reconcileUnit, verifySource)
	if err != nil {
		return err
	}
	if !serviceaction.UnitStopped(false, before) {
		return errors.New("tenant catalog reconcile service is not at the fail-closed baseline")
	}
	targetBefore, err := authenticateCoreUnitState(ctx, controller, tenantCatalogReadyTarget, verifySource)
	if err != nil || targetBefore["ActiveState"] != "inactive" || targetBefore["SubState"] != "dead" {
		return errors.Join(errors.New("tenant catalog readiness target is not at the fail-closed baseline"), err)
	}
	if err := verifyEvidence(); err != nil {
		return err
	}
	if err := requireTenantCatalogReady(ctx, controller); err != nil {
		return err
	}
	afterTarget, err := authenticateCoreUnitState(ctx, controller, reconcileUnit, verifySource)
	if err != nil {
		return err
	}
	if err := verifyFreshSuccessfulTenantReconcile(before, afterTarget); err != nil {
		return err
	}
	target, err := authenticateCoreUnitState(ctx, controller, tenantCatalogReadyTarget, verifySource)
	if err != nil || target["ActiveState"] != "active" || target["SubState"] != "active" {
		return errors.Join(errors.New("fresh tenant reconciliation did not activate the readiness target"), err)
	}
	return verifyEvidence()
}

func verifyFreshSuccessfulTenantReconcile(before, after map[string]string) error {
	beforeStarted, beforeStartErr := strconv.ParseUint(before["ExecMainStartTimestampMonotonic"], 10, 64)
	started, startErr := strconv.ParseUint(after["ExecMainStartTimestampMonotonic"], 10, 64)
	exited, exitErr := strconv.ParseUint(after["ExecMainExitTimestampMonotonic"], 10, 64)
	if after["LoadState"] != "loaded" || after["UnitFileState"] != "static" || after["ActiveState"] != "inactive" || after["SubState"] != "dead" ||
		after["Result"] != "success" || after["ConditionResult"] != "yes" || after["ExecMainCode"] != "1" || after["ExecMainStatus"] != "0" ||
		after["InvocationID"] == "" || after["InvocationID"] == before["InvocationID"] || beforeStartErr != nil || startErr != nil || exitErr != nil ||
		started == 0 || started <= beforeStarted || exited < started {
		return errors.New("tenant catalog reconcile service did not complete a fresh successful unskipped invocation")
	}
	return nil
}

func verifyCoreTenantCatalogState(ctx context.Context, controller systemdctl.Controller, portal config.Portal, requireReadyTarget bool, verifySource coreSourceVerifier) (resultErr error) {
	if ctx == nil || controller == nil || portal.DatabasePath() == "" || portal.AuditPath() == "" || verifySource == nil {
		return errors.New("core tenant catalog proof is unavailable")
	}
	target, err := authenticateCoreUnitState(ctx, controller, tenantCatalogReadyTarget, verifySource)
	wantActive, wantSubState := "inactive", "dead"
	if requireReadyTarget {
		wantActive, wantSubState = "active", "active"
	}
	if err != nil || target["LoadState"] != "loaded" || target["UnitFileState"] != "static" || target["ActiveState"] != wantActive || target["SubState"] != wantSubState {
		return errors.Join(errors.New("tenant catalog readiness target is not in an exact stable state"), err)
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
	return admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller)
}

type coreCaddyPublication struct {
	generation       serviceaction.CaddyPublishingGeneration
	transaction      *edgepublication.Transaction
	edgeContent      serviceaction.PortalEdgeContentSnapshot
	portalGeneration serviceaction.PortalEdgeGeneration
}

func (publication coreCaddyPublication) Verify() error {
	if publication.transaction == nil || publication.generation.MainPID == "" || publication.generation.InvocationID == "" {
		return errors.New("nested edge publication is unavailable")
	}
	return publication.transaction.Verify()
}

func convergeCoreFleet(ctx context.Context, controller systemdctl.Controller, portal config.Portal, verifySource coreSourceVerifier, verifyTransaction func() error) (publication coreCaddyPublication, resultErr error) {
	if ctx == nil || controller == nil || verifySource == nil || verifyTransaction == nil {
		return coreCaddyPublication{}, errors.New("core fleet activation dependencies are unavailable")
	}
	for _, unit := range corePersistentServiceUnits {
		if err := verifyTransaction(); err != nil {
			return publication, err
		}
		if err := convergeCorePersistentEnablement(ctx, controller, unit, true, verifySource, syncCorePersistentEnablement); err != nil {
			return publication, fmt.Errorf("persistently enable core service: %w", err)
		}
	}
	for _, unit := range corePersistentServiceUnits {
		if err := verifyTransaction(); err != nil {
			return publication, err
		}
		if err := startAndProveCoreService(ctx, controller, unit, verifySource); err != nil {
			return publication, fmt.Errorf("start authenticated core service: %w", err)
		}
	}
	if err := verifyTransaction(); err != nil {
		return publication, err
	}
	var err error
	publication, err = publishCoreCaddyEdge(ctx, controller, portal)
	if err != nil {
		return coreCaddyPublication{}, err
	}
	for _, timer := range coreTimerUnits {
		if err := errors.Join(verifyTransaction(), publication.Verify()); err != nil {
			return publication, err
		}
		if err := enableAndProveCoreTimer(ctx, controller, timer, verifySource, syncCorePersistentEnablement); err != nil {
			return publication, fmt.Errorf("enable authenticated core timer: %w", err)
		}
	}
	if err := errors.Join(verifyTransaction(), publication.Verify()); err != nil {
		return publication, err
	}
	if err := verifyEveryCoreUnitSource(ctx, controller, verifySource); err != nil {
		return publication, err
	}
	if err := verifyCoreFleetDesiredState(ctx, controller, portal, verifySource, true); err != nil {
		return publication, err
	}
	if err := errors.Join(verifyTransaction(), publication.Verify()); err != nil {
		return publication, err
	}
	if err := errors.Join(verifyInstalledCoreFleetHelpers(), serviceaction.VerifyInstalledEdgeAdmissionHelper()); err != nil {
		return publication, fmt.Errorf("immutable core fleet helper set changed during guarded fleet proof: %w", err)
	}
	if err := verifyCoreBackupEnvironment(); err != nil {
		return publication, fmt.Errorf("production off-host backup environment changed during guarded fleet proof: %w", err)
	}
	if err := errors.Join(verifyTransaction(), publication.Verify()); err != nil {
		return publication, err
	}
	finalGeneration, err := serviceaction.VerifyPublishedEdge(ctx, portal, controller, publication.edgeContent, publication.portalGeneration)
	if err != nil || finalGeneration != publication.generation {
		return publication, errors.Join(errors.New("guarded Caddy generation changed during final fleet proof"), err)
	}
	return publication, errors.Join(verifyTransaction(), publication.Verify())
}

func publishCoreCaddyEdge(ctx context.Context, controller systemdctl.Controller, portal config.Portal) (coreCaddyPublication, error) {
	if err := edgepublication.ValidateProductionPortalEdgeBinding(portal); err != nil {
		return coreCaddyPublication{}, err
	}
	edgeContent, err := serviceaction.CapturePortalEdgeContent(portal)
	if err != nil {
		return coreCaddyPublication{}, fmt.Errorf("capture protected Portal content for core edge publication: %w", err)
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return coreCaddyPublication{}, err
	}
	proofErr := errors.Join(
		admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data),
		admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller),
	)
	if err := errors.Join(proofErr, data.Close()); err != nil {
		return coreCaddyPublication{}, fmt.Errorf("refuse core edge publication without a converged tenant catalog: %w", err)
	}
	portalGeneration, err := serviceaction.PreparePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return coreCaddyPublication{}, fmt.Errorf("prepare Portal generation for core edge publication: %w", err)
	}
	portalGeneration, err = serviceaction.VerifyPortalEdgePublicationReadiness(ctx, portal, controller, edgeContent.PolicyID, edgeContent.BrandID, &portalGeneration, false)
	if err != nil {
		return coreCaddyPublication{}, fmt.Errorf("refuse core edge publication before full direct readiness: %w", err)
	}
	if current, err := serviceaction.CapturePortalEdgeContent(portal); err != nil || current != edgeContent {
		return coreCaddyPublication{}, errors.Join(errors.New("protected Portal content changed before core edge publication"), err)
	}
	if err := serviceaction.VerifyInstalledEdgeAdmissionHelper(); err != nil {
		return coreCaddyPublication{}, err
	}
	edgeTransaction, err := edgepublication.Begin()
	if err != nil {
		return coreCaddyPublication{}, fmt.Errorf("persist nested Caddy edge transaction: %w", err)
	}
	if err := serviceaction.ExecuteCaddyEdgeCommit(ctx, controller, serviceaction.VerifyProductionSource, edgeTransaction.Verify); err != nil {
		return coreCaddyPublication{}, edgepublication.Abort(controller, edgeTransaction, errors.Join(errors.New("core Caddy publication action failed"), err), serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
	}
	publishingGeneration, err := serviceaction.VerifyPublishedEdge(ctx, portal, controller, edgeContent, portalGeneration)
	if err != nil {
		return coreCaddyPublication{}, edgepublication.Abort(controller, edgeTransaction, errors.Join(errors.New("core edge publication post-action proof failed"), err), serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
	}
	// Ownership deliberately crosses the function boundary. The edge permit
	// remains locked, and Caddy remains in guarded start-post, until the caller
	// has durably committed the outer core transaction.
	return coreCaddyPublication{
		generation: publishingGeneration, transaction: edgeTransaction,
		edgeContent: edgeContent, portalGeneration: portalGeneration,
	}, nil
}

func abortCoreFleetActivation(ctx context.Context, controller systemdctl.Controller, transaction *coreactivation.Transaction, edgeTransaction *edgepublication.Transaction, portal config.Portal, verifySource coreSourceVerifier, cause error) error {
	if cause == nil {
		cause = errors.New("core activation failed")
	}
	// Close the public edge first while its watcher is still blocked. The
	// explicit fail-close action happens before ownership is released; the
	// watcher then independently rejects the still-present evidence.
	edgeDisableErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return rollbackCoreCaddy(cleanupContext, controller)
	})
	edgeCloseErr := error(nil)
	if edgeTransaction != nil {
		edgeCloseErr = edgeTransaction.Close()
	}
	edgeReconcileErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return edgepublication.ReconcilePending(cleanupContext, controller, serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
	})
	closeErr := error(nil)
	if transaction != nil {
		closeErr = transaction.Close()
	}
	coreRollbackErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return rollbackCoreFleetFailClosed(cleanupContext, controller, verifySource, syncCorePersistentEnablement)
	})
	tenantProofErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
		return verifyCoreTenantCatalogState(cleanupContext, controller, portal, false, verifySource)
	})
	rollbackErr := errors.Join(edgeDisableErr, edgeReconcileErr, coreRollbackErr, tenantProofErr)
	if rollbackErr != nil {
		return errors.Join(errors.New("core activation failed and fail-closed fleet state is ambiguous; durable evidence was retained"), cause, closeErr, edgeCloseErr, rollbackErr)
	}
	settleErr := settleCoreRollbackEvidence()
	if settleErr != nil {
		return errors.Join(errors.New("core activation failed; the fleet was disabled but crash evidence was retained"), cause, closeErr, edgeCloseErr, settleErr)
	}
	return errors.Join(errors.New("core activation failed; the complete core fleet was durably disabled and crash evidence was reconciled"), cause, closeErr, edgeCloseErr)
}

func reconcilePendingCoreActivation(ctx context.Context, controller systemdctl.Controller, verifySource coreSourceVerifier) error {
	pending, loadErr := coreactivation.LoadPending()
	if pending == nil && loadErr == nil {
		return nil
	}
	rollbackErr := rollbackCoreFleetFailClosed(ctx, controller, verifySource, syncCorePersistentEnablement)
	if rollbackErr != nil {
		if pending != nil {
			_ = pending.Close()
		}
		return errors.Join(errors.New("pending core activation could not be rolled back; evidence was retained"), loadErr, rollbackErr)
	}
	if loadErr != nil {
		return errors.Join(errors.New("core fleet was disabled because crash evidence is unsafe; evidence was retained"), loadErr)
	}
	defer pending.Close()
	if err := pending.ReconcileStalePermit(); err != nil {
		return fmt.Errorf("core fleet was disabled but stale permit reconciliation failed: %w", err)
	}
	if err := pending.RemoveJournalAfterRollback(); err != nil {
		return fmt.Errorf("core fleet was disabled but journal settlement failed: %w", err)
	}
	return nil
}

func settleCoreRollbackEvidence() error {
	pending, err := coreactivation.LoadPending()
	if err != nil || pending == nil {
		return err
	}
	defer pending.Close()
	if err := pending.ReconcileStalePermit(); err != nil {
		return err
	}
	return pending.RemoveJournalAfterRollback()
}

func rollbackCoreFleetFailClosed(ctx context.Context, controller systemdctl.Controller, verifySource coreSourceVerifier, syncEnablement coreEnablementSync) error {
	if ctx == nil || controller == nil || verifySource == nil || syncEnablement == nil {
		return errors.New("core fleet rollback dependencies are unavailable")
	}
	var failures []error
	for _, timer := range coreTimerUnits {
		failures = append(failures, convergeCorePersistentEnablement(ctx, controller, timer, false, verifySource, syncEnablement))
		target, _ := serviceaction.TimerTargetService(timer)
		failures = append(failures, controller.Action(ctx, "stop", target))
	}
	failures = append(failures, rollbackCoreCaddy(ctx, controller))
	for _, unit := range coreRollbackServiceUnits {
		failures = append(failures, convergeCorePersistentEnablement(ctx, controller, unit, false, verifySource, syncEnablement))
	}
	for _, unit := range []string{"workagent-healthcheck.service", "workagent-backup.service", "workagent-tenant-config-reconcile.service"} {
		failures = append(failures, controller.Action(ctx, "stop", unit))
	}
	failures = append(failures, controller.Action(ctx, "stop", tenantCatalogReadyTarget))
	for _, unit := range coreactivation.CoreUnits() {
		if unit == "caddy.service" {
			continue
		}
		failures = append(failures, settleCoreUnitFailureState(ctx, controller, unit, verifySource))
	}
	if err := verifyCoreRollbackState(ctx, controller, verifySource); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func settleCoreUnitFailureState(ctx context.Context, controller systemdctl.Controller, unit string, verifySource coreSourceVerifier) error {
	properties, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if err != nil {
		return err
	}
	passive := strings.HasSuffix(unit, ".timer") || strings.HasSuffix(unit, ".target")
	if serviceaction.UnitStopped(passive, properties) {
		return nil
	}
	processFree := (properties["ActiveState"] == "inactive" && properties["SubState"] == "dead") ||
		(properties["ActiveState"] == "failed" && properties["SubState"] == "failed")
	if !passive {
		processFree = processFree && properties["MainPID"] == "0" && properties["ControlPID"] == "0"
	}
	if !processFree {
		return errors.New("core unit is neither cleanly stopped nor terminal and process-free")
	}
	if err := controller.Action(ctx, "reset-failed", unit); err != nil {
		return err
	}
	settled, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if err != nil || !serviceaction.UnitStopped(passive, settled) {
		return errors.Join(errors.New("core unit failure state did not reset to inactive and process-free"), err)
	}
	final, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if err != nil || !reflect.DeepEqual(settled, final) {
		return errors.Join(errors.New("reset core unit state changed during durable authentication"), err)
	}
	return nil
}

func convergeCorePersistentEnablement(ctx context.Context, controller systemdctl.Controller, unit string, enabled bool, verifySource coreSourceVerifier, syncEnablement coreEnablementSync) error {
	properties, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if err != nil {
		// Stopping or disabling is fail-closed even when the loaded source is
		// already unauthenticated. Preserve the authentication error afterward.
		if enabled {
			return err
		}
	}
	action := "enable"
	arguments := []string{action, unit}
	if !enabled {
		action = "disable"
		arguments = []string{action, "--now", unit}
	}
	actionErr := controller.Action(ctx, arguments...)
	after, readErr := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if readErr != nil {
		return errors.Join(err, actionErr, readErr)
	}
	want := "disabled"
	if enabled {
		want = "enabled"
	}
	if after["UnitFileState"] != want {
		return errors.Join(err, actionErr, fmt.Errorf("core persistent state did not read back as %s", want))
	}
	if properties != nil && (properties["FragmentPath"] != after["FragmentPath"] || properties["DropInPaths"] != after["DropInPaths"]) {
		return errors.Join(err, actionErr, errors.New("core unit source changed across persistent enablement mutation"))
	}
	if syncErr := syncEnablement(enabled, unit, after["FragmentPath"]); syncErr != nil {
		return errors.Join(err, actionErr, syncErr)
	}
	final, finalErr := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if finalErr != nil || final["UnitFileState"] != want || final["FragmentPath"] != after["FragmentPath"] || final["DropInPaths"] != after["DropInPaths"] {
		return errors.Join(err, actionErr, finalErr, errors.New("core persistent state changed during durable readback"))
	}
	return errors.Join(err, actionErr)
}

func startAndProveCoreService(ctx context.Context, controller systemdctl.Controller, unit string, verifySource coreSourceVerifier) error {
	before, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if err != nil {
		return err
	}
	if before["UnitFileState"] != "enabled" {
		return errors.New("core service is not persistently enabled before start")
	}
	if serviceaction.ServiceRunning(before) {
		return nil
	}
	if !serviceaction.UnitStopped(false, before) {
		return errors.New("core service is not in a clean startable state")
	}
	if err := controller.Action(ctx, "start", unit); err != nil {
		return err
	}
	after, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
	if err != nil {
		return err
	}
	if after["UnitFileState"] != "enabled" || !serviceaction.ServiceRunning(after) {
		return errors.New("core service did not become active, running, and process-backed")
	}
	return nil
}

func enableAndProveCoreTimer(ctx context.Context, controller systemdctl.Controller, timer string, verifySource coreSourceVerifier, syncEnablement coreEnablementSync) error {
	target, ok := serviceaction.TimerTargetService(timer)
	if !ok {
		return errors.New("core timer target is unavailable")
	}
	if _, err := authenticateCoreUnitState(ctx, controller, target, verifySource); err != nil {
		return err
	}
	if err := convergeCorePersistentEnablement(ctx, controller, timer, true, verifySource, syncEnablement); err != nil {
		return err
	}
	if err := controller.Action(ctx, "start", timer); err != nil {
		return err
	}
	properties, err := authenticateCoreUnitState(ctx, controller, timer, verifySource)
	if err != nil {
		return err
	}
	if properties["UnitFileState"] != "enabled" || properties["ActiveState"] != "active" || properties["SubState"] != "waiting" {
		return errors.New("core timer is not persistently enabled, active, and waiting")
	}
	// Persistent timers may immediately launch their oneshot target. The
	// backup target can be blocked on the A_EX lock held by this transaction;
	// authenticating its source is safe, requiring inactivity would deadlock.
	_, err = authenticateCoreUnitState(ctx, controller, target, verifySource)
	return err
}

func verifyEveryCoreUnitSource(ctx context.Context, controller systemdctl.Controller, verifySource coreSourceVerifier) error {
	for _, unit := range coreactivation.CoreUnits() {
		if _, err := authenticateCoreUnitState(ctx, controller, unit, verifySource); err != nil {
			return fmt.Errorf("authenticate core unit: %w", err)
		}
	}
	return nil
}

func verifyCoreFleetDesiredState(ctx context.Context, controller systemdctl.Controller, portal config.Portal, verifySource coreSourceVerifier, allowCoreGuardedCaddy bool) (resultErr error) {
	for _, unit := range corePersistentServiceUnits {
		properties, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
		if err != nil || properties["UnitFileState"] != "enabled" || !serviceaction.ServiceRunning(properties) {
			return errors.Join(errors.New("core service final state is not enabled and running"), err)
		}
	}
	caddy, err := authenticateCoreUnitState(ctx, controller, "caddy.service", verifySource)
	caddyReady := serviceaction.ServiceRunning(caddy)
	if allowCoreGuardedCaddy {
		mainPID, pidErr := strconv.ParseUint(caddy["MainPID"], 10, 64)
		controlPID, controlErr := strconv.ParseUint(caddy["ControlPID"], 10, 64)
		caddyReady = pidErr == nil && controlErr == nil && mainPID > 0 && controlPID > 0 && mainPID != controlPID &&
			caddy["ActiveState"] == "activating" && caddy["SubState"] == "start-post" && caddy["Result"] == "success"
	}
	if err != nil || caddy["UnitFileState"] != "enabled" || !caddyReady {
		return errors.Join(errors.New("Caddy final state is not enabled and running"), err)
	}
	for _, timer := range coreTimerUnits {
		properties, err := authenticateCoreUnitState(ctx, controller, timer, verifySource)
		if err != nil || properties["UnitFileState"] != "enabled" || properties["ActiveState"] != "active" || properties["SubState"] != "waiting" {
			return errors.Join(errors.New("core timer final state is not enabled, active, and waiting"), err)
		}
	}
	target, err := authenticateCoreUnitState(ctx, controller, "workagent-tenant-catalog-ready.target", verifySource)
	if err != nil || target["ActiveState"] != "active" {
		return errors.Join(errors.New("tenant catalog readiness target is not active"), err)
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
	return admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller)
}

// verifyConvergedCoreFleet is the output-loss retry fast path. It performs no
// systemd mutation: every persistent link, manager source, running process,
// tenant mapping, signed Caddy live configuration, and full local HTTPS
// readiness report must already be exact. Any partial state falls through to
// the journaled convergence transaction.
func verifyConvergedCoreFleet(ctx context.Context, controller systemdctl.Controller, portal config.Portal, verifySource coreSourceVerifier) error {
	if err := verifyCoreFleetDesiredState(ctx, controller, portal, verifySource, false); err != nil {
		return err
	}
	for _, unit := range append(append([]string(nil), corePersistentServiceUnits...), append([]string{"caddy.service"}, coreTimerUnits...)...) {
		properties, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
		if err != nil {
			return err
		}
		if err := verifyCorePersistentEnablementLink(unit, properties["FragmentPath"]); err != nil {
			return err
		}
	}
	content, err := serviceaction.CapturePortalEdgeContent(portal)
	if err != nil {
		return err
	}
	portalGeneration, err := serviceaction.CapturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return err
	}
	caddyBefore, err := authenticateCoreUnitState(ctx, controller, "caddy.service", verifySource)
	if err != nil || !serviceaction.ServiceRunning(caddyBefore) {
		return errors.Join(errors.New("converged Caddy generation is unavailable"), err)
	}
	if err := serviceaction.VerifyCaddyLiveConfig(ctx, caddyBefore["MainPID"]); err != nil {
		return err
	}
	if err := errors.Join(verifyInstalledCoreFleetHelpers(), serviceaction.VerifyInstalledEdgeAdmissionHelper()); err != nil {
		return fmt.Errorf("immutable core fleet helper set changed during converged-fleet proof: %w", err)
	}
	if _, err := serviceaction.VerifyPortalEdgePublicationReadiness(ctx, portal, controller, content.PolicyID, content.BrandID, &portalGeneration, true); err != nil {
		return err
	}
	if err := serviceaction.VerifyCaddyLiveConfig(ctx, caddyBefore["MainPID"]); err != nil {
		return err
	}
	if err := verifyCoreBackupEnvironment(); err != nil {
		return fmt.Errorf("production off-host backup environment changed during converged-fleet proof: %w", err)
	}
	caddyAfter, err := authenticateCoreUnitState(ctx, controller, "caddy.service", verifySource)
	if err != nil || !reflect.DeepEqual(caddyBefore, caddyAfter) {
		return errors.Join(errors.New("Caddy generation changed during converged-fleet proof"), err)
	}
	currentContent, err := serviceaction.CapturePortalEdgeContent(portal)
	if err != nil || currentContent != content {
		return errors.Join(errors.New("protected Portal content changed during converged-fleet proof"), err)
	}
	return nil
}

func verifyCoreRollbackState(ctx context.Context, controller systemdctl.Controller, verifySource coreSourceVerifier) error {
	for _, unit := range append(append([]string(nil), corePersistentServiceUnits...), append([]string{"caddy.service"}, coreTimerUnits...)...) {
		properties, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
		if err != nil || properties["UnitFileState"] != "disabled" {
			return errors.Join(errors.New("core rollback did not durably disable a persistent unit"), err)
		}
		if strings.HasSuffix(unit, ".timer") {
			if !serviceaction.UnitStopped(true, properties) {
				return errors.New("core rollback left a timer active")
			}
		} else if !serviceaction.UnitStopped(false, properties) {
			return errors.New("core rollback left a service process active")
		}
	}
	for _, unit := range []string{"workagent-backup.service", "workagent-healthcheck.service", "workagent-tenant-config-reconcile.service"} {
		properties, err := authenticateCoreUnitState(ctx, controller, unit, verifySource)
		if err != nil || !serviceaction.UnitStopped(false, properties) {
			return errors.Join(errors.New("core rollback left a static service active"), err)
		}
	}
	target, err := authenticateCoreUnitState(ctx, controller, "workagent-tenant-catalog-ready.target", verifySource)
	if err != nil || target["ActiveState"] != "inactive" || target["SubState"] != "dead" {
		return errors.Join(errors.New("core rollback did not leave the readiness target inactive"), err)
	}
	return nil
}

func authenticateCoreUnitState(ctx context.Context, controller systemdctl.Controller, unit string, verifySource coreSourceVerifier) (map[string]string, error) {
	if ctx == nil || controller == nil || verifySource == nil {
		return nil, errors.New("core unit source authenticator is unavailable")
	}
	properties := coreUnitPropertyNames(unit)
	if len(properties) == 0 {
		return nil, errors.New("core unit is outside the exact fleet")
	}
	before, err := controller.Properties(ctx, unit, properties...)
	if err != nil {
		return nil, err
	}
	if err := verifySource(unit, before); err != nil {
		return nil, err
	}
	after, err := controller.Properties(ctx, unit, properties...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return nil, errors.Join(errors.New("core unit state or source changed during authentication"), err)
	}
	return after, nil
}

func coreUnitPropertyNames(unit string) []string {
	if unit == "caddy.service" {
		return serviceaction.PropertyNames(false, unit)
	}
	common := []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"}
	switch unit {
	case "workagent-tenant-catalog-ready.target":
		return common
	case "workagent-backup.timer", "workagent-healthcheck.timer":
		return append(common, "Unit", "Persistent")
	case "workagent-tenant-config-reconcile.service", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service",
		"workagent-chatforward-browser.service", "workagent-portal.service", "workagent-backup.service", "workagent-healthcheck.service":
		properties := append(common, "MainPID", "ControlPID", "Result", "InvocationID", "ActiveEnterTimestampMonotonic", "ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx", "Type", "User", "Group")
		if unit == "workagent-tenant-config-reconcile.service" {
			properties = append(properties, "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic", "ExecMainCode", "ExecMainStatus", "ConditionResult")
		}
		return properties
	default:
		return nil
	}
}

func verifyProductionCoreUnitSource(unit string, properties map[string]string, portal config.Portal) error {
	if err := serviceaction.VerifyCoreManagerContract(unit, properties); err != nil {
		return err
	}
	if unit == "caddy.service" {
		return serviceaction.VerifyProductionSource(unit, properties)
	}
	if unit == "workagent-portal.service" {
		return serviceaction.VerifyPortalEdgeUnitSourceAt(properties, portal, serviceaction.ProductionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"}, "/etc/systemd/system")
	}
	return verifyCoreUnitSourceAt(unit, properties, serviceaction.ProductionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"})
}

// Recovery must not depend on a readable Portal configuration or database.
// The credentials drop-in has exactly two signed shapes (optional admin
// credential disabled/enabled), so both can be authenticated without loading
// product state before the pending fleet has been stopped.
func verifyProductionCoreRollbackUnitSource(unit string, properties map[string]string) error {
	if err := serviceaction.VerifyCoreManagerContract(unit, properties); err != nil {
		return err
	}
	if unit == "caddy.service" {
		return serviceaction.VerifyProductionSource(unit, properties)
	}
	if unit == "workagent-portal.service" {
		return verifyPortalRollbackUnitSourceAt(properties, serviceaction.ProductionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"}, "/etc/systemd/system")
	}
	return verifyCoreUnitSourceAt(unit, properties, serviceaction.ProductionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"})
}

func verifyPortalRollbackUnitSourceAt(properties map[string]string, controlRoot string, systemdRoots []string, dropInRoot string) error {
	fragmentAccepted := false
	for _, root := range systemdRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("Portal rollback systemd root is invalid")
		}
		if properties["FragmentPath"] == filepath.Join(root, "workagent-portal.service") {
			fragmentAccepted = true
		}
	}
	if !fragmentAccepted || !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || !filepath.IsAbs(dropInRoot) || filepath.Clean(dropInRoot) != dropInRoot {
		return errors.New("Portal rollback source namespace is invalid")
	}
	fragment := properties["FragmentPath"]
	chatDropIn := filepath.Join(dropInRoot, "workagent-portal.service.d", "chatforward.conf")
	credentialsDropIn := filepath.Join(dropInRoot, "workagent-portal.service.d", "credentials.conf")
	dropIns := strings.Fields(properties["DropInPaths"])
	if len(dropIns) != 2 || !serviceaction.SameExactWords(dropIns, []string{chatDropIn, credentialsDropIn}) {
		return errors.New("Portal rollback drop-in namespace is not exact")
	}
	for _, path := range []string{fragment, chatDropIn, credentialsDropIn} {
		if err := serviceaction.VerifyInstalledSystemdSourceFile(path); err != nil {
			return err
		}
	}
	for _, check := range [][2]string{
		{fragment, filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service")},
		{chatDropIn, filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service.d/chatforward.conf")},
	} {
		installed, err := release.ProtectedFileSHA256(check[0], true)
		reference, referenceErr := release.ProtectedFileSHA256(check[1], true)
		if err != nil || referenceErr != nil || installed != reference {
			return errors.Join(errors.New("Portal rollback source does not match the signed control release"), err, referenceErr)
		}
	}
	installedCredentials, err := release.ProtectedFileSHA256(credentialsDropIn, true)
	if err != nil {
		return err
	}
	disabledDigest, disabledErr := serviceaction.PortalCredentialsReferenceDigest(config.Portal{}, controlRoot)
	enabledDigest, enabledErr := serviceaction.PortalCredentialsReferenceDigest(config.Portal{AdminMasterPasswordHashFile: "present"}, controlRoot)
	if disabledErr != nil || enabledErr != nil || (installedCredentials != disabledDigest && installedCredentials != enabledDigest) {
		return errors.Join(errors.New("Portal credential drop-in is outside the two signed rollback shapes"), disabledErr, enabledErr)
	}
	return nil
}

func verifyCoreUnitSourceAt(unit string, properties map[string]string, controlRoot string, systemdRoots []string) error {
	if !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || len(systemdRoots) == 0 {
		return errors.New("core systemd source verifier layout is invalid")
	}
	allowed := false
	for _, candidate := range coreactivation.CoreUnits() {
		if unit == candidate && unit != "caddy.service" && unit != "workagent-portal.service" {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("unit is outside the signed core source contract")
	}
	fragment := properties["FragmentPath"]
	accepted := false
	for _, root := range systemdRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("core systemd source root is invalid")
		}
		if fragment == filepath.Join(root, unit) {
			accepted = true
		}
	}
	if !accepted || len(strings.Fields(properties["DropInPaths"])) != 0 {
		return errors.New("core systemd source namespace or drop-in set is not exact")
	}
	if err := serviceaction.VerifyInstalledSystemdSourceFile(fragment); err != nil {
		return err
	}
	installed, err := release.ProtectedFileSHA256(fragment, true)
	if err != nil {
		return err
	}
	reference, err := release.ProtectedFileSHA256(filepath.Join(controlRoot, "share", "deploy", "systemd", unit), true)
	if err != nil || installed != reference {
		return errors.Join(errors.New("installed core unit does not match the signed control release"), err)
	}
	return nil
}

type coreFleetHelperBinding struct {
	installed string
	reference string
}

func verifyInstalledCoreFleetHelpers() error {
	bindings := make([]coreFleetHelperBinding, 0, 3)
	for _, name := range []string{"workagent-core-activation-admission-v1", "workagent-recovery-activation-admission-v1", "workagent-fixed-root-exec-v1"} {
		bindings = append(bindings, coreFleetHelperBinding{
			installed: filepath.Join("/usr/libexec", name),
			reference: filepath.Join(serviceaction.ProductionControlRoot, "share/deploy/libexec", name),
		})
	}
	return verifyInstalledCoreFleetHelpersAt(bindings, []string{"/usr", "/usr/libexec"})
}

func verifyInstalledCoreFleetHelpersAt(bindings []coreFleetHelperBinding, ancestors []string) error {
	if len(bindings) == 0 || len(ancestors) == 0 {
		return errors.New("immutable core fleet helper set is unavailable")
	}
	for _, directory := range ancestors {
		info, err := os.Lstat(directory)
		stat, ok := fsutil.InfoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("immutable core fleet helper ancestor %s is unsafe", directory), err)
		}
	}
	seen := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		if !filepath.IsAbs(binding.installed) || filepath.Clean(binding.installed) != binding.installed || !filepath.IsAbs(binding.reference) || filepath.Clean(binding.reference) != binding.reference || seen[binding.installed] {
			return errors.New("immutable core fleet helper binding is invalid")
		}
		seen[binding.installed] = true
		info, err := os.Lstat(binding.installed)
		before, ok := fsutil.InfoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 || before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 {
			return errors.Join(fmt.Errorf("installed immutable core fleet helper is unsafe: %s", binding.installed), err)
		}
		installedDigest, err := release.ProtectedFileSHA256(binding.installed, true)
		if err != nil {
			return err
		}
		referenceDigest, err := release.ProtectedFileSHA256(binding.reference, true)
		if err != nil || installedDigest != referenceDigest {
			return errors.Join(fmt.Errorf("installed core fleet helper does not match the signed control release: %s", binding.installed), err)
		}
		afterInfo, err := os.Lstat(binding.installed)
		after, afterOK := fsutil.InfoSyscallStat(afterInfo)
		if err != nil || !afterOK || !sameCoreFleetHelperIdentity(before, after) {
			return errors.Join(fmt.Errorf("installed core fleet helper changed during authentication: %s", binding.installed), err)
		}
	}
	return nil
}

func sameCoreFleetHelperIdentity(first, second *syscall.Stat_t) bool {
	return first != nil && second != nil && first.Dev == second.Dev && first.Ino == second.Ino && first.Mode == second.Mode &&
		first.Uid == second.Uid && first.Gid == second.Gid && first.Nlink == second.Nlink && first.Size == second.Size &&
		first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

func syncCorePersistentEnablement(enabled bool, unit, fragmentPath string) error {
	if !strings.Contains(unit, ".") || filepath.Base(fragmentPath) != unit || !filepath.IsAbs(fragmentPath) || filepath.Clean(fragmentPath) != fragmentPath {
		return errors.New("core persistent enablement input is invalid")
	}
	wants := "/etc/systemd/system/multi-user.target.wants"
	if strings.HasSuffix(unit, ".timer") {
		wants = "/etc/systemd/system/timers.target.wants"
	}
	for _, directory := range []string{"/etc/systemd/system", wants} {
		info, err := os.Lstat(directory)
		stat, ok := fsutil.InfoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.Join(errors.New("core persistent enablement directory is unsafe"), err)
		}
	}
	linkPath := filepath.Join(wants, unit)
	if err := verifyCoreEnablementLink(linkPath, fragmentPath, enabled); err != nil {
		return err
	}
	if err := fsutil.SyncDirectory(wants); err != nil {
		return fmt.Errorf("sync core persistent wants directory: %w", err)
	}
	if err := fsutil.SyncDirectory("/etc/systemd/system"); err != nil {
		return fmt.Errorf("sync core persistent systemd directory: %w", err)
	}
	return verifyCoreEnablementLink(linkPath, fragmentPath, enabled)
}

func verifyCoreEnablementLink(linkPath, fragmentPath string, enabled bool) error {
	info, err := os.Lstat(linkPath)
	if !enabled {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.Join(errors.New("core persistent enablement link remains or is unreadable"), err)
	}
	stat, ok := fsutil.InfoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.Join(errors.New("core persistent enablement link is unsafe"), err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil || target != fragmentPath {
		return errors.Join(errors.New("core persistent enablement link target is not exact"), err)
	}
	return nil
}

func verifyCorePersistentEnablementLink(unit, fragmentPath string) error {
	wants := "/etc/systemd/system/multi-user.target.wants"
	if strings.HasSuffix(unit, ".timer") {
		wants = "/etc/systemd/system/timers.target.wants"
	}
	return verifyCoreEnablementLink(filepath.Join(wants, unit), fragmentPath, true)
}
