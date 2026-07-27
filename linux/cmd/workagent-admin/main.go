package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backupquiescence"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/coreactivation"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/edgepublication"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/safelog"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

var (
	prepareTenantActivation           = admin.PrepareTenantActivation
	replayTenantActivation            = admin.ReplayTenantActivation
	verifyLiveTenantActivationCatalog = admin.VerifyLiveTenantActivationCatalog
	syncCaddyEnablementForAction      = syncCaddyPersistentEnablement
)

func acquireTenantActivationOrchestrator(ctx context.Context) (*lifecyclelock.Guard, error) {
	guard, err := lifecyclelock.AcquireActivationExclusive(ctx)
	if err != nil {
		return nil, err
	}
	if err := backup.AssertNoPendingRecoveryActivation(); err != nil {
		return nil, errors.Join(err, guard.Close())
	}
	return guard, nil
}

func acquireCleanTenantActivationMutation(ctx context.Context) (*lifecyclelock.Guard, error) {
	guard, err := acquireTenantActivationOrchestrator(ctx)
	if err != nil {
		return nil, err
	}
	if err := admin.AssertTenantActivationClean(); err != nil {
		return nil, errors.Join(err, guard.Close())
	}
	return guard, nil
}

func acquireServiceActivationReconciler(ctx context.Context) (*lifecyclelock.Guard, error) {
	return lifecyclelock.AcquireActivationExclusiveForEdgeReconciliation(ctx)
}

func assertCleanServiceActionBoundary() error {
	return errors.Join(
		wrapUnlessNil("refuse service action while backup quiescence recovery is pending", backupquiescence.AssertClean()),
		backup.AssertNoPendingRecoveryActivation(),
		admin.AssertTenantActivationClean(),
	)
}

func wrapUnlessNil(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

func acquireAuthenticatedControlConsumer(ctx context.Context) (*lifecyclelock.FixedConsumerGuards, error) {
	guard, err := lifecyclelock.AcquireFixedConsumer(ctx, productionControlRoot)
	if err != nil {
		return nil, err
	}
	if err := verifyRunningControlExecutable(); err != nil {
		return nil, errors.Join(err, guard.Close())
	}
	return guard, nil
}

func verifyRunningControlExecutable() error {
	_, err := release.Verify(productionControlRoot, filepath.Join(productionControlRoot, "manifest.json"), release.VerifyOptions{
		RequiredExecutablePaths: []string{"bin/workagent-admin", "share/deploy/libexec/workagent-core-activation-admission-v1", "share/deploy/libexec/workagent-edge-publication-admission-v1"},
		RequireRootOwner:        true,
		RequireSignature:        true,
		SignaturePath:           filepath.Join(productionControlRoot, "manifest.sig"),
		PublicKeyPath:           "/etc/workagent/trust/release-signing.pub",
		AllowedScopes:           []string{release.ScopePortal},
	})
	if err != nil {
		return fmt.Errorf("authenticate current control release: %w", err)
	}
	running, err := unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open running workagent-admin executable: %w", err)
	}
	defer unix.Close(running)
	currentPath := filepath.Join(productionControlRoot, "bin/workagent-admin")
	current, err := unix.Open(currentPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open current signed workagent-admin executable: %w", err)
	}
	defer unix.Close(current)
	var runningStat unix.Stat_t
	var currentStat unix.Stat_t
	if err := unix.Fstat(running, &runningStat); err != nil {
		return err
	}
	if err := unix.Fstat(current, &currentStat); err != nil {
		return err
	}
	if runningStat.Dev != currentStat.Dev || runningStat.Ino != currentStat.Ino || currentStat.Mode&unix.S_IFMT != unix.S_IFREG || currentStat.Mode&0o7777 != 0o555 || currentStat.Uid != 0 || currentStat.Gid != 0 || currentStat.Nlink != 1 {
		return errors.New("running workagent-admin is not the current signed control executable")
	}
	return nil
}

func main() {
	logger := log.New(safelog.NewWriter(os.Stderr, "workagent-admin"), "", 0)
	if len(os.Args) < 2 {
		usage(logger)
	}
	var err error
	switch os.Args[1] {
	case "init-admin":
		err = createUser(os.Args[2:], true, true)
	case "create-user":
		err = createUser(os.Args[2:], false, false)
	case "set-password":
		err = setPassword(os.Args[2:])
	case "set-enabled":
		err = setEnabled(os.Args[2:])
	case "activate-tenant-catalog":
		err = activateTenantCatalog(os.Args[2:])
	case "activate-core-fleet":
		err = activateCoreFleet(os.Args[2:])
	case "service-action":
		err = serviceAction(os.Args[2:])
	case "assert-activation-clean":
		err = assertActivationClean(os.Args[2:])
	case "list-users":
		err = listUsers(os.Args[2:])
	case "set-chatgpt-pro-limit":
		err = setChatGPTProLimit(os.Args[2:])
	case "set-limits":
		err = setLimits(os.Args[2:])
	case "runtime-status", "runtime-start", "runtime-stop", "runtime-restart":
		err = runtimeCommand(os.Args[1], os.Args[2:])
	case "verify-tenant":
		err = verifyTenant(os.Args[2:])
	case "reconcile-tenant-files":
		err = reconcileTenantFiles(os.Args[2:])
	case "verify-host":
		err = verifyHost(os.Args[2:])
	default:
		usage(logger)
	}
	if err != nil {
		logger.Fatal(err)
	}
}

func usage(logger *log.Logger) {
	logger.Fatal("usage: workagent-admin <init-admin|create-user|set-password|set-enabled|activate-tenant-catalog|activate-core-fleet|service-action|set-limits|runtime-status|runtime-start|runtime-stop|runtime-restart|list-users|set-chatgpt-pro-limit|verify-tenant|reconcile-tenant-files|verify-host> [options]")
}

func createUser(arguments []string, forceAdmin, requireEmpty bool) (resultErr error) {
	flags := flag.NewFlagSet("create-user", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	tenantPath := flags.String("tenant-config", "", "tenant configuration")
	username := flags.String("username", "", "Portal username")
	passwordPath := flags.String("password-file", "", "protected password input file")
	adminUser := flags.Bool("admin", false, "grant Portal administration")
	initial := flags.Bool("initial", false, "initialize an administrator before the first runtime release activation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if forceAdmin {
		*adminUser = true
	}
	if *initial && (!forceAdmin || !requireEmpty) {
		return errors.New("--initial is valid only with init-admin")
	}
	if os.Geteuid() != 0 {
		return errors.New("Portal identity creation must run as root")
	}
	ctx := context.Background()
	activation, err := acquireCleanTenantActivationMutation(ctx)
	if err != nil {
		return fmt.Errorf("acquire Portal identity activation lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	catalog, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire Portal identity/catalog lifecycle lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	portalConfig, tenant, err := loadBoundTenant(*configPath, *tenantPath, *initial)
	if err != nil {
		return err
	}
	if err := admin.AssertTenantFileCatalogClean(portalConfig); err != nil {
		return fmt.Errorf("refuse Portal identity creation with an uncommitted tenant catalog: %w", err)
	}
	if err := auth.ValidatePortalUsername(*username); err != nil {
		return err
	}
	password, err := readPassword(*passwordPath)
	if err != nil {
		return err
	}
	defer auth.Zero(password)
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	// The Portal database, SQLite sidecars, audit sink and runtime lock must be
	// created by the unprivileged Portal identity.  Reading the root-only
	// bootstrap inputs and validating host state happens first; this permanent
	// privilege drop happens before Store can create any durable state.
	if err := dropToPortalRuntime(portalConfig.RuntimeUser); err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	closeWith := func(operation error) error {
		return errors.Join(operation, data.Close())
	}
	if requireEmpty {
		count, err := data.UserCount(ctx)
		if err != nil {
			return closeWith(err)
		}
		if count != 0 {
			return closeWith(errors.New("init-admin is allowed only on an empty Portal database"))
		}
	}
	pendingIdentity := store.PortalUserIdentity{
		TenantID: tenant.TenantID, RuntimeUser: tenant.RuntimeUser, DataRoot: tenant.DataRoot, Enabled: *initial,
	}
	if err := admin.VerifyLiveTenantIdentityCatalogWithPendingCreate(ctx, portalConfig, data, pendingIdentity); err != nil {
		return closeWith(fmt.Errorf("Portal identity creation would not close the tenant catalog gap: %w", err))
	}
	created, err := data.CreateUserWithEnabled(ctx, *username, hash, tenant.TenantID, tenant.RuntimeUser, tenant.DataRoot, *initial, *adminUser, time.Now().UTC())
	if err != nil {
		return closeWith(err)
	}
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portalConfig, data); err != nil {
		return closeWith(fmt.Errorf("Portal identity catalog did not converge after user creation: %w", err))
	}
	if !*initial {
		if err := admin.VerifyLiveTenantActivationCatalog(ctx, portalConfig, data, systemdctl.Default()); err != nil {
			return closeWith(fmt.Errorf("disabled Portal identity did not converge with systemd activation state: %w", err))
		}
	}
	if err := data.Audit(ctx, store.AuditEvent{Action: "admin.user.add", Outcome: "success", Username: created.Username, TenantID: created.TenantID, RemoteIP: "local-admin", Details: map[string]any{"admin_role": created.Admin}}); err != nil {
		return closeWith(err)
	}
	if err := data.Close(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"created": true, "user": created})
}

func setPassword(arguments []string) error {
	flags := flag.NewFlagSet("set-password", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	username := flags.String("username", "", "Portal username")
	passwordPath := flags.String("password-file", "", "protected password input file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := auth.ValidatePortalUsername(*username); err != nil {
		return err
	}
	password, err := readPassword(*passwordPath)
	if err != nil {
		return err
	}
	defer auth.Zero(password)
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	portalConfig, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := data.SetPassword(ctx, *username, hash, now); err != nil {
		return err
	}
	userValue, err := data.UserByUsername(ctx, *username)
	if err != nil {
		return fmt.Errorf("password was reset but the audit subject could not be reloaded: %w", err)
	}
	return data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.reset_password", Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin"})
}

func setEnabled(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("set-enabled", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	username := flags.String("username", "", "Portal username")
	enabled := flags.Bool("enabled", false, "new enabled state")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	ctx := context.Background()
	controller := systemdctl.Default()
	activation, err := acquireTenantActivationOrchestrator(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant activation lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	if err := reconcilePendingTenantActivationBeforeReady(ctx, *configPath, controller); err != nil {
		return err
	}
	if *enabled {
		if err := requireTenantCatalogReady(ctx, controller); err != nil {
			return err
		}
	}
	catalog, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant configuration snapshot lock: %w", err)
	}
	defer func() {
		if catalog != nil {
			resultErr = errors.Join(resultErr, catalog.Close())
		}
	}()
	portalConfig, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	if err := applyUserEnabledState(ctx, portalConfig, data, *username, *enabled, controller); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "username": store.NormalizeUsername(*username), "enabled": *enabled})
}

func portalActivationIdentities(ctx context.Context, data *store.Store) ([]store.PortalUserIdentity, error) {
	if ctx == nil || data == nil {
		return nil, errors.New("Portal activation identity reader is unavailable")
	}
	users, err := data.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	identities := make([]store.PortalUserIdentity, 0, len(users))
	for _, userValue := range users {
		identities = append(identities, store.PortalUserIdentity{
			TenantID: userValue.TenantID, RuntimeUser: userValue.RuntimeUser, DataRoot: userValue.DataRoot, Enabled: userValue.Enabled,
		})
	}
	return identities, nil
}

// activateTenantCatalog is the explicit migration/bootstrap boundary for a
// database that already contains enabled users while every restored socket is
// still disabled. It persistently converges the complete catalog before the
// readiness target is allowed to run, then starts and proves every enabled
// socket without changing any Portal identity.
const (
	productionControlRoot                   = "/opt/workagent/control"
	productionMigrationReportPath           = "/var/lib/workagent/migration/report.json"
	productionMigrationPlanPath             = "/var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json"
	productionMigrationReceiptStagePath     = "/var/lib/workagent/migration/cutover/.cliproxy-live-verification.json.workagent-stage"
	productionMigrationPublicationJournal   = "/var/lib/workagent/migration/import-stage/journal.json"
	productionCLIProxyServiceCredentialPath = "/run/credentials/cliproxyapi.service/cliproxy-management-key"
)

type tenantCatalogActivationAdmission func(context.Context, config.Portal, *store.Store, []store.PortalUserIdentity) error

func activateTenantCatalog(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("activate-tenant-catalog", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	initial := flags.Bool("initial", false, "confirm a fresh one-admin bootstrap with no Windows migration evidence")
	report := flags.String("report", productionMigrationReportPath, "protected completed Windows migration report")
	plan := flags.String("plan", productionMigrationPlanPath, "protected CLIProxy migration cutover plan")
	credential := flags.String("credential", productionCLIProxyServiceCredentialPath, "CLIProxy service-local management credential identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("activate-tenant-catalog does not accept positional arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("tenant catalog activation must run as root")
	}
	if *initial && (*report != productionMigrationReportPath || *plan != productionMigrationPlanPath || *credential != productionCLIProxyServiceCredentialPath) {
		return errors.New("initial tenant activation does not accept migration evidence overrides")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	controller := systemdctl.Default()
	activation, err := acquireTenantActivationOrchestrator(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant catalog activation lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()

	fixed, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire authenticated control root for tenant catalog activation: %w", err)
	}
	defer func() {
		if fixed != nil {
			resultErr = errors.Join(resultErr, fixed.Close())
		}
	}()
	var receiptValidation cliproxy.LiveVerificationReceiptValidation
	admission := tenantCatalogActivationAdmission(func(ctx context.Context, portal config.Portal, data *store.Store, identities []store.PortalUserIdentity) error {
		if *initial {
			return validateInitialTenantCatalogActivation(ctx, data, identities)
		}
		endpoint := portal.CLIProxy
		endpoint.ManagementCredentialFile = *credential
		policy, err := productconfig.LoadPolicy(portal.PolicyFile)
		if err != nil {
			return err
		}
		receiptValidation, err = cliproxy.ValidateMigrationLiveVerificationReceipt(ctx, cliproxy.LiveVerificationReceiptValidationOptions{
			ReportPath: *report, PlanPath: *plan, PortalDatabasePath: portal.DatabasePath(), CLIProxy: endpoint, Policy: policy,
		})
		if err != nil {
			return fmt.Errorf("validate fresh CLIProxy migration live-verification receipt: %w", err)
		}
		return nil
	})
	portalConfig, identities, err := convergeStoredTenantActivationCatalogLocked(ctx, *configPath, controller, admission)
	if err != nil {
		return err
	}
	if err := fixed.Close(); err != nil {
		return fmt.Errorf("release authenticated control snapshot before readiness activation: %w", err)
	}
	fixed = nil
	if err := requireTenantCatalogReady(ctx, controller); err != nil {
		return err
	}
	started, err := startStoredTenantActivationCatalog(ctx, *configPath, portalConfig, identities, controller)
	if err != nil {
		return err
	}
	if !*initial {
		if err := cliproxy.ValidateMigrationLiveVerificationServiceGeneration(ctx, receiptValidation.ServiceGenerationSHA256); err != nil {
			return fmt.Errorf("CLIProxy service generation changed across tenant activation: %w", err)
		}
	}
	result := map[string]any{
		"activated": true, "mode": map[bool]string{true: "initial", false: "windows-migration"}[*initial],
		"tenants": len(identities), "enabled_sockets": started,
	}
	if !*initial {
		result["migration_receipt"] = cliproxy.MigrationLiveVerificationReceiptPath
		result["migration_receipt_sha256"] = receiptValidation.ReceiptSHA256
		result["migration_receipt_expires_at"] = receiptValidation.ExpiresAt
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func convergeStoredTenantActivationCatalogLocked(ctx context.Context, configPath string, controller systemdctl.Controller, admission tenantCatalogActivationAdmission) (portal config.Portal, identities []store.PortalUserIdentity, resultErr error) {
	if ctx == nil || controller == nil || admission == nil {
		return config.Portal{}, nil, errors.New("tenant catalog activation dependencies are unavailable")
	}
	loadedPortal, err := config.LoadPortal(configPath)
	if err != nil {
		return config.Portal{}, nil, err
	}
	portal = loadedPortal
	if err := portal.ValidateProductionLayout(configPath); err != nil {
		return config.Portal{}, nil, err
	}
	if err := admin.VerifyPortalFiles(portal, configPath); err != nil {
		return config.Portal{}, nil, err
	}
	if err := admin.AssertTenantFileCatalogClean(portal); err != nil {
		return config.Portal{}, nil, fmt.Errorf("refuse activation with an uncommitted tenant file catalog: %w", err)
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return config.Portal{}, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data); err != nil {
		return config.Portal{}, nil, fmt.Errorf("refuse activation with a mismatched Portal identity catalog: %w", err)
	}
	identities, err = portalActivationIdentities(ctx, data)
	if err != nil {
		return config.Portal{}, nil, err
	}
	if err := admission(ctx, portal, data, identities); err != nil {
		return config.Portal{}, nil, err
	}
	if err := admin.ConvergeTenantActivationCatalog(ctx, identities, controller); err != nil {
		return config.Portal{}, nil, fmt.Errorf("converge complete tenant activation catalog: %w", err)
	}
	return portal, identities, nil
}

func validateInitialTenantCatalogActivation(ctx context.Context, data *store.Store, identities []store.PortalUserIdentity) error {
	if ctx == nil || data == nil {
		return errors.New("initial tenant catalog activation evidence is unavailable")
	}
	for _, path := range []string{
		productionMigrationReportPath,
		productionMigrationPlanPath,
		cliproxy.MigrationLiveVerificationReceiptPath,
		productionMigrationReceiptStagePath,
		productionMigrationPublicationJournal,
	} {
		if err := requireInitialMigrationArtifactAbsent(path); err != nil {
			return err
		}
	}
	users, err := data.ListUsers(ctx)
	if err != nil {
		return err
	}
	return validateInitialTenantCatalogShape(users, identities)
}

func validateInitialTenantCatalogShape(users []store.User, identities []store.PortalUserIdentity) error {
	if len(users) != 1 || len(identities) != 1 || !users[0].Admin || !users[0].Enabled ||
		identities[0].TenantID != users[0].TenantID || identities[0].RuntimeUser != users[0].RuntimeUser ||
		identities[0].DataRoot != users[0].DataRoot || !identities[0].Enabled {
		return errors.New("initial tenant activation requires exactly one enabled administrator identity")
	}
	return nil
}

func requireInitialMigrationArtifactAbsent(path string) error {
	const migrationRoot = "/var/lib/workagent/migration"
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("initial migration evidence path is invalid")
	}
	relative, err := filepath.Rel(migrationRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("initial migration evidence path is outside the production migration root")
	}
	current := "/var/lib/workagent"
	for _, component := range append([]string{"migration"}, strings.Split(filepath.Dir(relative), string(filepath.Separator))...) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, inspectErr := os.Lstat(current)
		if errors.Is(inspectErr, os.ErrNotExist) {
			return nil
		}
		stat, ok := infoSyscallStat(info)
		if inspectErr != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("initial migration evidence parent is unsafe: %s", current)
		}
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect initial migration evidence %s: %w", path, err)
	}
	return fmt.Errorf("initial activation is forbidden because migration evidence exists: %s", path)
}

func startStoredTenantActivationCatalog(ctx context.Context, configPath string, expectedPortal config.Portal, expectedIdentities []store.PortalUserIdentity, controller systemdctl.Controller) (started int, resultErr error) {
	catalog, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire tenant catalog snapshot for socket activation: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	portal, err := config.LoadPortal(configPath)
	if err != nil {
		return 0, err
	}
	if !reflect.DeepEqual(portal, expectedPortal) {
		return 0, errors.New("Portal configuration changed across the tenant catalog readiness boundary")
	}
	if err := admin.AssertTenantFileCatalogClean(portal); err != nil {
		return 0, err
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data); err != nil {
		return 0, err
	}
	identities, err := portalActivationIdentities(ctx, data)
	if err != nil {
		return 0, err
	}
	if !reflect.DeepEqual(identities, expectedIdentities) {
		return 0, errors.New("Portal identity catalog changed across the tenant catalog readiness boundary")
	}
	for _, identity := range identities {
		if !identity.Enabled {
			continue
		}
		tenantPath := filepath.Join(portal.Paths.TenantConfigs, identity.TenantID+".json")
		tenant, err := config.LoadTenant(tenantPath)
		if err != nil || tenant.RuntimeUser != identity.RuntimeUser || tenant.DataRoot != identity.DataRoot {
			return started, errors.Join(errors.New("enabled tenant identity changed before socket activation"), err)
		}
		if err := admin.VerifyTenantConfigPath(portal, tenant, tenantPath); err != nil {
			return started, err
		}
		if _, err := admin.VerifyTenantHost(portal, tenant); err != nil {
			return started, err
		}
		socketUnit := "workagent-userhost@" + identity.TenantID + ".socket"
		if err := controller.Action(ctx, "start", socketUnit); err != nil {
			return started, fmt.Errorf("start enabled tenant socket %s: %w", socketUnit, err)
		}
		if err := admin.VerifyTenantService(ctx, portal, tenant, admin.ServiceVerificationOptions{RequireReadySocket: true, Controller: controller}); err != nil {
			return started, fmt.Errorf("verify enabled tenant socket %s: %w", socketUnit, err)
		}
		started++
	}
	if err := admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller); err != nil {
		return started, fmt.Errorf("prove activated tenant catalog: %w", err)
	}
	return started, nil
}

var (
	adminActivationLockPath                           = lifecyclelock.ActivationPath
	assertBackupQuiescenceCleanForInheritedActivation = backupquiescence.AssertClean
	assertCoreActivationCleanForInheritedActivation   = coreactivation.AssertClean
	assertEdgePublicationCleanForInheritedActivation  = edgepublication.AssertClean
)

func assertActivationClean(arguments []string) error {
	flags := flag.NewFlagSet("assert-activation-clean", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lockFD := flags.Int("lock-fd", -1, "inherited activation-lock descriptor")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *lockFD != 3 {
		return errors.New("assert-activation-clean requires exactly --lock-fd 3")
	}
	if os.Geteuid() != 0 {
		return errors.New("activation cleanliness assertion must run as root")
	}
	if err := adoptInheritedActivationLock(*lockFD, adminActivationLockPath); err != nil {
		return err
	}
	return assertActivationStateCleanUnderAdoptedLock()
}

// assertActivationStateCleanUnderAdoptedLock is restricted to callers that
// already proved and exclusively locked the canonical activation descriptor.
// That authority prevents a new edge or tenant transaction from appearing
// between these fail-closed checks and the caller's service mutation.
func assertActivationStateCleanUnderAdoptedLock() error {
	if err := assertBackupQuiescenceCleanForInheritedActivation(); err != nil {
		return fmt.Errorf("refuse activation mutation with pending backup quiescence recovery: %w", err)
	}
	if err := assertCoreActivationCleanForInheritedActivation(); err != nil {
		return fmt.Errorf("refuse activation mutation with a pending core activation: %w", err)
	}
	if err := assertEdgePublicationCleanForInheritedActivation(); err != nil {
		return fmt.Errorf("refuse activation mutation with a pending edge publication: %w", err)
	}
	if err := backup.AssertNoPendingRecoveryActivation(); err != nil {
		return err
	}
	if err := admin.AssertTenantActivationClean(); err != nil {
		return err
	}
	return nil
}

// adoptInheritedActivationLock proves that fd is the exact protected lock
// inode and acquires LOCK_EX on that inherited open-file description. When a
// shell parent retains the descriptor, the lock remains held after this short
// verifier exits and protects the parent's entire interactive operation.
func adoptInheritedActivationLock(fd int, path string) error {
	if fd < 3 || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("inherited tenant activation lock input is invalid")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || (flags&unix.O_ACCMODE != unix.O_RDONLY && flags&unix.O_ACCMODE != unix.O_RDWR) {
		return errors.New("inherited tenant activation lock has an unsafe access mode")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Mode&0o7777 != 0o600 || opened.Uid != 0 || opened.Gid != 0 || opened.Nlink != 1 || opened.Size != 0 {
		return errors.New("inherited tenant activation lock descriptor is unsafe")
	}
	info, err := os.Lstat(path)
	stat, ok := infoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || uint64(stat.Dev) != opened.Dev || stat.Ino != opened.Ino || uint32(stat.Mode) != opened.Mode || stat.Uid != opened.Uid || stat.Gid != opened.Gid || stat.Nlink != opened.Nlink || stat.Size != opened.Size {
		return errors.New("inherited tenant activation lock pathname is unsafe or changed")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("acquire inherited tenant activation lock: %w", err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != opened.Dev || after.Ino != opened.Ino || after.Mode != opened.Mode || after.Uid != opened.Uid || after.Gid != opened.Gid || after.Nlink != opened.Nlink || after.Size != opened.Size {
		return errors.New("inherited tenant activation lock changed after acquisition")
	}
	return nil
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return value, ok
}

var serviceActionAllowlist = map[string]map[string]bool{
	"cliproxyapi.service":         {"start": true, "stop": true, "restart": true},
	"caddy.service":               {"enable-now": true},
	"workagent-backup.timer":      {"enable-now": true},
	"workagent-healthcheck.timer": {"enable-now": true},
}

const edgePublicationConfirmation = "PUBLISH-WORKAGENT-EDGE"

const productionCaddyBinarySHA256 = "33cd4c300c46fef824abe017fb3c5698698c41cd7eaf9cf097126d5ac6e4cf4a"

const (
	productionPortalAddress      = "127.0.0.1:42580"
	productionPortalPublicOrigin = "https://workagent.example.invalid"
	edgePublicationJournalPath   = "/var/lib/workagent-edge/publication.json"
	edgePublicationPermitPath    = "/run/workagent-edge/publication.permit"
)

type edgePublicationJournal struct {
	SchemaVersion int    `json:"schema_version"`
	BootID        string `json:"boot_id"`
	PermitDevice  uint64 `json:"permit_device"`
	PermitInode   uint64 `json:"permit_inode"`
}

type edgePublicationPermit struct {
	SchemaVersion int    `json:"schema_version"`
	BootID        string `json:"boot_id"`
	JournalDevice uint64 `json:"journal_device"`
	JournalInode  uint64 `json:"journal_inode"`
}

type edgePublicationTransaction struct {
	permitFD       int
	permitStat     unix.Stat_t
	journalStat    unix.Stat_t
	permitPayload  []byte
	journalPayload []byte
}

func beginEdgePublication() (_ *edgePublicationTransaction, resultErr error) {
	if err := validateEdgePublicationDirectories(); err != nil {
		return nil, err
	}
	for _, path := range []string{edgePublicationJournalPath, edgePublicationPermitPath} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(errors.New("edge-publication crash evidence already exists"), err)
		}
	}
	bootID, err := currentEdgePublicationBootID()
	if err != nil {
		return nil, err
	}
	transaction := &edgePublicationTransaction{permitFD: -1}
	journalFD := -1
	permitLinked := false
	journalLinked := false
	defer func() {
		if resultErr == nil {
			return
		}
		var cleanupErrors []error
		// Caddy is still disabled. Removing a published permit before its
		// journal ensures a cleanup crash leaves only a canonical lone journal.
		if permitLinked {
			if err := unlinkEdgeArtifactIdentity(edgePublicationPermitPath, transaction.permitStat); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				cleanupErrors = append(cleanupErrors, syncEdgeDirectory(filepath.Dir(edgePublicationPermitPath)))
			}
		}
		if journalLinked {
			if err := unlinkEdgeArtifactIdentity(edgePublicationJournalPath, transaction.journalStat); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				cleanupErrors = append(cleanupErrors, syncEdgeDirectory(filepath.Dir(edgePublicationJournalPath)))
			}
		}
		if journalFD >= 0 {
			cleanupErrors = append(cleanupErrors, unix.Close(journalFD))
			journalFD = -1
		}
		if transaction.permitFD >= 0 {
			cleanupErrors = append(cleanupErrors, unix.Close(transaction.permitFD))
			transaction.permitFD = -1
		}
		resultErr = errors.Join(resultErr, errors.Join(cleanupErrors...))
	}()

	permitFD, err := unix.Open(filepath.Dir(edgePublicationPermitPath), unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create anonymous edge-publication permit: %w", err)
	}
	transaction.permitFD = permitFD
	if err := unix.Fchmod(permitFD, 0o600); err != nil {
		return nil, err
	}
	if err := unix.Flock(permitFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock anonymous edge-publication permit: %w", err)
	}
	if err := unix.Fstat(permitFD, &transaction.permitStat); err != nil || !safeEdgeAnonymousArtifactStat(transaction.permitStat, true) {
		return nil, errors.Join(errors.New("anonymous edge-publication permit inode is unsafe"), err)
	}

	journalFD, err = unix.Open(filepath.Dir(edgePublicationJournalPath), unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create anonymous edge-publication journal: %w", err)
	}
	if err := unix.Fchmod(journalFD, 0o600); err != nil {
		return nil, err
	}
	if err := unix.Fstat(journalFD, &transaction.journalStat); err != nil || !safeEdgeAnonymousArtifactStat(transaction.journalStat, true) {
		return nil, errors.Join(errors.New("anonymous edge-publication journal inode is unsafe"), err)
	}

	journal := edgePublicationJournal{SchemaVersion: 1, BootID: bootID, PermitDevice: transaction.permitStat.Dev, PermitInode: transaction.permitStat.Ino}
	transaction.journalPayload, err = canonicalEdgePublicationJSON(journal)
	if err != nil {
		return nil, err
	}
	permit := edgePublicationPermit{SchemaVersion: 1, BootID: bootID, JournalDevice: transaction.journalStat.Dev, JournalInode: transaction.journalStat.Ino}
	transaction.permitPayload, err = canonicalEdgePublicationJSON(permit)
	if err != nil {
		return nil, err
	}
	if err := writeEdgeFD(journalFD, transaction.journalPayload); err != nil {
		return nil, err
	}
	if err := writeEdgeFD(permitFD, transaction.permitPayload); err != nil {
		return nil, err
	}
	if err := unix.Fsync(journalFD); err != nil {
		return nil, err
	}
	if err := unix.Fsync(permitFD); err != nil {
		return nil, err
	}
	if err := unix.Fstat(journalFD, &transaction.journalStat); err != nil || !safeEdgeAnonymousArtifactStat(transaction.journalStat, false) {
		return nil, errors.Join(errors.New("anonymous edge-publication journal payload is unsafe"), err)
	}
	if err := unix.Fstat(permitFD, &transaction.permitStat); err != nil || !safeEdgeAnonymousArtifactStat(transaction.permitStat, false) {
		return nil, errors.Join(errors.New("anonymous edge-publication permit payload is unsafe"), err)
	}

	if err := unix.Linkat(journalFD, "", unix.AT_FDCWD, edgePublicationJournalPath, unix.AT_EMPTY_PATH); err != nil {
		return nil, fmt.Errorf("publish canonical edge-publication journal: %w", err)
	}
	journalLinked = true
	if err := unix.Fstat(journalFD, &transaction.journalStat); err != nil || !safeEdgeArtifactStat(transaction.journalStat, false) {
		return nil, errors.Join(errors.New("published edge-publication journal inode is unsafe"), err)
	}
	if err := syncEdgeDirectory(filepath.Dir(edgePublicationJournalPath)); err != nil {
		return nil, err
	}
	if err := unix.Linkat(permitFD, "", unix.AT_FDCWD, edgePublicationPermitPath, unix.AT_EMPTY_PATH); err != nil {
		return nil, fmt.Errorf("publish canonical edge-publication permit: %w", err)
	}
	permitLinked = true
	if err := unix.Fstat(permitFD, &transaction.permitStat); err != nil || !safeEdgeArtifactStat(transaction.permitStat, false) {
		return nil, errors.Join(errors.New("published edge-publication permit inode is unsafe"), err)
	}
	if err := syncEdgeDirectory(filepath.Dir(edgePublicationPermitPath)); err != nil {
		return nil, err
	}
	closeErr := unix.Close(journalFD)
	journalFD = -1
	if closeErr != nil {
		return nil, closeErr
	}
	return transaction, nil
}

func (transaction *edgePublicationTransaction) Commit() error {
	if transaction == nil || transaction.permitFD < 0 {
		return errors.New("edge-publication transaction is unavailable")
	}
	if err := transaction.Verify(); err != nil {
		return err
	}
	// The durable journal is removed and synced first. The volatile permit
	// pathname is the final commit signal observed by the blocking systemd
	// watcher; no fallible durability operation may follow that signal. On any
	// earlier error this method deliberately retains the permit lock so the
	// watcher cannot admit Caddy before the caller proves fail-closed disablement.
	if err := unix.Unlink(edgePublicationJournalPath); err != nil {
		return err
	}
	if err := syncEdgeDirectory(filepath.Dir(edgePublicationJournalPath)); err != nil {
		return err
	}
	if err := unix.Unlink(edgePublicationPermitPath); err != nil {
		return err
	}
	closeErr := unix.Close(transaction.permitFD)
	transaction.permitFD = -1
	return closeErr
}

func (transaction *edgePublicationTransaction) Verify() error {
	if transaction == nil || transaction.permitFD < 0 {
		return errors.New("edge-publication transaction is unavailable")
	}
	if err := validateEdgePublicationDirectories(); err != nil {
		return err
	}
	if err := verifyEdgeOpenArtifact(transaction.permitFD, edgePublicationPermitPath, transaction.permitStat, transaction.permitPayload); err != nil {
		return err
	}
	journalFD, err := unix.Open(edgePublicationJournalPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	journalErr := verifyEdgeOpenArtifact(journalFD, edgePublicationJournalPath, transaction.journalStat, transaction.journalPayload)
	return errors.Join(journalErr, unix.Close(journalFD))
}

func (transaction *edgePublicationTransaction) Close() error {
	if transaction == nil || transaction.permitFD < 0 {
		return nil
	}
	err := unix.Close(transaction.permitFD)
	transaction.permitFD = -1
	return err
}

func reconcilePendingEdgePublication(ctx context.Context, controller systemdctl.Controller) error {
	if ctx == nil || controller == nil {
		return errors.New("edge-publication reconciler is unavailable")
	}
	discoveryErr := validateEdgePublicationDirectories()
	journalSeen, journalDiscoveryErr := edgeArtifactEntryPresent(edgePublicationJournalPath)
	permitSeen, permitDiscoveryErr := edgeArtifactEntryPresent(edgePublicationPermitPath)
	discoveryErr = errors.Join(discoveryErr, journalDiscoveryErr, permitDiscoveryErr)
	if discoveryErr == nil && !journalSeen && !permitSeen {
		// Absence is admitted only through two stable protected-parent passes.
		if err := validateEdgePublicationDirectories(); err == nil {
			journalAgain, journalErr := edgeArtifactEntryPresent(edgePublicationJournalPath)
			permitAgain, permitErr := edgeArtifactEntryPresent(edgePublicationPermitPath)
			if journalErr == nil && permitErr == nil && !journalAgain && !permitAgain {
				return nil
			}
			discoveryErr = errors.Join(journalErr, permitErr, errorUnless(!journalAgain && !permitAgain, "edge-publication evidence appeared during absence proof"))
		} else {
			discoveryErr = err
		}
	}
	disableErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return rollbackPublishedCaddyFailClosed(cleanupContext, controller)
	})
	if disableErr != nil {
		return errors.Join(errors.New("disable Caddy under its currently authenticated manager contract for edge-publication recovery"), disableErr)
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("Caddy was durably disabled, but manager reload failed; edge evidence was retained: %w", err)
	}
	if err := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return rollbackPublishedCaddyFailClosed(cleanupContext, controller)
	}); err != nil {
		return fmt.Errorf("Caddy was disabled before reload, but its reloaded fail-closed contract could not be authenticated; edge evidence was retained: %w", err)
	}
	if discoveryErr != nil {
		return fmt.Errorf("Caddy was durably disabled because edge-publication state could not be proved clean; unsafe evidence was retained: %w", discoveryErr)
	}
	if err := validateEdgePublicationDirectories(); err != nil {
		return fmt.Errorf("Caddy was durably disabled, but edge-publication parents are unsafe: %w", err)
	}
	journalPresent, journalStat, err := edgeArtifactState(edgePublicationJournalPath, true)
	if err != nil {
		return fmt.Errorf("Caddy was durably disabled, but the edge journal is unsafe and was retained: %w", err)
	}
	permitPresent, permitStat, err := edgeArtifactState(edgePublicationPermitPath, true)
	if err != nil {
		return fmt.Errorf("Caddy was durably disabled, but the edge permit is unsafe and was retained: %w", err)
	}
	if !journalPresent && !permitPresent {
		return errors.New("Caddy was durably disabled after edge evidence disappeared during recovery; no artifact was deleted")
	}
	permitFD := -1
	if permitPresent {
		permitFD, err = unix.Open(edgePublicationPermitPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(permitFD)
		var opened unix.Stat_t
		if err := unix.Fstat(permitFD, &opened); err != nil || !sameEdgeArtifactStat(opened, permitStat) {
			return errors.Join(errors.New("edge-publication permit changed during recovery"), err)
		}
		if err := unix.Flock(permitFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("edge-publication permit is still owned by another publisher: %w", err)
		}
	}
	journalFD := -1
	if journalPresent {
		journalFD, err = unix.Open(edgePublicationJournalPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open edge-publication journal for recovery: %w", err)
		}
		defer unix.Close(journalFD)
	}
	if err := validateRecoverableEdgePublicationEvidence(journalPresent, journalFD, journalStat, permitPresent, permitFD, permitStat); err != nil {
		return fmt.Errorf("Caddy was durably disabled, but invalid edge-publication crash evidence was retained: %w", err)
	}
	if err := validateRecoverableEdgePublicationEvidence(journalPresent, journalFD, journalStat, permitPresent, permitFD, permitStat); err != nil {
		return fmt.Errorf("edge-publication crash evidence changed before recovery deletion and was retained: %w", err)
	}
	if journalPresent {
		if err := unix.Unlink(edgePublicationJournalPath); err != nil {
			return err
		}
		if err := syncEdgeDirectory(filepath.Dir(edgePublicationJournalPath)); err != nil {
			return err
		}
	}
	if permitPresent {
		if err := unix.Flock(permitFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("edge-publication permit lock changed before final recovery deletion: %w", err)
		}
		if err := validateRecoverableEdgePublicationEvidence(false, -1, unix.Stat_t{}, true, permitFD, permitStat); err != nil {
			return fmt.Errorf("edge-publication permit changed after journal recovery and was retained: %w", err)
		}
		if err := unix.Unlink(edgePublicationPermitPath); err != nil {
			return err
		}
	}
	return nil
}

func edgeArtifactEntryPresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, fmt.Errorf("inspect edge-publication evidence path %s: %w", path, err)
}

func unlinkEdgeArtifactIdentity(path string, expected unix.Stat_t) error {
	present, current, err := edgeArtifactState(path, false)
	if err != nil || !present || current.Dev != expected.Dev || current.Ino != expected.Ino {
		return errors.Join(fmt.Errorf("refuse to unlink replaced edge-publication artifact %s", path), err)
	}
	return unix.Unlink(path)
}

func validateRecoverableEdgePublicationEvidence(journalPresent bool, journalFD int, journalStat unix.Stat_t, permitPresent bool, permitFD int, permitStat unix.Stat_t) error {
	if !journalPresent && !permitPresent {
		return errors.New("edge-publication evidence is absent")
	}
	var journal edgePublicationJournal
	if journalPresent {
		payload, err := readEdgeOpenArtifact(journalFD, edgePublicationJournalPath, journalStat, false)
		if err != nil {
			return fmt.Errorf("read edge-publication journal: %w", err)
		}
		journal, err = decodeCanonicalEdgeJournal(payload)
		if err != nil {
			return err
		}
	}
	if permitPresent {
		payload, err := readEdgeOpenArtifact(permitFD, edgePublicationPermitPath, permitStat, true)
		if err != nil {
			return fmt.Errorf("read edge-publication permit: %w", err)
		}
		if len(payload) == 0 {
			return errors.New("visible edge-publication permit is empty")
		}
		permit, err := decodeCanonicalEdgePermit(payload)
		if err != nil {
			return err
		}
		currentBootID, err := currentEdgePublicationBootID()
		if err != nil {
			return err
		}
		if !journalPresent {
			// The success path durably removes the journal before the volatile
			// permit. A canonical lone permit is therefore a recoverable final
			// commit transition once Caddy has already been disabled.
			if permit.BootID != currentBootID {
				return errors.New("lone edge-publication permit belongs to another boot")
			}
			return nil
		}
		if journal.BootID != permit.BootID || journal.PermitDevice != permitStat.Dev || journal.PermitInode != permitStat.Ino ||
			permit.JournalDevice != journalStat.Dev || permit.JournalInode != journalStat.Ino {
			return errors.New("edge-publication journal and permit are not mutually bound")
		}
		if permit.BootID != currentBootID {
			return errors.New("paired edge-publication evidence belongs to another boot")
		}
		return nil
	}
	// Begin publishes the durable journal before the volatile permit. A lone
	// journal can therefore be a current-boot begin tail or a previous-boot
	// crash after /run was cleared, and remains safely recoverable.
	return nil
}

func decodeCanonicalEdgeJournal(payload []byte) (edgePublicationJournal, error) {
	var journal edgePublicationJournal
	if err := decodeCanonicalEdgePublicationJSON(payload, &journal); err != nil {
		return edgePublicationJournal{}, fmt.Errorf("edge-publication journal is not canonical: %w", err)
	}
	if journal.SchemaVersion != 1 || journal.PermitDevice == 0 || journal.PermitInode == 0 || !canonicalEdgeBootID(journal.BootID) {
		return edgePublicationJournal{}, errors.New("edge-publication journal fields are invalid")
	}
	return journal, nil
}

func decodeCanonicalEdgePermit(payload []byte) (edgePublicationPermit, error) {
	var permit edgePublicationPermit
	if err := decodeCanonicalEdgePublicationJSON(payload, &permit); err != nil {
		return edgePublicationPermit{}, fmt.Errorf("edge-publication permit is not canonical: %w", err)
	}
	if permit.SchemaVersion != 1 || permit.JournalDevice == 0 || permit.JournalInode == 0 || !canonicalEdgeBootID(permit.BootID) {
		return edgePublicationPermit{}, errors.New("edge-publication permit fields are invalid")
	}
	return permit, nil
}

func decodeCanonicalEdgePublicationJSON(payload []byte, destination any) error {
	if len(payload) == 0 || len(payload) > 1024 || payload[len(payload)-1] != '\n' {
		return errors.New("edge-publication JSON size or termination is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.Join(errors.New("edge-publication JSON shape is invalid"), err)
	}
	canonical, err := canonicalEdgePublicationJSON(destination)
	if err != nil || !bytes.Equal(canonical, payload) {
		return errors.Join(errors.New("edge-publication JSON encoding is not canonical"), err)
	}
	return nil
}

func canonicalEdgeBootID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && len(value) == 36
}

func readEdgeOpenArtifact(fd int, path string, expected unix.Stat_t, allowEmpty bool) ([]byte, error) {
	if fd < 0 || expected.Size < 0 || expected.Size > 1024 || !safeEdgeArtifactStat(expected, allowEmpty) {
		return nil, errors.New("edge-publication artifact descriptor contract is invalid")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameEdgeArtifactStat(opened, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact descriptor changed"), err)
	}
	present, pathStat, err := edgeArtifactState(path, allowEmpty)
	if err != nil || !present || !sameEdgeArtifactStat(pathStat, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact path changed"), err)
	}
	buffer := make([]byte, int(expected.Size)+1)
	count, err := unix.Pread(fd, buffer, 0)
	if err != nil || count != int(expected.Size) {
		return nil, errors.Join(errors.New("edge-publication artifact content length changed"), err)
	}
	if err := unix.Fstat(fd, &opened); err != nil || !sameEdgeArtifactStat(opened, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact changed while reading"), err)
	}
	present, pathStat, err = edgeArtifactState(path, allowEmpty)
	if err != nil || !present || !sameEdgeArtifactStat(pathStat, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact path changed while reading"), err)
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func validateEdgePublicationDirectories() error {
	for _, path := range []string{filepath.Dir(edgePublicationJournalPath), filepath.Dir(edgePublicationPermitPath)} {
		info, err := os.Lstat(path)
		stat, ok := infoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("edge-publication directory %s is unsafe", path), err)
		}
	}
	return nil
}

func edgeArtifactState(path string, allowEmpty bool) (bool, unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Lstat(path, &stat)
	if errors.Is(err, unix.ENOENT) {
		return false, unix.Stat_t{}, nil
	}
	if err != nil {
		return false, unix.Stat_t{}, errors.Join(errors.New("inspect edge-publication artifact"), err)
	}
	if !safeEdgeArtifactStat(stat, allowEmpty) {
		return false, unix.Stat_t{}, errors.New("edge-publication artifact metadata is unsafe")
	}
	return true, stat, nil
}

func safeEdgeArtifactStat(stat unix.Stat_t, allowEmpty bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 1 && stat.Size >= 0 && stat.Size <= 1024 && (allowEmpty || stat.Size > 0)
}

func safeEdgeAnonymousArtifactStat(stat unix.Stat_t, allowEmpty bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 0 && stat.Size >= 0 && stat.Size <= 1024 && (allowEmpty || stat.Size > 0)
}

func sameEdgeArtifactStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink && left.Size == right.Size
}

func canonicalEdgePublicationJSON(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > 1023 {
		return nil, errors.Join(errors.New("edge-publication evidence is invalid"), err)
	}
	return append(payload, '\n'), nil
}

func currentEdgePublicationBootID() (string, error) {
	payload, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(payload) != 37 || payload[36] != '\n' {
		return "", errors.Join(errors.New("current boot identity is invalid"), err)
	}
	value := string(payload[:36])
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return "", errors.New("current boot identity is not canonical")
	}
	return value, nil
}

func writeEdgeFD(fd int, payload []byte) error {
	for len(payload) > 0 {
		written, err := unix.Write(fd, payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func verifyEdgeOpenArtifact(fd int, path string, expected unix.Stat_t, payload []byte) error {
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameEdgeArtifactStat(opened, expected) {
		return errors.Join(errors.New("edge-publication artifact descriptor changed"), err)
	}
	present, pathStat, err := edgeArtifactState(path, false)
	if err != nil || !present || !sameEdgeArtifactStat(pathStat, expected) {
		return errors.Join(errors.New("edge-publication artifact path changed"), err)
	}
	buffer := make([]byte, len(payload)+1)
	count, err := unix.Pread(fd, buffer, 0)
	if err != nil || count != len(payload) || !bytes.Equal(buffer[:count], payload) {
		return errors.Join(errors.New("edge-publication artifact content changed"), err)
	}
	return nil
}

func syncEdgeDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Fsync(fd)
	return errors.Join(err, unix.Close(fd))
}

func serviceAction(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("service-action", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	action := flags.String("action", "", "start, stop, restart, or enable-now")
	unit := flags.String("unit", "", "exact allow-listed systemd unit")
	confirm := flags.String("confirm", "", "exact edge-publication confirmation for Caddy only")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("service-action does not accept positional arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("service-action must run as root")
	}
	allowed, ok := serviceActionAllowlist[*unit]
	if !ok || !allowed[*action] {
		return errors.New("service-action unit/action pair is not allow-listed")
	}
	if err := validateServiceActionConfirmation(*action, *unit, *confirm); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	activation, err := acquireServiceActivationReconciler(ctx)
	if err != nil {
		return fmt.Errorf("acquire service activation reconciliation boundary: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	controller := systemdctl.Default()
	if err := reconcilePendingEdgePublication(ctx, controller); err != nil {
		return fmt.Errorf("reconcile an incomplete edge publication before service action: %w", err)
	}
	if err := assertCleanServiceActionBoundary(); err != nil {
		return err
	}
	catalog, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire service-action catalog snapshot: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	portal, err := config.LoadPortal("/etc/workagent/portal.json")
	if err != nil {
		return err
	}
	if err := portal.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		return err
	}
	if err := admin.VerifyPortalFiles(portal, "/etc/workagent/portal.json"); err != nil {
		return err
	}
	if err := admin.AssertTenantFileCatalogClean(portal); err != nil {
		return fmt.Errorf("refuse service action with an uncommitted tenant catalog: %w", err)
	}
	var portalGeneration portalEdgeGeneration
	var edgeContent portalEdgeContentSnapshot
	var edgeTransaction *edgePublicationTransaction
	if *unit == "caddy.service" {
		if err := validateProductionPortalEdgeBinding(portal); err != nil {
			return err
		}
		edgeContent, err = capturePortalEdgeContent(portal)
		if err != nil {
			return fmt.Errorf("capture protected Portal content generation: %w", err)
		}
		data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
		if err != nil {
			return err
		}
		proofErr := errors.Join(
			admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data),
			admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller),
		)
		if err := errors.Join(proofErr, data.Close()); err != nil {
			return fmt.Errorf("refuse edge publication without a converged tenant catalog: %w", err)
		}
		// A manager reload alone does not bind an already-running process to the
		// newly loaded unit definition. Quiesce the public edge, force Portal into
		// a new authenticated invocation, and only then collect readiness.
		portalGeneration, err = preparePortalEdgeGeneration(ctx, portal, controller)
		if err != nil {
			return fmt.Errorf("prepare authenticated Portal generation for edge publication: %w", err)
		}
		portalGeneration, err = verifyPortalEdgePublicationReadiness(ctx, portal, controller, edgeContent.PolicyID, edgeContent.BrandID, &portalGeneration, false)
		if err != nil {
			return fmt.Errorf("refuse edge publication before full local readiness: %w", err)
		}
		if currentContent, err := capturePortalEdgeContent(portal); err != nil || currentContent != edgeContent {
			return errors.Join(errors.New("protected Portal content changed across the forced Portal restart while Caddy remains disabled"), err)
		}
		if err := verifyInstalledEdgeAdmissionHelper(); err != nil {
			return fmt.Errorf("authenticate immutable edge-publication admission helper before transaction begin: %w", err)
		}
		edgeTransaction, err = beginEdgePublication()
		if err != nil {
			return fmt.Errorf("persist edge-publication crash recovery evidence before enabling Caddy: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, edgeTransaction.Close()) }()
	}
	var actionErr error
	if edgeTransaction != nil {
		actionErr = executeCaddyEdgeCommit(ctx, controller, verifyProductionServiceActionSource, edgeTransaction.Verify)
	} else {
		actionErr = executeAllowlistedServiceAction(ctx, controller, *action, *unit)
	}
	if actionErr != nil {
		if edgeTransaction != nil {
			return abortEdgePublication(controller, edgeTransaction, errors.Join(errors.New("Caddy publication action failed"), actionErr))
		}
		return actionErr
	}
	if *unit == "caddy.service" {
		publishingGeneration, err := verifyPublishedEdge(ctx, portal, controller, edgeContent, portalGeneration)
		if err != nil {
			return abortEdgePublication(controller, edgeTransaction, errors.Join(errors.New("edge publication post-action proof failed"), err))
		}
		if err := edgeTransaction.Commit(); err != nil {
			return failClosedAfterEdgeCommitError(controller, edgeTransaction, err)
		}
		if err := settleCommittedCaddyEdge(ctx, controller, publishingGeneration); err != nil {
			rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
				return rollbackPublishedCaddyFailClosed(cleanupContext, controller)
			})
			if rollbackErr == nil {
				return errors.Join(errors.New("edge-publication watcher did not settle the proved generation; Caddy was durably disabled"), err)
			}
			return errors.Join(errors.New("edge-publication watcher did not settle the proved generation and Caddy final state is ambiguous"), err, rollbackErr)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "action": *action, "unit": *unit})
}

func abortEdgePublication(controller systemdctl.Controller, transaction *edgePublicationTransaction, cause error) error {
	if controller == nil || transaction == nil || cause == nil {
		return errors.Join(errors.New("edge-publication abort is unavailable"), cause)
	}
	rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return rollbackPublishedCaddyFailClosed(cleanupContext, controller)
	})
	if rollbackErr != nil {
		closeErr := transaction.Close()
		return errors.Join(errors.New("edge publication failed and Caddy final state is ambiguous; crash evidence was retained"), cause, rollbackErr, closeErr)
	}
	commitErr := transaction.Commit()
	if commitErr == nil {
		return errors.Join(errors.New("edge publication failed; Caddy was durably disabled and crash evidence was cleared"), cause)
	}
	closeErr := transaction.Close()
	reconcileErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return reconcilePendingEdgePublication(cleanupContext, controller)
	})
	if reconcileErr == nil {
		return errors.Join(errors.New("edge publication failed; Caddy was durably disabled and residual crash evidence was reconciled"), cause, commitErr, closeErr)
	}
	return errors.Join(errors.New("edge publication failed after Caddy was disabled, but residual crash evidence could not be cleared"), cause, commitErr, closeErr, reconcileErr)
}

func failClosedAfterEdgeCommitError(controller systemdctl.Controller, transaction *edgePublicationTransaction, commitErr error) error {
	if controller == nil || transaction == nil || commitErr == nil {
		return errors.Join(errors.New("edge-publication commit failure handler is unavailable"), commitErr)
	}
	// Commit deliberately retains the permit lock on every error before its
	// final volatile unlink. Keep the blocking watcher alive until Caddy has
	// first been proved disabled, then release the lock and reconcile whatever
	// durable or volatile evidence remains.
	rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return rollbackPublishedCaddyFailClosed(cleanupContext, controller)
	})
	closeErr := transaction.Close()
	reconcileErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return reconcilePendingEdgePublication(cleanupContext, controller)
	})
	if rollbackErr == nil && reconcileErr == nil {
		return errors.Join(errors.New("edge proof succeeded but its durable commit failed; Caddy was disabled and crash evidence was reconciled"), commitErr, closeErr)
	}
	return errors.Join(errors.New("edge proof succeeded but its durable commit failed; Caddy or crash-evidence final state is ambiguous"), commitErr, closeErr, rollbackErr, reconcileErr)
}

func validateProductionPortalEdgeBinding(portal config.Portal) error {
	if portal.Listener.Address != productionPortalAddress || portal.Listener.PublicOrigin != productionPortalPublicOrigin {
		return errors.New("Portal listener and public origin do not match the signed Caddy publication boundary")
	}
	return nil
}

func preparePortalEdgeGeneration(ctx context.Context, portal config.Portal, controller systemdctl.Controller) (portalEdgeGeneration, error) {
	if ctx == nil || controller == nil {
		return portalEdgeGeneration{}, errors.New("Portal edge-generation controller is unavailable")
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return portalEdgeGeneration{}, fmt.Errorf("reload systemd manager before Portal restart: %w", err)
	}
	before, err := capturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return portalEdgeGeneration{}, fmt.Errorf("authenticate manager-loaded Portal definition before restart: %w", err)
	}
	if err := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return disableCaddyFailClosed(cleanupContext, controller, serviceActionPropertyNames(false, "caddy.service"), verifyProductionServiceActionSource)
	}); err != nil {
		return portalEdgeGeneration{}, fmt.Errorf("durably quiesce Caddy before Portal generation replacement: %w", err)
	}
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		actionErr := controller.Action(ctx, "restart", "workagent-portal.service")
		after, proofErr := capturePortalEdgeGeneration(ctx, portal, controller)
		if proofErr == nil && portalGenerationAdvanced(before, after) {
			return after, nil
		}
		failures = append(failures, errors.Join(actionErr, proofErr, errorUnless(portalGenerationAdvanced(before, after), "Portal restart did not enter a new invocation")))
	}
	return portalEdgeGeneration{}, errors.Join(errors.New("Portal failed to enter a new authenticated generation while Caddy remains durably disabled"), errors.Join(failures...))
}

func portalGenerationAdvanced(before, after portalEdgeGeneration) bool {
	beforeStamp, beforeErr := strconv.ParseUint(before.ActiveEnterTimestampMonotonic, 10, 64)
	afterStamp, afterErr := strconv.ParseUint(after.ActiveEnterTimestampMonotonic, 10, 64)
	return before.InvocationID != "" && after.InvocationID != "" && before.InvocationID != after.InvocationID && beforeErr == nil && afterErr == nil && afterStamp > beforeStamp
}

func validateServiceActionConfirmation(action, unit, confirm string) error {
	if unit == "caddy.service" {
		if action != "enable-now" || confirm != edgePublicationConfirmation {
			return errors.New("Caddy edge publication requires --confirm " + edgePublicationConfirmation)
		}
		return nil
	}
	if confirm != "" {
		return errors.New("--confirm is restricted to Caddy edge publication")
	}
	return nil
}

type edgeReadinessComponent struct {
	Ready bool `json:"ready"`
}

type edgeReadinessReport struct {
	Status     string                            `json:"status"`
	Ready      bool                              `json:"ready"`
	CheckedAt  time.Time                         `json:"checked_at"`
	PolicyID   string                            `json:"policy_id"`
	BrandID    string                            `json:"brand_id"`
	Components map[string]edgeReadinessComponent `json:"components"`
}

type portalEdgeGeneration struct {
	MainPID                       string
	InvocationID                  string
	ActiveEnterTimestampMonotonic string
	FragmentPath                  string
	DropInPaths                   string
	ExecStart                     string
}

type caddyPublishingGeneration struct {
	MainPID                         string
	ControlPID                      string
	InvocationID                    string
	ExecMainStartTimestampMonotonic string
	FragmentPath                    string
	DropInPaths                     string
	ExecStart                       string
	ExecStartPre                    string
	ExecStartPost                   string
}

type portalEdgeContentSnapshot struct {
	PortalSHA256   string
	PolicySHA256   string
	BrandSHA256    string
	LogoSHA256     string
	LogoDarkSHA256 string
	FaviconSHA256  string
	AppIconSHA256  string
	PolicyID       string
	BrandID        string
}

func capturePortalEdgeContent(expected config.Portal) (portalEdgeContentSnapshot, error) {
	current, err := config.LoadPortal("/etc/workagent/portal.json")
	if err != nil || !reflect.DeepEqual(current, expected) {
		return portalEdgeContentSnapshot{}, errors.Join(errors.New("Portal configuration changed from the protected command snapshot"), err)
	}
	if err := current.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		return portalEdgeContentSnapshot{}, err
	}
	if err := admin.VerifyPortalFiles(current, "/etc/workagent/portal.json"); err != nil {
		return portalEdgeContentSnapshot{}, err
	}
	policy, err := productconfig.LoadPolicy(current.PolicyFile)
	if err != nil {
		return portalEdgeContentSnapshot{}, err
	}
	brand, err := productconfig.LoadBrand(current.BrandFile)
	if err != nil {
		return portalEdgeContentSnapshot{}, err
	}
	digests := make(map[string]string, 7)
	for label, path := range map[string]string{"portal": "/etc/workagent/portal.json", "policy": current.PolicyFile, "brand": current.BrandFile} {
		digest, err := release.ProtectedFileSHA256(path, true)
		if err != nil {
			return portalEdgeContentSnapshot{}, fmt.Errorf("hash protected Portal %s content: %w", label, err)
		}
		digests[label] = digest
	}
	for label, asset := range map[string]string{"logo": "logo", "logo_dark": "logo-dark", "favicon": "favicon", "app_icon": "app-icon"} {
		path, ok := brand.AssetPath(asset)
		if !ok {
			return portalEdgeContentSnapshot{}, fmt.Errorf("resolve protected Portal brand asset %s", asset)
		}
		digest, err := release.ProtectedFileSHA256(path, true)
		if err != nil {
			return portalEdgeContentSnapshot{}, fmt.Errorf("hash protected Portal brand asset %s: %w", asset, err)
		}
		digests[label] = digest
	}
	return portalEdgeContentSnapshot{
		PortalSHA256: digests["portal"], PolicySHA256: digests["policy"], BrandSHA256: digests["brand"], LogoSHA256: digests["logo"],
		LogoDarkSHA256: digests["logo_dark"], FaviconSHA256: digests["favicon"], AppIconSHA256: digests["app_icon"], PolicyID: policy.PolicyID, BrandID: brand.BrandID,
	}, nil
}

func verifyPortalEdgePublicationReadiness(ctx context.Context, portal config.Portal, controller systemdctl.Controller, expectedPolicyID, expectedBrandID string, expectedGeneration *portalEdgeGeneration, throughCaddy bool) (portalEdgeGeneration, error) {
	if ctx == nil || controller == nil {
		return portalEdgeGeneration{}, errors.New("Portal edge-readiness verifier is unavailable")
	}
	before, err := capturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return portalEdgeGeneration{}, err
	}
	if expectedGeneration != nil && before != *expectedGeneration {
		return portalEdgeGeneration{}, errors.New("Portal service generation changed across edge publication")
	}
	if err := admin.VerifyPortalService(ctx, portal, controller); err != nil {
		return portalEdgeGeneration{}, err
	}
	publicOrigin, err := url.Parse(portal.Listener.PublicOrigin)
	if err != nil || publicOrigin.Scheme != "https" || publicOrigin.Host == "" || publicOrigin.Path != "" || publicOrigin.RawQuery != "" || publicOrigin.Fragment != "" {
		return portalEdgeGeneration{}, errors.New("Portal public origin is invalid for edge readiness")
	}
	endpoint := "http://" + portal.Listener.Address + "/readyz"
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext,
		DisableKeepAlives: true,
	}
	if throughCaddy {
		endpoint = strings.TrimSuffix(portal.Listener.PublicOrigin, "/") + "/readyz"
		dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
		transport.DialContext = func(dialContext context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dialContext, "tcp", "127.0.0.1:443")
		}
		transport.ForceAttemptHTTP2 = true
		transport.TLSHandshakeTimeout = 5 * time.Second
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Portal readiness redirected")
		},
	}
	probeContext := ctx
	cancelProbe := func() {}
	if throughCaddy {
		probeContext, cancelProbe = context.WithTimeout(ctx, 2*time.Minute)
	}
	report, probeErr := probePortalEdgeReadiness(probeContext, client, endpoint, publicOrigin.Host, !throughCaddy, throughCaddy)
	cancelProbe()
	transport.CloseIdleConnections()
	if probeErr != nil {
		return portalEdgeGeneration{}, probeErr
	}
	if err := validatePortalEdgeReadinessReport(report, time.Now().UTC(), expectedPolicyID, expectedBrandID); err != nil {
		return portalEdgeGeneration{}, err
	}
	after, err := capturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return portalEdgeGeneration{}, err
	}
	if after != before {
		return portalEdgeGeneration{}, errors.New("Portal service generation or authenticated source changed during readiness proof")
	}
	return after, nil
}

func probePortalEdgeReadiness(ctx context.Context, client *http.Client, endpoint, host string, attestForwardedHTTPS, retry bool) (edgeReadinessReport, error) {
	attempts := 1
	if retry {
		attempts = 16
	}
	var failures []error
	for attempt := 1; attempt <= attempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return edgeReadinessReport{}, err
		}
		request.Host = host
		if attestForwardedHTTPS {
			request.Header.Set("X-Forwarded-Proto", "https")
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			report, responseErr := decodePortalEdgeReadinessResponse(response)
			if responseErr == nil {
				return report, nil
			}
			failures = append(failures, responseErr)
		} else {
			failures = append(failures, requestErr)
		}
		if attempt < attempts {
			select {
			case <-ctx.Done():
				return edgeReadinessReport{}, errors.Join(errors.New("Portal readiness probe was cancelled"), ctx.Err(), errors.Join(failures...))
			case <-time.After(5 * time.Second):
			}
		}
	}
	return edgeReadinessReport{}, errors.Join(errors.New("Portal readiness endpoint did not become ready"), errors.Join(failures...))
}

func decodePortalEdgeReadinessResponse(response *http.Response) (edgeReadinessReport, error) {
	if response == nil || response.Body == nil {
		return edgeReadinessReport{}, errors.New("Portal readiness response is unavailable")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" || response.ContentLength > 256*1024 {
		return edgeReadinessReport{}, errors.New("Portal readiness endpoint did not return an exact JSON success")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if err != nil || len(payload) == 0 || len(payload) > 256*1024 {
		return edgeReadinessReport{}, errors.Join(errors.New("Portal readiness response is invalid or oversized"), err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var report edgeReadinessReport
	if err := decoder.Decode(&report); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return edgeReadinessReport{}, errors.New("Portal readiness response is invalid or oversized")
	}
	return report, nil
}

func validatePortalEdgeReadinessReport(report edgeReadinessReport, now time.Time, expectedPolicyID, expectedBrandID string) error {
	required := []string{"audit", "brand", "chat_forward", "cli_proxy", "database", "host", "notifications", "policy", "renderer", "tenants"}
	now = now.UTC()
	if expectedPolicyID == "" || expectedBrandID == "" || report.Status != "ready" || !report.Ready || report.CheckedAt.Before(now.Add(-30*time.Second)) || report.CheckedAt.After(now.Add(5*time.Second)) || report.PolicyID != expectedPolicyID || report.BrandID != expectedBrandID || len(report.Components) != len(required) {
		return errors.New("Portal readiness response is incomplete")
	}
	for _, component := range required {
		if !report.Components[component].Ready {
			return fmt.Errorf("Portal readiness component %s is not ready", component)
		}
	}
	return nil
}

func capturePortalEdgeGeneration(ctx context.Context, portal config.Portal, controller systemdctl.Controller) (portalEdgeGeneration, error) {
	// Use the same complete manager command vector as every production
	// service-action proof. A Portal restart is part of edge publication, so a
	// manager-only Exec* or privilege-flag drift must fail before the restart
	// and again on each post-restart/readiness capture even when the signed unit
	// files on disk remain unchanged.
	properties := serviceActionPropertyNames(false, "workagent-portal.service")
	before, err := controller.Properties(ctx, "workagent-portal.service", properties...)
	if err != nil {
		return portalEdgeGeneration{}, fmt.Errorf("inspect Portal generation before source authentication: %w", err)
	}
	if err := verifyPortalEdgeManagerContract(before); err != nil {
		return portalEdgeGeneration{}, err
	}
	if err := verifyPortalEdgeUnitSourceAt(before, portal, productionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"}, "/etc/systemd/system"); err != nil {
		return portalEdgeGeneration{}, fmt.Errorf("authenticate Portal unit source: %w", err)
	}
	after, err := controller.Properties(ctx, "workagent-portal.service", properties...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return portalEdgeGeneration{}, errors.Join(errors.New("Portal generation changed during source authentication"), err)
	}
	stamp, stampErr := strconv.ParseUint(after["ActiveEnterTimestampMonotonic"], 10, 64)
	if after["InvocationID"] == "" || stampErr != nil || stamp == 0 {
		return portalEdgeGeneration{}, errors.New("Portal service generation identity is unavailable")
	}
	return portalEdgeGeneration{
		MainPID: after["MainPID"], InvocationID: after["InvocationID"], ActiveEnterTimestampMonotonic: after["ActiveEnterTimestampMonotonic"],
		FragmentPath: after["FragmentPath"], DropInPaths: after["DropInPaths"], ExecStart: after["ExecStart"],
	}, nil
}

func verifyPortalEdgeManagerContract(properties map[string]string) error {
	if err := verifyServiceActionManagerContract("workagent-portal.service", properties); err != nil {
		return fmt.Errorf("Portal manager-loaded definition is not the complete signed production contract: %w", err)
	}
	if properties["UnitFileState"] != "enabled" || !serviceActionServiceRunning(properties) {
		return errors.New("Portal manager-loaded unit or running generation does not match the signed production contract")
	}
	return nil
}

func exactSystemdExec(value, executable, flattenedArgv string) bool {
	prefix := "{ path=" + executable + " ; argv[]=" + flattenedArgv + " ; ignore_errors=no ;"
	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, " }") && strings.Count(value, "{ path=") == 1
}

func exactPrivilegedSystemdExec(value, executable, flattenedArgv string) bool {
	prefix := "{ path=" + executable + " ; argv[]=" + flattenedArgv + " ; flags=privileged ;"
	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, " }") && strings.Count(value, "{ path=") == 1
}

type systemdExecContract struct {
	executable    string
	flattenedArgv string
	privileged    bool
}

func exactSystemdExecSequence(value string, contracts ...systemdExecContract) bool {
	if len(contracts) == 0 || strings.Count(value, "{ path=") != len(contracts) {
		return false
	}
	remaining := value
	for index, contract := range contracts {
		end := strings.Index(remaining, " }")
		if end < 0 {
			return false
		}
		record := remaining[:end+2]
		matches := exactSystemdExec(record, contract.executable, contract.flattenedArgv)
		if contract.privileged {
			matches = exactPrivilegedSystemdExec(record, contract.executable, contract.flattenedArgv)
		}
		if !matches {
			return false
		}
		remaining = remaining[end+2:]
		if index+1 < len(contracts) {
			if !strings.HasPrefix(remaining, " ; ") {
				return false
			}
			remaining = remaining[3:]
		}
	}
	return remaining == ""
}

func verifyPortalEdgeUnitSourceAt(properties map[string]string, portal config.Portal, controlRoot string, systemdRoots []string, dropInRoot string) error {
	if !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || !filepath.IsAbs(dropInRoot) || filepath.Clean(dropInRoot) != dropInRoot || len(systemdRoots) == 0 {
		return errors.New("Portal source verifier layout is invalid")
	}
	fragmentAccepted := false
	for _, root := range systemdRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("Portal systemd source root is invalid")
		}
		if properties["FragmentPath"] == filepath.Join(root, "workagent-portal.service") {
			fragmentAccepted = true
		}
	}
	if !fragmentAccepted {
		return errors.New("Portal fragment path is outside the authenticated systemd namespace")
	}
	fragment := properties["FragmentPath"]
	chatDropIn := filepath.Join(dropInRoot, "workagent-portal.service.d", "chatforward.conf")
	credentialsDropIn := filepath.Join(dropInRoot, "workagent-portal.service.d", "credentials.conf")
	dropIns := strings.Fields(properties["DropInPaths"])
	if len(dropIns) != 2 || !sameExactWords(dropIns, []string{chatDropIn, credentialsDropIn}) {
		return errors.New("Portal drop-in namespace is not exact")
	}
	for _, path := range []string{fragment, chatDropIn, credentialsDropIn} {
		if err := verifyInstalledSystemdSourceFile(path); err != nil {
			return err
		}
	}
	checks := [][2]string{
		{fragment, filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service")},
		{chatDropIn, filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service.d/chatforward.conf")},
	}
	for _, check := range checks {
		installedDigest, err := release.ProtectedFileSHA256(check[0], true)
		if err != nil {
			return err
		}
		referenceDigest, referenceErr := release.ProtectedFileSHA256(check[1], true)
		if referenceErr != nil || installedDigest != referenceDigest {
			return errors.Join(errors.New("Portal unit source does not match the signed control release"), referenceErr)
		}
	}
	expectedCredentialsDigest, err := portalCredentialsReferenceDigest(portal, controlRoot)
	if err != nil {
		return err
	}
	installedCredentialsDigest, err := release.ProtectedFileSHA256(credentialsDropIn, true)
	if err != nil || installedCredentialsDigest != expectedCredentialsDigest {
		return errors.Join(errors.New("Portal credential drop-in does not exactly match the signed production template"), err)
	}
	return nil
}

func verifyInstalledSystemdSourceFile(path string) error {
	info, err := os.Lstat(path)
	stat, ok := infoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.New("installed systemd source file metadata is unsafe")
	}
	return nil
}

func portalCredentialsReferenceDigest(portal config.Portal, controlRoot string) (string, error) {
	referencePath := filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service.d/credentials.conf.example")
	referenceDigest, err := release.ProtectedFileSHA256(referencePath, true)
	if err != nil {
		return "", err
	}
	payload, err := os.ReadFile(referencePath)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(payload)) != referenceDigest {
		return "", errors.Join(errors.New("Portal credential reference changed while it was read"), err)
	}
	if portal.AdminMasterPasswordHashFile != "" {
		const commented = "# LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred"
		const enabled = "LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred"
		if bytes.Count(payload, []byte(commented)) != 1 {
			return "", errors.New("Portal credential reference optional administrator line is not exact")
		}
		payload = bytes.Replace(payload, []byte(commented), []byte(enabled), 1)
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload)), nil
}

func sameExactWords(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	wanted := make(map[string]bool, len(expected))
	for _, value := range expected {
		if value == "" || wanted[value] {
			return false
		}
		wanted[value] = true
	}
	for _, value := range actual {
		if !wanted[value] {
			return false
		}
		delete(wanted, value)
	}
	return len(wanted) == 0
}

func verifyPublishedEdge(ctx context.Context, portal config.Portal, controller systemdctl.Controller, expectedContent portalEdgeContentSnapshot, portalGeneration portalEdgeGeneration) (caddyPublishingGeneration, error) {
	currentContent, err := capturePortalEdgeContent(portal)
	if err != nil || currentContent != expectedContent {
		return caddyPublishingGeneration{}, errors.Join(errors.New("protected Portal content changed before live edge proof"), err)
	}
	if err := admin.AssertTenantFileCatalogClean(portal); err != nil {
		return caddyPublishingGeneration{}, err
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return caddyPublishingGeneration{}, err
	}
	proofErr := errors.Join(
		admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data),
		admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller),
	)
	if err := errors.Join(proofErr, data.Close()); err != nil {
		return caddyPublishingGeneration{}, fmt.Errorf("tenant catalog changed during edge publication: %w", err)
	}
	caddyBefore, err := captureCaddyPublishingGeneration(ctx, controller, nil)
	if err != nil {
		return caddyPublishingGeneration{}, err
	}
	if err := verifyCaddyLiveConfig(ctx, caddyBefore.MainPID); err != nil {
		return caddyPublishingGeneration{}, fmt.Errorf("Caddy live configuration does not match the signed Caddyfile before TLS proof: %w", err)
	}
	if _, err := verifyPortalEdgePublicationReadiness(ctx, portal, controller, expectedContent.PolicyID, expectedContent.BrandID, &portalGeneration, true); err != nil {
		return caddyPublishingGeneration{}, err
	}
	if err := verifyCaddyLiveConfig(ctx, caddyBefore.MainPID); err != nil {
		return caddyPublishingGeneration{}, fmt.Errorf("Caddy live configuration changed during TLS proof: %w", err)
	}
	caddyAfter, err := captureCaddyPublishingGeneration(ctx, controller, &caddyBefore)
	if err != nil {
		return caddyPublishingGeneration{}, err
	}
	if caddyAfter != caddyBefore {
		return caddyPublishingGeneration{}, errors.New("Caddy generation changed during the live TLS edge-readiness proof")
	}
	currentContent, err = capturePortalEdgeContent(portal)
	if err != nil || currentContent != expectedContent {
		return caddyPublishingGeneration{}, errors.Join(errors.New("protected Portal content changed during live edge proof"), err)
	}
	return caddyAfter, nil
}

func verifyCaddyLiveConfig(ctx context.Context, expectedPID string) error {
	account, err := user.Lookup("caddy")
	if err != nil {
		return fmt.Errorf("lookup Caddy service identity: %w", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	pid, pidErr := strconv.ParseUint(expectedPID, 10, 31)
	if uidErr != nil || gidErr != nil || pidErr != nil || pid == 0 {
		return errors.New("Caddy service identity or generation PID is invalid")
	}
	return verifyCaddyLiveConfigAt(ctx, "/run/caddy-admin/admin.sock", filepath.Join(productionControlRoot, "share/deploy/caddy/Caddyfile"), int32(pid), uint32(uid), uint32(gid))
}

func verifyCaddyLiveConfigAt(ctx context.Context, socketPath, signedCaddyfilePath string, expectedPID int32, expectedUID, expectedGID uint32) error {
	if ctx == nil || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || !filepath.IsAbs(signedCaddyfilePath) || filepath.Clean(signedCaddyfilePath) != signedCaddyfilePath {
		return errors.New("Caddy live-config verifier layout is invalid")
	}
	parentPath := filepath.Dir(socketPath)
	parentInfo, parentErr := os.Lstat(parentPath)
	parentStat, parentOK := infoSyscallStat(parentInfo)
	socketInfo, socketErr := os.Lstat(socketPath)
	socketStat, socketOK := infoSyscallStat(socketInfo)
	if parentErr != nil || !parentOK || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 || parentStat.Uid != expectedUID || parentStat.Gid != expectedGID {
		return errors.Join(errors.New("Caddy protected admin directory is missing or unsafe"), parentErr)
	}
	if socketErr != nil || !socketOK || socketInfo.Mode()&os.ModeSymlink != 0 || socketInfo.Mode()&os.ModeSocket == 0 || socketStat.Uid != expectedUID || socketStat.Gid != expectedGID || socketStat.Nlink != 1 {
		return errors.Join(errors.New("Caddy protected admin socket is missing or unsafe"), socketErr)
	}
	referenceDigest, err := release.ProtectedFileSHA256(signedCaddyfilePath, true)
	if err != nil {
		return err
	}
	caddyfile, err := os.ReadFile(signedCaddyfilePath)
	if err != nil || len(caddyfile) == 0 || len(caddyfile) > 1024*1024 || fmt.Sprintf("%x", sha256.Sum256(caddyfile)) != referenceDigest {
		return errors.Join(errors.New("signed Caddyfile changed while it was read"), err)
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
			connection, err := dialer.DialContext(dialContext, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			if err := verifyUnixPeerCredentials(connection, expectedPID, expectedUID, expectedGID); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return connection, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Caddy admin API redirected")
	}}
	defer transport.CloseIdleConnections()
	adapted, err := requestCaddyAdminJSON(ctx, client, http.MethodPost, "http://localhost/adapt", bytes.NewReader(caddyfile), "text/caddyfile")
	if err != nil {
		return fmt.Errorf("adapt signed Caddyfile through the running Caddy generation: %w", err)
	}
	live, err := requestCaddyAdminJSON(ctx, client, http.MethodGet, "http://localhost/config/", nil, "")
	if err != nil {
		return fmt.Errorf("read running Caddy configuration: %w", err)
	}
	if !bytes.Equal(adapted, live) {
		return errors.New("running Caddy configuration is not semantically equal to the signed Caddyfile")
	}
	parentAfter, parentAfterErr := os.Lstat(parentPath)
	parentAfterStat, parentAfterOK := infoSyscallStat(parentAfter)
	socketAfter, socketAfterErr := os.Lstat(socketPath)
	socketAfterStat, socketAfterOK := infoSyscallStat(socketAfter)
	if parentAfterErr != nil || socketAfterErr != nil || !parentAfterOK || !socketAfterOK || parentAfterStat.Dev != parentStat.Dev || parentAfterStat.Ino != parentStat.Ino || parentAfterStat.Mode != parentStat.Mode || parentAfterStat.Uid != parentStat.Uid || parentAfterStat.Gid != parentStat.Gid || socketAfterStat.Dev != socketStat.Dev || socketAfterStat.Ino != socketStat.Ino || socketAfterStat.Mode != socketStat.Mode || socketAfterStat.Uid != socketStat.Uid || socketAfterStat.Gid != socketStat.Gid || socketAfterStat.Nlink != socketStat.Nlink {
		return errors.New("Caddy admin socket identity changed during live-config proof")
	}
	return nil
}

func verifyUnixPeerCredentials(connection net.Conn, expectedPID int32, expectedUID, expectedGID uint32) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("Caddy admin connection is not a Unix stream")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credentials *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil || credentials == nil || credentials.Pid != expectedPID || credentials.Uid != expectedUID || credentials.Gid != expectedGID {
		return errors.Join(errors.New("Caddy admin socket peer is not the authenticated service generation"), controlErr)
	}
	return nil
}

func requestCaddyAdminJSON(ctx context.Context, client *http.Client, method, endpoint string, body io.Reader, contentType string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" || response.ContentLength > 4*1024*1024 || len(response.Header.Values("Warning")) != 0 {
		return nil, errors.New("Caddy admin API did not return an exact JSON success")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil || len(payload) == 0 || len(payload) > 4*1024*1024 {
		return nil, errors.Join(errors.New("Caddy admin JSON response is invalid or oversized"), err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("Caddy admin response is not exactly one JSON value")
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, errors.New("Caddy admin response is not a non-empty configuration object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func captureCaddyPublishingGeneration(ctx context.Context, controller systemdctl.Controller, expected *caddyPublishingGeneration) (caddyPublishingGeneration, error) {
	properties := serviceActionPropertyNames(false, "caddy.service")
	before, err := controller.Properties(ctx, "caddy.service", properties...)
	if err != nil {
		return caddyPublishingGeneration{}, err
	}
	if err := authenticateCaddyServiceActionState("caddy.service", before, verifyProductionServiceActionSource); err != nil {
		return caddyPublishingGeneration{}, err
	}
	generation, err := caddyPublishingGenerationFromProperties(before)
	if err != nil {
		return caddyPublishingGeneration{}, err
	}
	if expected != nil && generation != *expected {
		return caddyPublishingGeneration{}, errors.New("Caddy publishing generation changed from its authenticated boundary")
	}
	after, err := controller.Properties(ctx, "caddy.service", properties...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return caddyPublishingGeneration{}, errors.Join(errors.New("Caddy publishing generation changed during source authentication"), err)
	}
	return generation, nil
}

func caddyPublishingGenerationFromProperties(properties map[string]string) (caddyPublishingGeneration, error) {
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 31)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 31)
	started, startErr := strconv.ParseUint(properties["ExecMainStartTimestampMonotonic"], 10, 64)
	if properties["LoadState"] != "loaded" || properties["UnitFileState"] != "enabled" || properties["ActiveState"] != "activating" || properties["SubState"] != "start-post" ||
		properties["Result"] != "success" || properties["InvocationID"] == "" || mainErr != nil || controlErr != nil || startErr != nil || mainPID == 0 || controlPID == 0 || mainPID == controlPID || started == 0 {
		return caddyPublishingGeneration{}, errors.New("Caddy did not enter the exact guarded start-post publication state")
	}
	return caddyPublishingGeneration{
		MainPID: properties["MainPID"], ControlPID: properties["ControlPID"], InvocationID: properties["InvocationID"],
		ExecMainStartTimestampMonotonic: properties["ExecMainStartTimestampMonotonic"], FragmentPath: properties["FragmentPath"], DropInPaths: properties["DropInPaths"],
		ExecStart: properties["ExecStart"], ExecStartPre: properties["ExecStartPre"], ExecStartPost: properties["ExecStartPost"],
	}, nil
}

func settleCommittedCaddyEdge(ctx context.Context, controller systemdctl.Controller, expected caddyPublishingGeneration) error {
	if ctx == nil || controller == nil || expected.MainPID == "" || expected.InvocationID == "" {
		return errors.New("Caddy committed-generation settlement boundary is unavailable")
	}
	propertyNames := serviceActionPropertyNames(false, "caddy.service")
	var failures []error
	for attempt := 1; attempt <= 100; attempt++ {
		properties, err := controller.Properties(ctx, "caddy.service", propertyNames...)
		if err != nil {
			return fmt.Errorf("read Caddy manager state while its committed watcher settled: %w", err)
		}
		authErr := authenticateCaddyServiceActionState("caddy.service", properties, verifyProductionServiceActionSource)
		stamp, stampErr := strconv.ParseUint(properties["ActiveEnterTimestampMonotonic"], 10, 64)
		stable := properties["MainPID"] == expected.MainPID && properties["InvocationID"] == expected.InvocationID &&
			properties["ExecMainStartTimestampMonotonic"] == expected.ExecMainStartTimestampMonotonic && properties["FragmentPath"] == expected.FragmentPath &&
			properties["DropInPaths"] == expected.DropInPaths && properties["ExecStart"] == expected.ExecStart && properties["ExecStartPre"] == expected.ExecStartPre && properties["ExecStartPost"] == expected.ExecStartPost
		if authErr != nil || !stable {
			return errors.Join(errors.New("Caddy generation or authenticated source changed while its committed watcher settled"), authErr, errorUnless(stable, "Caddy committed generation identity changed"))
		}
		settled := properties["LoadState"] == "loaded" && properties["UnitFileState"] == "enabled" && properties["ActiveState"] == "active" && properties["SubState"] == "running" &&
			properties["ControlPID"] == "0" && properties["Result"] == "success" && stampErr == nil && stamp > 0
		if settled {
			after, readErr := controller.Properties(ctx, "caddy.service", propertyNames...)
			if readErr == nil && reflect.DeepEqual(properties, after) {
				return nil
			}
			return errors.Join(errors.New("Caddy settled generation changed during final authentication"), readErr)
		}
		stillGuarded := properties["ActiveState"] == "activating" && properties["SubState"] == "start-post" && properties["ControlPID"] == expected.ControlPID && properties["Result"] == "success"
		if !stillGuarded {
			return errors.New("Caddy left its exact guarded start-post state without settling active/running")
		}
		failures = append(failures, errors.New("Caddy publication watcher is still settling"))
		if attempt < 100 {
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), errors.Join(failures...))
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return errors.Join(errors.New("Caddy publication watcher did not settle the committed generation"), errors.Join(failures...))
}

func rollbackPublishedCaddyFailClosed(ctx context.Context, controller systemdctl.Controller) error {
	properties := serviceActionPropertyNames(false, "caddy.service")
	return disableCaddyFailClosed(ctx, controller, properties, verifyProductionServiceActionSource)
}

type serviceActionSourceVerifier func(string, map[string]string) error
type serviceActionDependencyVerifier func(context.Context, systemdctl.Controller, string) error
type edgeEvidenceVerifier func() error

func executeAllowlistedServiceAction(ctx context.Context, controller systemdctl.Controller, action, unit string) error {
	return executeAllowlistedServiceActionWithDependencyVerifier(ctx, controller, action, unit, verifyProductionServiceActionSource, verifyProductionServiceActionDependencies)
}

func executeAllowlistedServiceActionWithVerifier(ctx context.Context, controller systemdctl.Controller, action, unit string, verifySource serviceActionSourceVerifier) error {
	return executeAllowlistedServiceActionWithDependencyVerifier(ctx, controller, action, unit, verifySource, nil)
}

func executeAllowlistedServiceActionWithDependencyVerifier(ctx context.Context, controller systemdctl.Controller, action, unit string, verifySource serviceActionSourceVerifier, verifyDependencies serviceActionDependencyVerifier) error {
	if ctx == nil || controller == nil || verifySource == nil {
		return errors.New("service-action controller is unavailable")
	}
	allowed, ok := serviceActionAllowlist[unit]
	if !ok || !allowed[action] {
		return errors.New("service-action unit/action pair is not allow-listed")
	}
	isTimer := strings.HasSuffix(unit, ".timer")
	if unit == "caddy.service" {
		return executeCaddyEdgeCommit(ctx, controller, verifySource, func() error { return nil })
	}
	propertyNames := serviceActionPropertyNames(isTimer, unit)
	before, err := controller.Properties(ctx, unit, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect %s before %s: %w", unit, action, err)
	}
	if err := verifyServiceActionPrecondition(action, isTimer, before); err != nil {
		return err
	}
	if err := verifySource(unit, before); err != nil {
		return fmt.Errorf("authenticate %s unit source before %s: %w", unit, action, err)
	}
	if verifyDependencies != nil {
		if err := verifyDependencies(ctx, controller, unit); err != nil {
			return fmt.Errorf("authenticate %s target dependency before %s: %w", unit, action, err)
		}
	}
	effectiveAction := action
	if unit == "cliproxyapi.service" && action == "start" && serviceActionServiceRunning(before) {
		effectiveAction = "restart"
	}
	if effectiveAction != "restart" {
		if err := verifyServiceActionDesired(effectiveAction, isTimer, before, before); err == nil {
			return nil
		}
	}
	arguments := []string{effectiveAction, unit}
	if effectiveAction == "enable-now" {
		arguments = []string{"enable", "--now", unit}
	}
	var attempts []error
	var observed map[string]string
	for attempt := 1; attempt <= 2; attempt++ {
		actionErr := controller.Action(ctx, arguments...)
		properties, readErr := controller.Properties(ctx, unit, propertyNames...)
		if readErr == nil {
			observed = properties
			sourceErr := verifySource(unit, properties)
			var dependencyErr error
			if verifyDependencies != nil {
				dependencyErr = verifyDependencies(ctx, controller, unit)
			}
			if sourceErr != nil || dependencyErr != nil {
				cause := errors.Join(errors.New("service-action result is unsafe because its unit or target dependency failed authentication after mutation"), actionErr, sourceErr, dependencyErr)
				if isTimer {
					rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
						return disableTimerFailClosed(cleanupContext, controller, unit, propertyNames, verifySource)
					})
					if rollbackErr == nil {
						return errors.Join(errors.New("timer mutation was durably disabled after authentication failure"), cause)
					}
					return errors.Join(errors.New("timer mutation and its durable final state are ambiguous"), cause, rollbackErr)
				}
				if effectiveAction == "start" || effectiveAction == "restart" {
					compensationErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
						return compensateServiceActionToInactive(cleanupContext, controller, unit, false, before, propertyNames, verifySource)
					})
					return errors.Join(cause, compensationErr)
				}
				return cause
			}
			if properties["FragmentPath"] != before["FragmentPath"] || properties["DropInPaths"] != before["DropInPaths"] ||
				(effectiveAction != "enable-now" && properties["UnitFileState"] != before["UnitFileState"]) {
				return errors.Join(errors.New("service-action result is ambiguous because authenticated source or persistent state changed"), actionErr)
			}
			proofErr := verifyServiceActionDesired(effectiveAction, isTimer, before, properties)
			if proofErr == nil {
				return nil
			}
			attempts = append(attempts, errors.Join(actionErr, proofErr))
		} else {
			attempts = append(attempts, errors.Join(actionErr, fmt.Errorf("read back %s after %s attempt %d: %w", unit, action, attempt, readErr)))
		}
	}
	cause := errors.Join(attempts...)
	if effectiveAction == "enable-now" {
		if verifyDependencies != nil {
			if dependencyErr := verifyDependencies(ctx, controller, unit); dependencyErr != nil {
				rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
					return disableTimerFailClosed(cleanupContext, controller, unit, propertyNames, verifySource)
				})
				return errors.Join(errors.New("timer target dependency changed before durable settlement"), cause, dependencyErr, rollbackErr)
			}
		}
		return withServiceActionCleanup(func(cleanupContext context.Context) error {
			return settleFailedEnableNow(cleanupContext, controller, unit, isTimer, before, observed, propertyNames, verifySource, cause)
		})
	}
	if effectiveAction == "start" || effectiveAction == "restart" {
		compensationErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
			return compensateServiceActionToInactive(cleanupContext, controller, unit, isTimer, before, propertyNames, verifySource)
		})
		if compensationErr == nil {
			return errors.Join(errors.New("service action failed after retry and was compensated to a proved inactive state"), cause)
		}
		return errors.Join(errors.New("service action failed after retry and its final state is ambiguous"), cause, compensationErr)
	}
	return errors.Join(errors.New("stop service action failed after retry and its final state is ambiguous"), cause)
}

func executeCaddyEdgeCommit(ctx context.Context, controller systemdctl.Controller, verifySource serviceActionSourceVerifier, verifyEvidence edgeEvidenceVerifier) error {
	const unit = "caddy.service"
	if verifyEvidence == nil {
		return errors.New("Caddy edge-evidence verifier is unavailable")
	}
	if err := verifyEvidence(); err != nil {
		return fmt.Errorf("authenticate edge-publication evidence before manager reload: %w", err)
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd manager immediately before Caddy publication: %w", err)
	}
	propertyNames := serviceActionPropertyNames(false, unit)
	before, err := controller.Properties(ctx, unit, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect Caddy after manager reload: %w", err)
	}
	if err := verifyServiceActionPrecondition("enable-now", false, before); err != nil {
		return err
	}
	if err := authenticateCaddyServiceActionState(unit, before, verifySource); err != nil {
		return fmt.Errorf("authenticate Caddy after manager reload: %w", err)
	}
	if before["UnitFileState"] != "disabled" || !serviceActionUnitStopped(false, before) {
		return errors.New("Caddy publication requires an exactly disabled, inactive, and process-free starting state")
	}
	if err := verifyEvidence(); err != nil {
		return fmt.Errorf("edge-publication evidence changed before durable Caddy enablement: %w", err)
	}
	var enableFailures []error
	var enabled map[string]string
	for attempt := 1; attempt <= 2; attempt++ {
		actionErr := controller.Action(ctx, "enable", unit)
		properties, readErr := controller.Properties(ctx, unit, propertyNames...)
		if readErr == nil {
			authErr := authenticateCaddyServiceActionState(unit, properties, verifySource)
			stableSource := properties["FragmentPath"] == before["FragmentPath"] && properties["DropInPaths"] == before["DropInPaths"]
			persistedInactive := properties["UnitFileState"] == "enabled" && serviceActionUnitStopped(false, properties)
			var durabilityErr error
			if authErr == nil && stableSource && persistedInactive {
				durabilityErr = syncCaddyEnablementForAction(true, properties["FragmentPath"])
			}
			if authErr == nil && stableSource && persistedInactive && durabilityErr == nil {
				enabled = properties
				break
			}
			enableFailures = append(enableFailures, errors.Join(actionErr, authErr, durabilityErr, errorUnless(stableSource, "Caddy authenticated source changed while enabling"), errorUnless(persistedInactive, "Caddy did not remain inactive while its durable enablement was committed")))
		} else {
			enableFailures = append(enableFailures, errors.Join(actionErr, readErr))
		}
	}
	if enabled == nil {
		rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
			return disableCaddyFailClosed(cleanupContext, controller, propertyNames, verifySource)
		})
		if rollbackErr == nil {
			return errors.Join(errors.New("Caddy enablement failed and was durably disabled before publication"), errors.Join(enableFailures...))
		}
		return errors.Join(errors.New("Caddy enablement failed and its durable final state is ambiguous"), errors.Join(enableFailures...), rollbackErr)
	}
	if err := verifyEvidence(); err != nil {
		return failCaddyGuardedStart(controller, propertyNames, verifySource, fmt.Errorf("edge-publication evidence changed after durable Caddy enablement: %w", err))
	}
	startErr := controller.Action(ctx, "start", "--no-block", unit)
	var startFailures []error
	for attempt := 1; attempt <= 600; attempt++ {
		properties, readErr := controller.Properties(ctx, unit, propertyNames...)
		if readErr == nil {
			evidenceErr := verifyEvidence()
			authErr := authenticateCaddyServiceActionState(unit, properties, verifySource)
			stableSource := properties["FragmentPath"] == enabled["FragmentPath"] && properties["DropInPaths"] == enabled["DropInPaths"] && properties["UnitFileState"] == "enabled"
			if evidenceErr != nil || authErr != nil || !stableSource {
				return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy guarded startup lost authenticated source, durable enablement, or publication authority"), startErr, evidenceErr, authErr, errorUnless(stableSource, "Caddy source or durable enablement changed during guarded startup")))
			}
			generation, generationErr := caddyPublishingGenerationFromProperties(properties)
			newInvocation := generationErr == nil && generation.InvocationID != "" && generation.InvocationID != before["InvocationID"]
			if generationErr == nil && newInvocation {
				after, stableErr := controller.Properties(ctx, unit, propertyNames...)
				finalEvidenceErr := verifyEvidence()
				if stableErr == nil && finalEvidenceErr == nil && reflect.DeepEqual(properties, after) {
					return nil
				}
				return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy guarded start-post generation or evidence changed during authentication"), startErr, stableErr, finalEvidenceErr, errorUnless(reflect.DeepEqual(properties, after), "Caddy guarded generation was unstable")))
			}
			if !caddySafePublicationTransition(properties, before, attempt) {
				return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy entered an impossible state before edge-publication commit"), startErr, generationErr, errorUnless(newInvocation, "Caddy guarded invocation identity is invalid")))
			}
			startFailures = append(startFailures, generationErr)
		} else {
			return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy manager state became unreadable after guarded start mutation"), startErr, readErr))
		}
		if attempt < 600 {
			select {
			case <-ctx.Done():
				attempt = 600
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return disableCaddyFailClosed(cleanupContext, controller, propertyNames, verifySource)
	})
	if rollbackErr == nil {
		return errors.Join(errors.New("Caddy failed to enter a new authenticated guarded start-post generation and was durably disabled"), startErr, errors.Join(startFailures...))
	}
	return errors.Join(errors.New("Caddy guarded startup failed and its durable final state is ambiguous"), startErr, errors.Join(startFailures...), rollbackErr)
}

func caddySafePublicationTransition(properties, before map[string]string, attempt int) bool {
	if properties["LoadState"] != "loaded" || properties["UnitFileState"] != "enabled" || properties["Result"] != "success" {
		return false
	}
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 31)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 31)
	if mainErr != nil || controlErr != nil {
		return false
	}
	if properties["ActiveState"] == "inactive" && properties["SubState"] == "dead" {
		return attempt <= 20 && mainPID == 0 && controlPID == 0 && properties["InvocationID"] == before["InvocationID"]
	}
	if properties["ActiveState"] != "activating" || properties["InvocationID"] == "" || properties["InvocationID"] == before["InvocationID"] {
		return false
	}
	switch properties["SubState"] {
	case "start-pre":
		return mainPID == 0 && controlPID > 0
	case "start":
		return mainPID > 0
	default:
		return false
	}
}

func failCaddyGuardedStart(controller systemdctl.Controller, propertyNames []string, verifySource serviceActionSourceVerifier, cause error) error {
	rollbackErr := withServiceActionCleanup(func(cleanupContext context.Context) error {
		return disableCaddyFailClosed(cleanupContext, controller, propertyNames, verifySource)
	})
	if rollbackErr == nil {
		return errors.Join(errors.New("Caddy guarded startup was rejected and durably disabled"), cause)
	}
	return errors.Join(errors.New("Caddy guarded startup was rejected and its final state is ambiguous"), cause, rollbackErr)
}

func errorUnless(condition bool, message string) error {
	if condition {
		return nil
	}
	return errors.New(message)
}

func withServiceActionCleanup(operation func(context.Context) error) error {
	if operation == nil {
		return errors.New("service-action cleanup operation is unavailable")
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return operation(cleanupContext)
}

func disableCaddyFailClosed(ctx context.Context, controller systemdctl.Controller, propertyNames []string, verifySource serviceActionSourceVerifier) error {
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		before, beforeErr := controller.Properties(ctx, "caddy.service", propertyNames...)
		var beforeAuthErr error
		if beforeErr == nil {
			beforeAuthErr = authenticateCaddyServiceActionState("caddy.service", before, verifySource)
		}
		actionErr := controller.Action(ctx, "disable", "--now", "caddy.service")
		properties, readErr := controller.Properties(ctx, "caddy.service", propertyNames...)
		if readErr == nil {
			authErr := authenticateCaddyServiceActionState("caddy.service", properties, verifySource)
			stableSource := beforeErr == nil && before["FragmentPath"] == properties["FragmentPath"] && before["DropInPaths"] == properties["DropInPaths"]
			var durabilityErr error
			if authErr == nil && properties["UnitFileState"] == "disabled" {
				durabilityErr = syncCaddyEnablementForAction(false, properties["FragmentPath"])
			}
			if beforeErr == nil && beforeAuthErr == nil && authErr == nil && stableSource && durabilityErr == nil && properties["UnitFileState"] == "disabled" && serviceActionUnitStopped(false, properties) {
				after, stableErr := controller.Properties(ctx, "caddy.service", propertyNames...)
				if stableErr == nil && reflect.DeepEqual(properties, after) {
					return nil
				}
				failures = append(failures, errors.Join(actionErr, errors.New("cleanly stopped Caddy changed during fail-closed authentication"), stableErr))
				continue
			}
			if beforeErr == nil && beforeAuthErr == nil && authErr == nil && stableSource && durabilityErr == nil && properties["UnitFileState"] == "disabled" && caddyTerminalProcessFree(properties) {
				resetErr := controller.Action(ctx, "reset-failed", "caddy.service")
				settled, settleErr := controller.Properties(ctx, "caddy.service", propertyNames...)
				settledAuthErr := authenticateCaddyServiceActionState("caddy.service", settled, verifySource)
				if resetErr == nil && settleErr == nil && settledAuthErr == nil && settled["UnitFileState"] == "disabled" && serviceActionUnitStopped(false, settled) {
					after, stableErr := controller.Properties(ctx, "caddy.service", propertyNames...)
					if stableErr == nil && reflect.DeepEqual(settled, after) {
						return nil
					}
					failures = append(failures, errors.Join(actionErr, resetErr, errors.New("reset Caddy failure state changed during final authentication"), stableErr))
					continue
				}
				failures = append(failures, errors.Join(actionErr, resetErr, settleErr, settledAuthErr, errors.New("Caddy failure state did not reset to disabled, inactive, and process-free")))
				continue
			}
			failures = append(failures, errors.Join(beforeErr, beforeAuthErr, actionErr, authErr, durabilityErr, errorUnless(stableSource, "Caddy manager source changed during fail-closed disable"), errors.New("Caddy did not read back as authenticated, durably disabled, and inactive")))
		} else {
			failures = append(failures, errors.Join(beforeErr, beforeAuthErr, actionErr, readErr))
		}
	}
	return errors.Join(failures...)
}

func caddyTerminalProcessFree(properties map[string]string) bool {
	if properties["MainPID"] != "0" || properties["ControlPID"] != "0" {
		return false
	}
	return (properties["ActiveState"] == "inactive" && properties["SubState"] == "dead") ||
		(properties["ActiveState"] == "failed" && properties["SubState"] == "failed")
}

func syncCaddyPersistentEnablement(enabled bool, fragmentPath string) error {
	const systemdRoot = "/etc/systemd/system"
	const wantsDirectory = "/etc/systemd/system/multi-user.target.wants"
	const linkPath = wantsDirectory + "/caddy.service"
	if fragmentPath != "/usr/lib/systemd/system/caddy.service" {
		return errors.New("Caddy fragment path is invalid for persistent enablement")
	}
	for _, directory := range []string{systemdRoot, wantsDirectory} {
		info, err := os.Lstat(directory)
		stat, ok := infoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o755 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("Caddy enablement directory %s is unsafe", directory), err)
		}
	}
	if err := verifyCaddyEnablementEntry(linkPath, fragmentPath, enabled); err != nil {
		return err
	}
	if err := syncEdgeDirectory(wantsDirectory); err != nil {
		return fmt.Errorf("durably sync Caddy enablement directory: %w", err)
	}
	if err := syncEdgeDirectory(systemdRoot); err != nil {
		return fmt.Errorf("durably sync systemd configuration directory: %w", err)
	}
	return verifyCaddyEnablementEntry(linkPath, fragmentPath, enabled)
}

func verifyCaddyEnablementEntry(linkPath, fragmentPath string, enabled bool) error {
	info, err := os.Lstat(linkPath)
	if !enabled {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.Join(errors.New("Caddy persistent enablement entry still exists or is unreadable"), err)
	}
	stat, ok := infoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.Join(errors.New("Caddy persistent enablement symlink is unsafe"), err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil || target != fragmentPath {
		return errors.Join(errors.New("Caddy persistent enablement symlink target is not exact"), err)
	}
	return nil
}

func authenticateCaddyServiceActionState(unit string, properties map[string]string, verifySource serviceActionSourceVerifier) error {
	return errors.Join(verifySource(unit, properties), verifyCaddyManagerContract(properties))
}

func verifyCaddyManagerContract(properties map[string]string) error {
	const start = "/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile"
	const reload = "/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force"
	const coreAdmit = "/usr/libexec/workagent-core-activation-admission-v1"
	const admit = "/usr/libexec/workagent-edge-publication-admission-v1"
	const watch = "/usr/libexec/workagent-edge-publication-admission-v1 --watch $MAINPID"
	contract := func(executable, arguments string, privileged bool) systemdExecContract {
		return systemdExecContract{executable: executable, flattenedArgv: arguments, privileged: privileged}
	}
	if properties["NeedDaemonReload"] != "no" || properties["Type"] != "notify" || properties["User"] != "caddy" || properties["Group"] != "caddy" ||
		properties["RuntimeDirectory"] != "caddy-admin" || properties["RuntimeDirectoryMode"] != "0700" ||
		properties["TimeoutStartUSec"] != "6min" || properties["TimeoutStartFailureMode"] != "kill" || properties["KillMode"] != "control-group" ||
		properties["SendSIGKILL"] != "yes" || properties["FinalKillSignal"] != "9" || properties["Restart"] != "no" ||
		properties["NoNewPrivileges"] != "yes" || properties["AmbientCapabilities"] != "cap_net_bind_service" || properties["CapabilityBoundingSet"] != "cap_net_bind_service" ||
		!exactCoreManagerExecVector(properties["ExecStart"], properties["ExecStartEx"], []systemdExecContract{contract("/usr/bin/caddy", start, false)}) ||
		!exactCoreManagerExecVector(properties["ExecStartPre"], properties["ExecStartPreEx"], []systemdExecContract{
			contract("/usr/libexec/workagent-core-activation-admission-v1", coreAdmit, true),
			contract("/usr/libexec/workagent-edge-publication-admission-v1", admit, true),
		}) ||
		!exactCoreManagerExecVector(properties["ExecStartPost"], properties["ExecStartPostEx"], []systemdExecContract{
			contract("/usr/libexec/workagent-edge-publication-admission-v1", watch, true),
		}) ||
		!exactCoreManagerExecVector(properties["ExecReload"], properties["ExecReloadEx"], []systemdExecContract{contract("/usr/bin/caddy", reload, false)}) ||
		!exactCoreManagerExecVector(properties["ExecStop"], properties["ExecStopEx"], nil) ||
		!exactCoreManagerExecVector(properties["ExecStopPost"], properties["ExecStopPostEx"], nil) {
		return errors.New("Caddy manager-loaded unit does not match the signed production contract")
	}
	return nil
}

func serviceActionPropertyNames(isTimer bool, unit string) []string {
	properties := []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"}
	if !isTimer {
		properties = append(properties, "MainPID", "ControlPID", "Result", "InvocationID", "ActiveEnterTimestampMonotonic")
	}
	switch unit {
	case "caddy.service":
		properties = append(properties, "ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx", "ExecMainStartTimestampMonotonic", "TimeoutStartUSec", "TimeoutStartFailureMode", "KillMode", "SendSIGKILL", "FinalKillSignal", "Restart", "Type", "User", "Group", "RuntimeDirectory", "RuntimeDirectoryMode", "NoNewPrivileges", "AmbientCapabilities", "CapabilityBoundingSet")
	case "workagent-tenant-config-reconcile.service", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", "workagent-chatforward-browser.service", "workagent-portal.service", "workagent-backup.service", "workagent-healthcheck.service":
		properties = append(properties, "ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx", "Type", "User", "Group")
	case "workagent-backup.timer", "workagent-healthcheck.timer":
		properties = append(properties, "Unit", "Persistent")
	}
	return properties
}

func verifyServiceActionPrecondition(action string, isTimer bool, properties map[string]string) error {
	if properties["LoadState"] != "loaded" || properties["FragmentPath"] == "" || properties["UnitFileState"] == "" || (!isTimer && properties["ControlPID"] != "0") {
		return errors.New("service-action unit source or persistent state is unavailable before mutation")
	}
	if action == "enable-now" {
		if properties["UnitFileState"] != "disabled" && properties["UnitFileState"] != "enabled" {
			return errors.New("enable-now requires an exactly disabled or already-enabled persistent unit")
		}
		return nil
	}
	if isTimer {
		return errors.New("transient service actions do not accept timer units")
	}
	running := serviceActionServiceRunning(properties)
	stopped := serviceActionUnitStopped(false, properties)
	switch action {
	case "start":
		if !running && !stopped {
			return errors.New("start requires an exactly running or cleanly stopped service")
		}
	case "stop":
		if !running && !stopped {
			return errors.New("stop requires an exactly running or cleanly stopped service")
		}
	case "restart":
		if !running {
			return errors.New("restart requires an exactly running service generation")
		}
	default:
		return errors.New("service-action operation is invalid")
	}
	return nil
}

func verifyServiceActionDesired(action string, isTimer bool, before, properties map[string]string) error {
	if properties["LoadState"] != "loaded" || (!isTimer && properties["ControlPID"] != "0") {
		return errors.New("service-action unit did not read back as loaded and control-process-free")
	}
	if action == "stop" {
		if !serviceActionUnitStopped(isTimer, properties) {
			return errors.New("stopped service-action unit is not inactive and process-free")
		}
		return nil
	}
	if isTimer {
		if properties["ActiveState"] != "active" || properties["SubState"] != "waiting" || properties["UnitFileState"] != "enabled" {
			return errors.New("started service-action timer is not active, waiting, and persistently enabled")
		}
		return nil
	}
	if !serviceActionServiceRunning(properties) || (action == "enable-now" && properties["UnitFileState"] != "enabled") {
		return errors.New("started service-action service is not active, running, and process-backed")
	}
	if action == "start" || action == "restart" {
		beforeStamp, beforeErr := strconv.ParseUint(before["ActiveEnterTimestampMonotonic"], 10, 64)
		afterStamp, afterErr := strconv.ParseUint(properties["ActiveEnterTimestampMonotonic"], 10, 64)
		if properties["InvocationID"] == "" || properties["InvocationID"] == before["InvocationID"] || afterErr != nil || afterStamp == 0 ||
			(action == "restart" && (before["InvocationID"] == "" || beforeErr != nil || afterStamp <= beforeStamp)) ||
			(action == "start" && beforeErr == nil && afterStamp <= beforeStamp) {
			return errors.New("started service-action unit did not enter a new invocation")
		}
	}
	return nil
}

func serviceActionServiceRunning(properties map[string]string) bool {
	mainPID, err := strconv.ParseUint(properties["MainPID"], 10, 64)
	return err == nil && mainPID > 0 && properties["ActiveState"] == "active" && properties["SubState"] == "running" &&
		properties["ControlPID"] == "0" && properties["Result"] == "success"
}

func serviceActionUnitStopped(isTimer bool, properties map[string]string) bool {
	if properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" {
		return false
	}
	if isTimer {
		return true
	}
	return properties["MainPID"] == "0" && properties["ControlPID"] == "0" && properties["Result"] == "success"
}

func compensateServiceActionToInactive(ctx context.Context, controller systemdctl.Controller, unit string, isTimer bool, before map[string]string, propertyNames []string, verifySource serviceActionSourceVerifier) error {
	actionErr := controller.Action(ctx, "stop", unit)
	properties, readErr := controller.Properties(ctx, unit, propertyNames...)
	if readErr != nil {
		return errors.Join(actionErr, readErr)
	}
	if sourceErr := verifySource(unit, properties); sourceErr != nil {
		return errors.Join(actionErr, sourceErr)
	}
	if properties["FragmentPath"] != before["FragmentPath"] || properties["DropInPaths"] != before["DropInPaths"] || properties["UnitFileState"] != before["UnitFileState"] || !serviceActionUnitStopped(isTimer, properties) {
		return errors.Join(actionErr, errors.New("service-action inactive compensation did not read back exactly"))
	}
	return nil
}

func settleFailedEnableNow(ctx context.Context, controller systemdctl.Controller, unit string, isTimer bool, before, observed map[string]string, propertyNames []string, verifySource serviceActionSourceVerifier, cause error) error {
	if observed == nil {
		properties, err := controller.Properties(ctx, unit, propertyNames...)
		if err != nil {
			return errors.Join(errors.New("enable-now may have mutated durable state and its final state is unreadable"), cause, err)
		}
		observed = properties
	}
	if err := verifySource(unit, observed); err != nil || observed["FragmentPath"] != before["FragmentPath"] || observed["DropInPaths"] != before["DropInPaths"] {
		return errors.Join(errors.New("enable-now final state is ambiguous because its source is unauthenticated"), cause, err)
	}
	if observed["UnitFileState"] == "enabled" {
		return errors.Join(errors.New("enable-now durable intent is committed but activation is pending; rerun the exact command before cutover"), cause)
	}
	if observed["ActiveState"] == "active" {
		if err := withServiceActionCleanup(func(cleanupContext context.Context) error {
			return compensateServiceActionToInactive(cleanupContext, controller, unit, isTimer, before, propertyNames, verifySource)
		}); err != nil {
			return errors.Join(errors.New("enable-now left an active unit without proved durable intent and compensation is ambiguous"), cause, err)
		}
		return errors.Join(errors.New("enable-now failed and was compensated to a proved inactive state"), cause)
	}
	if observed["UnitFileState"] == before["UnitFileState"] && serviceActionUnitStopped(isTimer, observed) {
		return errors.Join(errors.New("enable-now failed without changing the proved durable or active state"), cause)
	}
	return errors.Join(errors.New("enable-now failed and its final durable state is ambiguous"), cause)
}

func verifyProductionServiceActionSource(unit string, properties map[string]string) error {
	if err := verifyServiceActionManagerContract(unit, properties); err != nil {
		return err
	}
	if err := verifyServiceActionSourceAt(unit, properties, productionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"}); err != nil {
		return err
	}
	if unit != "caddy.service" {
		return nil
	}
	if properties["FragmentPath"] != "/usr/lib/systemd/system/caddy.service" {
		return errors.New("Caddy base unit must be loaded from the exact production systemd namespace")
	}
	if err := verifyInstalledSystemdSourceFile(properties["FragmentPath"]); err != nil {
		return err
	}
	dropIns := strings.Fields(properties["DropInPaths"])
	if len(dropIns) != 1 || dropIns[0] != "/etc/systemd/system/caddy.service.d/workagent.conf" {
		return errors.New("Caddy installed drop-in set is not exact")
	}
	if err := verifyInstalledSystemdSourceFile(dropIns[0]); err != nil {
		return err
	}
	binaryInfo, err := os.Lstat("/usr/bin/caddy")
	binaryStat, ok := infoSyscallStat(binaryInfo)
	if err != nil || !ok || binaryInfo.Mode()&os.ModeSymlink != 0 || !binaryInfo.Mode().IsRegular() || binaryInfo.Mode().Perm() != 0o755 || binaryStat.Uid != 0 || binaryStat.Gid != 0 {
		return errors.New("Caddy binary identity is unsafe")
	}
	binaryDigest, err := release.ProtectedFileSHA256("/usr/bin/caddy", true)
	if err != nil || binaryDigest != productionCaddyBinarySHA256 {
		return errors.Join(errors.New("Caddy binary does not match the accepted production build"), err)
	}
	installedConfig, err := release.ProtectedFileSHA256("/etc/caddy/Caddyfile", true)
	if err != nil {
		return err
	}
	signedConfig, err := release.ProtectedFileSHA256(filepath.Join(productionControlRoot, "share/deploy/caddy/Caddyfile"), true)
	if err != nil || installedConfig != signedConfig {
		return errors.Join(errors.New("installed Caddy configuration does not match the signed control release"), err)
	}
	return verifyInstalledEdgeAdmissionHelper()
}

func verifyInstalledEdgeAdmissionHelper() error {
	const installed = "/usr/libexec/workagent-edge-publication-admission-v1"
	for _, directory := range []string{"/usr", "/usr/libexec"} {
		info, err := os.Lstat(directory)
		stat, ok := infoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("immutable edge helper ancestor %s is unsafe", directory), err)
		}
	}
	info, err := os.Lstat(installed)
	stat, ok := infoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o555 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.Join(errors.New("installed immutable edge-publication admission helper is unsafe"), err)
	}
	installedDigest, err := release.ProtectedFileSHA256(installed, true)
	if err != nil {
		return err
	}
	reference := filepath.Join(productionControlRoot, "share/deploy/libexec/workagent-edge-publication-admission-v1")
	referenceDigest, err := release.ProtectedFileSHA256(reference, true)
	if err != nil || installedDigest != referenceDigest {
		return errors.Join(errors.New("installed edge-publication admission helper does not match the signed control release"), err)
	}
	return nil
}

func verifyServiceActionManagerContract(unit string, properties map[string]string) error {
	switch unit {
	case "workagent-tenant-config-reconcile.service", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", "workagent-chatforward-browser.service", "workagent-portal.service", "workagent-backup.service", "workagent-healthcheck.service", "workagent-backup.timer", "workagent-healthcheck.timer", "caddy.service":
	default:
		return errors.New("service-action manager contract unit is not allow-listed")
	}
	if err := verifyCoreManagerContract(unit, properties); err != nil {
		return fmt.Errorf("service-action manager-loaded unit does not match the complete core contract: %w", err)
	}
	// verifyCoreServiceExecVectors already proves every ordinary command
	// vector and every extended vector except the deliberately empty reload-ex
	// field. Keep this boundary independently exact so a transient manager-only
	// reload command can never be admitted by a post-activation service action.
	if unit != "caddy.service" && strings.HasSuffix(unit, ".service") && properties["ExecReloadEx"] != "" {
		return errors.New("service-action manager-loaded service has an unexpected extended reload command")
	}
	return nil
}

func verifyProductionServiceActionDependencies(ctx context.Context, controller systemdctl.Controller, unit string) error {
	return verifyServiceActionDependencies(ctx, controller, unit, verifyProductionServiceActionSource)
}

func verifyServiceActionDependencies(ctx context.Context, controller systemdctl.Controller, unit string, verifySource serviceActionSourceVerifier) error {
	if ctx == nil || controller == nil || verifySource == nil {
		return errors.New("service-action dependency verifier is unavailable")
	}
	target, ok := timerTargetService(unit)
	if !ok {
		return nil
	}
	propertyNames := serviceActionPropertyNames(false, target)
	before, err := controller.Properties(ctx, target, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect timer target service %s: %w", target, err)
	}
	if err := verifySource(target, before); err != nil {
		return fmt.Errorf("authenticate timer target service %s: %w", target, err)
	}
	after, err := controller.Properties(ctx, target, propertyNames...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.Join(errors.New("timer target service changed during source authentication"), err)
	}
	if !serviceActionProcessFreeInactive(after) {
		return errors.New("timer target service must be inactive and process-free during timer enablement")
	}
	return nil
}

func timerTargetService(unit string) (string, bool) {
	switch unit {
	case "workagent-backup.timer":
		return "workagent-backup.service", true
	case "workagent-healthcheck.timer":
		return "workagent-healthcheck.service", true
	default:
		return "", false
	}
}

func disableTimerFailClosed(ctx context.Context, controller systemdctl.Controller, unit string, propertyNames []string, verifySource serviceActionSourceVerifier) error {
	target, ok := timerTargetService(unit)
	if !ok {
		return errors.New("timer fail-closed target is unavailable")
	}
	targetProperties := serviceActionPropertyNames(false, target)
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		disableErr := controller.Action(ctx, "disable", "--now", unit)
		stopErr := controller.Action(ctx, "stop", target)
		timerState, timerReadErr := controller.Properties(ctx, unit, propertyNames...)
		targetState, targetReadErr := controller.Properties(ctx, target, targetProperties...)
		timerAuthErr := error(nil)
		targetAuthErr := error(nil)
		if timerReadErr == nil {
			timerAuthErr = verifySource(unit, timerState)
		}
		if targetReadErr == nil {
			targetAuthErr = verifySource(target, targetState)
		}
		timerSafe := timerReadErr == nil && timerAuthErr == nil && timerState["UnitFileState"] == "disabled" && serviceActionUnitStopped(true, timerState)
		targetSafe := targetReadErr == nil && targetAuthErr == nil && serviceActionProcessFreeInactive(targetState)
		if timerSafe && targetSafe {
			return nil
		}
		failures = append(failures, errors.Join(disableErr, stopErr, timerReadErr, targetReadErr, timerAuthErr, targetAuthErr, errorUnless(timerSafe, "timer did not read back as authenticated, disabled, and inactive"), errorUnless(targetSafe, "timer target service did not read back as authenticated and process-free")))
	}
	return errors.Join(failures...)
}

func serviceActionProcessFreeInactive(properties map[string]string) bool {
	return properties["ActiveState"] == "inactive" && properties["SubState"] == "dead" && properties["MainPID"] == "0" && properties["ControlPID"] == "0"
}

func verifyServiceActionSourceAt(unit string, properties map[string]string, controlRoot string, systemdRoots []string) error {
	if !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || len(systemdRoots) == 0 {
		return errors.New("service-action source verifier layout is invalid")
	}
	var relative string
	switch unit {
	case "cliproxyapi.service", "workagent-backup.service", "workagent-backup.timer", "workagent-healthcheck.service", "workagent-healthcheck.timer", "caddy.service":
		relative = filepath.Join("share", "deploy", "systemd", unit)
	default:
		return errors.New("service-action source unit is not allow-listed")
	}
	fragment := properties["FragmentPath"]
	fragmentAccepted := false
	for _, root := range systemdRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("service-action systemd source root is invalid")
		}
		if fragment == filepath.Join(root, unit) {
			fragmentAccepted = true
		}
	}
	if !fragmentAccepted {
		return errors.New("service-action fragment path is outside the authenticated systemd namespace")
	}
	fragmentDigest, err := release.ProtectedFileSHA256(fragment, true)
	if err != nil {
		return err
	}
	referenceDigest, err := release.ProtectedFileSHA256(filepath.Join(controlRoot, relative), true)
	if err != nil || fragmentDigest != referenceDigest {
		return errors.Join(errors.New("service-action fragment does not match the signed control release"), err)
	}
	if unit != "caddy.service" {
		if len(strings.Fields(properties["DropInPaths"])) != 0 {
			return errors.New("service-action unit has an unexpected drop-in")
		}
		return nil
	}
	dropIns := strings.Fields(properties["DropInPaths"])
	dropInAccepted := false
	if len(dropIns) == 1 {
		for _, root := range systemdRoots {
			if dropIns[0] == filepath.Join(root, "caddy.service.d", "workagent.conf") {
				dropInAccepted = true
			}
		}
	}
	if !dropInAccepted {
		return errors.New("Caddy service drop-in namespace is not exact")
	}
	dropInDigest, err := release.ProtectedFileSHA256(dropIns[0], true)
	if err != nil {
		return err
	}
	referenceDigest, err = release.ProtectedFileSHA256(filepath.Join(controlRoot, "share/deploy/systemd/caddy.service.d/workagent.conf"), true)
	if err != nil || dropInDigest != referenceDigest {
		return errors.Join(errors.New("Caddy service drop-in does not match the signed control release"), err)
	}
	return nil
}

func reconcilePendingTenantActivationBeforeReady(ctx context.Context, configPath string, controller systemdctl.Controller) (resultErr error) {
	catalog, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant catalog to replay activation intent: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	portalConfig, err := config.LoadPortal(configPath)
	if err != nil {
		return err
	}
	if err := admin.AssertTenantFileCatalogClean(portalConfig); err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portalConfig, data); err != nil {
		return errors.Join(err, data.Close())
	}
	identities, identityErr := portalActivationIdentities(ctx, data)
	closeErr := data.Close()
	if identityErr != nil || closeErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	if err := replayTenantActivation(ctx, identities, controller); err != nil {
		return fmt.Errorf("replay pending tenant activation intent: %w", err)
	}
	return nil
}

func applyUserEnabledState(ctx context.Context, portalConfig config.Portal, data *store.Store, username string, enabled bool, controller systemdctl.Controller) error {
	if err := auth.ValidatePortalUsername(username); err != nil {
		return err
	}
	if controller == nil {
		return errors.New("systemd controller is required")
	}
	userValue, err := data.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	socketUnit := "workagent-userhost@" + userValue.TenantID + ".socket"
	serviceUnit := "workagent-userhost@" + userValue.TenantID + ".service"
	if err := admin.AssertTenantFileCatalogClean(portalConfig); err != nil {
		return fmt.Errorf("refuse tenant state change with an uncommitted catalog: %w", err)
	}
	if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portalConfig, data); err != nil {
		return fmt.Errorf("refuse tenant state change with a mismatched Portal identity catalog: %w", err)
	}
	if err := verifyLiveTenantActivationCatalog(ctx, portalConfig, data, controller); err != nil {
		return fmt.Errorf("refuse tenant state change with a mismatched activation catalog: %w", err)
	}
	var expectedTenant config.Tenant
	var tenantPath string
	if enabled {
		tenantPath = filepath.Join(portalConfig.Paths.TenantConfigs, userValue.TenantID+".json")
		expectedTenant, err = config.LoadTenant(tenantPath)
		if err != nil || expectedTenant.RuntimeUser != userValue.RuntimeUser || expectedTenant.DataRoot != userValue.DataRoot {
			return fmt.Errorf("tenant identity is not ready for enablement: %w", err)
		}
		if err := admin.VerifyTenantConfigPath(portalConfig, expectedTenant, tenantPath); err != nil {
			return err
		}
		if _, err := admin.VerifyTenantHost(portalConfig, expectedTenant); err != nil {
			return err
		}
		if err := admin.VerifyTenantService(ctx, portalConfig, expectedTenant, admin.ServiceVerificationOptions{Controller: controller}); err != nil {
			return err
		}
	}
	now, err := commitUserEnabledState(ctx, data, userValue, enabled, controller)
	if err != nil {
		return err
	}
	if enabled {
		if err := controller.Action(ctx, "start", socketUnit); err != nil {
			return fmt.Errorf("start enabled tenant socket: %w", err)
		}
		currentTenant, tenantErr := config.LoadTenant(tenantPath)
		if tenantErr != nil || !admin.CanonicalTenantConfigEqual(currentTenant, expectedTenant) {
			return errors.Join(errors.New("tenant configuration changed during socket activation"), tenantErr)
		}
		if err := admin.VerifyTenantConfigPath(portalConfig, currentTenant, tenantPath); err != nil {
			return err
		}
		if err := admin.VerifyTenantService(ctx, portalConfig, currentTenant, admin.ServiceVerificationOptions{RequireReadySocket: true, Controller: controller}); err != nil {
			return fmt.Errorf("verify enabled tenant socket: %w", err)
		}
	}
	if err := verifyLiveTenantActivationCatalog(ctx, portalConfig, data, controller); err != nil {
		return fmt.Errorf("tenant activation state did not converge: %w", err)
	}
	outcome := "disabled"
	if enabled {
		outcome = "enabled"
	}
	return data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.state", Outcome: outcome, Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"enabled": enabled, "socket_unit": socketUnit, "service_unit": serviceUnit}})
}

// commitUserEnabledState is the crash-consistent database linearization
// boundary. The complete previous/desired decision is durable before sessions
// are revoked and the enabled bit changes. Replay then makes systemd match the
// complete committed database catalog; a crash at either side is recoverable.
func commitUserEnabledState(ctx context.Context, data *store.Store, userValue store.User, enabled bool, controller systemdctl.Controller) (time.Time, error) {
	identities, err := portalActivationIdentities(ctx, data)
	if err != nil {
		return time.Time{}, err
	}
	if err := prepareTenantActivation(ctx, identities, userValue.TenantID, enabled); err != nil {
		return time.Time{}, fmt.Errorf("record tenant activation intent: %w", err)
	}
	now := time.Now().UTC()
	if err := data.SetUserEnabled(ctx, userValue.Username, enabled, now); err != nil {
		current, identityErr := portalActivationIdentities(ctx, data)
		var replayErr error
		if identityErr == nil {
			replayErr = replayTenantActivation(ctx, current, controller)
		}
		return time.Time{}, errors.Join(err, identityErr, replayErr)
	}
	committed, err := data.UserByUsername(ctx, userValue.Username)
	if err != nil || committed.Enabled != enabled || committed.TenantID != userValue.TenantID || committed.RuntimeUser != userValue.RuntimeUser || committed.DataRoot != userValue.DataRoot {
		return time.Time{}, errors.Join(errors.New("Portal enabled state did not read back with the immutable tenant identity"), err)
	}
	currentIdentities, err := portalActivationIdentities(ctx, data)
	if err != nil {
		return time.Time{}, err
	}
	if err := replayTenantActivation(ctx, currentIdentities, controller); err != nil {
		return time.Time{}, fmt.Errorf("apply tenant activation intent after database commit: %w", err)
	}
	return now, nil
}

func listUsers(arguments []string) error {
	flags := flag.NewFlagSet("list-users", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	portalConfig, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	users, err := data.ListUsers(context.Background())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"users": users})
}

func setChatGPTProLimit(arguments []string) error {
	flags := flag.NewFlagSet("set-chatgpt-pro-limit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	username := flags.String("username", "", "Portal username")
	limit := flags.Int("weekly-limit", 0, "weekly ChatGPT Pro request limit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := auth.ValidatePortalUsername(*username); err != nil {
		return err
	}
	if *limit < 1 || *limit > 10000 {
		return errors.New("--weekly-limit must be between 1 and 10000")
	}
	portalConfig, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	ctx := context.Background()
	userValue, err := data.UserByUsername(ctx, *username)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := data.SetChatGPTProWeeklyLimit(ctx, userValue.ID, *limit, now); err != nil {
		return err
	}
	if err := data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.set_chatgpt_pro_limit", Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"weekly_limit": *limit}}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "username": userValue.Username, "weekly_limit": *limit})
}

func setLimits(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("set-limits", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	username := flags.String("username", "", "Portal username")
	memoryMiB := flags.Uint64("memory-mib", config.DefaultResourceLimits().MemoryBytes/(1024*1024), "memory limit in MiB")
	cpuPercent := flags.Uint("cpu-percent", uint(config.DefaultResourceLimits().CPUPercent), "CPU percentage")
	activeProcesses := flags.Uint("active-processes", uint(config.DefaultResourceLimits().ActiveProcesses), "active process limit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("set-limits must run as root")
	}
	if *memoryMiB > ^uint64(0)/(1024*1024) || *cpuPercent > 100 || *activeProcesses > 4096 {
		return errors.New("resource-limit flag is outside the supported range")
	}
	limits := config.ResourceLimits{MemoryBytes: *memoryMiB * 1024 * 1024, CPUPercent: uint32(*cpuPercent), ActiveProcesses: uint32(*activeProcesses)}
	if err := limits.Validate(); err != nil {
		return err
	}
	ctx := context.Background()
	controller := systemdctl.Default()
	activation, err := acquireCleanTenantActivationMutation(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant activation lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	if err := requireTenantCatalogReady(ctx, controller); err != nil {
		return err
	}
	resultUsername := ""
	var resultPortal config.Portal
	var expectedTenant config.Tenant
	var socketUnit, serviceUnit string
	restartSocket := false
	resumeAllowed := false
	updateSucceeded := false
	callbackErr := admin.WithTenantFileCatalogTransaction(ctx, func(transaction *admin.TenantFileCatalogTransaction) (resultErr error) {
		portalConfig, err := config.LoadPortal(*configPath)
		if err != nil {
			return err
		}
		if _, err := transaction.ReconcilePendingTenantFiles(ctx, portalConfig, controller); err != nil {
			return fmt.Errorf("reconcile an older tenant transaction before reading resource state: %w", err)
		}
		data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, data.Close()) }()
		userValue, err := data.UserByUsername(ctx, *username)
		if err != nil {
			return err
		}
		tenantPath := filepath.Join(portalConfig.Paths.TenantConfigs, userValue.TenantID+".json")
		tenant, err := config.LoadTenant(tenantPath)
		if err != nil {
			return err
		}
		if tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
			return errors.New("tenant identity does not match the Portal database")
		}
		resultPortal = portalConfig
		resultUsername = userValue.Username
		socketUnit = "workagent-userhost@" + tenant.TenantID + ".socket"
		serviceUnit = "workagent-userhost@" + tenant.TenantID + ".service"
		socket, err := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState")
		if err != nil || socket["LoadState"] != "loaded" {
			return fmt.Errorf("inspect tenant socket before resource update: %w", err)
		}
		restartSocket = socket["ActiveState"] == "active"
		if restartSocket {
			if err := controller.Action(ctx, "stop", socketUnit); err != nil {
				return fmt.Errorf("quiesce tenant socket: %w", err)
			}
		}
		expectedTenant = tenant
		if err := controller.Action(ctx, "stop", serviceUnit); err != nil {
			resumeAllowed = restartSocket
			return fmt.Errorf("stop tenant service for resource update: %w", err)
		}
		previous := tenant
		tenant.Limits = limits
		if err := tenant.Validate(); err != nil {
			resumeAllowed = restartSocket
			return err
		}
		updateErr := transaction.UpdateTenantFiles(ctx, portalConfig, []config.Tenant{tenant}, controller)
		if updateErr == nil {
			expectedTenant = tenant
			updateSucceeded = true
			resumeAllowed = restartSocket
			return nil
		} else {
			rollbackErr := transaction.UpdateTenantFiles(ctx, portalConfig, []config.Tenant{previous}, controller)
			if rollbackErr != nil {
				// A pending/failed rollback is intentionally left quiesced. Starting
				// the socket could expose a mixed or unreloaded generation.
				resumeAllowed = false
				return errors.Join(updateErr, fmt.Errorf("roll back tenant files while retaining the catalog lock: %w", rollbackErr))
			}
			expectedTenant = previous
			resumeAllowed = restartSocket
			return updateErr
		}
	})
	if expectedTenant.TenantID == "" {
		return callbackErr
	}
	if resumeAllowed {
		if err := requireTenantCatalogReady(ctx, controller); err != nil {
			return errors.Join(callbackErr, err)
		}
	}
	// The ready target is already active before C_SH is taken. Retain C_SH from
	// the clean-marker proof through any socket start and final readback, so the
	// activated process cannot observe a different tenant generation.
	catalog, lockErr := acquireAuthenticatedControlConsumer(ctx)
	if lockErr != nil {
		if resumeAllowed {
			_ = controller.Action(ctx, "stop", socketUnit)
			_ = controller.Action(ctx, "stop", serviceUnit)
		}
		return errors.Join(callbackErr, fmt.Errorf("acquire post-update tenant catalog snapshot: %w", lockErr))
	}
	currentPortal, portalErr := config.LoadPortal(*configPath)
	currentPath := ""
	var currentTenant config.Tenant
	var tenantErr error
	if portalErr == nil {
		currentPath = filepath.Join(currentPortal.Paths.TenantConfigs, expectedTenant.TenantID+".json")
		currentTenant, tenantErr = config.LoadTenant(currentPath)
	}
	readbackErr := errors.Join(portalErr, tenantErr)
	if readbackErr == nil && (!reflect.DeepEqual(currentPortal, resultPortal) || !admin.CanonicalTenantConfigEqual(currentTenant, expectedTenant)) {
		readbackErr = errors.New("tenant catalog changed across the resource update activation boundary")
	}
	if readbackErr == nil {
		readbackErr = admin.VerifyTenantConfigPath(currentPortal, currentTenant, currentPath)
	}
	if readbackErr == nil {
		readbackErr = admin.AssertTenantFileCatalogClean(currentPortal)
	}
	if readbackErr == nil && resumeAllowed {
		data, openErr := store.Open(currentPortal.DatabasePath(), currentPortal.AuditPath())
		if openErr != nil {
			readbackErr = openErr
		} else {
			readbackErr = errors.Join(admin.VerifyLiveTenantIdentityCatalog(ctx, currentPortal, data), data.Close())
		}
	}
	if readbackErr == nil && resumeAllowed {
		if err := controller.Action(ctx, "start", socketUnit); err != nil {
			readbackErr = fmt.Errorf("restart tenant socket after resource transaction: %w", err)
		}
	}
	if readbackErr == nil {
		readbackErr = admin.VerifyTenantService(ctx, currentPortal, currentTenant, admin.ServiceVerificationOptions{RequireReadySocket: resumeAllowed, Controller: controller})
	}
	if readbackErr == nil {
		data, openErr := store.Open(currentPortal.DatabasePath(), currentPortal.AuditPath())
		if openErr != nil {
			readbackErr = openErr
		} else {
			readbackErr = errors.Join(admin.VerifyLiveTenantActivationCatalog(ctx, currentPortal, data, controller), data.Close())
		}
	}
	if readbackErr != nil {
		if resumeAllowed {
			_ = controller.Action(ctx, "stop", socketUnit)
			_ = controller.Action(ctx, "stop", serviceUnit)
		}
	}
	readbackErr = errors.Join(readbackErr, catalog.Close())
	if readbackErr != nil {
		return errors.Join(callbackErr, readbackErr)
	}
	if callbackErr != nil {
		return callbackErr
	}
	if !updateSucceeded {
		return errors.New("tenant resource update did not reach a committed generation")
	}
	data, err := store.Open(currentPortal.DatabasePath(), currentPortal.AuditPath())
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	auditErr := data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.set_limits", Outcome: "success", Username: resultUsername, TenantID: currentTenant.TenantID, RemoteIP: "local-admin", Details: map[string]any{"memory_bytes": limits.MemoryBytes, "cpu_percent": limits.CPUPercent, "active_processes": limits.ActiveProcesses}})
	if err := errors.Join(auditErr, data.Close()); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "username": resultUsername, "limits": limits})
}

const tenantCatalogReadyTarget = "workagent-tenant-catalog-ready.target"

func requireTenantCatalogReady(ctx context.Context, controller systemdctl.Controller) error {
	if ctx == nil || controller == nil {
		return errors.New("tenant catalog readiness controller is unavailable")
	}
	properties, err := controller.Properties(ctx, tenantCatalogReadyTarget, "LoadState", "ActiveState", "UnitFileState")
	if err != nil {
		return fmt.Errorf("inspect tenant catalog readiness target: %w", err)
	}
	if properties["LoadState"] != "loaded" || properties["UnitFileState"] != "static" {
		return errors.New("tenant catalog readiness target is not loaded and static")
	}
	if err := controller.Action(ctx, "start", tenantCatalogReadyTarget); err != nil {
		return fmt.Errorf("start tenant catalog readiness target: %w", err)
	}
	properties, err = controller.Properties(ctx, tenantCatalogReadyTarget, "LoadState", "ActiveState", "UnitFileState")
	if err != nil {
		return fmt.Errorf("read back tenant catalog readiness target: %w", err)
	}
	if properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" || properties["UnitFileState"] != "static" {
		return errors.New("tenant catalog readiness target did not read back as loaded, active, and static")
	}
	return nil
}

func runtimeCommand(operation string, arguments []string) (resultErr error) {
	flags := flag.NewFlagSet(operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	username := flags.String("username", "", "Portal username; omit only for runtime-status")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if operation != "runtime-status" && os.Geteuid() != 0 {
		return errors.New("runtime lifecycle commands must run as root")
	}
	ctx := context.Background()
	controller := systemdctl.Default()
	activation := operation == "runtime-start" || operation == "runtime-restart"
	var activationGuard *lifecyclelock.Guard
	if operation != "runtime-status" {
		guard, lockErr := acquireCleanTenantActivationMutation(ctx)
		if lockErr != nil {
			return fmt.Errorf("acquire tenant activation lock: %w", lockErr)
		}
		activationGuard = guard
		defer func() { resultErr = errors.Join(resultErr, activationGuard.Close()) }()
	}
	if activation {
		if err := requireTenantCatalogReady(ctx, controller); err != nil {
			return err
		}
	}
	var catalog *lifecyclelock.FixedConsumerGuards
	var err error
	if operation != "runtime-status" {
		catalog, err = acquireAuthenticatedControlConsumer(ctx)
		if err != nil {
			return fmt.Errorf("acquire tenant configuration snapshot lock: %w", err)
		}
		defer func() {
			if catalog != nil {
				resultErr = errors.Join(resultErr, catalog.Close())
			}
		}()
	}
	portalConfig, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	if activation {
		if err := admin.AssertTenantFileCatalogClean(portalConfig); err != nil {
			return fmt.Errorf("refuse runtime activation with an uncommitted catalog: %w", err)
		}
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	if activation {
		if err := admin.VerifyLiveTenantIdentityCatalog(ctx, portalConfig, data); err != nil {
			return fmt.Errorf("refuse runtime activation with a mismatched Portal identity catalog: %w", err)
		}
	}
	var users []store.User
	if strings.TrimSpace(*username) == "" {
		if operation != "runtime-status" {
			return errors.New("--username is required")
		}
		users, err = data.ListUsers(ctx)
	} else {
		var value store.User
		value, err = data.UserByUsername(ctx, *username)
		users = []store.User{value}
	}
	if err != nil {
		return err
	}
	states := make([]map[string]any, 0, len(users))
	for _, userValue := range users {
		socketUnit := "workagent-userhost@" + userValue.TenantID + ".socket"
		serviceUnit := "workagent-userhost@" + userValue.TenantID + ".service"
		rollbackActivation := func(cause error) error {
			if !activation {
				return cause
			}
			return restoreEnabledTenantRuntimeAfterFailure(ctx, portalConfig, data, userValue, controller, socketUnit, serviceUnit, cause)
		}
		var verifiedTenant config.Tenant
		if operation != "runtime-status" {
			if (operation == "runtime-start" || operation == "runtime-restart") && !userValue.Enabled {
				return errors.New("disabled users cannot start a runtime")
			}
			if operation != "runtime-stop" {
				tenantPath := filepath.Join(portalConfig.Paths.TenantConfigs, userValue.TenantID+".json")
				tenant, err := config.LoadTenant(tenantPath)
				if err != nil || tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
					return errors.New("tenant runtime identity is invalid")
				}
				verifiedTenant = tenant
				if err := admin.VerifyTenantConfigPath(portalConfig, tenant, tenantPath); err != nil {
					return err
				}
				if _, err := admin.VerifyTenantHost(portalConfig, tenant); err != nil {
					return err
				}
				if err := admin.VerifyTenantService(ctx, portalConfig, tenant, admin.ServiceVerificationOptions{Controller: controller}); err != nil {
					return err
				}
			}
			var actionErr error
			switch operation {
			case "runtime-start":
				if err := controller.Action(ctx, "enable", "--now", socketUnit); err != nil {
					actionErr = err
				}
				if actionErr == nil {
					actionErr = controller.Action(ctx, "start", serviceUnit)
				}
			case "runtime-stop":
				actionErr = controller.Action(ctx, "stop", serviceUnit)
			case "runtime-restart":
				if err := controller.Action(ctx, "enable", "--now", socketUnit); err != nil {
					actionErr = err
				}
				if actionErr == nil {
					actionErr = controller.Action(ctx, "restart", serviceUnit)
				}
			}
			if actionErr != nil {
				return rollbackActivation(actionErr)
			}
			if activation {
				currentPortal, err := config.LoadPortal(*configPath)
				if err != nil {
					return rollbackActivation(err)
				}
				tenantPath := filepath.Join(currentPortal.Paths.TenantConfigs, userValue.TenantID+".json")
				currentTenant, err := config.LoadTenant(tenantPath)
				if err != nil || !reflect.DeepEqual(currentPortal, portalConfig) || !admin.CanonicalTenantConfigEqual(currentTenant, verifiedTenant) ||
					currentTenant.RuntimeUser != userValue.RuntimeUser || currentTenant.DataRoot != userValue.DataRoot {
					return rollbackActivation(errors.New("tenant runtime identity changed during activation"))
				}
				if err := admin.VerifyTenantConfigPath(currentPortal, currentTenant, tenantPath); err != nil {
					return rollbackActivation(err)
				}
				if err := admin.VerifyTenantService(ctx, currentPortal, currentTenant, admin.ServiceVerificationOptions{RequireReadySocket: true, Controller: controller}); err != nil {
					return rollbackActivation(err)
				}
			}
		}
		socket, err := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState", "UnitFileState")
		if err != nil {
			return rollbackActivation(err)
		}
		service, err := controller.Properties(ctx, serviceUnit, "LoadState", "ActiveState", "SubState", "MainPID", "MemoryCurrent", "TasksCurrent", "CPUUsageNSec")
		if err != nil {
			return rollbackActivation(err)
		}
		if activation {
			mainPID, pidErr := strconv.ParseUint(service["MainPID"], 10, 64)
			if socket["LoadState"] != "loaded" || socket["ActiveState"] != "active" ||
				(socket["UnitFileState"] != "enabled" && socket["UnitFileState"] != "enabled-runtime") ||
				service["LoadState"] != "loaded" || service["ActiveState"] != "active" || service["SubState"] != "running" || pidErr != nil || mainPID == 0 {
				return rollbackActivation(errors.New("tenant runtime did not read back as enabled, active, and running"))
			}
		}
		if operation != "runtime-status" {
			if err := admin.VerifyLiveTenantActivationCatalog(ctx, portalConfig, data, controller); err != nil {
				return fmt.Errorf("tenant activation catalog did not converge: %w", err)
			}
		}
		if operation != "runtime-status" {
			action := "admin.runtime." + strings.TrimPrefix(operation, "runtime-")
			if err := data.Audit(ctx, store.AuditEvent{OccurredAt: time.Now().UTC(), Action: action, Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"service_unit": serviceUnit, "socket_unit": socketUnit}}); err != nil {
				return rollbackActivation(err)
			}
		}
		states = append(states, map[string]any{"username": userValue.Username, "tenant_id": userValue.TenantID, "user_enabled": userValue.Enabled, "socket_unit": socketUnit, "socket_active": socket["ActiveState"], "socket_enabled": socket["UnitFileState"], "service_unit": serviceUnit, "service_active": service["ActiveState"], "service_substate": service["SubState"], "main_pid": service["MainPID"], "memory_current": service["MemoryCurrent"], "tasks_current": service["TasksCurrent"], "cpu_usage_nsec": service["CPUUsageNSec"]})
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"runtimes": states})
}

// restoreEnabledTenantRuntimeAfterFailure preserves the durable invariant for
// runtime-start/restart. The Portal row was enabled before the command, so a
// failure must not reuse the new-enablement rollback that disables the socket
// while leaving the DB row enabled. If the persistently enabled socket cannot
// be restored and proved, the account is revoked before the runtime is
// disabled and stopped.
func restoreEnabledTenantRuntimeAfterFailure(ctx context.Context, portal config.Portal, data *store.Store, userValue store.User, controller systemdctl.Controller, socketUnit, serviceUnit string, cause error) error {
	if ctx == nil || data == nil || controller == nil || !userValue.Enabled {
		return errors.Join(cause, errors.New("enabled tenant runtime restoration is unavailable"))
	}
	stopErr := controller.Action(ctx, "stop", serviceUnit)
	enableErr := controller.Action(ctx, "enable", "--now", socketUnit)
	socket, readErr := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState", "UnitFileState")
	restored := enableErr == nil && readErr == nil && socket["LoadState"] == "loaded" && socket["UnitFileState"] == "enabled" &&
		(socket["ActiveState"] == "active" || socket["ActiveState"] == "inactive")
	if restored {
		if stopErr != nil {
			stopErr = fmt.Errorf("stop tenant service while restoring failed runtime activation: %w", stopErr)
		}
		return errors.Join(cause, stopErr)
	}
	_, revokeErr := commitUserEnabledState(ctx, data, userValue, false, controller)
	proofErr := error(nil)
	if revokeErr == nil {
		proofErr = admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller)
	}
	if enableErr != nil {
		enableErr = fmt.Errorf("restore persistently enabled tenant socket: %w", enableErr)
	}
	if readErr != nil {
		readErr = fmt.Errorf("read back restored tenant socket: %w", readErr)
	} else if !restored {
		readErr = errors.New("restored tenant socket did not read back as persistently enabled and stable")
	}
	if revokeErr != nil {
		revokeErr = fmt.Errorf("revoke tenant after activation restoration failed: %w", revokeErr)
	}
	return errors.Join(cause, stopErr, enableErr, readErr, revokeErr, proofErr)
}

type verifyTenantOptions struct {
	configPath       string
	tenantID         string
	requireQuiescent bool
}

func parseVerifyTenantOptions(arguments []string) (verifyTenantOptions, error) {
	var options verifyTenantOptions
	flags := flag.NewFlagSet("verify-tenant", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.configPath, "config", "/etc/workagent/portal.json", "Portal configuration")
	flags.StringVar(&options.tenantID, "tenant-id", "", "tenant UUID")
	flags.BoolVar(&options.requireQuiescent, "require-quiescent", false, "reject any process using the tenant runtime UID")
	if err := flags.Parse(arguments); err != nil {
		return verifyTenantOptions{}, err
	}
	return options, nil
}

func verifyTenantQuiescence(runtimeUID uint32, required bool, check func(uint32) error) error {
	if !required {
		return nil
	}
	if check == nil {
		return errors.New("tenant runtime process audit is unavailable")
	}
	return check(runtimeUID)
}

func verifyTenant(arguments []string) (resultErr error) {
	options, err := parseVerifyTenantOptions(arguments)
	if err != nil {
		return err
	}
	ctx := context.Background()
	catalog, err := acquireAuthenticatedControlConsumer(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant configuration snapshot lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	portalConfig, err := config.LoadPortal(options.configPath)
	if err != nil {
		return err
	}
	if err := admin.VerifyPortalFiles(portalConfig, options.configPath); err != nil {
		return fmt.Errorf("verify Portal product files: %w", err)
	}
	tenantPath := filepath.Join(portalConfig.Paths.TenantConfigs, options.tenantID+".json")
	tenant, err := config.LoadTenant(tenantPath)
	if err != nil {
		return err
	}
	if tenant.TenantID != options.tenantID {
		return errors.New("tenant ID does not match the configuration")
	}
	if err := admin.VerifyTenantConfigPath(portalConfig, tenant, tenantPath); err != nil {
		return err
	}
	if err := admin.AssertTenantFileCatalogClean(portalConfig); err != nil {
		return err
	}
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	identityErr := admin.VerifyLiveTenantIdentityCatalog(ctx, portalConfig, data)
	var enabledErr error
	if identityErr == nil && options.requireQuiescent {
		userValue, lookupErr := data.UserByTenantID(ctx, tenant.TenantID)
		if lookupErr != nil {
			enabledErr = lookupErr
		} else if !userValue.Enabled || userValue.RuntimeUser != tenant.RuntimeUser || userValue.DataRoot != tenant.DataRoot {
			enabledErr = errors.New("tenant runtime startup is not authorized by an enabled Portal identity")
		}
	}
	if err := errors.Join(identityErr, enabledErr, data.Close()); err != nil {
		return fmt.Errorf("verify Portal database tenant identity catalog: %w", err)
	}
	verified, err := admin.VerifyTenantHost(portalConfig, tenant)
	if err != nil {
		return err
	}
	if _, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true}); err != nil {
		return err
	}
	if err := admin.VerifyTenantService(ctx, portalConfig, tenant, admin.ServiceVerificationOptions{RequireReadySocket: options.requireQuiescent}); err != nil {
		return err
	}
	if err := verifyTenantQuiescence(verified.RuntimeUID, options.requireQuiescent, admin.VerifyRuntimeUIDQuiescent); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "tenant_id": tenant.TenantID, "runtime_uid": verified.RuntimeUID, "release_id": verified.Release.Manifest.ReleaseID})
}

type tenantFileReconcileRunner func(context.Context, string, systemdctl.Controller, func() error) (admin.TenantFileReconcileResult, error)

func reconcileTenantFiles(arguments []string) error {
	return reconcileTenantFilesWithDependencies(arguments, admin.ReconcileTenantFiles, verifyRunningControlExecutable)
}

func reconcileTenantFilesWithDependencies(arguments []string, run tenantFileReconcileRunner, authenticate func() error) error {
	if run == nil || authenticate == nil {
		return errors.New("tenant file reconciler authentication boundary is unavailable")
	}
	flags := flag.NewFlagSet("reconcile-tenant-files", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("reconcile-tenant-files does not accept positional arguments")
	}
	result, err := run(context.Background(), *configPath, systemdctl.Default(), authenticate)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"reconciled": true, "pending_journals": result.PendingJournals,
		"verified_tenants": result.VerifiedTenants, "loaded_units": result.LoadedUnits,
	})
}

func verifyHost(arguments []string) error {
	flags := flag.NewFlagSet("verify-host", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	portalConfig, err := config.LoadPortal(*configPath)
	if err != nil {
		return err
	}
	if err := admin.VerifyPortalFiles(portalConfig, *configPath); err != nil {
		return fmt.Errorf("verify Portal product files: %w", err)
	}
	serviceContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	serviceErr := admin.VerifyPortalService(serviceContext, portalConfig, nil)
	cancel()
	if serviceErr != nil {
		return fmt.Errorf("verify Portal service: %w", serviceErr)
	}
	report, err := hostcheck.Inspect(portalConfig)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	return report.Error()
}

func loadBoundTenant(portalPath, tenantPath string, initial bool) (config.Portal, config.Tenant, error) {
	portalConfig, err := config.LoadPortal(portalPath)
	if err != nil {
		return config.Portal{}, config.Tenant{}, err
	}
	if initial {
		if err := admin.VerifyPortalFiles(portalConfig, portalPath); err != nil {
			return config.Portal{}, config.Tenant{}, fmt.Errorf("verify initial Portal product files: %w", err)
		}
	}
	if tenantPath == "" {
		return config.Portal{}, config.Tenant{}, errors.New("--tenant-config is required")
	}
	tenant, err := config.LoadTenant(tenantPath)
	if err != nil {
		return config.Portal{}, config.Tenant{}, err
	}
	if err := admin.VerifyTenantConfigPath(portalConfig, tenant, tenantPath); err != nil {
		return config.Portal{}, config.Tenant{}, err
	}
	if initial {
		if _, err := admin.VerifyTenantBootstrap(portalConfig, tenant); err != nil {
			return config.Portal{}, config.Tenant{}, err
		}
	} else if _, err := admin.VerifyTenantHost(portalConfig, tenant); err != nil {
		return config.Portal{}, config.Tenant{}, err
	}
	return portalConfig, tenant, nil
}

func readPassword(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("--password-file must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 1024 {
		return nil, errors.New("password input must be a protected regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	payload = []byte(strings.TrimSuffix(strings.TrimSuffix(string(payload), "\n"), "\r"))
	if err := auth.ValidatePortalPassword(payload); err != nil {
		auth.Zero(payload)
		return nil, fmt.Errorf("invalid password input: %w", err)
	}
	return payload, nil
}
