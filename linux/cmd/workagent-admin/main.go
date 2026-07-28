package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backupquiescence"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/coreactivation"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/edgepublication"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/safelog"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/serviceaction"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

var (
	prepareTenantActivation           = admin.PrepareTenantActivation
	replayTenantActivation            = admin.ReplayTenantActivation
	verifyLiveTenantActivationCatalog = admin.VerifyLiveTenantActivationCatalog
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
		AllowedScopes:           []string{release.ScopePortal},
	})
	if err != nil {
		return fmt.Errorf("verify current control release: %w", err)
	}
	return release.VerifyRunningExecutable(productionControlRoot, "workagent-admin")
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
	logger.Fatal("usage: workagent-admin <init-admin|create-user|set-password|set-enabled|activate-tenant-catalog|activate-core-fleet|service-action|assert-activation-clean|set-limits|runtime-status|runtime-start|runtime-stop|runtime-restart|list-users|set-chatgpt-pro-limit|verify-tenant|reconcile-tenant-files|verify-host> [options]")
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

// activateTenantCatalog is the explicit fresh-bootstrap boundary for a
// database that already contains an enabled administrator while every restored
// socket is still disabled. It persistently converges the complete catalog
// before the readiness target is allowed to run, then starts and proves every
// enabled socket without changing any Portal identity.
const productionControlRoot = "/opt/workagent/control"

type tenantCatalogActivationAdmission func(context.Context, config.Portal, *store.Store, []store.PortalUserIdentity) error

func activateTenantCatalog(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("activate-tenant-catalog", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	initial := flags.Bool("initial", false, "confirm a fresh one-admin bootstrap")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("activate-tenant-catalog does not accept positional arguments")
	}
	if !*initial {
		return errors.New("activate-tenant-catalog requires --initial to confirm the fresh bootstrap")
	}
	if os.Geteuid() != 0 {
		return errors.New("tenant catalog activation must run as root")
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
	admission := tenantCatalogActivationAdmission(func(ctx context.Context, portal config.Portal, data *store.Store, identities []store.PortalUserIdentity) error {
		return validateInitialTenantCatalogActivation(ctx, data, identities)
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
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"activated": true, "mode": "initial",
		"tenants": len(identities), "enabled_sockets": started,
	})
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
	stat, ok := fsutil.InfoSyscallStat(info)
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
	if !serviceaction.Allowed(*unit, *action) {
		return errors.New("service-action unit/action pair is not allow-listed")
	}
	if err := serviceaction.ValidateConfirmation(*action, *unit, *confirm); err != nil {
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
	if err := edgepublication.ReconcilePending(ctx, controller, serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed); err != nil {
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
	var portalGeneration serviceaction.PortalEdgeGeneration
	var edgeContent serviceaction.PortalEdgeContentSnapshot
	var edgeTransaction *edgepublication.Transaction
	if *unit == "caddy.service" {
		if err := edgepublication.ValidateProductionPortalEdgeBinding(portal); err != nil {
			return err
		}
		edgeContent, err = serviceaction.CapturePortalEdgeContent(portal)
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
		portalGeneration, err = serviceaction.PreparePortalEdgeGeneration(ctx, portal, controller)
		if err != nil {
			return fmt.Errorf("prepare authenticated Portal generation for edge publication: %w", err)
		}
		portalGeneration, err = serviceaction.VerifyPortalEdgePublicationReadiness(ctx, portal, controller, edgeContent.PolicyID, edgeContent.BrandID, &portalGeneration, false)
		if err != nil {
			return fmt.Errorf("refuse edge publication before full local readiness: %w", err)
		}
		if currentContent, err := serviceaction.CapturePortalEdgeContent(portal); err != nil || currentContent != edgeContent {
			return errors.Join(errors.New("protected Portal content changed across the forced Portal restart while Caddy remains disabled"), err)
		}
		if err := serviceaction.VerifyInstalledEdgeAdmissionHelper(); err != nil {
			return fmt.Errorf("authenticate immutable edge-publication admission helper before transaction begin: %w", err)
		}
		edgeTransaction, err = edgepublication.Begin()
		if err != nil {
			return fmt.Errorf("persist edge-publication crash recovery evidence before enabling Caddy: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, edgeTransaction.Close()) }()
	}
	var actionErr error
	if edgeTransaction != nil {
		actionErr = serviceaction.ExecuteCaddyEdgeCommit(ctx, controller, serviceaction.VerifyProductionSource, edgeTransaction.Verify)
	} else {
		actionErr = serviceaction.Execute(ctx, controller, *action, *unit)
	}
	if actionErr != nil {
		if edgeTransaction != nil {
			return edgepublication.Abort(controller, edgeTransaction, errors.Join(errors.New("Caddy publication action failed"), actionErr), serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
		}
		return actionErr
	}
	if *unit == "caddy.service" {
		publishingGeneration, err := serviceaction.VerifyPublishedEdge(ctx, portal, controller, edgeContent, portalGeneration)
		if err != nil {
			return edgepublication.Abort(controller, edgeTransaction, errors.Join(errors.New("edge publication post-action proof failed"), err), serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
		}
		if err := edgeTransaction.Commit(); err != nil {
			return edgepublication.FailClosedAfterCommitError(controller, edgeTransaction, err, serviceaction.WithCleanup, serviceaction.RollbackPublishedCaddyFailClosed)
		}
		if err := serviceaction.SettleCommittedCaddyEdge(ctx, controller, publishingGeneration); err != nil {
			rollbackErr := serviceaction.WithCleanup(func(cleanupContext context.Context) error {
				return serviceaction.RollbackPublishedCaddyFailClosed(cleanupContext, controller)
			})
			if rollbackErr == nil {
				return errors.Join(errors.New("edge-publication watcher did not settle the proved generation; Caddy was durably disabled"), err)
			}
			return errors.Join(errors.New("edge-publication watcher did not settle the proved generation and Caddy final state is ambiguous"), err, rollbackErr)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "action": *action, "unit": *unit})
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
