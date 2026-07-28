package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "tenant" {
		fatal("usage: workagent-provision tenant [options]")
	}
	if err := provisionTenant(os.Args[2:]); err != nil {
		fatal(err.Error())
	}
}

func provisionTenant(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("tenant", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	portalConfigPath := flags.String("portal-config", "/etc/workagent/portal.json", "Portal configuration")
	tenantID := flags.String("tenant-id", "", "canonical tenant UUID")
	runtimeUser := flags.String("runtime-user", "", "dedicated locked Linux account")
	projectID := flags.Uint("project-id", 0, "unique XFS project ID")
	diskLimit := flags.Uint64("disk-hard-limit-bytes", 0, "XFS project hard limit")
	memoryLimit := flags.Uint64("memory-bytes", config.DefaultResourceLimits().MemoryBytes, "tenant memory limit")
	cpuLimit := flags.Uint("cpu-percent", uint(config.DefaultResourceLimits().CPUPercent), "tenant CPU percentage")
	processLimit := flags.Uint("active-processes", uint(config.DefaultResourceLimits().ActiveProcesses), "tenant active process limit")
	releasesRoot := flags.String("releases-root", "/opt/workagent/aionui/releases", "runtime release channel root")
	pointerFile := flags.String("pointer", "/opt/workagent/aionui/current.json", "runtime release pointer")
	scope := flags.String("scope", "runtime", "runtime release scope")
	initial := flags.Bool("initial", false, "provision before the first runtime release activation")
	reconcile := flags.Bool("reconcile", false, "reconcile an existing matching tenant")
	start := flags.Bool("start", false, "enable and start the tenant socket after verification")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("tenant provisioning must run as root")
	}
	if err := validateProvisionActivationMode(*initial, *start); err != nil {
		return err
	}
	parsedID, err := uuid.Parse(*tenantID)
	if err != nil || parsedID.String() != *tenantID {
		return errors.New("--tenant-id must be a canonical UUID")
	}
	ctx := context.Background()
	controller := systemdctl.Default()
	activation, err := lifecyclelock.AcquireActivationExclusive(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant activation lock: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, activation.Close()) }()
	if err := backup.AssertNoPendingRecoveryActivation(); err != nil {
		return err
	}
	if err := admin.AssertTenantActivationClean(); err != nil {
		return fmt.Errorf("refuse tenant provisioning with a pending activation transaction: %w", err)
	}
	var portal config.Portal
	var tenant config.Tenant
	var runtimeUID uint64
	var socketUnit, serviceUnit string
	restartSocket := false
	restoreSocketOnFailure := false
	err = admin.WithTenantFileCatalogTransaction(ctx, func(transaction *admin.TenantFileCatalogTransaction) error {
		portal, err = config.LoadPortal(*portalConfigPath)
		if err != nil {
			return err
		}
		if err := portal.ValidateProductionLayout(*portalConfigPath); err != nil {
			return err
		}
		if err := admin.VerifyPortalFiles(portal, *portalConfigPath); err != nil {
			return err
		}
		if _, err := transaction.ReconcilePendingTenantFiles(ctx, portal, controller); err != nil {
			return fmt.Errorf("reconcile interrupted tenant catalog before provisioning reads: %w", err)
		}
		portalAccount, err := user.Lookup(portal.RuntimeUser)
		if err != nil {
			return err
		}
		portalUID, err := strconv.ParseUint(portalAccount.Uid, 10, 32)
		if err != nil || portalUID == 0 {
			return errors.New("Portal runtime UID is invalid")
		}
		dataRoot := filepath.Join(portal.Paths.TenantData, *tenantID)
		tenant = config.Tenant{
			SchemaVersion: config.TenantSchemaVersion, TenantID: *tenantID, RuntimeUser: *runtimeUser, DataRoot: dataRoot,
			SocketPath: filepath.Join(portal.Paths.RuntimeSockets, *tenantID+".sock"), SocketActivation: true, PortalUID: uint32(portalUID), PortalOrigin: portal.Listener.PublicOrigin,
			IdleReapSeconds:  portal.Runtime.IdleReapSeconds,
			OutboundProxyURL: portal.OutboundProxyURL,
			Capacity:         config.TenantCapacity{SlotDirectory: "/run/workagent/capacity", MaxInstances: portal.Runtime.MaxConcurrentInstances, ProjectID: uint32(*projectID), DiskHardLimitBytes: *diskLimit},
			Limits:           config.ResourceLimits{MemoryBytes: *memoryLimit, CPUPercent: uint32(*cpuLimit), ActiveProcesses: uint32(*processLimit)},
			Release:          config.TenantRelease{ReleasesRoot: *releasesRoot, PointerFile: *pointerFile, Scope: *scope},
			Backend: config.Backend{
				Executable: "bin/aionui-web", Arguments: []string{"start", "--port", "{listen_port}", "--data-dir", "{data_root}/data", "--work-dir", "{data_root}/workspace", "--log-dir", "{data_root}/logs", "--static-dir", "{release_root}/static", "--backend-bin", "{release_root}/bin/aioncore", "--no-open"},
				RequiredReleaseFiles: []string{"static/index.html", "workagent-builtin-assistants/assistants.json", "workagent-builtin-assistants/rules/aionui-assistant.en-US.md", "workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md", "workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md"}, WorkingDirectory: filepath.Join(dataRoot, "workspace"),
				HealthPath: "/healthz", ActivityProbe: "aionui", StartupTimeoutSeconds: 60, RequireModelBootstrap: true, ModelBootstrapTimeoutSeconds: 120,
				AgentCLI:     config.AgentCLI{BinDirectory: "bin", CodexExecutable: "bin/codex", KimiExecutable: "bin/kimi", PythonExecutable: "bin/python3", ProbeTimeoutSeconds: 30},
				Migration:    config.BackendMigration{Enabled: true, Executable: "bin/aioncore", Arguments: []string{"--port", "{listen_port}", "--data-dir", "{data_root}/data", "--work-dir", "{data_root}/workspace", "--log-dir", "{data_root}/logs", "--managed-resources-mode", "bundled"}, WorkingDirectory: filepath.Join(dataRoot, "workspace"), HealthPath: "/health", StartupTimeoutSeconds: 60, ShutdownTimeoutSeconds: 10},
				InternalAuth: config.BackendInternalAuth{Enabled: true, DatabasePath: filepath.Join(dataRoot, "data", "aionui-backend.db")},
			},
		}
		if err := tenant.Validate(); err != nil {
			return err
		}
		if err := admin.ValidateTenantBinding(portal, tenant); err != nil {
			return err
		}
		if err := ensureUniqueTenant(portal, tenant); err != nil {
			return err
		}
		tenantConfigPath := filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json")
		reconciling := false
		if existing, err := config.LoadTenant(tenantConfigPath); err == nil {
			if !*reconcile {
				return errors.New("tenant configuration already exists; use --reconcile only for the same immutable identity")
			}
			if existing.TenantID != tenant.TenantID || existing.RuntimeUser != tenant.RuntimeUser || existing.DataRoot != tenant.DataRoot || existing.Capacity.ProjectID != tenant.Capacity.ProjectID {
				return errors.New("existing tenant immutable identity does not match")
			}
			tenant.Limits = existing.Limits.Effective()
			reconciling = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect existing tenant configuration: %w", err)
		}
		if err := validateProvisionExistingActivation(reconciling, *start); err != nil {
			return err
		}
		if err := verifyProvisionCatalogAdmission(ctx, portal, tenant, reconciling); err != nil {
			return fmt.Errorf("tenant provisioning identity-catalog admission: %w", err)
		}
		if err := ensureRuntimeAccount(tenant.RuntimeUser, tenant.DataRoot); err != nil {
			return err
		}
		if err := admin.EnsureCapacitySlots(context.Background(), tenant.Capacity.SlotDirectory, tenant.Capacity.MaxInstances); err != nil {
			return err
		}
		runtimeAccount, err := user.Lookup(tenant.RuntimeUser)
		if err != nil {
			return err
		}
		runtimeUID, err = strconv.ParseUint(runtimeAccount.Uid, 10, 32)
		if err != nil || runtimeUID == 0 || runtimeUID == portalUID {
			return errors.New("dedicated tenant UID is invalid")
		}
		runtimeGID, err := strconv.ParseUint(runtimeAccount.Gid, 10, 32)
		if err != nil || runtimeGID == 0 {
			return errors.New("dedicated tenant GID is invalid")
		}
		socketUnit = "workagent-userhost@" + tenant.TenantID + ".socket"
		serviceUnit = "workagent-userhost@" + tenant.TenantID + ".service"
		if reconciling {
			properties, err := controller.Properties(context.Background(), socketUnit, "LoadState", "ActiveState")
			if err != nil {
				return fmt.Errorf("inspect tenant socket before reconcile: %w", err)
			}
			if properties["LoadState"] != "loaded" {
				return errors.New("tenant socket template is not loaded")
			}
			restartSocket = properties["ActiveState"] == "active"
			if *initial && properties["ActiveState"] != "inactive" {
				return errors.New("initial tenant bootstrap requires the existing tenant socket to be inactive")
			}
			if restartSocket {
				if err := controller.Action(context.Background(), "stop", socketUnit); err != nil {
					return fmt.Errorf("quiesce tenant socket before reconcile: %w", err)
				}
				restoreSocketOnFailure = true
			}
			if err := controller.Action(context.Background(), "stop", serviceUnit); err != nil {
				return fmt.Errorf("stop tenant service before reconcile: %w", err)
			}
		}
		if err := ensureTenantRoot(tenant.DataRoot, uint32(runtimeUID), uint32(runtimeGID)); err != nil {
			return err
		}
		if _, err := hostcheck.VerifyTenantQuota(tenant.DataRoot, tenant.Capacity.ProjectID, tenant.Capacity.DiskHardLimitBytes); err != nil {
			if _, assignErr := hostcheck.AssignTenantQuota(tenant.DataRoot, tenant.Capacity.ProjectID, tenant.Capacity.DiskHardLimitBytes); assignErr != nil {
				return fmt.Errorf("assign tenant XFS project quota: %w", assignErr)
			}
		}
		// From this point a durable catalog transaction may be present. Any failure
		// must leave the runtime quiesced for explicit replay; the pre-publication
		// restore path is no longer authorized.
		restoreSocketOnFailure = false
		if *initial {
			if err := admin.RequireInitialReleasePointerAbsent(tenant.Release.PointerFile); err != nil {
				return err
			}
			if err := transaction.UpdateTenantFiles(ctx, portal, []config.Tenant{tenant}, controller); err != nil {
				return err
			}
			if _, err := admin.VerifyTenantBootstrap(portal, tenant); err != nil {
				return fmt.Errorf("provisioned tenant failed bootstrap verification: %w", err)
			}
		} else {
			err = transaction.UpdateTenantFiles(ctx, portal, []config.Tenant{tenant}, controller)
			if err == nil {
				_, err = admin.VerifyTenantHost(portal, tenant)
			}
		}
		if err != nil {
			return fmt.Errorf("provisioned tenant publication failed: %w", err)
		}
		if err := admin.VerifyTenantConfigPath(portal, tenant, tenantConfigPath); err != nil {
			return fmt.Errorf("provisioned tenant configuration failed verification: %w", err)
		}
		return nil
	})
	if err != nil {
		if restoreSocketOnFailure {
			restoreErr := activateProvisionedSocket(ctx, controller, *portalConfigPath, portal, tenant, socketUnit, serviceUnit)
			return errors.Join(err, func() error {
				if restoreErr == nil {
					return nil
				}
				return fmt.Errorf("restore tenant socket after pre-publication failure: %w", restoreErr)
			}())
		}
		return err
	}
	unit := socketUnit
	socketShouldBeReady := *start || restartSocket
	restoreSocketOnFailure = false
	if socketShouldBeReady {
		if err := activateProvisionedSocket(ctx, controller, *portalConfigPath, portal, tenant, unit, serviceUnit); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"provisioned": true, "initial_bootstrap": *initial, "tenant_id": tenant.TenantID, "runtime_user": tenant.RuntimeUser, "runtime_uid": runtimeUID, "project_id": tenant.Capacity.ProjectID, "socket_unit": unit, "started": socketShouldBeReady})
}

func verifyProvisionCatalogAdmission(ctx context.Context, portal config.Portal, candidate config.Tenant, reconciling bool) error {
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return err
	}
	var verifyErr error
	if reconciling {
		userValue, lookupErr := data.UserByTenantID(ctx, candidate.TenantID)
		switch {
		case lookupErr == nil:
			if userValue.RuntimeUser != candidate.RuntimeUser || userValue.DataRoot != candidate.DataRoot {
				verifyErr = errors.New("existing Portal identity does not match the reconciled tenant")
			} else {
				verifyErr = admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data)
			}
		case errors.Is(lookupErr, store.ErrNotFound):
			verifyErr = admin.VerifyLiveTenantIdentityCatalogWithPendingCreate(ctx, portal, data, store.PortalUserIdentity{
				TenantID: candidate.TenantID, RuntimeUser: candidate.RuntimeUser, DataRoot: candidate.DataRoot,
			})
		default:
			verifyErr = lookupErr
		}
	} else {
		verifyErr = admin.VerifyLiveTenantIdentityCatalogAllowEmpty(ctx, portal, data)
	}
	return errors.Join(verifyErr, data.Close())
}

func activateProvisionedSocket(
	ctx context.Context,
	controller systemdctl.Controller,
	portalConfigPath string,
	expectedPortal config.Portal,
	expectedTenant config.Tenant,
	socketUnit, serviceUnit string,
) (resultErr error) {
	if ctx == nil || controller == nil || portalConfigPath == "" || socketUnit == "" || serviceUnit == "" {
		return errors.New("tenant socket activation runtime is unavailable")
	}
	const readyTarget = "workagent-tenant-catalog-ready.target"
	verifySnapshot := func(requireReadySocket bool) error {
		currentPortal, portalErr := config.LoadPortal(portalConfigPath)
		if portalErr != nil {
			return portalErr
		}
		if !reflect.DeepEqual(currentPortal, expectedPortal) {
			return errors.New("Portal catalog changed during socket activation")
		}
		if err := admin.AssertTenantFileCatalogClean(currentPortal); err != nil {
			return fmt.Errorf("tenant catalog is not committed for socket activation: %w", err)
		}
		currentPath := filepath.Join(currentPortal.Paths.TenantConfigs, expectedTenant.TenantID+".json")
		currentTenant, tenantErr := config.LoadTenant(currentPath)
		if tenantErr != nil {
			return tenantErr
		}
		if !admin.CanonicalTenantConfigEqual(currentTenant, expectedTenant) {
			return errors.New("tenant catalog changed during socket activation")
		}
		if err := admin.VerifyTenantConfigPath(currentPortal, currentTenant, currentPath); err != nil {
			return err
		}
		data, err := store.Open(currentPortal.DatabasePath(), currentPortal.AuditPath())
		if err != nil {
			return err
		}
		identityErr := admin.VerifyLiveTenantIdentityCatalog(ctx, currentPortal, data)
		if requireReadySocket {
			identityErr = admin.VerifyLiveTenantActivationCatalog(ctx, currentPortal, data, controller)
		}
		if identityErr == nil {
			userValue, lookupErr := data.UserByTenantID(ctx, expectedTenant.TenantID)
			if lookupErr != nil {
				identityErr = lookupErr
			} else if !userValue.Enabled || userValue.RuntimeUser != expectedTenant.RuntimeUser || userValue.DataRoot != expectedTenant.DataRoot {
				identityErr = errors.New("tenant socket activation is not authorized by an enabled Portal identity")
			}
		}
		if err := errors.Join(identityErr, data.Close()); err != nil {
			return fmt.Errorf("verify Portal database tenant identity catalog: %w", err)
		}
		return admin.VerifyTenantService(ctx, currentPortal, currentTenant, admin.ServiceVerificationOptions{RequireReadySocket: requireReadySocket, Controller: controller})
	}
	// A newly enabled Portal row can legitimately precede its first persistent
	// socket link. Close that one fail-closed bootstrap gap under A_EX and C_SH,
	// then release C_SH before the cold target runs its C_EX reconciler.
	bootstrapCatalog, err := lifecyclelock.AcquireCatalogShared(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant catalog snapshot before socket enablement: %w", err)
	}
	if err := verifySnapshot(false); err != nil {
		return errors.Join(fmt.Errorf("verify tenant catalog before socket activation: %w", err), bootstrapCatalog.Close())
	}
	if err := controller.Action(ctx, "enable", socketUnit); err != nil {
		return errors.Join(fmt.Errorf("persistently enable tenant socket before readiness reconciliation: %w", err), bootstrapCatalog.Close())
	}
	state, stateErr := controller.Properties(ctx, socketUnit, "LoadState", "UnitFileState")
	if stateErr != nil || state["LoadState"] != "loaded" || state["UnitFileState"] != "enabled" {
		return errors.Join(fmt.Errorf("tenant socket did not read back as persistently enabled: %w", stateErr), bootstrapCatalog.Close())
	}
	if err := bootstrapCatalog.Close(); err != nil {
		return errors.New("release tenant catalog snapshot before readiness reconciliation")
	}
	if err := controller.Action(ctx, "start", readyTarget); err != nil {
		return fmt.Errorf("establish tenant catalog readiness before socket activation: %w", err)
	}
	properties, err := controller.Properties(ctx, readyTarget, "LoadState", "ActiveState", "UnitFileState")
	if err != nil || properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" || properties["UnitFileState"] != "static" {
		return fmt.Errorf("tenant catalog readiness target is not loaded, active, and static: %w", err)
	}
	catalog, err := lifecyclelock.AcquireCatalogShared(ctx)
	if err != nil {
		return fmt.Errorf("acquire tenant catalog snapshot before socket activation: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	if err := verifySnapshot(false); err != nil {
		return fmt.Errorf("reverify tenant catalog after readiness reconciliation: %w", err)
	}
	rollback := func() {
		_ = controller.Action(ctx, "stop", socketUnit)
		_ = controller.Action(ctx, "stop", serviceUnit)
	}
	if err := controller.Action(ctx, "start", socketUnit); err != nil {
		rollback()
		return fmt.Errorf("activate tenant socket: %w", err)
	}
	if err := verifySnapshot(true); err != nil {
		rollback()
		return fmt.Errorf("started tenant socket failed verification: %w", err)
	}
	return nil
}

func validateProvisionActivationMode(initial, start bool) error {
	if initial && start {
		return errors.New("initial tenant bootstrap cannot start an unactivated runtime")
	}
	return nil
}

func validateProvisionExistingActivation(reconciling, start bool) error {
	if start && !reconciling {
		return errors.New("a newly provisioned tenant cannot start until its Portal user identity has been created")
	}
	return nil
}

func ensureUniqueTenant(portal config.Portal, candidate config.Tenant) error {
	entries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == candidate.TenantID+".json" {
			continue
		}
		value, err := config.LoadTenant(filepath.Join(portal.Paths.TenantConfigs, entry.Name()))
		if err != nil {
			return err
		}
		if value.RuntimeUser == candidate.RuntimeUser || value.DataRoot == candidate.DataRoot || value.Capacity.ProjectID == candidate.Capacity.ProjectID {
			return errors.New("tenant runtime user, data root, and XFS project ID must be globally unique")
		}
	}
	return nil
}

func ensureRuntimeAccount(name, dataRoot string) error {
	if _, err := user.Lookup(name); err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return err
		}
		shell := "/usr/sbin/nologin"
		if _, statErr := os.Stat(shell); statErr != nil {
			shell = "/sbin/nologin"
		}
		if err := run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", dataRoot, "--shell", shell, name); err != nil {
			return err
		}
	}
	tenant := config.Tenant{RuntimeUser: name, DataRoot: dataRoot}
	if _, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{}); err != nil {
		return err
	}
	if err := run("usermod", "--append", "--groups", "workagent-slots", name); err != nil {
		return err
	}
	if err := run("passwd", "--lock", name); err != nil {
		return err
	}
	_, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true})
	return err
}

func ensureTenantRoot(path string, uid, gid uint32) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("tenant data root is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("tenant data root ownership is unavailable")
	}
	if stat.Uid != uid || stat.Gid != gid {
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) != 0 {
			return errors.New("refusing to change ownership of a non-empty tenant root")
		}
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			return err
		}
	}
	return os.Chmod(path, 0o700)
}

func run(name string, arguments ...string) error {
	programs := map[string]string{
		"useradd": "/usr/sbin/useradd",
		"usermod": "/usr/sbin/usermod",
		"passwd":  "/usr/bin/passwd",
	}
	program, allowed := programs[name]
	if !allowed {
		return fmt.Errorf("unsupported account command %s", name)
	}
	command := exec.Command(program, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "workagent-provision:", message)
	os.Exit(1)
}
