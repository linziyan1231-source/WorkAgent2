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
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
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
	publicKey := flags.String("public-key", "/etc/workagent/trust/release-signing.pub", "trusted release verification key")
	scope := flags.String("scope", "runtime", "runtime release scope")
	reconcile := flags.Bool("reconcile", false, "reconcile an existing matching tenant")
	start := flags.Bool("start", false, "enable and start the tenant socket after verification")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("tenant provisioning must run as root")
	}
	parsedID, err := uuid.Parse(*tenantID)
	if err != nil || parsedID.String() != *tenantID {
		return errors.New("--tenant-id must be a canonical UUID")
	}
	portal, err := config.LoadPortal(*portalConfigPath)
	if err != nil {
		return err
	}
	if err := portal.ValidateProductionLayout(*portalConfigPath); err != nil {
		return err
	}
	if err := admin.VerifyPortalFiles(portal, *portalConfigPath); err != nil {
		return err
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
	tenant := config.Tenant{
		SchemaVersion: config.TenantSchemaVersion, TenantID: *tenantID, RuntimeUser: *runtimeUser, DataRoot: dataRoot,
		SocketPath: filepath.Join(portal.Paths.RuntimeSockets, *tenantID+".sock"), SocketActivation: true, PortalUID: uint32(portalUID), PortalOrigin: portal.Listener.PublicOrigin,
		IdleReapSeconds:  portal.Runtime.IdleReapSeconds,
		OutboundProxyURL: portal.OutboundProxyURL,
		Capacity:         config.TenantCapacity{SlotDirectory: "/run/workagent/capacity", MaxInstances: portal.Runtime.MaxConcurrentInstances, ProjectID: uint32(*projectID), DiskHardLimitBytes: *diskLimit},
		Limits:           config.ResourceLimits{MemoryBytes: *memoryLimit, CPUPercent: uint32(*cpuLimit), ActiveProcesses: uint32(*processLimit)},
		Release:          config.TenantRelease{ReleasesRoot: *releasesRoot, PointerFile: *pointerFile, PublicKeyFile: *publicKey, Scope: *scope},
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
	runtimeUID, err := strconv.ParseUint(runtimeAccount.Uid, 10, 32)
	if err != nil || runtimeUID == 0 || runtimeUID == portalUID {
		return errors.New("dedicated tenant UID is invalid")
	}
	runtimeGID, err := strconv.ParseUint(runtimeAccount.Gid, 10, 32)
	if err != nil || runtimeGID == 0 {
		return errors.New("dedicated tenant GID is invalid")
	}
	controller := systemdctl.Default()
	socketUnit := "workagent-userhost@" + tenant.TenantID + ".socket"
	serviceUnit := "workagent-userhost@" + tenant.TenantID + ".service"
	restartSocket := false
	restoreSocketOnFailure := false
	defer func() {
		if !restoreSocketOnFailure || resultErr == nil {
			return
		}
		if err := controller.Action(context.Background(), "start", socketUnit); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restore tenant socket after failed reconcile: %w", err))
		}
	}()
	if reconciling {
		properties, err := controller.Properties(context.Background(), socketUnit, "LoadState", "ActiveState")
		if err != nil {
			return fmt.Errorf("inspect tenant socket before reconcile: %w", err)
		}
		if properties["LoadState"] != "loaded" {
			return errors.New("tenant socket template is not loaded")
		}
		restartSocket = properties["ActiveState"] == "active"
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
	if err := admin.WriteTenantFiles(context.Background(), portal, tenant); err != nil {
		return err
	}
	if err := controller.Action(context.Background(), "daemon-reload"); err != nil {
		return err
	}
	if err := admin.VerifyTenantConfigPath(portal, tenant, tenantConfigPath); err != nil {
		return fmt.Errorf("provisioned tenant configuration failed verification: %w", err)
	}
	if err := admin.VerifyTenantService(context.Background(), portal, tenant, admin.ServiceVerificationOptions{}); err != nil {
		return fmt.Errorf("provisioned tenant service failed verification: %w", err)
	}
	if _, err := admin.VerifyTenantHost(portal, tenant); err != nil {
		return fmt.Errorf("provisioned tenant failed host verification: %w", err)
	}
	unit := socketUnit
	socketShouldBeReady := *start || restartSocket
	if *start {
		if err := controller.Action(context.Background(), "enable", "--now", unit); err != nil {
			return err
		}
	} else if restartSocket {
		if err := controller.Action(context.Background(), "start", unit); err != nil {
			return fmt.Errorf("restore reconciled tenant socket: %w", err)
		}
	}
	restoreSocketOnFailure = false
	if socketShouldBeReady {
		if err := admin.VerifyTenantService(context.Background(), portal, tenant, admin.ServiceVerificationOptions{RequireReadySocket: true}); err != nil {
			return fmt.Errorf("started tenant socket failed verification: %w", err)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"provisioned": true, "tenant_id": tenant.TenantID, "runtime_user": tenant.RuntimeUser, "runtime_uid": runtimeUID, "project_id": tenant.Capacity.ProjectID, "socket_unit": unit, "started": socketShouldBeReady})
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
