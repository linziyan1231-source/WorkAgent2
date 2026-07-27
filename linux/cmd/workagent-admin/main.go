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
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/safelog"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

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
	logger.Fatal("usage: workagent-admin <init-admin|create-user|set-password|set-enabled|set-limits|runtime-status|runtime-start|runtime-stop|runtime-restart|list-users|set-chatgpt-pro-limit|verify-tenant|verify-host> [options]")
}

func createUser(arguments []string, forceAdmin, requireEmpty bool) error {
	flags := flag.NewFlagSet("create-user", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	tenantPath := flags.String("tenant-config", "", "tenant configuration")
	username := flags.String("username", "", "Portal username")
	passwordPath := flags.String("password-file", "", "protected password input file")
	adminUser := flags.Bool("admin", false, "grant Portal administration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if forceAdmin {
		*adminUser = true
	}
	portalConfig, tenant, err := loadBoundTenant(*configPath, *tenantPath)
	if err != nil {
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
	data, err := store.Open(portalConfig.DatabasePath(), portalConfig.AuditPath())
	if err != nil {
		return err
	}
	defer data.Close()
	ctx := context.Background()
	if requireEmpty {
		count, err := data.UserCount(ctx)
		if err != nil {
			return err
		}
		if count != 0 {
			return errors.New("init-admin is allowed only on an empty Portal database")
		}
	}
	created, err := data.CreateUser(ctx, *username, hash, tenant.TenantID, tenant.RuntimeUser, tenant.DataRoot, *adminUser, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := data.Audit(ctx, store.AuditEvent{Action: "admin.user.add", Outcome: "success", Username: created.Username, TenantID: created.TenantID, RemoteIP: "local-admin", Details: map[string]any{"admin_role": created.Admin}}); err != nil {
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

func setEnabled(arguments []string) error {
	flags := flag.NewFlagSet("set-enabled", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/workagent/portal.json", "Portal configuration")
	username := flags.String("username", "", "Portal username")
	enabled := flags.Bool("enabled", false, "new enabled state")
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
	ctx := context.Background()
	if err := applyUserEnabledState(ctx, portalConfig, data, *username, *enabled, systemdctl.Default()); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "username": store.NormalizeUsername(*username), "enabled": *enabled})
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
	now := time.Now().UTC()
	if enabled {
		path := filepath.Join(portalConfig.Paths.TenantConfigs, userValue.TenantID+".json")
		tenant, err := config.LoadTenant(path)
		if err != nil || tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
			return fmt.Errorf("tenant identity is not ready for enablement: %w", err)
		}
		if err := admin.VerifyTenantConfigPath(portalConfig, tenant, path); err != nil {
			return err
		}
		if _, err := admin.VerifyTenantHost(portalConfig, tenant); err != nil {
			return err
		}
		if err := admin.VerifyTenantService(ctx, portalConfig, tenant, admin.ServiceVerificationOptions{Controller: controller}); err != nil {
			return err
		}
		if err := controller.Action(ctx, "enable", "--now", socketUnit); err != nil {
			return fmt.Errorf("enable tenant socket: %w", err)
		}
		if err := admin.VerifyTenantService(ctx, portalConfig, tenant, admin.ServiceVerificationOptions{RequireReadySocket: true, Controller: controller}); err != nil {
			_ = controller.Action(ctx, "disable", "--now", socketUnit)
			return fmt.Errorf("verify enabled tenant socket: %w", err)
		}
		if err := data.SetUserEnabled(ctx, userValue.Username, true, now); err != nil {
			_ = controller.Action(ctx, "disable", "--now", socketUnit)
			_ = controller.Action(ctx, "stop", serviceUnit)
			return err
		}
		return data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.state", Outcome: "enabled", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"enabled": true, "socket_unit": socketUnit}})
	}

	if err := data.SetUserEnabled(ctx, userValue.Username, false, now); err != nil {
		return err
	}
	var lifecycleErrors []error
	if err := controller.Action(ctx, "disable", "--now", socketUnit); err != nil {
		lifecycleErrors = append(lifecycleErrors, fmt.Errorf("disable tenant socket: %w", err))
	}
	if err := controller.Action(ctx, "stop", serviceUnit); err != nil {
		lifecycleErrors = append(lifecycleErrors, fmt.Errorf("stop tenant service: %w", err))
	}
	outcome := "disabled"
	if len(lifecycleErrors) != 0 {
		outcome = "disabled_stop_failed"
	}
	auditErr := data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.state", Outcome: outcome, Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"enabled": false, "socket_unit": socketUnit, "service_unit": serviceUnit}})
	return errors.Join(append(lifecycleErrors, auditErr)...)
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

func setLimits(arguments []string) error {
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
	tenantPath := filepath.Join(portalConfig.Paths.TenantConfigs, userValue.TenantID+".json")
	tenant, err := config.LoadTenant(tenantPath)
	if err != nil {
		return err
	}
	if tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
		return errors.New("tenant identity does not match the Portal database")
	}
	controller := systemdctl.Default()
	socketUnit := "workagent-userhost@" + tenant.TenantID + ".socket"
	serviceUnit := "workagent-userhost@" + tenant.TenantID + ".service"
	socket, err := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState")
	if err != nil || socket["LoadState"] != "loaded" {
		return fmt.Errorf("inspect tenant socket before resource update: %w", err)
	}
	restartSocket := socket["ActiveState"] == "active"
	if restartSocket {
		if err := controller.Action(ctx, "stop", socketUnit); err != nil {
			return fmt.Errorf("quiesce tenant socket: %w", err)
		}
	}
	resume := func() error {
		if restartSocket {
			return controller.Action(ctx, "start", socketUnit)
		}
		return nil
	}
	if err := controller.Action(ctx, "stop", serviceUnit); err != nil {
		_ = resume()
		return fmt.Errorf("stop tenant service for resource update: %w", err)
	}
	previous := tenant
	tenant.Limits = limits
	if err := tenant.Validate(); err != nil {
		_ = resume()
		return err
	}
	if err := admin.WriteTenantFiles(ctx, portalConfig, tenant); err != nil {
		_ = admin.WriteTenantFiles(ctx, portalConfig, previous)
		_ = resume()
		return err
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		_ = admin.WriteTenantFiles(ctx, portalConfig, previous)
		_ = controller.Action(ctx, "daemon-reload")
		_ = resume()
		return err
	}
	if err := admin.VerifyTenantService(ctx, portalConfig, tenant, admin.ServiceVerificationOptions{Controller: controller}); err != nil {
		_ = admin.WriteTenantFiles(ctx, portalConfig, previous)
		_ = controller.Action(ctx, "daemon-reload")
		_ = resume()
		return err
	}
	if err := resume(); err != nil {
		return fmt.Errorf("resource limits updated but tenant socket restart failed: %w", err)
	}
	if restartSocket {
		if err := admin.VerifyTenantService(ctx, portalConfig, tenant, admin.ServiceVerificationOptions{RequireReadySocket: true, Controller: controller}); err != nil {
			return fmt.Errorf("resource limits updated but tenant socket verification failed: %w", err)
		}
	}
	now := time.Now().UTC()
	if err := data.Audit(ctx, store.AuditEvent{OccurredAt: now, Action: "admin.user.set_limits", Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"memory_bytes": limits.MemoryBytes, "cpu_percent": limits.CPUPercent, "active_processes": limits.ActiveProcesses}}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"updated": true, "username": userValue.Username, "limits": limits})
}

func runtimeCommand(operation string, arguments []string) error {
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
	controller := systemdctl.Default()
	states := make([]map[string]any, 0, len(users))
	for _, userValue := range users {
		socketUnit := "workagent-userhost@" + userValue.TenantID + ".socket"
		serviceUnit := "workagent-userhost@" + userValue.TenantID + ".service"
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
			switch operation {
			case "runtime-start":
				if err := controller.Action(ctx, "enable", "--now", socketUnit); err != nil {
					return err
				}
				if err := controller.Action(ctx, "start", serviceUnit); err != nil {
					return err
				}
			case "runtime-stop":
				if err := controller.Action(ctx, "stop", serviceUnit); err != nil {
					return err
				}
			case "runtime-restart":
				if err := controller.Action(ctx, "enable", "--now", socketUnit); err != nil {
					return err
				}
				if err := controller.Action(ctx, "restart", serviceUnit); err != nil {
					return err
				}
			}
			action := "admin.runtime." + strings.TrimPrefix(operation, "runtime-")
			if err := data.Audit(ctx, store.AuditEvent{OccurredAt: time.Now().UTC(), Action: action, Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: "local-admin", Details: map[string]any{"service_unit": serviceUnit, "socket_unit": socketUnit}}); err != nil {
				return err
			}
		}
		socket, err := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState", "UnitFileState")
		if err != nil {
			return err
		}
		service, err := controller.Properties(ctx, serviceUnit, "LoadState", "ActiveState", "SubState", "MainPID", "MemoryCurrent", "TasksCurrent", "CPUUsageNSec")
		if err != nil {
			return err
		}
		states = append(states, map[string]any{"username": userValue.Username, "tenant_id": userValue.TenantID, "user_enabled": userValue.Enabled, "socket_unit": socketUnit, "socket_active": socket["ActiveState"], "socket_enabled": socket["UnitFileState"], "service_unit": serviceUnit, "service_active": service["ActiveState"], "service_substate": service["SubState"], "main_pid": service["MainPID"], "memory_current": service["MemoryCurrent"], "tasks_current": service["TasksCurrent"], "cpu_usage_nsec": service["CPUUsageNSec"]})
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"runtimes": states})
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

func verifyTenant(arguments []string) error {
	options, err := parseVerifyTenantOptions(arguments)
	if err != nil {
		return err
	}
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
	verified, err := admin.VerifyTenantHost(portalConfig, tenant)
	if err != nil {
		return err
	}
	if _, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true}); err != nil {
		return err
	}
	if err := admin.VerifyTenantService(context.Background(), portalConfig, tenant, admin.ServiceVerificationOptions{}); err != nil {
		return err
	}
	if err := verifyTenantQuiescence(verified.RuntimeUID, options.requireQuiescent, admin.VerifyRuntimeUIDQuiescent); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "tenant_id": tenant.TenantID, "runtime_uid": verified.RuntimeUID, "release_id": verified.Release.Manifest.ReleaseID})
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

func loadBoundTenant(portalPath, tenantPath string) (config.Portal, config.Tenant, error) {
	portalConfig, err := config.LoadPortal(portalPath)
	if err != nil {
		return config.Portal{}, config.Tenant{}, err
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
	if _, err := admin.VerifyTenantHost(portalConfig, tenant); err != nil {
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
