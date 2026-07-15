package admin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aionuiportal/internal/adminipc"
	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/auth"
	"aionuiportal/internal/cliproxy"
	"aionuiportal/internal/config"
	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/kimi"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/release"
	"aionuiportal/internal/scheduler"
	"aionuiportal/internal/store"
	"aionuiportal/internal/winutil"
	"golang.org/x/sys/windows"
)

type Manager struct {
	ConfigPath       string
	Config           config.Portal
	Store            *store.Store
	Instances        *instance.Manager
	Tasks            scheduler.Controller
	ProfileDirectory func(string) (string, error)
}

type UserStatus struct {
	User        store.User
	Status      *ipc.Status
	Sessions    int
	Requests    int
	WebSockets  int
	StatusError error
}

type KimiOAuthSeedResult struct {
	SHA256    string
	Output    string
	Restarted bool
}

type ModelBootstrapOptions struct {
	SSHTarget         string
	RemoteHelperPath  string
	BaseURL           string
	CodexDefaultModel string
	CodexModels       []string
	KimiModels        []string
	RPM               int
	CodexDailyUSD     float64
	CodexWeeklyUSD    float64
	KimiDailyUSD      float64
	KimiWeeklyUSD     float64
	Update            bool
}

type ModelBootstrapResult struct {
	Outcome    string
	CodexKeyID string
	KimiKeyID  string
	Restarted  bool
}

func Open(configPath string) (*Manager, error) {
	cfg, err := config.LoadPortal(configPath)
	if err != nil {
		return nil, err
	}
	data, err := store.Open(cfg.DatabasePath, cfg.AuditLogPath)
	if err != nil {
		return nil, err
	}
	tasks := scheduler.Controller{}
	return &Manager{ConfigPath: filepath.Clean(configPath), Config: cfg, Store: data, Instances: instance.New(cfg, data, tasks), Tasks: tasks,
		ProfileDirectory: winutil.ProfileDirectoryForSID}, nil
}

func (m *Manager) Close() error { return m.Store.Close() }

func (m *Manager) AddUser(ctx context.Context, username, windowsAccount string, adminRole bool, password []byte) (store.User, error) {
	defer auth.Zero(password)
	if err := auth.ValidatePortalUsername(username); err != nil {
		return store.User{}, err
	}
	if _, err := m.Store.UserByUsername(ctx, username); err == nil {
		return store.User{}, errors.New("Portal username already exists")
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	if err := auth.ValidatePortalPassword(password); err != nil {
		return store.User{}, err
	}
	sid, canonical, err := winutil.ValidateStandardAccount(windowsAccount)
	if err != nil {
		return store.User{}, err
	}
	if _, err := m.Store.UserBySID(ctx, sid); err == nil {
		return store.User{}, errors.New("Windows SID is already mapped to a Portal user")
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return store.User{}, err
	}
	userConfig, err := m.provisionUserFiles(sid, canonical)
	if err != nil {
		return store.User{}, err
	}
	user, err := m.Store.CreateUser(ctx, username, hash, sid, canonical, adminRole, time.Now())
	if err != nil {
		return store.User{}, fmt.Errorf("Portal user creation failed after private files were provisioned at %s: %w", userConfig.DataRoot, err)
	}
	if err := m.Store.Audit(ctx, "admin.user.add", "success", user.Username, sid, "local-admin", map[string]any{"admin_role": adminRole}, time.Now()); err != nil {
		return user, fmt.Errorf("Portal user was created but its audit event could not be recorded: %w", err)
	}
	return user, nil
}

func (m *Manager) SetUserEnabled(ctx context.Context, username string, enabled bool) error {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if err := m.Store.SetUserEnabled(ctx, username, enabled, time.Now()); err != nil {
		return err
	}
	outcome := "enabled"
	if !enabled {
		outcome = "disabled"
		stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.Instances.Stop(stopCtx, user.WindowsSID)
		cancel()
		if err != nil && !isPipeUnavailable(err) {
			auditErr := m.Store.Audit(ctx, "admin.user.state", "disabled_stop_failed", user.Username, user.WindowsSID, "local-admin", map[string]any{"enabled": false}, time.Now())
			return fmt.Errorf("Portal account was disabled but its UserHost could not be stopped: %w", errors.Join(err, auditErr))
		}
	}
	if err := m.Store.Audit(ctx, "admin.user.state", outcome, user.Username, user.WindowsSID, "local-admin", map[string]any{"enabled": enabled}, time.Now()); err != nil {
		return fmt.Errorf("Portal account state was changed but its audit event could not be recorded: %w", err)
	}
	return nil
}

func (m *Manager) ResetPortalPassword(ctx context.Context, username string, password []byte) error {
	defer auth.Zero(password)
	if err := auth.ValidatePortalPassword(password); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := m.Store.ResetPassword(ctx, username, hash, time.Now()); err != nil {
		return err
	}
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("Portal password was reset but the audit subject could not be reloaded: %w", err)
	}
	if err := m.Store.Audit(ctx, "admin.user.reset_password", "success", username, user.WindowsSID, "local-admin", map[string]any{}, time.Now()); err != nil {
		return fmt.Errorf("Portal password was reset but its audit event could not be recorded: %w", err)
	}
	return nil
}

func (m *Manager) ValidateKimiOAuthSource(ctx context.Context, sourceOAuthPath, sourceConfigPath string) error {
	pythonPath, err := m.kimiPythonPath()
	if err != nil {
		return err
	}
	return kimi.ValidateSource(ctx, sourceOAuthPath, sourceConfigPath, pythonPath, nil)
}

func (m *Manager) HasKimiOAuth(ctx context.Context, username string) (bool, error) {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return false, err
	}
	dataRoot, err := m.UserDataRootForSID(user.WindowsSID)
	if err != nil {
		return false, err
	}
	return kimi.HasCredential(filepath.Join(dataRoot, "profile", ".kimi", "credentials", "kimi-code.json"))
}

func (m *Manager) SeedKimiOAuth(ctx context.Context, username, sourceOAuthPath, sourceConfigPath string) (KimiOAuthSeedResult, error) {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return KimiOAuthSeedResult{}, err
	}
	dataRoot, err := m.UserDataRootForSID(user.WindowsSID)
	if err != nil {
		return KimiOAuthSeedResult{}, err
	}
	pythonPath, err := m.kimiPythonPath()
	if err != nil {
		return KimiOAuthSeedResult{}, err
	}
	wasRunning := false
	if status, statusErr := m.Instances.Status(ctx, user.WindowsSID); statusErr == nil {
		wasRunning = status.Healthy || status.State == "starting"
	} else if !isPipeUnavailable(statusErr) {
		return KimiOAuthSeedResult{}, fmt.Errorf("inspect target UserHost before Kimi OAuth seeding: %w", statusErr)
	}
	seeded, err := kimi.Seed(ctx, kimi.SeedOptions{
		SourceOAuthPath:  sourceOAuthPath,
		SourceConfigPath: sourceConfigPath,
		TargetProfile:    filepath.Join(dataRoot, "profile"),
		PythonPath:       pythonPath,
		BeforeWrite: func() error {
			stopErr := m.Instances.Stop(ctx, user.WindowsSID)
			if stopErr != nil && !isPipeUnavailable(stopErr) {
				return stopErr
			}
			return nil
		},
	})
	if err != nil {
		return KimiOAuthSeedResult{}, err
	}
	policy := winutil.PrivateTreePolicy(user.WindowsSID)
	if err := winutil.ApplyTreeACL(dataRoot, policy); err != nil {
		return KimiOAuthSeedResult{}, fmt.Errorf("Kimi OAuth was seeded but its private ACL could not be applied: %w", err)
	}
	if err := winutil.VerifyTreeACL(dataRoot, policy); err != nil {
		return KimiOAuthSeedResult{}, fmt.Errorf("Kimi OAuth was seeded but its private ACL could not be verified: %w", err)
	}
	restarted := false
	if wasRunning && user.Enabled {
		if _, err := m.Instances.Ensure(ctx, user.WindowsSID); err != nil {
			return KimiOAuthSeedResult{}, fmt.Errorf("Kimi OAuth was seeded but the previously running UserHost could not be restarted: %w", err)
		}
		restarted = true
	}
	if err := m.Store.Audit(ctx, "admin.kimi_oauth.seed", "success", user.Username, user.WindowsSID, "local-admin",
		map[string]any{"sha256": seeded.SHA256, "restarted": restarted}, time.Now()); err != nil {
		return KimiOAuthSeedResult{}, fmt.Errorf("Kimi OAuth was seeded but its audit event could not be recorded: %w", err)
	}
	return KimiOAuthSeedResult{SHA256: seeded.SHA256, Output: seeded.Output, Restarted: restarted}, nil
}

func (m *Manager) kimiPythonPath() (string, error) {
	root := agentcli.RootFromAionReleases(m.Config.ReleasesRoot)
	verified, err := agentcli.VerifyCurrent(root)
	if err != nil {
		return "", fmt.Errorf("verify shared agent CLI release before Kimi OAuth seeding: %w", err)
	}
	return filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiRelativePath)), nil
}

func (m *Manager) ModelBootstrapStatus(ctx context.Context, username string) (modelbootstrap.Status, error) {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return modelbootstrap.Status{}, err
	}
	dataRoot, err := m.UserDataRootForSID(user.WindowsSID)
	if err != nil {
		return modelbootstrap.Status{}, err
	}
	return modelbootstrap.Inspect(dataRoot)
}

func (m *Manager) ProvisionModelBootstrap(ctx context.Context, username string, options ModelBootstrapOptions) (ModelBootstrapResult, error) {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return ModelBootstrapResult{}, err
	}
	dataRoot, err := m.UserDataRootForSID(user.WindowsSID)
	if err != nil {
		return ModelBootstrapResult{}, err
	}
	status, err := modelbootstrap.Inspect(dataRoot)
	if err != nil {
		return ModelBootstrapResult{}, err
	}
	if status.Applied && !options.Update {
		return ModelBootstrapResult{Outcome: "SKIP", CodexKeyID: status.State.CodexKeyID, KimiKeyID: status.State.KimiKeyID}, nil
	}
	if status.Pending && !options.Update {
		return ModelBootstrapResult{Outcome: "PENDING", CodexKeyID: status.State.CodexKeyID, KimiKeyID: status.State.KimiKeyID}, nil
	}

	wasRunning := false
	if instanceStatus, statusErr := m.Instances.Status(ctx, user.WindowsSID); statusErr == nil {
		wasRunning = instanceStatus.Healthy || instanceStatus.State == "starting"
	} else if !isPipeUnavailable(statusErr) {
		return ModelBootstrapResult{}, fmt.Errorf("inspect target UserHost before model bootstrap: %w", statusErr)
	}
	stopErr := m.Instances.Stop(ctx, user.WindowsSID)
	if stopErr != nil && !isPipeUnavailable(stopErr) {
		return ModelBootstrapResult{}, fmt.Errorf("stop target UserHost before model bootstrap: %w", stopErr)
	}

	client := cliproxy.Client{SSHTarget: options.SSHTarget, HelperPath: options.RemoteHelperPath}
	bundle, err := client.Provision(ctx, cliproxy.ProvisionOptions{Username: user.Username, WindowsSID: user.WindowsSID, BaseURL: options.BaseURL,
		CodexDefaultModel: options.CodexDefaultModel, CodexModels: options.CodexModels, KimiModels: options.KimiModels, RPM: options.RPM,
		CodexDailyUSD: options.CodexDailyUSD, CodexWeeklyUSD: options.CodexWeeklyUSD, KimiDailyUSD: options.KimiDailyUSD, KimiWeeklyUSD: options.KimiWeeklyUSD})
	if err != nil {
		return ModelBootstrapResult{}, err
	}
	if err := modelbootstrap.Stage(dataRoot, bundle, options.Update); err != nil {
		return ModelBootstrapResult{}, fmt.Errorf("stage private model bootstrap: %w", err)
	}
	policy := winutil.PrivateTreePolicy(user.WindowsSID)
	if err := winutil.ApplyTreeACL(dataRoot, policy); err != nil {
		return ModelBootstrapResult{}, fmt.Errorf("model bootstrap was staged but its private ACL could not be applied: %w", err)
	}
	if err := winutil.VerifyTreeACL(dataRoot, policy); err != nil {
		return ModelBootstrapResult{}, fmt.Errorf("model bootstrap was staged but its private ACL could not be verified: %w", err)
	}

	result := ModelBootstrapResult{Outcome: "PENDING", CodexKeyID: bundle.CodexKeyID, KimiKeyID: bundle.KimiKeyID}
	if wasRunning && user.Enabled {
		if _, err := m.Instances.Ensure(ctx, user.WindowsSID); err != nil {
			return ModelBootstrapResult{}, fmt.Errorf("model bootstrap was staged but the previously running UserHost could not apply it: %w", err)
		}
		applied, err := modelbootstrap.Inspect(dataRoot)
		if err != nil || !applied.Applied {
			return ModelBootstrapResult{}, fmt.Errorf("restarted UserHost did not publish the model bootstrap marker: %v", err)
		}
		result.Outcome, result.Restarted = "APPLIED", true
	}
	if err := m.Store.Audit(ctx, "admin.model_bootstrap.provision", "success", user.Username, user.WindowsSID, "local-admin",
		map[string]any{"codex_key_id": bundle.CodexKeyID, "kimi_key_id": bundle.KimiKeyID, "outcome": result.Outcome, "restarted": result.Restarted}, time.Now()); err != nil {
		return result, fmt.Errorf("model bootstrap succeeded but its audit event could not be recorded: %w", err)
	}
	return result, nil
}

func (m *Manager) MapWindowsAccount(ctx context.Context, username, windowsAccount string) (store.User, error) {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return store.User{}, err
	}
	sid, canonical, err := winutil.ValidateStandardAccount(windowsAccount)
	if err != nil {
		return store.User{}, err
	}
	if strings.EqualFold(sid, user.WindowsSID) {
		if strings.EqualFold(canonical, user.WindowsUsername) {
			return user, nil
		}
		return m.renameWindowsAccount(ctx, user, canonical)
	}
	if mapped, err := m.Store.UserBySID(ctx, sid); err == nil {
		return store.User{}, fmt.Errorf("Windows SID is already mapped to Portal user %s", mapped.Username)
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, err
	}
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopErr := m.Instances.Stop(stopCtx, user.WindowsSID)
	cancel()
	if stopErr != nil && !isPipeUnavailable(stopErr) {
		return store.User{}, stopErr
	}
	if err := m.Tasks.Remove(ctx, user.WindowsSID); err != nil && !isTaskMissing(err) {
		return store.User{}, fmt.Errorf("remove old SID task before remapping: %w", err)
	}
	if _, err := m.provisionUserFiles(sid, canonical); err != nil {
		return store.User{}, fmt.Errorf("old SID task was removed but new SID files could not be provisioned: %w", err)
	}
	if err := m.Store.MapWindowsIdentity(ctx, username, sid, canonical, time.Now()); err != nil {
		return store.User{}, fmt.Errorf("old SID task was removed and new SID files were provisioned, but the Portal mapping could not be updated: %w", err)
	}
	mapped, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return store.User{}, err
	}
	if err := m.Store.Audit(ctx, "admin.user.map_windows_sid", "success", username, sid, "local-admin",
		map[string]any{"previous_sid": user.WindowsSID}, time.Now()); err != nil {
		return mapped, fmt.Errorf("Windows SID mapping was updated but its audit event could not be recorded: %w", err)
	}
	return mapped, nil
}

func (m *Manager) renameWindowsAccount(ctx context.Context, user store.User, canonical string) (store.User, error) {
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopErr := m.Instances.Stop(stopCtx, user.WindowsSID)
	cancel()
	if stopErr != nil && !isPipeUnavailable(stopErr) {
		return store.User{}, stopErr
	}
	if err := m.Tasks.Remove(ctx, user.WindowsSID); err != nil && !isTaskMissing(err) {
		return store.User{}, fmt.Errorf("remove task with the previous Windows account name: %w", err)
	}
	path := m.userConfigPath(user.WindowsSID)
	cfg, err := config.LoadUserHost(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg, err = m.provisionUserFiles(user.WindowsSID, canonical)
	}
	if err != nil {
		return store.User{}, fmt.Errorf("task with the previous Windows account name was removed but the UserHost config could not be loaded: %w", err)
	}
	if err := m.validateUserHostLayout(cfg, user.WindowsSID); err != nil {
		return store.User{}, err
	}
	if !strings.EqualFold(cfg.WindowsUsername, user.WindowsUsername) && !strings.EqualFold(cfg.WindowsUsername, canonical) {
		return store.User{}, fmt.Errorf("existing UserHost config belongs to unexpected Windows account %q", cfg.WindowsUsername)
	}
	if !strings.EqualFold(cfg.WindowsUsername, canonical) {
		cfg.WindowsUsername = canonical
		if err := writeJSONAtomic(path, cfg); err != nil {
			return store.User{}, err
		}
	}
	policy := winutil.UserConfigPolicy(m.Config.PortalServiceSID, user.WindowsSID)
	if err := winutil.ApplyTreeACL(filepath.Dir(path), policy); err != nil {
		return store.User{}, err
	}
	if err := winutil.VerifyTreeACL(filepath.Dir(path), policy); err != nil {
		return store.User{}, err
	}
	if err := m.Store.MapWindowsIdentity(ctx, user.Username, user.WindowsSID, canonical, time.Now()); err != nil {
		return store.User{}, fmt.Errorf("UserHost config was updated but the Portal mapping could not be updated: %w", err)
	}
	mapped, err := m.Store.UserByUsername(ctx, user.Username)
	if err != nil {
		return store.User{}, err
	}
	if err := m.Store.Audit(ctx, "admin.user.rename_windows_account", "success", mapped.Username, mapped.WindowsSID, "local-admin",
		map[string]any{"previous_windows_username": user.WindowsUsername}, time.Now()); err != nil {
		return mapped, fmt.Errorf("Windows account name was updated but its audit event could not be recorded: %w", err)
	}
	return mapped, nil
}

func (m *Manager) InstallOrUpdateTask(ctx context.Context, username string, password []byte, restart bool) (ipc.Status, error) {
	defer auth.Zero(password)
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return ipc.Status{}, err
	}
	if !user.Enabled {
		return ipc.Status{}, errors.New("Portal user is disabled")
	}
	if restart {
		stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		stopErr := m.Instances.Stop(stopCtx, user.WindowsSID)
		cancel()
		if stopErr != nil && !isPipeUnavailable(stopErr) {
			return ipc.Status{}, fmt.Errorf("stop existing UserHost before task credential update: %w", stopErr)
		}
		waitForPipeExit(user.WindowsSID, 15*time.Second)
	}
	spec := m.taskSpec(user)
	if err := m.Tasks.Register(ctx, spec, password); err != nil {
		return ipc.Status{}, err
	}
	info, err := m.Tasks.Info(ctx, user.WindowsSID)
	if err != nil {
		return ipc.Status{}, fmt.Errorf("read back registered task: %w", err)
	}
	if err := scheduler.VerifySpec(info, spec); err != nil {
		return ipc.Status{}, fmt.Errorf("registered task verification failed: %w", err)
	}
	status, err := m.Instances.Ensure(ctx, user.WindowsSID)
	if err != nil {
		latest, infoErr := m.Tasks.Info(context.Background(), user.WindowsSID)
		if infoErr == nil {
			return ipc.Status{}, fmt.Errorf("task credential verification failed (LastTaskResult=0x%08x): %w", uint32(latest.LastTaskResult), err)
		}
		return ipc.Status{}, err
	}
	if !containsCheck(status.Checks, "whoami-user") || !strings.EqualFold(status.WindowsSID, user.WindowsSID) {
		return ipc.Status{}, errors.New("UserHost did not verify whoami /user under the scheduled task identity")
	}
	if err := m.Store.Audit(ctx, "admin.task.register", "success", user.Username, user.WindowsSID, "local-admin",
		map[string]any{"task_name": info.Name}, time.Now()); err != nil {
		return status, fmt.Errorf("scheduled task credentials and identity were verified but the audit event could not be recorded: %w", err)
	}
	return status, nil
}

func (m *Manager) RemoveTask(ctx context.Context, username string) error {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopErr := m.Instances.Stop(stopCtx, user.WindowsSID)
	cancel()
	if stopErr != nil && !isPipeUnavailable(stopErr) {
		return stopErr
	}
	if err := m.Tasks.Remove(ctx, user.WindowsSID); err != nil {
		return err
	}
	if err := m.Store.Audit(ctx, "admin.task.remove", "success", user.Username, user.WindowsSID, "local-admin", map[string]any{}, time.Now()); err != nil {
		return fmt.Errorf("scheduled task was removed but its audit event could not be recorded: %w", err)
	}
	return nil
}

func (m *Manager) List(ctx context.Context) ([]UserStatus, error) {
	users, err := m.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]UserStatus, 0, len(users))
	for _, user := range users {
		item := UserStatus{User: user}
		if snapshot, snapshotErr := m.adminSnapshot(ctx, user.WindowsSID); snapshotErr == nil {
			item.Status, item.Sessions, item.Requests, item.WebSockets = snapshot.Status, snapshot.Sessions, snapshot.Requests, snapshot.WebSockets
		} else {
			statusCtx, cancel := context.WithTimeout(ctx, time.Second)
			status, statusErr := m.Instances.Status(statusCtx, user.WindowsSID)
			cancel()
			if statusErr == nil {
				item.Status = &status
			} else if !isPipeUnavailable(statusErr) {
				item.StatusError = statusErr
			}
			item.Sessions, err = m.Store.SessionCountForUser(ctx, user.ID, time.Now())
			if err != nil {
				return nil, fmt.Errorf("count sessions for %s: %w", user.Username, err)
			}
		}
		result = append(result, item)
	}
	return result, nil
}

func (m *Manager) UserStatus(ctx context.Context, user store.User) (UserStatus, error) {
	if snapshot, err := m.adminSnapshot(ctx, user.WindowsSID); err == nil {
		return UserStatus{User: user, Status: snapshot.Status, Sessions: snapshot.Sessions, Requests: snapshot.Requests, WebSockets: snapshot.WebSockets}, nil
	}
	status, err := m.Instances.Status(ctx, user.WindowsSID)
	if err != nil {
		if !isPipeUnavailable(err) {
			return UserStatus{}, err
		}
		status = ipc.Status{WindowsSID: user.WindowsSID, State: "stopped", Healthy: false, FailureReason: "UserHost IPC is unavailable"}
	}
	sessions, err := m.Store.SessionCountForUser(ctx, user.ID, time.Now())
	if err != nil {
		return UserStatus{}, fmt.Errorf("count sessions for %s: %w", user.Username, err)
	}
	return UserStatus{User: user, Status: &status, Sessions: sessions}, nil
}

func (m *Manager) adminSnapshot(ctx context.Context, sid string) (adminipc.Response, error) {
	nonce, err := auth.RandomToken(18)
	if err != nil {
		return adminipc.Response{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return adminipc.Call(callCtx, adminipc.Request{Command: "status", WindowsSID: sid, Nonce: nonce})
}

func (m *Manager) SetLimits(ctx context.Context, username string, limits config.ResourceLimits) error {
	user, err := m.Store.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	stopErr := m.Instances.Stop(stopCtx, user.WindowsSID)
	cancel()
	if stopErr != nil && !isPipeUnavailable(stopErr) {
		return stopErr
	}
	path := m.userConfigPath(user.WindowsSID)
	cfg, err := config.LoadUserHost(path)
	if err != nil {
		return err
	}
	cfg.Limits = limits
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := writeJSONAtomic(path, cfg); err != nil {
		return err
	}
	policy := winutil.UserConfigPolicy(m.Config.PortalServiceSID, user.WindowsSID)
	if err := winutil.ApplyTreeACL(filepath.Dir(path), policy); err != nil {
		return fmt.Errorf("resource limits were updated but the UserHost config ACL could not be applied: %w", err)
	}
	if err := winutil.VerifyTreeACL(filepath.Dir(path), policy); err != nil {
		return fmt.Errorf("resource limits were updated but the UserHost config ACL could not be verified: %w", err)
	}
	if err := m.Store.Audit(ctx, "admin.user.set_limits", "success", user.Username, user.WindowsSID, "local-admin",
		map[string]any{"memory_bytes": limits.MemoryBytes, "cpu_percent": limits.CPUPercent, "active_processes": limits.ActiveProcesses}, time.Now()); err != nil {
		return fmt.Errorf("resource limits were updated but the audit event could not be recorded: %w", err)
	}
	return nil
}

func (m *Manager) VerifyACLs(ctx context.Context) []error {
	var failures []error
	failures = append(failures, m.verifyBaseACLs()...)
	verified, err := release.VerifyCurrent(m.Config.CurrentReleaseFile, m.Config.ReleasesRoot, m.Config.SupportedAionCore)
	if err != nil {
		failures = append(failures, err)
	} else if err := winutil.VerifyTreeACL(verified.Path, winutil.SharedReadOnlyPolicy()); err != nil {
		failures = append(failures, err)
	}
	agentRoot := agentcli.RootFromAionReleases(m.Config.ReleasesRoot)
	if _, err := agentcli.VerifyCurrent(agentRoot); err != nil {
		failures = append(failures, fmt.Errorf("shared agent CLI release: %w", err))
	} else if err := winutil.VerifyTreeACL(agentRoot, winutil.SharedReadOnlyPolicy()); err != nil {
		failures = append(failures, fmt.Errorf("shared agent CLI ACL: %w", err))
	}
	users, err := m.Store.ListUsers(ctx)
	if err != nil {
		return append(failures, err)
	}
	for _, user := range users {
		dataRoot, err := m.UserDataRootForSID(user.WindowsSID)
		if err != nil {
			failures = append(failures, fmt.Errorf("user %s private data layout: %w", user.Username, err))
			continue
		}
		if err := winutil.VerifyTreeACL(dataRoot, winutil.PrivateTreePolicy(user.WindowsSID)); err != nil {
			failures = append(failures, fmt.Errorf("user %s private data: %w", user.Username, err))
		}
		if err := winutil.VerifyTreeACL(filepath.Dir(m.userConfigPath(user.WindowsSID)), winutil.UserConfigPolicy(m.Config.PortalServiceSID, user.WindowsSID)); err != nil {
			failures = append(failures, fmt.Errorf("user %s fixed config: %w", user.Username, err))
		}
	}
	return failures
}

func (m *Manager) servicePrivateDirectories() []string {
	paths := []string{filepath.Dir(m.Config.DatabasePath), filepath.Dir(m.Config.AuditLogPath), m.Config.UserConfigRoot}
	if m.Config.UsesTLS() {
		paths = append(paths, filepath.Dir(m.Config.TLSCertificateFile))
	}
	return paths
}

func (m *Manager) servicePrivateFiles() []string {
	paths := []string{m.ConfigPath, m.Config.DatabasePath, m.Config.AuditLogPath, m.Config.PortalLogPath}
	if m.Config.UsesTLS() {
		paths = append(paths, m.Config.TLSCertificateFile, m.Config.TLSPrivateKeyFile)
	}
	return paths
}

func (m *Manager) usageCredentialFiles() []string {
	if m.Config.UsageSSHIdentityFile == "" || m.Config.UsageSSHKnownHostsFile == "" {
		return nil
	}
	return []string{m.Config.UsageSSHIdentityFile, m.Config.UsageSSHIdentityFile + ".pub", m.Config.UsageSSHKnownHostsFile}
}

func (m *Manager) ApplyACLs(ctx context.Context) []error {
	var failures []error
	if err := winutil.ApplyTreeACL(filepath.Dir(m.Config.UserHostExecutable), winutil.SharedReadOnlyPolicy()); err != nil {
		failures = append(failures, fmt.Errorf("Portal program directory: %w", err))
	}
	servicePolicy := winutil.ServicePrivatePolicy(m.Config.PortalServiceSID)
	for _, path := range m.servicePrivateDirectories() {
		if err := os.MkdirAll(path, 0o700); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := winutil.ApplyACL(path, servicePolicy); err != nil {
			failures = append(failures, fmt.Errorf("service path %s: %w", path, err))
		}
	}
	for _, path := range []string{m.Config.AuditLogPath, m.Config.PortalLogPath} {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			failures = append(failures, fmt.Errorf("create log %s before ACL application: %w", path, err))
		} else if err := file.Close(); err != nil {
			failures = append(failures, fmt.Errorf("close log %s before ACL application: %w", path, err))
		}
	}
	for _, path := range m.servicePrivateFiles() {
		if _, err := os.Stat(path); err != nil {
			failures = append(failures, fmt.Errorf("required service file %s: %w", path, err))
			continue
		}
		if err := winutil.ApplyACL(path, servicePolicy); err != nil {
			failures = append(failures, fmt.Errorf("service file %s: %w", path, err))
		}
	}
	credentialFiles := m.usageCredentialFiles()
	if len(credentialFiles) != 0 {
		credentialPolicy := winutil.ServiceCredentialPolicy(m.Config.PortalServiceSID)
		credentialRoot := filepath.Dir(credentialFiles[0])
		if err := os.MkdirAll(credentialRoot, 0o700); err != nil {
			failures = append(failures, fmt.Errorf("create usage credential directory: %w", err))
		} else if err := winutil.ApplyACL(credentialRoot, credentialPolicy); err != nil {
			failures = append(failures, fmt.Errorf("usage credential directory: %w", err))
		}
		for _, path := range credentialFiles {
			if info, err := os.Lstat(path); err != nil {
				failures = append(failures, fmt.Errorf("required usage credential file %s: %w", path, err))
			} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				failures = append(failures, fmt.Errorf("usage credential file %s is not a regular non-reparse file", path))
			} else if err := winutil.ApplyACL(path, credentialPolicy); err != nil {
				failures = append(failures, fmt.Errorf("usage credential file %s: %w", path, err))
			}
		}
	}
	failures = append(failures, m.applyReleaseControlACLs()...)
	if verified, err := release.VerifyCurrent(m.Config.CurrentReleaseFile, m.Config.ReleasesRoot, m.Config.SupportedAionCore); err != nil {
		failures = append(failures, fmt.Errorf("shared release: %w", err))
	} else {
		if err := winutil.ApplyTreeACL(verified.Path, winutil.SharedReadOnlyPolicy()); err != nil {
			failures = append(failures, err)
		}
	}
	agentRoot := agentcli.RootFromAionReleases(m.Config.ReleasesRoot)
	if err := winutil.ApplyTreeACL(agentRoot, winutil.SharedReadOnlyPolicy()); err != nil {
		failures = append(failures, fmt.Errorf("shared agent CLI ACL: %w", err))
	} else if _, err := agentcli.VerifyCurrent(agentRoot); err != nil {
		failures = append(failures, fmt.Errorf("shared agent CLI release: %w", err))
	}
	users, err := m.Store.ListUsers(ctx)
	if err != nil {
		return append(failures, err)
	}
	for _, user := range users {
		dataRoot, err := m.UserDataRootForSID(user.WindowsSID)
		if err != nil {
			failures = append(failures, fmt.Errorf("user %s private data layout: %w", user.Username, err))
			continue
		}
		if err := winutil.ApplyTreeACL(dataRoot, winutil.PrivateTreePolicy(user.WindowsSID)); err != nil {
			failures = append(failures, fmt.Errorf("user %s private data: %w", user.Username, err))
		}
		if err := winutil.ApplyTreeACL(filepath.Dir(m.userConfigPath(user.WindowsSID)), winutil.UserConfigPolicy(m.Config.PortalServiceSID, user.WindowsSID)); err != nil {
			failures = append(failures, fmt.Errorf("user %s fixed config: %w", user.Username, err))
		}
	}
	return failures
}

func (m *Manager) verifyBaseACLs() []error {
	var failures []error
	if err := winutil.VerifyTreeACL(filepath.Dir(m.Config.UserHostExecutable), winutil.SharedReadOnlyPolicy()); err != nil {
		failures = append(failures, fmt.Errorf("Portal program directory: %w", err))
	}
	servicePolicy := winutil.ServicePrivatePolicy(m.Config.PortalServiceSID)
	for _, path := range m.servicePrivateDirectories() {
		if err := winutil.VerifyACL(path, servicePolicy); err != nil {
			failures = append(failures, fmt.Errorf("service path %s: %w", path, err))
		}
	}
	for _, path := range m.servicePrivateFiles() {
		if _, err := os.Stat(path); err != nil {
			failures = append(failures, fmt.Errorf("required service file %s: %w", path, err))
			continue
		}
		if err := winutil.VerifyACL(path, servicePolicy); err != nil {
			failures = append(failures, fmt.Errorf("service file %s: %w", path, err))
		}
	}
	credentialFiles := m.usageCredentialFiles()
	if len(credentialFiles) != 0 {
		credentialPolicy := winutil.ServiceCredentialPolicy(m.Config.PortalServiceSID)
		if err := winutil.VerifyACL(filepath.Dir(credentialFiles[0]), credentialPolicy); err != nil {
			failures = append(failures, fmt.Errorf("usage credential directory: %w", err))
		}
		for _, path := range credentialFiles {
			if info, err := os.Lstat(path); err != nil {
				failures = append(failures, fmt.Errorf("required usage credential file %s: %w", path, err))
			} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				failures = append(failures, fmt.Errorf("usage credential file %s is not a regular non-reparse file", path))
			} else if err := winutil.VerifyACL(path, credentialPolicy); err != nil {
				failures = append(failures, fmt.Errorf("usage credential file %s: %w", path, err))
			}
		}
	}
	failures = append(failures, m.verifyReleaseControlACLs()...)
	return failures
}

func (m *Manager) applyReleaseControlACLs() []error {
	policy := winutil.SharedReadOnlyPolicy()
	var failures []error
	for _, path := range []string{filepath.Dir(m.Config.ReleasesRoot), m.Config.ReleasesRoot} {
		if err := winutil.ApplyACL(path, policy); err != nil {
			failures = append(failures, fmt.Errorf("shared release control directory %s: %w", path, err))
		}
	}
	for _, path := range []string{m.Config.CurrentReleaseFile, filepath.Join(filepath.Dir(m.Config.CurrentReleaseFile), "previous.json")} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && path != m.Config.CurrentReleaseFile {
			continue
		} else if err != nil {
			failures = append(failures, fmt.Errorf("shared release pointer %s: %w", path, err))
			continue
		}
		if err := winutil.ApplyACL(path, policy); err != nil {
			failures = append(failures, fmt.Errorf("shared release pointer %s: %w", path, err))
		}
	}
	return failures
}

func (m *Manager) verifyReleaseControlACLs() []error {
	policy := winutil.SharedReadOnlyPolicy()
	var failures []error
	for _, path := range []string{filepath.Dir(m.Config.ReleasesRoot), m.Config.ReleasesRoot, m.Config.CurrentReleaseFile} {
		if err := winutil.VerifyACL(path, policy); err != nil {
			failures = append(failures, fmt.Errorf("shared release control path %s: %w", path, err))
		}
	}
	previous := filepath.Join(filepath.Dir(m.Config.CurrentReleaseFile), "previous.json")
	if _, err := os.Stat(previous); err == nil {
		if err := winutil.VerifyACL(previous, policy); err != nil {
			failures = append(failures, fmt.Errorf("shared release pointer %s: %w", previous, err))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		failures = append(failures, err)
	}
	return failures
}

func (m *Manager) Readiness(ctx context.Context) []error {
	var failures []error
	if err := m.Tasks.Check(ctx); err != nil {
		failures = append(failures, fmt.Errorf("Task Scheduler COM: %w", err))
	}
	if m.Config.UsesTLS() {
		if _, err := tls.LoadX509KeyPair(m.Config.TLSCertificateFile, m.Config.TLSPrivateKeyFile); err != nil {
			failures = append(failures, fmt.Errorf("TLS key pair: %w", err))
		}
	}
	if _, err := release.VerifyCurrent(m.Config.CurrentReleaseFile, m.Config.ReleasesRoot, m.Config.SupportedAionCore); err != nil {
		failures = append(failures, fmt.Errorf("shared release: %w", err))
	}
	failures = append(failures, m.VerifyACLs(ctx)...)
	users, err := m.Store.ListUsers(ctx)
	if err != nil {
		return append(failures, err)
	}
	for _, user := range users {
		info, err := m.Tasks.Info(ctx, user.WindowsSID)
		if err != nil {
			failures = append(failures, fmt.Errorf("user %s task: %w", user.Username, err))
			continue
		}
		if err := scheduler.VerifySpec(info, m.taskSpec(user)); err != nil {
			failures = append(failures, fmt.Errorf("user %s task: %w", user.Username, err))
		}
	}
	return failures
}

func (m *Manager) provisionUserFiles(sid, canonical string) (config.UserHost, error) {
	profile, dataRoot, err := m.profileDataRoot(sid)
	if err != nil {
		return config.UserHost{}, err
	}
	configPath := m.userConfigPath(sid)
	var recovered *config.UserHost
	if _, err := os.Stat(configPath); err == nil {
		existing, err := config.LoadUserHost(configPath)
		if err != nil {
			return config.UserHost{}, err
		}
		if err := m.validateUserHostLayout(existing, sid); err != nil {
			return config.UserHost{}, err
		}
		if !strings.EqualFold(existing.WindowsUsername, canonical) {
			return config.UserHost{}, fmt.Errorf("existing UserHost config belongs to Windows account %q, not %q", existing.WindowsUsername, canonical)
		}
		recovered = &existing
	} else if !errors.Is(err, os.ErrNotExist) {
		return config.UserHost{}, err
	}
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		return config.UserHost{}, fmt.Errorf("create private data root %s: %w", dataRoot, err)
	}
	for _, name := range []string{"profile", "data", "config", "credentials", "oauth", "workspace", "cache", "logs", "temp", "runtime", filepath.Join("profile", "AppData", "Roaming"), filepath.Join("profile", "AppData", "Local")} {
		if err := os.MkdirAll(filepath.Join(dataRoot, name), 0o700); err != nil {
			return config.UserHost{}, err
		}
	}
	if err := winutil.ApplyTreeACL(dataRoot, winutil.PrivateTreePolicy(sid)); err != nil {
		return config.UserHost{}, err
	}
	if err := winutil.VerifyTreeACL(dataRoot, winutil.PrivateTreePolicy(sid)); err != nil {
		return config.UserHost{}, err
	}
	if recovered != nil {
		policy := winutil.UserConfigPolicy(m.Config.PortalServiceSID, sid)
		if err := winutil.ApplyTreeACL(filepath.Dir(configPath), policy); err != nil {
			return config.UserHost{}, err
		}
		if err := winutil.VerifyTreeACL(filepath.Dir(configPath), policy); err != nil {
			return config.UserHost{}, err
		}
		return *recovered, nil
	}
	webPort, migrationPort, err := m.allocatePortBlocks()
	if err != nil {
		return config.UserHost{}, err
	}
	userConfig := config.UserHost{ConfigVersion: 1, WindowsSID: sid, WindowsUsername: canonical, WindowsProfile: profile, DataRoot: dataRoot,
		ReleasesRoot: m.Config.ReleasesRoot, CurrentReleaseFile: m.Config.CurrentReleaseFile, PortalServiceSID: m.Config.PortalServiceSID,
		PipeName: config.PipeNameForSID(sid), WebPort: webPort, WebPortTries: 32, MigrationPortStart: migrationPort, MigrationPortTries: 16,
		StartupSeconds: m.Config.InstanceStartupSeconds, ShutdownSeconds: 30, OutboundProxyURL: m.Config.OutboundProxyURL,
		SupportedAionCore: append([]string(nil), m.Config.SupportedAionCore...),
		Limits:            config.ResourceLimits{MemoryBytes: 4 * 1024 * 1024 * 1024, CPUPercent: 50, ActiveProcesses: 64}}
	if err := userConfig.Validate(); err != nil {
		return config.UserHost{}, err
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return config.UserHost{}, err
	}
	if err := writeJSONAtomic(configPath, userConfig); err != nil {
		return config.UserHost{}, err
	}
	if err := winutil.ApplyTreeACL(filepath.Dir(configPath), winutil.UserConfigPolicy(m.Config.PortalServiceSID, sid)); err != nil {
		return config.UserHost{}, err
	}
	if err := winutil.VerifyTreeACL(filepath.Dir(configPath), winutil.UserConfigPolicy(m.Config.PortalServiceSID, sid)); err != nil {
		return config.UserHost{}, err
	}
	return userConfig, nil
}

func (m *Manager) validateUserHostLayout(cfg config.UserHost, sid string) error {
	expectedProfile, expectedDataRoot, err := m.profileDataRoot(sid)
	if err != nil {
		return err
	}
	checks := []struct {
		name     string
		actual   string
		expected string
		path     bool
	}{
		{"Windows SID", cfg.WindowsSID, sid, false},
		{"Windows profile", cfg.WindowsProfile, expectedProfile, true},
		{"data root", cfg.DataRoot, expectedDataRoot, true},
		{"releases root", cfg.ReleasesRoot, m.Config.ReleasesRoot, true},
		{"current release pointer", cfg.CurrentReleaseFile, m.Config.CurrentReleaseFile, true},
		{"Portal service SID", cfg.PortalServiceSID, m.Config.PortalServiceSID, false},
	}
	for _, check := range checks {
		actual, expected := check.actual, check.expected
		if check.path {
			actual, expected = filepath.Clean(actual), filepath.Clean(expected)
		}
		if !strings.EqualFold(actual, expected) {
			return fmt.Errorf("existing UserHost config has unexpected %s %q; expected %q", check.name, check.actual, check.expected)
		}
	}
	return nil
}

func (m *Manager) UserDataRootForSID(sid string) (string, error) {
	cfg, err := config.LoadUserHost(m.userConfigPath(sid))
	if err != nil {
		return "", err
	}
	if err := m.validateUserHostLayout(cfg, sid); err != nil {
		return "", err
	}
	return cfg.DataRoot, nil
}

func (m *Manager) profileDataRoot(sid string) (string, string, error) {
	resolver := m.ProfileDirectory
	if resolver == nil {
		resolver = winutil.ProfileDirectoryForSID
	}
	profile, err := resolver(sid)
	if err != nil {
		return "", "", err
	}
	profile = filepath.Clean(profile)
	profilesRoot := filepath.Clean(m.Config.UserProfilesRoot)
	if !filepath.IsAbs(profile) || !strings.EqualFold(filepath.Dir(profile), profilesRoot) || strings.EqualFold(profile, profilesRoot) {
		return "", "", fmt.Errorf("Windows profile %s for %s must be a direct child of %s", profile, sid, profilesRoot)
	}
	return profile, filepath.Join(profile, config.UserDataDirectoryName), nil
}

func (m *Manager) allocatePortBlocks() (int, int, error) {
	used := make(map[int]bool)
	entries, err := os.ReadDir(m.Config.UserConfigRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	for _, entry := range entries {
		cfg, err := config.LoadUserHost(filepath.Join(m.Config.UserConfigRoot, entry.Name(), "userhost.json"))
		if err == nil {
			used[cfg.WebPort] = true
		}
	}
	for slot := 0; slot < 200; slot++ {
		web := 30000 + slot*64
		if !used[web] {
			return web, 48000 + slot*32, nil
		}
	}
	return 0, 0, errors.New("no configured internal port block remains")
}

func (m *Manager) taskSpec(user store.User) scheduler.Spec {
	return scheduler.Spec{WindowsSID: user.WindowsSID, WindowsUsername: user.WindowsUsername, Executable: m.Config.UserHostExecutable,
		ConfigPath: m.userConfigPath(user.WindowsSID), WorkingDirectory: filepath.Dir(m.Config.UserHostExecutable), PortalServiceSID: m.Config.PortalServiceSID}
}

func (m *Manager) userConfigPath(sid string) string {
	return filepath.Join(m.Config.UserConfigRoot, sid, "userhost.json")
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary := path + fmt.Sprintf(".tmp-%d", os.Getpid())
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(temporary)
	to, _ := windows.UTF16PtrFromString(path)
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	ok = true
	return nil
}

func containsCheck(checks []string, target string) bool {
	for _, check := range checks {
		if check == target {
			return true
		}
	}
	return false
}

func waitForPipeExit(sid string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		_, err := ipc.Call(ctx, config.PipeNameForSID(sid), ipc.Request{Command: "status", Nonce: "wait-for-exit-nonce"})
		cancel()
		if err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func isPipeUnavailable(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "pipe") && (strings.Contains(text, "not found") || strings.Contains(text, "cannot find") || strings.Contains(text, "找不到"))
}

func isTaskMissing(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "0x80070002") || strings.Contains(text, "cannot find") || strings.Contains(text, "找不到")
}
