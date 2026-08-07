package instance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/store"
)

var (
	ErrNotHealthy    = errors.New("user instance is not healthy")
	ErrDraining      = errors.New("user instance is draining")
	ErrInstanceLimit = errors.New("maximum running user instances reached")
	ErrUserDisabled  = errors.New("Portal user is disabled")
)

type TaskController interface {
	Start(context.Context, string) error
}

type IPCCaller func(context.Context, string, ipc.Request) (ipc.Response, error)

type Route struct {
	Status     ipc.Status
	Auth       ipc.AuthMaterial
	InstanceID string
}

type UserHostCommandError struct {
	Command string
	Code    string
	Message string
}

func (e *UserHostCommandError) Error() string {
	return fmt.Sprintf("UserHost %s failed (%s): %s", e.Command, e.Code, e.Message)
}

type runtimeState struct {
	mu             sync.Mutex
	draining       bool
	requests       int
	webSockets     int
	auth           ipc.AuthMaterial
	authInstanceID string
}

type Manager struct {
	cfg      config.Portal
	store    *store.Store
	tasks    TaskController
	call     IPCCaller
	now      func() time.Time
	mu       sync.Mutex
	runtimes map[string]*runtimeState
}

func New(cfg config.Portal, data *store.Store, tasks TaskController) *Manager {
	return NewWithIPC(cfg, data, tasks, ipc.Call)
}

func NewWithIPC(cfg config.Portal, data *store.Store, tasks TaskController, call IPCCaller) *Manager {
	return &Manager{cfg: cfg, store: data, tasks: tasks, call: call, now: time.Now, runtimes: make(map[string]*runtimeState)}
}

func (m *Manager) runtime(sid string) *runtimeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.runtimes[sid]
	if state == nil {
		state = &runtimeState{}
		m.runtimes[sid] = state
	}
	return state
}

func (m *Manager) status(ctx context.Context, sid string) (ipc.Status, error) {
	response, err := m.command(ctx, sid, "status")
	if err != nil {
		return ipc.Status{}, err
	}
	if response.Status == nil || !equalSID(response.Status.WindowsSID, sid) {
		return ipc.Status{}, errors.New("UserHost returned an invalid status identity")
	}
	return *response.Status, nil
}

func (m *Manager) Status(ctx context.Context, sid string) (ipc.Status, error) {
	return m.status(ctx, sid)
}

// ProbeActivity asks the UserHost to refresh its authoritative activity
// snapshot. Unknown activity remains fail-closed inside the UserHost.
func (m *Manager) ProbeActivity(ctx context.Context, sid string) (ipc.Activity, error) {
	response, err := m.command(ctx, sid, "activity")
	if err != nil {
		return ipc.Activity{}, err
	}
	if response.Status == nil || !equalSID(response.Status.WindowsSID, sid) {
		return ipc.Activity{}, errors.New("UserHost returned an invalid activity identity")
	}
	return response.Status.Activity, nil
}

func (m *Manager) Ensure(ctx context.Context, sid string) (ipc.Status, error) {
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.draining {
		return ipc.Status{}, ErrDraining
	}
	if err := m.requireEnabled(ctx, sid); err != nil {
		return ipc.Status{}, err
	}
	if status, err := m.status(ctx, sid); err == nil && status.Healthy {
		return status, nil
	}
	count, err := m.runningCount(ctx, sid)
	if err != nil {
		return ipc.Status{}, fmt.Errorf("count running instances: %w", err)
	}
	if count >= m.cfg.MaxRunningInstances {
		return ipc.Status{}, ErrInstanceLimit
	}
	if m.tasks == nil {
		return ipc.Status{}, errors.New("Task Scheduler controller is unavailable")
	}
	if err := m.tasks.Start(ctx, sid); err != nil {
		return ipc.Status{}, fmt.Errorf("start scheduled UserHost task: %w", err)
	}
	return m.waitHealthyLocked(ctx, sid, state, time.Duration(m.cfg.InstanceStartupSeconds)*time.Second)
}

// WaitHealthy waits for an already-started UserHost without starting another
// scheduled-task run. Provisioning uses this when the task is demonstrably
// still running after the normal interactive-login startup deadline.
func (m *Manager) WaitHealthy(ctx context.Context, sid string, timeout time.Duration) (ipc.Status, error) {
	if timeout <= 0 {
		return ipc.Status{}, errors.New("UserHost healthy wait timeout must be positive")
	}
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.draining {
		return ipc.Status{}, ErrDraining
	}
	if err := m.requireEnabled(ctx, sid); err != nil {
		return ipc.Status{}, err
	}
	return m.waitHealthyLocked(ctx, sid, state, timeout)
}

func (m *Manager) waitHealthyLocked(ctx context.Context, sid string, state *runtimeState, timeout time.Duration) (ipc.Status, error) {
	deadline := m.now().Add(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var lastStatus ipc.Status
	var lastErr error
	for {
		status, err := m.status(ctx, sid)
		if err == nil {
			lastStatus = status
			if status.Healthy {
				if err := m.requireEnabled(ctx, sid); err != nil {
					_, stopErr := m.command(ctx, sid, "stop")
					state.auth, state.authInstanceID = ipc.AuthMaterial{}, ""
					if stopErr != nil {
						return ipc.Status{}, fmt.Errorf("%w; newly started UserHost could not be stopped: %v", err, stopErr)
					}
					return ipc.Status{}, err
				}
				return status, nil
			}
			if status.State == "failed" && status.FailureReason != "" {
				return ipc.Status{}, fmt.Errorf("UserHost startup failed: %s", status.FailureReason)
			}
		} else {
			lastErr = err
		}
		if !m.now().Before(deadline) {
			if lastStatus.FailureReason != "" {
				return ipc.Status{}, fmt.Errorf("UserHost did not become healthy: %s", lastStatus.FailureReason)
			}
			return ipc.Status{}, fmt.Errorf("UserHost did not become healthy before the startup deadline: %v", lastErr)
		}
		select {
		case <-ctx.Done():
			return ipc.Status{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Manager) requireEnabled(ctx context.Context, sid string) error {
	user, err := m.store.UserBySID(ctx, sid)
	if err != nil {
		return fmt.Errorf("load Portal user before instance start: %w", err)
	}
	if !user.Enabled {
		return ErrUserDisabled
	}
	return nil
}

func (m *Manager) runningCount(ctx context.Context, excludeSID string) (int, error) {
	users, err := m.store.ListManagedUsers(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, user := range users {
		if equalSID(user.WindowsSID, excludeSID) {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		status, err := m.status(probeCtx, user.WindowsSID)
		cancel()
		if err == nil && (status.Healthy || status.State == "starting") {
			count++
		}
	}
	return count, nil
}

func (m *Manager) Route(ctx context.Context, sid string) (Route, error) {
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.draining {
		return Route{}, ErrDraining
	}
	status, err := m.status(ctx, sid)
	if err != nil || !status.Healthy || status.WebPort < 1024 {
		state.auth, state.authInstanceID = ipc.AuthMaterial{}, ""
		if err != nil {
			return Route{}, fmt.Errorf("read UserHost status: %w", err)
		}
		return Route{}, ErrNotHealthy
	}
	instanceID := id(status)
	if state.authInstanceID != instanceID {
		response, err := m.command(ctx, sid, "auth")
		if err != nil {
			return Route{}, err
		}
		if response.Auth == nil || response.Auth.CookieHeader == "" {
			return Route{}, errors.New("UserHost returned incomplete internal authentication")
		}
		state.auth = *response.Auth
		state.authInstanceID = instanceID
	}
	return Route{Status: status, Auth: state.auth, InstanceID: instanceID}, nil
}

func (m *Manager) Touch(ctx context.Context, sid string) error {
	_, err := m.command(ctx, sid, "touch")
	return err
}

func (m *Manager) ModelKeyIDs(ctx context.Context, sid string) (modelbootstrap.KeyIDs, error) {
	if err := m.requireEnabled(ctx, sid); err != nil {
		return modelbootstrap.KeyIDs{}, err
	}
	response, err := m.command(ctx, sid, "model_key_ids")
	if err != nil {
		return modelbootstrap.KeyIDs{}, err
	}
	if response.ModelKeyIDs == nil {
		return modelbootstrap.KeyIDs{}, errors.New("UserHost returned no applied model mapping")
	}
	ids := modelbootstrap.KeyIDs{CodexKeyID: response.ModelKeyIDs.CodexKeyID, KimiKeyID: response.ModelKeyIDs.KimiKeyID}
	if err := ids.ValidateForSID(sid); err != nil {
		return modelbootstrap.KeyIDs{}, fmt.Errorf("UserHost applied model mapping did not match the requested Windows identity: %w", err)
	}
	return ids, nil
}

func (m *Manager) StorageUsage(ctx context.Context, sid string) (ipc.StorageUsage, error) {
	if err := m.requireEnabled(ctx, sid); err != nil {
		return ipc.StorageUsage{}, err
	}
	response, err := m.command(ctx, sid, "storage_usage")
	if err != nil {
		return ipc.StorageUsage{}, err
	}
	if response.StorageUsage == nil || !validStorageBucket(response.StorageUsage.Personal) || !validStorageBucket(response.StorageUsage.Shared) {
		return ipc.StorageUsage{}, errors.New("UserHost returned invalid independent storage usage")
	}
	return *response.StorageUsage, nil
}

func validStorageBucket(value ipc.StorageBucketUsage) bool {
	if value.LimitBytes == 0 || value.MeasuredAt == "" {
		return false
	}
	expectedRemaining := uint64(0)
	if value.UsedBytes < value.LimitBytes {
		expectedRemaining = value.LimitBytes - value.UsedBytes
	}
	return value.RemainingBytes == expectedRemaining
}

func (m *Manager) WriteUsageSnapshot(ctx context.Context, sid string, snapshot []byte) error {
	if len(snapshot) == 0 || len(snapshot) > 64*1024 || !json.Valid(snapshot) {
		return errors.New("usage snapshot is invalid")
	}
	response, err := m.request(ctx, sid, ipc.Request{Command: "usage_snapshot", UsageSnapshot: json.RawMessage(snapshot)})
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New("UserHost rejected usage snapshot")
	}
	return nil
}

func (m *Manager) OAuthStart(ctx context.Context, sid string, start ipc.OAuthStartRequest) (ipc.OAuthResult, error) {
	response, err := m.request(ctx, sid, ipc.Request{Command: "oauth_start", OAuthStart: &start})
	if err != nil {
		return ipc.OAuthResult{}, err
	}
	if response.OAuth == nil || response.OAuth.AuthorizationURL == "" || response.OAuth.FlowID == "" {
		return ipc.OAuthResult{}, errors.New("UserHost returned an incomplete OAuth authorization result")
	}
	return *response.OAuth, nil
}

func (m *Manager) OAuthComplete(ctx context.Context, sid string, complete ipc.OAuthCompleteRequest) error {
	_, err := m.request(ctx, sid, ipc.Request{Command: "oauth_complete", OAuthComplete: &complete})
	return err
}

func (m *Manager) OAuthCancel(ctx context.Context, sid string, cancel ipc.OAuthCancelRequest) error {
	_, err := m.request(ctx, sid, ipc.Request{Command: "oauth_cancel", OAuthCancel: &cancel})
	return err
}

func (m *Manager) CreateProject(ctx context.Context, sid, name string) (ipc.ProjectCreateResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.ProjectCreateResult{}, err
	}
	request := ipc.ProjectCreateRequest{InstanceID: id(status), Name: name}
	response, err := m.request(ctx, sid, ipc.Request{Command: "project_create", ProjectCreate: &request})
	if err != nil {
		return ipc.ProjectCreateResult{}, err
	}
	if response.ProjectCreate == nil || response.ProjectCreate.Path == "" || response.ProjectCreate.ProjectID == "" {
		return ipc.ProjectCreateResult{}, errors.New("UserHost returned an incomplete project creation result")
	}
	return *response.ProjectCreate, nil
}

func (m *Manager) RenameProject(ctx context.Context, sid, oldName, newName string, force, legacyRoot bool) (ipc.ProjectRenameResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.ProjectRenameResult{}, err
	}
	request := ipc.ProjectRenameRequest{InstanceID: id(status), OldName: oldName, NewName: newName, Force: force, LegacyRoot: legacyRoot}
	response, err := m.request(ctx, sid, ipc.Request{Command: "project_rename", ProjectRename: &request})
	if err != nil {
		return ipc.ProjectRenameResult{}, err
	}
	if response.ProjectRename == nil || response.ProjectRename.NewPath == "" || response.ProjectRename.OldPath == "" || response.ProjectRename.ProjectID == "" {
		return ipc.ProjectRenameResult{}, errors.New("UserHost returned an incomplete project rename result")
	}
	return *response.ProjectRename, nil
}

func (m *Manager) ResolveProject(ctx context.Context, sid, projectID string) (ipc.ProjectResolveResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.ProjectResolveResult{}, err
	}
	request := ipc.ProjectResolveRequest{InstanceID: id(status), ProjectID: projectID}
	response, err := m.request(ctx, sid, ipc.Request{Command: "project_resolve", ProjectResolve: &request})
	if err != nil {
		return ipc.ProjectResolveResult{}, err
	}
	if response.ProjectResolve == nil || response.ProjectResolve.Path == "" {
		return ipc.ProjectResolveResult{}, errors.New("UserHost returned an incomplete project resolution result")
	}
	return *response.ProjectResolve, nil
}

func (m *Manager) ListProjects(ctx context.Context, sid string) (ipc.ProjectListResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.ProjectListResult{}, err
	}
	request := ipc.ProjectListRequest{InstanceID: id(status)}
	response, err := m.request(ctx, sid, ipc.Request{Command: "project_list", ProjectList: &request})
	if err != nil {
		return ipc.ProjectListResult{}, err
	}
	if response.ProjectList == nil {
		return ipc.ProjectListResult{}, errors.New("UserHost returned no project list")
	}
	return *response.ProjectList, nil
}

func (m *Manager) ProvisionSharedProject(ctx context.Context, sid string, request ipc.SharedProjectRequest) (ipc.SharedProjectResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.SharedProjectResult{}, err
	}
	request.InstanceID = id(status)
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_project_provision", SharedProject: &request})
	if err != nil {
		return ipc.SharedProjectResult{}, err
	}
	if response.SharedProject == nil || response.SharedProject.ProjectID != request.ProjectID {
		return ipc.SharedProjectResult{}, errors.New("UserHost returned an invalid shared project result")
	}
	return *response.SharedProject, nil
}

func (m *Manager) UpdateSharedProjectACL(ctx context.Context, sid string, request ipc.SharedProjectRequest) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_project_acl", SharedProject: &request})
	if err != nil {
		return err
	}
	if response.SharedProject == nil || response.SharedProject.ProjectID != request.ProjectID {
		return errors.New("UserHost returned an invalid shared project ACL result")
	}
	return nil
}

func (m *Manager) FinishSharedProjectProvisioning(ctx context.Context, sid string, request ipc.SharedProjectRequest, commit bool) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	request.Commit = commit
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_project_finish", SharedProject: &request})
	if err != nil {
		return err
	}
	if response.SharedProject == nil || response.SharedProject.ProjectID != request.ProjectID {
		return errors.New("UserHost returned an invalid shared project finalization result")
	}
	return nil
}

func (m *Manager) RunSharedAgent(ctx context.Context, sid string, request ipc.SharedAgentRequest) (ipc.SharedAgentResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.SharedAgentResult{}, err
	}
	request.InstanceID = id(status)
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_agent_run", SharedAgent: &request})
	if err != nil {
		return ipc.SharedAgentResult{}, err
	}
	if response.SharedAgent == nil || response.SharedAgent.RuntimeConversationID == "" {
		return ipc.SharedAgentResult{}, errors.New("UserHost returned an invalid shared agent result")
	}
	return *response.SharedAgent, nil
}

func (m *Manager) StopSharedAgent(ctx context.Context, sid string, request ipc.SharedAgentStopRequest) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	_, err = m.request(ctx, sid, ipc.Request{Command: "shared_agent_stop", SharedAgentStop: &request})
	return err
}

func (m *Manager) InstallSharedAgentCredential(ctx context.Context, sid string, request ipc.SharedAgentCredentialRequest) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_agent_credential_install", SharedCredential: &request})
	if err != nil {
		return err
	}
	if response.SharedCredential == nil || !response.SharedCredential.Installed {
		return errors.New("UserHost did not retain the shared Agent credential")
	}
	return nil
}

func (m *Manager) VerifySharedAgentCredential(ctx context.Context, sid, credentialID string) (bool, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return false, err
	}
	request := ipc.SharedAgentCredentialRequest{InstanceID: id(status), CredentialID: credentialID}
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_agent_credential_verify", SharedCredential: &request})
	if err != nil {
		return false, err
	}
	if response.SharedCredential == nil {
		return false, errors.New("UserHost returned an invalid shared credential status")
	}
	return response.SharedCredential.Installed, nil
}

func (m *Manager) SharedFile(ctx context.Context, sid string, request ipc.SharedFileRequest) (ipc.SharedFileResult, error) {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return ipc.SharedFileResult{}, err
	}
	request.InstanceID = id(status)
	response, err := m.request(ctx, sid, ipc.Request{Command: "shared_file", SharedFile: &request})
	if err != nil {
		return ipc.SharedFileResult{}, err
	}
	if response.SharedFile == nil || !json.Valid(response.SharedFile.Data) {
		return ipc.SharedFileResult{}, errors.New("UserHost returned invalid shared file data")
	}
	return *response.SharedFile, nil
}

func (m *Manager) TransferSharedProject(ctx context.Context, sid string, request ipc.SharedTransferRequest) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	_, err = m.request(ctx, sid, ipc.Request{Command: "shared_project_transfer", SharedTransfer: &request})
	return err
}

func (m *Manager) FinishSharedProjectTransfer(ctx context.Context, sid string, request ipc.SharedTransferRequest, commit bool) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	request.Commit = commit
	_, err = m.request(ctx, sid, ipc.Request{Command: "shared_project_transfer_finish", SharedTransfer: &request})
	return err
}

func (m *Manager) RelocateSharedProjectConversations(ctx context.Context, sid string, request ipc.SharedConversationRelocateRequest) error {
	status, err := m.Ensure(ctx, sid)
	if err != nil {
		return err
	}
	request.InstanceID = id(status)
	_, err = m.request(ctx, sid, ipc.Request{Command: "shared_conversations_relocate", SharedRelocate: &request})
	return err
}

func (m *Manager) Stop(ctx context.Context, sid string) error {
	return m.drain(ctx, sid, "stop")
}

// Restart asks the SID-owned UserHost to tear down its complete process tree.
// The next authenticated browser request starts a fresh scheduled UserHost run.
func (m *Manager) Restart(ctx context.Context, sid string) error {
	return m.drain(ctx, sid, "restart")
}

func (m *Manager) drain(ctx context.Context, sid, command string) error {
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.draining = true
	defer func() { state.draining = false }()
	_, err := m.command(ctx, sid, command)
	state.auth, state.authInstanceID = ipc.AuthMaterial{}, ""
	return err
}

func (m *Manager) BeginRequest(sid string, webSocket bool) (func(), error) {
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.draining {
		return nil, ErrDraining
	}
	state.requests++
	if webSocket {
		state.webSockets++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			state.mu.Lock()
			defer state.mu.Unlock()
			state.requests--
			if webSocket {
				state.webSockets--
			}
		})
	}, nil
}

func (m *Manager) ConnectionCounts(sid string) (requests, webSockets int) {
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.requests, state.webSockets
}

func (m *Manager) ReapOnce(ctx context.Context) []error {
	users, err := m.store.ListManagedUsers(ctx)
	if err != nil {
		return []error{err}
	}
	var failures []error
	for _, user := range users {
		if err := m.reapUser(ctx, user); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", user.Username, err))
		}
	}
	return failures
}

func (m *Manager) reapUser(ctx context.Context, user store.User) error {
	status, err := m.status(ctx, user.WindowsSID)
	if err != nil || !status.Healthy {
		return nil
	}
	if m.now().Sub(time.Unix(status.LastActivityUnix, 0)) < time.Duration(m.cfg.IdleReapSeconds)*time.Second {
		return nil
	}
	if sessions, err := m.store.SessionCountForUser(ctx, user.ID, m.now()); err != nil || sessions != 0 {
		return err
	}
	state := m.runtime(user.WindowsSID)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.draining || state.requests != 0 || state.webSockets != 0 {
		return nil
	}
	response, err := m.command(ctx, user.WindowsSID, "activity")
	if err != nil || response.Status == nil || !response.Status.Activity.Known || response.Status.Activity.Active {
		return err
	}
	if sessions, err := m.store.SessionCountForUser(ctx, user.ID, m.now()); err != nil || sessions != 0 {
		return err
	}
	if state.requests != 0 || state.webSockets != 0 {
		return nil
	}
	state.draining = true
	defer func() { state.draining = false }()
	if _, err := m.command(ctx, user.WindowsSID, "stop"); err != nil {
		return err
	}
	state.auth, state.authInstanceID = ipc.AuthMaterial{}, ""
	return nil
}

func (m *Manager) command(ctx context.Context, sid, command string) (ipc.Response, error) {
	return m.request(ctx, sid, ipc.Request{Command: command})
}

func (m *Manager) request(ctx context.Context, sid string, request ipc.Request) (ipc.Response, error) {
	nonce, err := auth.RandomToken(18)
	if err != nil {
		return ipc.Response{}, err
	}
	request.Nonce = nonce
	response, err := m.call(ctx, config.PipeNameForSID(sid), request)
	if err != nil {
		return ipc.Response{}, err
	}
	if !response.OK {
		return ipc.Response{}, &UserHostCommandError{Command: request.Command, Code: response.ErrorCode, Message: response.ErrorMessage}
	}
	return response, nil
}

func id(status ipc.Status) string {
	return fmt.Sprintf("%s:%d:%d", status.Version, status.UserHostPID, status.StartedAtUnix)
}

func equalSID(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
