package instance

import (
	"context"
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
	deadline := m.now().Add(time.Duration(m.cfg.InstanceStartupSeconds) * time.Second)
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
	users, err := m.store.ListUsers(ctx)
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

func (m *Manager) Stop(ctx context.Context, sid string) error {
	state := m.runtime(sid)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.draining = true
	defer func() { state.draining = false }()
	_, err := m.command(ctx, sid, "stop")
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
	users, err := m.store.ListUsers(ctx)
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
		return ipc.Response{}, fmt.Errorf("UserHost %s failed (%s): %s", request.Command, response.ErrorCode, response.ErrorMessage)
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
