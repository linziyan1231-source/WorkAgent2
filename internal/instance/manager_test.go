package instance

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/store"
)

const managerSID = "S-1-5-21-1335169958-1819941586-1322872941-1322"

type fakeTask struct {
	mu      sync.Mutex
	starts  int
	started bool
	onStart func() error
}

func (f *fakeTask) Start(context.Context, string) error {
	f.mu.Lock()
	f.starts++
	f.started = true
	onStart := f.onStart
	f.mu.Unlock()
	if onStart != nil {
		return onStart()
	}
	return nil
}

func (f *fakeTask) isStarted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

func TestConcurrentEnsureStartsOneScheduledTask(t *testing.T) {
	data, cfg := managerStore(t)
	tasks := &fakeTask{}
	caller := func(_ context.Context, _ string, request ipc.Request) (ipc.Response, error) {
		if !tasks.isStarted() {
			return ipc.Response{}, errors.New("pipe not found")
		}
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true,
			Status: &ipc.Status{WindowsSID: managerSID, Healthy: true, State: "healthy", WebPort: 31001}}, nil
	}
	manager := NewWithIPC(cfg, data, tasks, caller)
	var wg sync.WaitGroup
	errorsOut := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := manager.Ensure(context.Background(), managerSID)
			errorsOut <- err
		}()
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	tasks.mu.Lock()
	defer tasks.mu.Unlock()
	if tasks.starts != 1 {
		t.Fatalf("scheduled task starts=%d, want 1", tasks.starts)
	}
}

func TestDisabledUserCannotStartScheduledTask(t *testing.T) {
	data, cfg := managerStore(t)
	if err := data.SetUserEnabled(context.Background(), "employee", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	tasks := &fakeTask{}
	manager := NewWithIPC(cfg, data, tasks, func(context.Context, string, ipc.Request) (ipc.Response, error) {
		return ipc.Response{}, errors.New("pipe not found")
	})
	if _, err := manager.Ensure(context.Background(), managerSID); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("disabled user start error=%v, want ErrUserDisabled", err)
	}
	tasks.mu.Lock()
	defer tasks.mu.Unlock()
	if tasks.starts != 0 {
		t.Fatalf("disabled user started scheduled task %d times", tasks.starts)
	}
}

func TestUserDisabledDuringStartupIsStoppedBeforeEnsureReturns(t *testing.T) {
	data, cfg := managerStore(t)
	tasks := &fakeTask{onStart: func() error {
		return data.SetUserEnabled(context.Background(), "employee", false, time.Now())
	}}
	stopCalls := 0
	caller := func(_ context.Context, _ string, request ipc.Request) (ipc.Response, error) {
		if request.Command == "status" && !tasks.isStarted() {
			return ipc.Response{}, errors.New("pipe not found")
		}
		if request.Command == "stop" {
			stopCalls++
			return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true}, nil
		}
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true,
			Status: &ipc.Status{WindowsSID: managerSID, Healthy: true, State: "healthy", WebPort: 31001}}, nil
	}
	manager := NewWithIPC(cfg, data, tasks, caller)
	if _, err := manager.Ensure(context.Background(), managerSID); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("concurrent disable error=%v, want ErrUserDisabled", err)
	}
	if stopCalls != 1 {
		t.Fatalf("newly started disabled UserHost stop calls=%d, want 1", stopCalls)
	}
}

func TestRouteCachesAuthOnlyForSameUserHostRun(t *testing.T) {
	data, cfg := managerStore(t)
	startedAt := int64(100)
	authCalls := 0
	caller := func(_ context.Context, _ string, request ipc.Request) (ipc.Response, error) {
		switch request.Command {
		case "status":
			return ipc.Response{ProtocolVersion: 1, Nonce: request.Nonce, OK: true, Status: &ipc.Status{WindowsSID: managerSID, Healthy: true, WebPort: 31001, UserHostPID: uint32(startedAt), StartedAtUnix: startedAt, Version: "2.1.29"}}, nil
		case "auth":
			authCalls++
			return ipc.Response{ProtocolVersion: 1, Nonce: request.Nonce, OK: true, Auth: &ipc.AuthMaterial{CookieHeader: "aionui-session=internal"}}, nil
		default:
			return ipc.Response{ProtocolVersion: 1, Nonce: request.Nonce, OK: true}, nil
		}
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	if _, err := manager.Route(context.Background(), managerSID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Route(context.Background(), managerSID); err != nil {
		t.Fatal(err)
	}
	startedAt++
	if _, err := manager.Route(context.Background(), managerSID); err != nil {
		t.Fatal(err)
	}
	if authCalls != 2 {
		t.Fatalf("auth IPC calls=%d, want one per UserHost run", authCalls)
	}
}

func TestIdleReapFailsSafeOnUnknownActivity(t *testing.T) {
	data, cfg := managerStore(t)
	cfg.IdleReapSeconds = 60
	known := false
	stopCalls := 0
	caller := func(_ context.Context, _ string, request ipc.Request) (ipc.Response, error) {
		status := &ipc.Status{WindowsSID: managerSID, Healthy: true, State: "healthy", LastActivityUnix: time.Now().Add(-2 * time.Hour).Unix()}
		if request.Command == "activity" {
			status.Activity = ipc.Activity{Known: known, Active: false, CheckedAtUnix: time.Now().Unix()}
		}
		if request.Command == "stop" {
			stopCalls++
			return ipc.Response{ProtocolVersion: 1, Nonce: request.Nonce, OK: true}, nil
		}
		return ipc.Response{ProtocolVersion: 1, Nonce: request.Nonce, OK: true, Status: status}, nil
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	if failures := manager.ReapOnce(context.Background()); len(failures) != 0 {
		t.Fatal(failures)
	}
	if stopCalls != 0 {
		t.Fatal("unknown activity was reaped")
	}
	known = true
	if failures := manager.ReapOnce(context.Background()); len(failures) != 0 {
		t.Fatal(failures)
	}
	if stopCalls != 1 {
		t.Fatalf("inactive known instance stop calls=%d", stopCalls)
	}
}

func TestProbeActivityRefreshesAndValidatesUserHostIdentity(t *testing.T) {
	data, cfg := managerStore(t)
	activity := ipc.Activity{Known: true, Active: false, Reason: "idle", CheckedAtUnix: time.Now().Unix()}
	wrongIdentity := false
	manager := NewWithIPC(cfg, data, &fakeTask{}, func(_ context.Context, _ string, request ipc.Request) (ipc.Response, error) {
		sid := managerSID
		if wrongIdentity {
			sid = "S-1-5-21-1988320210-1174886911-1684912000-8042"
		}
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true,
			Status: &ipc.Status{WindowsSID: sid, Activity: activity}}, nil
	})
	got, err := manager.ProbeActivity(context.Background(), managerSID)
	if err != nil || got != activity {
		t.Fatalf("activity=%+v err=%v", got, err)
	}
	wrongIdentity = true
	if _, err := manager.ProbeActivity(context.Background(), managerSID); err == nil {
		t.Fatal("activity probe accepted a mismatched UserHost SID")
	}
}

func TestOAuthIPCRequestsStayBoundToTheRequestedSIDAndInstance(t *testing.T) {
	data, cfg := managerStore(t)
	var seen []ipc.Request
	caller := func(_ context.Context, pipe string, request ipc.Request) (ipc.Response, error) {
		if pipe != config.PipeNameForSID(managerSID) {
			t.Fatalf("OAuth IPC used wrong pipe: %s", pipe)
		}
		seen = append(seen, request)
		response := ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true}
		if request.Command == "oauth_start" {
			response.OAuth = &ipc.OAuthResult{FlowID: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc", AuthorizationURL: "https://auth.example.test/?state=state"}
		}
		return response, nil
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	start := ipc.OAuthStartRequest{InstanceID: "run-7", ServerURL: "https://mcp.example.test", State: "state", RedirectURI: "https://portal.example.test/api/mcp/oauth/callback"}
	result, err := manager.OAuthStart(context.Background(), managerSID, start)
	if err != nil || result.FlowID == "" {
		t.Fatalf("OAuth start IPC failed: result=%+v err=%v", result, err)
	}
	complete := ipc.OAuthCompleteRequest{InstanceID: "run-7", FlowID: result.FlowID, ServerURL: start.ServerURL, Code: "authorization-code"}
	if err := manager.OAuthComplete(context.Background(), managerSID, complete); err != nil {
		t.Fatal(err)
	}
	cancel := ipc.OAuthCancelRequest{InstanceID: "run-7", FlowID: result.FlowID, ServerURL: start.ServerURL}
	if err := manager.OAuthCancel(context.Background(), managerSID, cancel); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[0].OAuthStart == nil || *seen[0].OAuthStart != start || seen[1].OAuthComplete == nil || *seen[1].OAuthComplete != complete ||
		seen[2].OAuthCancel == nil || *seen[2].OAuthCancel != cancel {
		t.Fatalf("OAuth IPC payload changed: %+v", seen)
	}
	for _, request := range seen {
		if len(request.Nonce) < 16 {
			t.Fatalf("OAuth IPC nonce was missing: %+v", request)
		}
	}
}

func TestModelKeyIDsStayBoundToRequestedSIDAndPipe(t *testing.T) {
	data, cfg := managerStore(t)
	want := modelbootstrap.KeyIDsForSID(managerSID)
	var seenPipe string
	var seenRequest ipc.Request
	caller := func(_ context.Context, pipe string, request ipc.Request) (ipc.Response, error) {
		seenPipe, seenRequest = pipe, request
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true,
			ModelKeyIDs: &ipc.ModelKeyIDs{CodexKeyID: want.CodexKeyID, KimiKeyID: want.KimiKeyID}}, nil
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	got, err := manager.ModelKeyIDs(context.Background(), managerSID)
	if err != nil || got != want {
		t.Fatalf("model key IDs=%+v err=%v, want %+v", got, err, want)
	}
	if seenPipe != config.PipeNameForSID(managerSID) || seenRequest.Command != "model_key_ids" || len(seenRequest.Nonce) < 16 {
		t.Fatalf("model marker IPC was not SID-bound: pipe=%q request=%+v", seenPipe, seenRequest)
	}
}

func TestModelKeyIDsRejectAnotherUsersWellFormedIDs(t *testing.T) {
	data, cfg := managerStore(t)
	other := modelbootstrap.KeyIDsForSID("S-1-5-21-1836781275-1957422218-1832856846-7828")
	caller := func(_ context.Context, pipe string, request ipc.Request) (ipc.Response, error) {
		if pipe != config.PipeNameForSID(managerSID) {
			t.Fatalf("model marker IPC used wrong pipe: %s", pipe)
		}
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true,
			ModelKeyIDs: &ipc.ModelKeyIDs{CodexKeyID: other.CodexKeyID, KimiKeyID: other.KimiKeyID}}, nil
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	if _, err := manager.ModelKeyIDs(context.Background(), managerSID); err == nil {
		t.Fatal("another user's well-formed key IDs were accepted from the requested user's pipe")
	}
}

func TestStorageUsageStaysBoundToRequestedSIDAndPipe(t *testing.T) {
	data, cfg := managerStore(t)
	want := ipc.StorageUsage{LimitBytes: 100, UsedBytes: 30, RemainingBytes: 70, MeasuredAt: "2026-07-26T08:00:00Z"}
	var seenPipe string
	var seenRequest ipc.Request
	caller := func(_ context.Context, pipe string, request ipc.Request) (ipc.Response, error) {
		seenPipe, seenRequest = pipe, request
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true, StorageUsage: &want}, nil
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	got, err := manager.StorageUsage(context.Background(), managerSID)
	if err != nil || got != want {
		t.Fatalf("storage usage=%+v err=%v, want %+v", got, err, want)
	}
	if seenPipe != config.PipeNameForSID(managerSID) || seenRequest.Command != "storage_usage" || len(seenRequest.Nonce) < 16 {
		t.Fatalf("storage usage IPC was not SID-bound: pipe=%q request=%+v", seenPipe, seenRequest)
	}
}

func TestStorageUsageRejectsInconsistentRemainingBytes(t *testing.T) {
	data, cfg := managerStore(t)
	caller := func(_ context.Context, _ string, request ipc.Request) (ipc.Response, error) {
		invalid := ipc.StorageUsage{LimitBytes: 100, UsedBytes: 30, RemainingBytes: 80, MeasuredAt: "2026-07-26T08:00:00Z"}
		return ipc.Response{ProtocolVersion: ipc.ProtocolVersion, Nonce: request.Nonce, OK: true, StorageUsage: &invalid}, nil
	}
	manager := NewWithIPC(cfg, data, &fakeTask{}, caller)
	if _, err := manager.StorageUsage(context.Background(), managerSID); err == nil {
		t.Fatal("inconsistent storage usage was accepted")
	}
}

func managerStore(t *testing.T) (*store.Store, config.Portal) {
	t.Helper()
	root := t.TempDir()
	data, err := store.Open(filepath.Join(root, "portal.db"), filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { data.Close() })
	hash, _ := auth.HashPassword([]byte("correct-employee-portal-password"))
	if _, err := data.CreateUser(context.Background(), "employee", hash, managerSID, `SERVER\test1`, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultPortal()
	cfg.Mode = "test"
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.MaxRunningInstances = 2
	return data, cfg
}
