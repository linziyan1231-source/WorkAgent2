package portal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/portalusage"
	"aionuiportal/internal/provisionipc"
	"aionuiportal/internal/store"
)

const (
	testSID1 = "S-1-5-21-100-200-300-1017"
	testSID2 = "S-1-5-21-100-200-300-1018"
)

type fakeInstances struct {
	mu                  sync.Mutex
	ensureSIDs          []string
	statusSIDs          []string
	routeSIDs           []string
	beginSIDs           []string
	route               instance.Route
	ensureError         error
	statusError         error
	touchError          error
	touchSIDs           []string
	oauthStarts         []ipc.OAuthStartRequest
	oauthCompletes      []ipc.OAuthCompleteRequest
	oauthCancels        []ipc.OAuthCancelRequest
	projectCreate       *ipc.ProjectCreateRequest
	projectCreateResult ipc.ProjectCreateResult
	projectCreateError  error
	projectRename       *ipc.ProjectRenameRequest
	projectRenameResult ipc.ProjectRenameResult
	projectRenameError  error
	sharedProject       *ipc.SharedProjectRequest
	sharedProjectResult ipc.SharedProjectResult
	sharedProjectError  error
	oauthStartError     error
	oauthCompleteError  error
	oauthCancelError    error
	requests            int
	webSockets          int
	modelKeyIDs         map[string]modelbootstrap.KeyIDs
	modelKeyIDSError    error
	modelKeyIDSIDs      []string
	storageUsage        ipc.StorageUsage
	storageUsageError   error
	storageErrorsBySID  map[string]error
	storageUsageSIDs    []string
	stopSIDs            []string
	restartSIDs         []string
	restartError        error
}

func (f *fakeInstances) Ensure(_ context.Context, sid string) (ipc.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureSIDs = append(f.ensureSIDs, sid)
	return f.route.Status, f.ensureError
}

func (f *fakeInstances) Status(_ context.Context, sid string) (ipc.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusSIDs = append(f.statusSIDs, sid)
	status := f.route.Status
	status.WindowsSID = sid
	return status, f.statusError
}

func (f *fakeInstances) Route(_ context.Context, sid string) (instance.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routeSIDs = append(f.routeSIDs, sid)
	return f.route, nil
}

func (f *fakeInstances) Touch(_ context.Context, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touchSIDs = append(f.touchSIDs, sid)
	return f.touchError
}

func (f *fakeInstances) OAuthStart(_ context.Context, _ string, request ipc.OAuthStartRequest) (ipc.OAuthResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oauthStarts = append(f.oauthStarts, request)
	flow := make([]byte, 32)
	for index := range flow {
		flow[index] = 7
	}
	return ipc.OAuthResult{
		FlowID:           base64.RawURLEncoding.EncodeToString(flow),
		AuthorizationURL: "https://auth.example.test/authorize?state=" + url.QueryEscape(request.State),
	}, f.oauthStartError
}

func (f *fakeInstances) OAuthComplete(_ context.Context, _ string, request ipc.OAuthCompleteRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oauthCompletes = append(f.oauthCompletes, request)
	return f.oauthCompleteError
}

func (f *fakeInstances) OAuthCancel(_ context.Context, _ string, request ipc.OAuthCancelRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oauthCancels = append(f.oauthCancels, request)
	return f.oauthCancelError
}

func (f *fakeInstances) CreateProject(_ context.Context, sid, name string) (ipc.ProjectCreateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureSIDs = append(f.ensureSIDs, sid)
	f.projectCreate = &ipc.ProjectCreateRequest{Name: name}
	return f.projectCreateResult, f.projectCreateError
}

func (f *fakeInstances) RenameProject(_ context.Context, sid, oldName, newName string, force, legacyRoot bool) (ipc.ProjectRenameResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureSIDs = append(f.ensureSIDs, sid)
	f.projectRename = &ipc.ProjectRenameRequest{OldName: oldName, NewName: newName, Force: force, LegacyRoot: legacyRoot}
	return f.projectRenameResult, f.projectRenameError
}

func (f *fakeInstances) ResolveProject(_ context.Context, _ string, _ string) (ipc.ProjectResolveResult, error) {
	return ipc.ProjectResolveResult{Path: `C:\Users\test\AionUiPortal\workspace\project`}, nil
}

func (f *fakeInstances) ListProjects(_ context.Context, _ string) (ipc.ProjectListResult, error) {
	return ipc.ProjectListResult{}, nil
}

func (f *fakeInstances) ProvisionSharedProject(_ context.Context, sid string, request ipc.SharedProjectRequest) (ipc.SharedProjectResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureSIDs = append(f.ensureSIDs, sid)
	f.sharedProject = &request
	result := f.sharedProjectResult
	if result.ProjectID == "" {
		result.ProjectID = request.ProjectID
	}
	return result, f.sharedProjectError
}

func (f *fakeInstances) FinishSharedProjectProvisioning(_ context.Context, _ string, _ ipc.SharedProjectRequest, _ bool) error {
	return nil
}

func (f *fakeInstances) RunSharedAgent(_ context.Context, _ string, _ ipc.SharedAgentRequest) (ipc.SharedAgentResult, error) {
	return ipc.SharedAgentResult{RuntimeConversationID: "runtime-test", AssistantBody: "done"}, nil
}

func (f *fakeInstances) StopSharedAgent(_ context.Context, _ string, _ ipc.SharedAgentStopRequest) error {
	return nil
}

func (f *fakeInstances) InstallSharedAgentCredential(_ context.Context, _ string, _ ipc.SharedAgentCredentialRequest) error {
	return nil
}

func (f *fakeInstances) VerifySharedAgentCredential(_ context.Context, _ string, _ string) (bool, error) {
	return true, nil
}

func (f *fakeInstances) SharedFile(_ context.Context, _ string, _ ipc.SharedFileRequest) (ipc.SharedFileResult, error) {
	return ipc.SharedFileResult{Data: json.RawMessage(`[]`)}, nil
}

func (f *fakeInstances) TransferSharedProject(_ context.Context, _ string, _ ipc.SharedTransferRequest) error {
	return nil
}
func (f *fakeInstances) FinishSharedProjectTransfer(_ context.Context, _ string, _ ipc.SharedTransferRequest, _ bool) error {
	return nil
}
func (f *fakeInstances) RelocateSharedProjectConversations(_ context.Context, _ string, _ ipc.SharedConversationRelocateRequest) error {
	return nil
}

func (f *fakeInstances) UpdateSharedProjectACL(_ context.Context, sid string, request ipc.SharedProjectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureSIDs = append(f.ensureSIDs, sid)
	f.sharedProject = &request
	return f.sharedProjectError
}

func (f *fakeInstances) BeginRequest(sid string, webSocket bool) (func(), error) {
	f.mu.Lock()
	f.beginSIDs = append(f.beginSIDs, sid)
	f.requests++
	if webSocket {
		f.webSockets++
	}
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.requests--
			if webSocket {
				f.webSockets--
			}
		})
	}, nil
}

func (f *fakeInstances) ModelKeyIDs(_ context.Context, sid string) (modelbootstrap.KeyIDs, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modelKeyIDSIDs = append(f.modelKeyIDSIDs, sid)
	if f.modelKeyIDSError != nil {
		return modelbootstrap.KeyIDs{}, f.modelKeyIDSError
	}
	if ids, exists := f.modelKeyIDs[sid]; exists {
		return ids, nil
	}
	return modelbootstrap.KeyIDsForSID(sid), nil
}

func (f *fakeInstances) StorageUsage(_ context.Context, sid string) (ipc.StorageUsage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storageUsageSIDs = append(f.storageUsageSIDs, sid)
	if f.storageUsage.Personal.LimitBytes == 0 {
		f.storageUsage = ipc.StorageUsage{
			Personal: ipc.StorageBucketUsage{LimitBytes: 60 * 1024 * 1024 * 1024, UsedBytes: 2 * 1024 * 1024 * 1024, RemainingBytes: 58 * 1024 * 1024 * 1024, MeasuredAt: "2026-07-26T08:00:00Z"},
			Shared:   ipc.StorageBucketUsage{LimitBytes: 20 * 1024 * 1024 * 1024, UsedBytes: 2 * 1024 * 1024 * 1024, RemainingBytes: 18 * 1024 * 1024 * 1024, MeasuredAt: "2026-07-26T08:00:00Z"},
		}
	}
	if err := f.storageErrorsBySID[sid]; err != nil {
		return ipc.StorageUsage{}, err
	}
	return f.storageUsage, f.storageUsageError
}

func (f *fakeInstances) WriteUsageSnapshot(_ context.Context, _ string, _ []byte) error { return nil }

func (f *fakeInstances) Stop(_ context.Context, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopSIDs = append(f.stopSIDs, sid)
	return nil
}

func (f *fakeInstances) Restart(_ context.Context, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restartSIDs = append(f.restartSIDs, sid)
	return f.restartError
}

type fakeUsageService struct {
	mu           sync.Mutex
	calls        []usageCall
	batchCalls   [][]string
	summary      portalusage.Summary
	summaryBySID map[string]portalusage.Summary
	err          error
}

type usageCall struct {
	sid string
	ids modelbootstrap.KeyIDs
}

func (f *fakeUsageService) Current(_ context.Context, sid string, ids modelbootstrap.KeyIDs) (portalusage.Summary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, usageCall{sid: sid, ids: ids})
	if summary, exists := f.summaryBySID[sid]; exists {
		return summary, f.err
	}
	return f.summary, f.err
}

func (f *fakeUsageService) CurrentMany(_ context.Context, sids []string) (map[string]portalusage.Summary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batchCalls = append(f.batchCalls, append([]string(nil), sids...))
	if f.err != nil {
		return nil, f.err
	}
	result := make(map[string]portalusage.Summary, len(sids))
	for _, sid := range sids {
		summary := f.summary
		if value, exists := f.summaryBySID[sid]; exists {
			summary = value
		}
		result[strings.ToUpper(sid)] = summary
	}
	return result, nil
}

func validUsageSummary() portalusage.Summary {
	return portalusage.Summary{AsOf: "2026-07-14T05:00:00Z", Providers: []portalusage.Provider{
		{Kind: portalusage.KindChatGPT, Label: "ChatGPT", Daily: portalusage.Window{LimitUSD: "20.00", UsedUSD: "1.25", RemainingUSD: "18.75", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: portalusage.Window{LimitUSD: "40.00", UsedUSD: "3.50", RemainingUSD: "36.50", ResetAt: "2026-07-21T00:00:00Z"}},
		{Kind: portalusage.KindKimi, Label: "Kimi", Daily: portalusage.Window{LimitUSD: "5.00", UsedUSD: "0.40", RemainingUSD: "4.60", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: portalusage.Window{LimitUSD: "10.00", UsedUSD: "1.10", RemainingUSD: "8.90", ResetAt: "2026-07-21T00:00:00Z"}},
	}}
}

func TestWrongPasswordNeverStartsInstance(t *testing.T) {
	server, data, instances := testServer(t)
	hash, err := auth.HashPassword([]byte("a-correct-portal-password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateUser(context.Background(), "employee-one", hash, testSID1, `SERVER\test1`, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		request := loginRequest(`{"username":"employee-one","password":"wrong-password"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if attempt == 5 {
			want = http.StatusUnauthorized
		}
		if response.Code != want {
			t.Fatalf("attempt %d: status=%d body=%s", attempt, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, loginRequest(`{"username":"employee-one","password":"a-correct-portal-password"}`))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked status=%d body=%s", response.Code, response.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.ensureSIDs) != 0 {
		t.Fatalf("invalid or rate-limited credentials started instances: %v", instances.ensureSIDs)
	}
}

func TestEmployeeCanRestartOnlyTheirSIDOwnedService(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/me/restart-service", nil)
	request.Header.Set("Origin", "https://portal.example.test")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"reconnect_after_ms":1000`) {
		t.Fatalf("restart status=%d body=%s", response.Code, response.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.restartSIDs) != 1 || instances.restartSIDs[0] != testSID1 {
		t.Fatalf("restart SIDs=%v, want current employee SID", instances.restartSIDs)
	}
	if len(instances.stopSIDs) != 0 {
		t.Fatalf("restart used administrator stop path: %v", instances.stopSIDs)
	}
}

func TestServiceRestartRejectsUntrustedOriginAndReportsRuntimeFailure(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	untrusted := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/me/restart-service", nil)
	untrusted.Header.Set("Origin", "https://attacker.example")
	untrusted.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	untrustedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(untrustedResponse, untrusted)
	if untrustedResponse.Code != http.StatusForbidden {
		t.Fatalf("untrusted restart status=%d body=%s", untrustedResponse.Code, untrustedResponse.Body.String())
	}

	instances.restartError = errors.New("protected UserHost pipe unavailable")
	failed := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/me/restart-service", nil)
	failed.Header.Set("Origin", "https://portal.example.test")
	failed.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	failedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(failedResponse, failed)
	if failedResponse.Code != http.StatusServiceUnavailable || !strings.Contains(failedResponse.Body.String(), "restart could not be started") {
		t.Fatalf("failed restart status=%d body=%s", failedResponse.Code, failedResponse.Body.String())
	}
}

func TestServiceRestartRequiresPostAndEmployeeSession(t *testing.T) {
	server, data, _ := testServer(t)

	methodResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(methodResponse, httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/me/restart-service", nil))
	if methodResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET restart status=%d body=%s", methodResponse.Code, methodResponse.Body.String())
	}

	unauthenticated := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/me/restart-service", nil)
	unauthenticated.Header.Set("Origin", "https://portal.example.test")
	unauthenticatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated restart status=%d body=%s", unauthenticatedResponse.Code, unauthenticatedResponse.Body.String())
	}

	password := []byte("correct-administrator-portal-password")
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateAdministrator(context.Background(), "restart-admin", hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, loginRequest(`{"username":"restart-admin","password":"correct-administrator-portal-password"}`))
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("administrator session cookie missing: %#v", cookies)
	}
	adminRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/me/restart-service", nil)
	adminRequest.Header.Set("Origin", "https://portal.example.test")
	adminRequest.AddCookie(cookies[0])
	adminResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusForbidden {
		t.Fatalf("administrator restart status=%d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
}

func TestAdministratorLoginSkipsInstanceAndCanManageUsers(t *testing.T) {
	server, data, instances := testServer(t)
	password := []byte("correct-administrator-portal-password")
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateAdministrator(context.Background(), "admin", hash, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateUser(context.Background(), "employee-two", hash, testSID2, `SERVER\test2`, false, time.Now()); err != nil {
		t.Fatal(err)
	}

	login := httptest.NewRecorder()
	server.Handler().ServeHTTP(login, loginRequest(`{"username":"admin","password":"correct-administrator-portal-password"}`))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"admin":true`) {
		t.Fatalf("administrator login status=%d body=%s", login.Code, login.Body.String())
	}
	instances.mu.Lock()
	if len(instances.ensureSIDs) != 0 || len(instances.beginSIDs) != 0 {
		instances.mu.Unlock()
		t.Fatalf("administrator login started an employee instance: ensure=%v begin=%v", instances.ensureSIDs, instances.beginSIDs)
	}
	instances.mu.Unlock()
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("administrator session cookie missing: %#v", cookies)
	}
	provisionRequests := make(chan provisionipc.Request, 1)
	server.provision = func(_ context.Context, request provisionipc.Request, report func(provisionipc.Progress)) (provisionipc.Response, error) {
		report(provisionipc.Progress{Percent: 62, Step: "creating_portal_account"})
		provisionRequests <- request
		created, err := data.CreateUser(context.Background(), request.Username, hash, "S-1-5-21-100-200-300-1019", `SERVER\test3`, false, time.Now())
		if err != nil {
			return provisionipc.Response{}, err
		}
		return provisionipc.Response{OK: true, User: &provisionipc.User{Username: created.Username, WindowsUsername: created.WindowsUsername, WindowsSID: created.WindowsSID}}, nil
	}
	invalidRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users", strings.NewReader(`{"username":"employee-three","portal_password":"short"}`))
	invalidRequest.Header.Set("Content-Type", "application/json")
	invalidRequest.Header.Set("Origin", "https://portal.example.test")
	invalidRequest.AddCookie(cookies[0])
	invalidResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusBadRequest || len(provisionRequests) != 0 {
		t.Fatalf("invalid password reached provisioner: status=%d body=%s", invalidResponse.Code, invalidResponse.Body.String())
	}
	addRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users", strings.NewReader(`{"username":"employee-three","portal_password":"new-employee-portal-password"}`))
	addRequest.Header.Set("Content-Type", "application/json")
	addRequest.Header.Set("Origin", "https://portal.example.test")
	addRequest.AddCookie(cookies[0])
	addResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(addResponse, addRequest)
	if addResponse.Code != http.StatusAccepted || !strings.Contains(addResponse.Body.String(), `"status":"running"`) {
		t.Fatalf("add status=%d body=%s", addResponse.Code, addResponse.Body.String())
	}
	var addPayload struct {
		Job provisionJob `json:"job"`
	}
	if err := json.Unmarshal(addResponse.Body.Bytes(), &addPayload); err != nil || addPayload.Job.ID == "" {
		t.Fatalf("decode provision job: payload=%+v err=%v", addPayload, err)
	}
	select {
	case request := <-provisionRequests:
		if request.Command != "add-user" || request.Username != "employee-three" || string(request.PortalPassword) != "new-employee-portal-password" {
			t.Fatalf("unexpected provision request: command=%q username=%q", request.Command, request.Username)
		}
	case <-time.After(time.Second):
		t.Fatal("provision job did not start")
	}
	var completed provisionJob
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		jobRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/admin/user-jobs?id="+url.QueryEscape(addPayload.Job.ID), nil)
		jobRequest.AddCookie(cookies[0])
		jobResponse := httptest.NewRecorder()
		server.Handler().ServeHTTP(jobResponse, jobRequest)
		var payload struct {
			Job provisionJob `json:"job"`
		}
		if jobResponse.Code != http.StatusOK || json.Unmarshal(jobResponse.Body.Bytes(), &payload) != nil {
			t.Fatalf("read provision job status=%d body=%s", jobResponse.Code, jobResponse.Body.String())
		}
		completed = payload.Job
		if completed.Status == "succeeded" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if completed.Status != "succeeded" || completed.Percent != 100 || completed.Step != "completed" {
		t.Fatalf("provision job did not complete: %+v", completed)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/admin/users", nil)
	listRequest.AddCookie(cookies[0])
	listResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), `"username":"employee-two"`) ||
		strings.Contains(listResponse.Body.String(), `"resource_usage"`) ||
		strings.Contains(listResponse.Body.String(), `"username":"admin"`) {
		t.Fatalf("administrator list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	instances.mu.Lock()
	if len(instances.ensureSIDs) != 0 || len(instances.beginSIDs) != 0 || len(instances.statusSIDs) != 0 {
		instances.mu.Unlock()
		t.Fatalf("administrator list touched employee runtimes: ensure=%v begin=%v status=%v", instances.ensureSIDs, instances.beginSIDs, instances.statusSIDs)
	}
	instances.mu.Unlock()

	server.provision = func(_ context.Context, request provisionipc.Request, _ func(provisionipc.Progress)) (provisionipc.Response, error) {
		if request.Command != "set-kimi-datasource" || request.Username != "employee-two" || !request.Enabled ||
			len(request.AllowedSources) != 2 || request.AllowedSources[0] != "arxiv" || request.DailyLimit != 25 || request.MonthlyLimit != 250 {
			t.Fatalf("unexpected Kimi datasource request: %+v", request)
		}
		return provisionipc.Response{OK: true, KimiDatasource: &provisionipc.KimiDatasourceGrant{Enabled: true, AllowedSources: request.AllowedSources,
			DailyLimit: request.DailyLimit, MonthlyLimit: request.MonthlyLimit}}, nil
	}
	kimiRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users/kimi-datasource",
		strings.NewReader(`{"username":"employee-two","enabled":true,"allowed_sources":["arxiv","scholar"],"daily_limit":25,"monthly_limit":250}`))
	kimiRequest.Header.Set("Content-Type", "application/json")
	kimiRequest.Header.Set("Origin", "https://portal.example.test")
	kimiRequest.AddCookie(cookies[0])
	kimiResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(kimiResponse, kimiRequest)
	if kimiResponse.Code != http.StatusOK || !strings.Contains(kimiResponse.Body.String(), `"enabled":true`) {
		t.Fatalf("Kimi datasource policy status=%d body=%s", kimiResponse.Code, kimiResponse.Body.String())
	}

	instances.storageErrorsBySID = map[string]error{"S-1-5-21-100-200-300-1019": errors.New("UserHost IPC is unavailable")}
	usageRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/admin/users/usage", nil)
	usageRequest.AddCookie(cookies[0])
	usageResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(usageResponse, usageRequest)
	if usageResponse.Code != http.StatusOK || strings.Count(usageResponse.Body.String(), `"resource_usage"`) != 2 ||
		!strings.Contains(usageResponse.Body.String(), `"used_bytes":2147483648`) ||
		!strings.Contains(usageResponse.Body.String(), `"username":"employee-three"`) {
		t.Fatalf("administrator usage status=%d body=%s", usageResponse.Code, usageResponse.Body.String())
	}
	instances.mu.Lock()
	if len(instances.ensureSIDs) != 0 || len(instances.modelKeyIDSIDs) != 0 || len(instances.storageUsageSIDs) != 2 {
		instances.mu.Unlock()
		t.Fatalf("administrator batch usage touched heavy runtime state: ensure=%v mappings=%v storage=%v", instances.ensureSIDs, instances.modelKeyIDSIDs, instances.storageUsageSIDs)
	}
	instances.mu.Unlock()
	usage := server.usage.(*fakeUsageService)
	usage.mu.Lock()
	if len(usage.batchCalls) != 1 || len(usage.batchCalls[0]) != 2 || len(usage.calls) != 0 {
		usage.mu.Unlock()
		t.Fatalf("administrator usage did not use one batch quota query: batch=%v single=%v", usage.batchCalls, usage.calls)
	}
	usage.mu.Unlock()

	invalidUsageRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/admin/users/usage?username=employee-two", nil)
	invalidUsageRequest.AddCookie(cookies[0])
	invalidUsageResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(invalidUsageResponse, invalidUsageRequest)
	if invalidUsageResponse.Code != http.StatusBadRequest {
		t.Fatalf("administrator batch usage accepted per-user query: status=%d body=%s", invalidUsageResponse.Code, invalidUsageResponse.Body.String())
	}

	disableRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users/disable", strings.NewReader(`{"username":"employee-two"}`))
	disableRequest.Header.Set("Content-Type", "application/json")
	disableRequest.Header.Set("Origin", "https://portal.example.test")
	disableRequest.AddCookie(cookies[0])
	disableResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(disableResponse, disableRequest)
	if disableResponse.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disableResponse.Code, disableResponse.Body.String())
	}
	disabled, err := data.UserByUsername(context.Background(), "employee-two")
	if err != nil || disabled.Enabled {
		t.Fatalf("employee was not disabled: user=%+v err=%v", disabled, err)
	}
	instances.mu.Lock()
	if len(instances.stopSIDs) != 1 || instances.stopSIDs[0] != testSID2 {
		instances.mu.Unlock()
		t.Fatalf("disabled employee instance was not stopped: %v", instances.stopSIDs)
	}
	instances.mu.Unlock()

	enableRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users/enable", strings.NewReader(`{"username":"employee-two"}`))
	enableRequest.Header.Set("Content-Type", "application/json")
	enableRequest.Header.Set("Origin", "https://portal.example.test")
	enableRequest.AddCookie(cookies[0])
	enableResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(enableResponse, enableRequest)
	if enableResponse.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", enableResponse.Code, enableResponse.Body.String())
	}
	enabled, err := data.UserByUsername(context.Background(), "employee-two")
	if err != nil || !enabled.Enabled {
		t.Fatalf("employee was not enabled: user=%+v err=%v", enabled, err)
	}
	if err := data.CreateSession(context.Background(), "employee-session-before-reset", enabled, time.Hour, "192.0.2.20", "employee-browser", time.Now()); err != nil {
		t.Fatal(err)
	}

	resetRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users/reset-password", strings.NewReader(`{"username":"employee-two","portal_password":"replacement-employee-password"}`))
	resetRequest.Header.Set("Content-Type", "application/json")
	resetRequest.Header.Set("Origin", "https://portal.example.test")
	resetRequest.AddCookie(cookies[0])
	resetResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(resetResponse, resetRequest)
	if resetResponse.Code != http.StatusOK {
		t.Fatalf("reset password status=%d body=%s", resetResponse.Code, resetResponse.Body.String())
	}
	resetUser, err := data.UserByUsername(context.Background(), "employee-two")
	if err != nil || !auth.VerifyPassword(resetUser.PasswordHash, []byte("replacement-employee-password")) || auth.VerifyPassword(resetUser.PasswordHash, password) {
		t.Fatalf("employee Portal password was not replaced: user=%+v err=%v", resetUser, err)
	}
	if _, err := data.Session(context.Background(), "employee-session-before-reset", time.Hour, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("employee session remained valid after administrator password reset: %v", err)
	}
	adminListRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/admin/users", nil)
	adminListRequest.AddCookie(cookies[0])
	adminListResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(adminListResponse, adminListRequest)
	if adminListResponse.Code != http.StatusOK {
		t.Fatalf("employee password reset invalidated administrator session: status=%d body=%s", adminListResponse.Code, adminListResponse.Body.String())
	}

	started := make(chan string, 2)
	release := make(chan struct{})
	server.provision = func(_ context.Context, request provisionipc.Request, _ func(provisionipc.Progress)) (provisionipc.Response, error) {
		started <- request.Username
		<-release
		return provisionipc.Response{}, errors.New("planned provision failure")
	}
	for _, username := range []string{"employee-four", "employee-five"} {
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/portal/admin/users",
			strings.NewReader(`{"username":"`+username+`","portal_password":"new-employee-portal-password"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://portal.example.test")
		request.AddCookie(cookies[0])
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("start concurrent provision for %s: status=%d body=%s", username, response.Code, response.Body.String())
		}
	}
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case username := <-started:
			seen[username] = true
		case <-time.After(time.Second):
			t.Fatalf("provision jobs did not run concurrently: %v", seen)
		}
	}
	close(release)
}

func TestFilesystemBrowseStartsAtWorkspaceAndRejectsEscape(t *testing.T) {
	root := `C:\Users\test1\AionUiPortal`
	initial := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/fs/browse?path=&showFiles=true", nil)
	if err := constrainFilesystemBrowse(initial, root); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "workspace")
	if got := initial.URL.Query().Get("path"); !strings.EqualFold(got, want) {
		t.Fatalf("initial browse path=%q, want %q", got, want)
	}

	allowed := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/fs/browse?path="+url.QueryEscape(`\\?\C:\Users\test1\AionUiPortal\workspace`), nil)
	if err := constrainFilesystemBrowse(allowed, root); err != nil {
		t.Fatalf("private descendant was rejected: %v", err)
	}
	if got := allowed.URL.Query().Get("path"); got != `C:\Users\test1\AionUiPortal\workspace` {
		t.Fatalf("verbatim path normalized to %q", got)
	}

	for _, outside := range []string{
		`C:\Users\Administrator`,
		`C:\Users\test1\AionUiPortal-other`,
		`C:\Users\test1\AionUiPortal\..\Documents`,
		`workspace`,
	} {
		request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/fs/browse?path="+url.QueryEscape(outside), nil)
		if err := constrainFilesystemBrowse(request, root); err == nil {
			t.Fatalf("outside browse path was accepted: %s", outside)
		}
	}
}

func TestProxyRejectsFilesystemBrowseEscapeBeforeStartingInstance(t *testing.T) {
	server, data, instances := testServer(t)
	server.profilePath = func(sid string) (string, error) {
		if sid != testSID1 {
			return "", fmt.Errorf("unexpected SID %s", sid)
		}
		return `C:\Users\test1`, nil
	}
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/fs/browse?path="+url.QueryEscape(`C:\Users\Administrator`), nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("outside browse status=%d body=%s", response.Code, response.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.beginSIDs) != 0 || len(instances.ensureSIDs) != 0 || len(instances.routeSIDs) != 0 {
		t.Fatalf("outside browse reached UserHost: begin=%v ensure=%v route=%v", instances.beginSIDs, instances.ensureSIDs, instances.routeSIDs)
	}
}

func TestRendererRootAndHashRouteFallbackDoNotRedirect(t *testing.T) {
	server, _, _ := testServer(t)
	for _, target := range []string{"https://portal.example.test/", "https://portal.example.test/conversations/123"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.String() != "real renderer placeholder" || response.Header().Get("Location") != "" {
			t.Fatalf("Renderer fallback for %s returned status=%d location=%q body=%q", target, response.Code, response.Header().Get("Location"), response.Body.String())
		}
	}
}

func TestRendererServesRealFileAndRejectsWindowsSeparator(t *testing.T) {
	server, _, _ := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/app.js", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "real static asset" {
		t.Fatalf("real static file returned status=%d body=%q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "https://portal.example.test/assets\\escape.js", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("Windows-separator path returned %d", response.Code)
	}
}

func TestRendererCachesOnlyFingerprintedStaticAssets(t *testing.T) {
	server, _, _ := testServer(t)
	for target, want := range map[string]string{
		"https://portal.example.test/assets/index-AbCdEf12.js": "public, max-age=31536000, immutable",
		"https://portal.example.test/app.js":                   "no-store",
		"https://portal.example.test/":                         "no-store",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != want {
			t.Fatalf("cache policy for %s: status=%d Cache-Control=%q, want %q", target, response.Code, response.Header().Get("Cache-Control"), want)
		}
	}
}

func TestAdditionalBrowserOriginsAreExactAndDoNotChangeOAuthOrigin(t *testing.T) {
	server, _, _ := testServerWithPublicURLAndOrigins(t, "http://portal.example.test", []string{
		"http://134.175.110.121:25808",
		"http://127.0.0.1:25808",
	})
	for _, origin := range []string{"http://portal.example.test", "http://134.175.110.121:25808", "http://127.0.0.1:25808"} {
		request := httptest.NewRequest(http.MethodPost, "http://portal.example.test/login", strings.NewReader("{"))
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("allowed origin %s returned status=%d body=%s", origin, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "http://portal.example.test/login", strings.NewReader("{"))
	request.Header.Set("Origin", "http://attacker.example.test")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unlisted origin returned status=%d body=%s", response.Code, response.Body.String())
	}
	if server.public.String() != "http://portal.example.test" {
		t.Fatalf("additional origins changed canonical public URL: %s", server.public)
	}
}

func TestUnauthenticatedRendererReceivesChineseLanguageOnly(t *testing.T) {
	server, _, instances := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/settings/client", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"language":"zh-CN"}` {
		t.Fatalf("login settings status=%d body=%s", response.Code, response.Body.String())
	}
	instances.mu.Lock()
	if len(instances.ensureSIDs) != 0 || len(instances.routeSIDs) != 0 {
		instances.mu.Unlock()
		t.Fatalf("unauthenticated language settings started or routed an instance: ensure=%v route=%v", instances.ensureSIDs, instances.routeSIDs)
	}
	instances.mu.Unlock()

	request = httptest.NewRequest(http.MethodPut, "https://portal.example.test/api/settings/client", strings.NewReader(`{"language":"en-US"}`))
	request.Header.Set("Origin", "https://portal.example.test")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated settings write status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLoginCookieAndPortalUserContract(t *testing.T) {
	server, data, instances := testServer(t)
	password := []byte("correct-employee-portal-password")
	hash, _ := auth.HashPassword(password)
	user, err := data.CreateUser(context.Background(), "portal-alice", hash, testSID1, `SERVER\test1`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, loginRequest(fmt.Sprintf(`{"username":"portal-alice","password":%q}`, string(password))))
	if response.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" {
		t.Fatalf("unsafe session cookie: %#v", cookies)
	}
	if strings.Contains(response.Body.String(), testSID1) || strings.Contains(response.Body.String(), cookies[0].Value) {
		t.Fatalf("login response leaked routing/session material: %s", response.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/auth/user", nil)
	request.AddCookie(cookies[0])
	userResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(userResponse, request)
	if userResponse.Code != http.StatusOK {
		t.Fatalf("auth user status=%d body=%s", userResponse.Code, userResponse.Body.String())
	}
	var payload struct {
		Success bool `json:"success"`
		User    struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := json.Unmarshal(userResponse.Body.Bytes(), &payload); err != nil || !payload.Success || payload.User.Username != user.Username || payload.User.ID != fmt.Sprint(user.ID) {
		t.Fatalf("unexpected Renderer user contract: %s err=%v", userResponse.Body.String(), err)
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.ensureSIDs) != 1 || instances.ensureSIDs[0] != testSID1 {
		t.Fatalf("login routed from anything other than stored SID: %v", instances.ensureSIDs)
	}
}

func TestPasswordChangeRequiresCurrentPasswordAndInvalidatesSessions(t *testing.T) {
	server, data, _ := testServer(t)
	currentPassword := []byte("correct-employee-portal-password")
	newPassword := []byte("new-employee-portal-password")
	hash, err := auth.HashPassword(currentPassword)
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(context.Background(), "password-alice", hash, testSID1, `SERVER\test1`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := data.CreateSession(context.Background(), token, user, time.Hour, "192.0.2.10", "old-browser", time.Now()); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"username":"password-alice","current_password":%q,"new_password":%q,"confirm_password":%q}`,
		string(currentPassword), string(newPassword), string(newPassword))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, changePasswordRequest(body))
	if response.Code != http.StatusOK {
		t.Fatalf("password change status=%d body=%s", response.Code, response.Body.String())
	}
	updated, err := data.UserByUsername(context.Background(), user.Username)
	if err != nil || !auth.VerifyPassword(updated.PasswordHash, newPassword) || auth.VerifyPassword(updated.PasswordHash, currentPassword) {
		t.Fatalf("password hash was not replaced safely: err=%v", err)
	}
	if _, err := data.Session(context.Background(), token, time.Hour, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old session survived password change: %v", err)
	}
}

func TestPasswordChangeRejectsInvalidCurrentPasswordAndConfirmation(t *testing.T) {
	server, data, _ := testServer(t)
	currentPassword := []byte("correct-employee-portal-password")
	hash, _ := auth.HashPassword(currentPassword)
	if _, err := data.CreateUser(context.Background(), "password-bob", hash, testSID1, `SERVER\test1`, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"invalid current password": `{"username":"password-bob","current_password":"wrong-employee-portal-password","new_password":"new-employee-portal-password","confirm_password":"new-employee-portal-password"}`,
		"mismatched confirmation":  `{"username":"password-bob","current_password":"correct-employee-portal-password","new_password":"new-employee-portal-password","confirm_password":"different-portal-password"}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, changePasswordRequest(body))
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest {
				t.Fatalf("rejected password change status=%d body=%s", response.Code, response.Body.String())
			}
			unchanged, err := data.UserByUsername(context.Background(), "password-bob")
			if err != nil || !auth.VerifyPassword(unchanged.PasswordHash, currentPassword) {
				t.Fatalf("rejected password change modified credentials: %v", err)
			}
		})
	}
}

func TestAdminMasterPasswordLoginIsDisabledByDefaultAndAuditedSeparatelyWhenConfigured(t *testing.T) {
	root := t.TempDir()
	server, data, _ := testServerAtRoot(t, root)
	userPassword := []byte("correct-employee-portal-password")
	masterPassword := []byte("administrator-master-password")
	userHash, _ := auth.HashPassword(userPassword)
	if _, err := data.CreateUser(context.Background(), "impersonated-alice", userHash, testSID1, `SERVER\test1`, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	requestBody := fmt.Sprintf(`{"username":"impersonated-alice","password":%q}`, string(masterPassword))
	disabledResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(disabledResponse, loginRequest(requestBody))
	if disabledResponse.Code != http.StatusUnauthorized {
		t.Fatalf("disabled admin master password login status=%d body=%s", disabledResponse.Code, disabledResponse.Body.String())
	}
	masterHash, _ := auth.HashPassword(masterPassword)
	server.adminMasterHash = masterHash
	enabledResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(enabledResponse, loginRequest(requestBody))
	if enabledResponse.Code != http.StatusOK {
		t.Fatalf("configured admin master password login status=%d body=%s", enabledResponse.Code, enabledResponse.Body.String())
	}
	if !strings.Contains(enabledResponse.Body.String(), `"username":"impersonated-alice"`) {
		t.Fatalf("admin master password login did not bind the target account: %s", enabledResponse.Body.String())
	}
	auditLog, err := os.ReadFile(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditLog), `"action":"portal.admin_impersonation"`) ||
		!strings.Contains(string(auditLog), `"authentication":"admin_master_password"`) {
		t.Fatalf("admin master password login was not distinctly audited: %s", auditLog)
	}
}

func TestAdminMasterPasswordCannotChangeTargetPassword(t *testing.T) {
	server, data, _ := testServer(t)
	userPassword := []byte("correct-employee-portal-password")
	masterPassword := []byte("administrator-master-password")
	userHash, _ := auth.HashPassword(userPassword)
	if _, err := data.CreateUser(context.Background(), "protected-alice", userHash, testSID1, `SERVER\test1`, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	server.adminMasterHash, _ = auth.HashPassword(masterPassword)
	body := fmt.Sprintf(`{"username":"protected-alice","current_password":%q,"new_password":"new-employee-portal-password","confirm_password":"new-employee-portal-password"}`,
		string(masterPassword))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, changePasswordRequest(body))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("admin master password changed target credentials: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminMasterPasswordHashLoaderFailsClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "admin-master.argon2id")
	validHash, err := auth.HashPassword([]byte("administrator-master-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(validHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAdminMasterPasswordHash(path)
	if err != nil || loaded != validHash {
		t.Fatalf("valid admin master password hash was not loaded: loaded=%q err=%v", loaded, err)
	}
	if err := os.WriteFile(path, []byte("not-an-argon2id-hash"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminMasterPasswordHash(path); err == nil {
		t.Fatal("malformed admin master password hash was accepted")
	}
	if _, err := loadAdminMasterPasswordHash(root); err == nil {
		t.Fatal("directory admin master password hash source was accepted")
	}
	oversized := filepath.Join(root, "oversized.argon2id")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), 1025), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminMasterPasswordHash(oversized); err == nil {
		t.Fatal("oversized admin master password hash source was accepted")
	}
}

func TestHTTPLoginCookieAndOAuthCallbackUseExplicitInsecureOrigin(t *testing.T) {
	server, data, instances := testServerWithPublicURL(t, "http://portal.example.test")
	password := []byte("correct-employee-portal-password")
	hash, _ := auth.HashPassword(password)
	if _, err := data.CreateUser(context.Background(), "portal-http-alice", hash, testSID1, `SERVER\test1`, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://portal.example.test/login", strings.NewReader(fmt.Sprintf(`{"username":"portal-http-alice","password":%q}`, string(password))))
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://portal.example.test")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP login status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != insecureSessionCookie || cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" {
		t.Fatalf("HTTP session cookie is unusable or overclaims TLS: %#v", cookies)
	}
	if response.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HTTP response advertised HSTS")
	}
	oauthRequest := httptest.NewRequest(http.MethodPost, "http://portal.example.test/api/mcp/oauth/login", strings.NewReader(`{"server_url":"https://mcp.example.test"}`))
	oauthRequest.Header.Set("Origin", "http://portal.example.test")
	oauthRequest.AddCookie(cookies[0])
	oauthResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(oauthResponse, oauthRequest)
	if oauthResponse.Code != http.StatusOK {
		t.Fatalf("HTTP OAuth start status=%d body=%s", oauthResponse.Code, oauthResponse.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.oauthStarts) != 1 || instances.oauthStarts[0].RedirectURI != "http://portal.example.test/api/mcp/oauth/callback" {
		t.Fatalf("OAuth callback did not use the configured HTTP origin: %#v", instances.oauthStarts)
	}
}

func TestRunServesPlainHTTPForHTTPPublicOrigin(t *testing.T) {
	server, _, _ := testServerWithPublicURL(t, "http://127.0.0.1:25808")
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	server.cfg.ListenAddress = address
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, requestErr := client.Get("http://" + address + "/healthz")
		if requestErr == nil {
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				cancel()
				t.Fatalf("plain HTTP health status=%d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("plain HTTP server did not become ready: %v", requestErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("plain HTTP server shutdown failed: %v", err)
	}
}

func TestLoginInvalidatesPreviousSessionBeforeIssuingAnother(t *testing.T) {
	server, data, _ := testServer(t)
	password := []byte("correct-employee-portal-password")
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(context.Background(), "portal-alice", hash, testSID1, `SERVER\test1`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := data.CreateSession(context.Background(), oldToken, user, time.Hour, "192.0.2.10", "old-browser", time.Now()); err != nil {
		t.Fatal(err)
	}
	request := loginRequest(fmt.Sprintf(`{"username":"portal-alice","password":%q}`, string(password)))
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: oldToken})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := data.Session(context.Background(), oldToken, time.Hour, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("previous session remains valid: %v", err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("new session cookie missing: %#v", cookies)
	}
	if _, err := data.Session(context.Background(), cookies[0].Value, time.Hour, time.Now()); err != nil {
		t.Fatalf("new session is invalid: %v", err)
	}
}

func TestSuccessfulLoginFailsClosedWhenAuditLogCannotBeWritten(t *testing.T) {
	root := t.TempDir()
	server, data, _ := testServerAtRoot(t, root)
	password := []byte("correct-employee-portal-password")
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(context.Background(), "portal-alice", hash, testSID1, `SERVER\test1`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "audit.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, loginRequest(fmt.Sprintf(`{"username":"portal-alice","password":%q}`, string(password))))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure did not fail login closed: status=%d body=%s", response.Code, response.Body.String())
	}
	if sessions, err := data.SessionCountForUser(context.Background(), user.ID, time.Now()); err != nil || sessions != 0 {
		t.Fatalf("session survived failed login audit: sessions=%d err=%v", sessions, err)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.MaxAge > 0 {
			t.Fatalf("active session cookie was returned after audit failure: %#v", cookie)
		}
	}
}

func TestLogoutDeletesServerSessionAndExpiresBrowserCookie(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/logout", nil)
	request.Header.Set("Origin", "https://portal.example.test")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := data.Session(context.Background(), token, time.Hour, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("logged-out session remains valid: %v", err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].MaxAge >= 0 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("logout did not securely expire the browser cookie: %#v", cookies)
	}
}

func TestProxyUsesSessionSIDAndContainsInternalAuthentication(t *testing.T) {
	upstreamListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamPort := upstreamListener.Addr().(*net.TCPAddr).Port
	seen := make(chan *http.Request, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		copy := r.Clone(r.Context())
		copy.Body = io.NopCloser(strings.NewReader(string(body)))
		seen <- copy
		w.Header().Add("Set-Cookie", "aionui-session=must-not-leak; HttpOnly")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	upstream.Listener = upstreamListener
	upstream.Start()
	defer upstream.Close()

	server, data, instances := testServer(t)
	hash, _ := auth.HashPassword([]byte("correct-employee-portal-password"))
	user, err := data.CreateUser(context.Background(), "portal-alice", hash, testSID1, `SERVER\test1`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token, _ := auth.RandomToken(32)
	if err := data.CreateSession(context.Background(), token, user, time.Hour, "192.0.2.10", "test-browser", time.Now()); err != nil {
		t.Fatal(err)
	}
	instances.route = instance.Route{Status: ipc.Status{WindowsSID: testSID1, Healthy: true, WebPort: upstreamPort, AionCorePort: 34123},
		Auth: ipc.AuthMaterial{CookieHeader: "aionui-session=internal-A; aionui-csrf-token=csrf-A", CSRFToken: "csrf-A"}}
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/files/upload?sid="+url.QueryEscape(testSID2)+"&port=9", strings.NewReader("real-shaped-upload-body"))
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("Origin", "https://portal.example.test")
	request.Header.Set("Cookie", sessionCookie+"="+token+"; aionui-session=attacker-B")
	request.Header.Set("Authorization", "Bearer attacker-B")
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	request.Header.Set("X-Windows-SID", testSID2)
	request.Header.Set("X-CSRF-Token", "attacker-csrf")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != "real-shaped-upload-body" {
		t.Fatalf("proxy response=%d body=%q", response.Code, response.Body.String())
	}
	if got := response.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("upstream cookie leaked to browser: %v", got)
	}
	proxied := <-seen
	if proxied.Header.Get("Cookie") != "aionui-session=internal-A; aionui-csrf-token=csrf-A" || proxied.Header.Get("X-CSRF-Token") != "csrf-A" {
		t.Fatalf("wrong internal authentication: cookie=%q csrf=%q", proxied.Header.Get("Cookie"), proxied.Header.Get("X-CSRF-Token"))
	}
	for _, name := range []string{"Authorization", "X-Forwarded-For", "X-Windows-SID"} {
		if value := proxied.Header.Get(name); value != "" {
			t.Fatalf("browser-controlled header %s reached upstream: %q", name, value)
		}
	}
	if proxied.Header.Get("Origin") != "http://127.0.0.1:34123" {
		t.Fatalf("untrusted public Origin reached internal backend: %q", proxied.Header.Get("Origin"))
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.routeSIDs) != 1 || instances.routeSIDs[0] != testSID1 {
		t.Fatalf("query/header changed the routed SID: %v", instances.routeSIDs)
	}
}

func TestProxyFailsClosedWhenActivityTouchFails(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	instances.touchError = errors.New("protected UserHost IPC unavailable")
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/system/info", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "activity") {
		t.Fatalf("touch failure was not surfaced: status=%d body=%s", response.Code, response.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.touchSIDs) != 1 || instances.touchSIDs[0] != testSID1 {
		t.Fatalf("activity touched the wrong SID: %v", instances.touchSIDs)
	}
	if instances.requests != 0 || instances.webSockets != 0 {
		t.Fatalf("request counters leaked after touch failure: requests=%d websockets=%d", instances.requests, instances.webSockets)
	}
}

func TestInternalAuthManagementIsNeverProxied(t *testing.T) {
	server, _, instances := testServer(t)
	for _, path := range []string{"/api/webui/reset-password", "/api/webui/generate-qr-token", "/api/auth/status", "/api/auth/internal-users"} {
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test"+path, strings.NewReader(`{}`))
		request.Header.Set("Origin", "https://portal.example.test")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s returned %d", path, response.Code)
		}
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.routeSIDs) != 0 || len(instances.ensureSIDs) != 0 {
		t.Fatalf("blocked internal auth routes touched an instance")
	}
}

func TestMcpOAuthLoginCreatesSessionAndInstanceBoundFlow(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/mcp/oauth/login", strings.NewReader(`{"server_url":"https://mcp.example.test"}`))
	request.Header.Set("Origin", "https://portal.example.test")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("OAuth start failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Pending          bool   `json:"pending"`
		State            string `json:"state"`
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || !body.Pending || !validPortalOAuthToken(body.State, 32) {
		t.Fatalf("invalid OAuth start response: body=%s err=%v", response.Body.String(), err)
	}
	authorizationURL, _ := url.Parse(body.AuthorizationURL)
	if authorizationURL.Query().Get("state") != body.State {
		t.Fatalf("authorization URL was not bound to Portal state: %s", body.AuthorizationURL)
	}
	if strings.Contains(response.Body.String(), "flow_id") {
		t.Fatalf("internal OAuth flow ID leaked to the browser: %s", response.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.ensureSIDs) != 1 || instances.ensureSIDs[0] != testSID1 || len(instances.routeSIDs) != 1 || len(instances.oauthStarts) != 1 {
		t.Fatalf("OAuth start was not routed to the session SID: ensure=%v route=%v starts=%v", instances.ensureSIDs, instances.routeSIDs, instances.oauthStarts)
	}
	start := instances.oauthStarts[0]
	if start.InstanceID != instances.route.InstanceID || start.ServerURL != "https://mcp.example.test" || start.State != body.State || start.RedirectURI != "https://portal.example.test/api/mcp/oauth/callback" {
		t.Fatalf("wrong UserHost OAuth start binding: %+v", start)
	}
}

func TestMcpOAuthCallbackIsSessionBoundSingleUseAndNeverCrossesUsers(t *testing.T) {
	server, data, instances := testServer(t)
	aliceToken := createPortalSession(t, data)
	startRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/mcp/oauth/login", strings.NewReader(`{"server_url":"https://mcp.example.test/sse"}`))
	startRequest.Header.Set("Origin", "https://portal.example.test")
	startRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: aliceToken})
	startResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusOK {
		t.Fatalf("OAuth start failed: %d %s", startResponse.Code, startResponse.Body.String())
	}
	var start struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(startResponse.Body.Bytes(), &start); err != nil || !validPortalOAuthToken(start.State, 32) {
		t.Fatalf("invalid start response: %s err=%v", startResponse.Body.String(), err)
	}

	hash, _ := auth.HashPassword([]byte("another-correct-portal-password"))
	bob, err := data.CreateUser(context.Background(), "portal-bob", hash, testSID2, `SERVER\test2`, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bobToken, _ := auth.RandomToken(32)
	if err := data.CreateSession(context.Background(), bobToken, bob, time.Hour, "192.0.2.11", "second-browser", time.Now()); err != nil {
		t.Fatal(err)
	}
	crossUser := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/callback?state="+url.QueryEscape(start.State)+"&code=wrong-user-code", nil)
	crossUser.AddCookie(&http.Cookie{Name: sessionCookie, Value: bobToken})
	crossResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(crossResponse, crossUser)
	if crossResponse.Code != http.StatusBadRequest {
		t.Fatalf("cross-user callback status=%d body=%s", crossResponse.Code, crossResponse.Body.String())
	}
	instances.mu.Lock()
	if len(instances.oauthCompletes) != 0 {
		instances.mu.Unlock()
		t.Fatal("cross-user callback reached UserHost completion")
	}
	instances.mu.Unlock()

	validCallback := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/callback?state="+url.QueryEscape(start.State)+"&code=alice-authorization-code", nil)
	validCallback.AddCookie(&http.Cookie{Name: sessionCookie, Value: aliceToken})
	validResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(validResponse, validCallback)
	if validResponse.Code != http.StatusOK || !strings.Contains(validResponse.Body.String(), "aionui-mcp-oauth-result") {
		t.Fatalf("valid callback failed: status=%d body=%s", validResponse.Code, validResponse.Body.String())
	}
	instances.mu.Lock()
	if len(instances.oauthCompletes) != 1 || instances.oauthCompletes[0].Code != "alice-authorization-code" ||
		instances.oauthCompletes[0].InstanceID != instances.route.InstanceID || instances.oauthCompletes[0].ServerURL != "https://mcp.example.test/sse" ||
		!validPortalOAuthToken(instances.oauthCompletes[0].FlowID, 32) {
		got := append([]ipc.OAuthCompleteRequest(nil), instances.oauthCompletes...)
		instances.mu.Unlock()
		t.Fatalf("valid callback reached wrong flow: %+v", got)
	}
	instances.mu.Unlock()

	replay := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/callback?state="+url.QueryEscape(start.State)+"&code=replayed-code", nil)
	replay.AddCookie(&http.Cookie{Name: sessionCookie, Value: aliceToken})
	replayResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status=%d body=%s", replayResponse.Code, replayResponse.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.oauthCompletes) != 1 {
		t.Fatalf("replayed callback completed %d flows", len(instances.oauthCompletes))
	}
}

func TestMcpOAuthCallbackRejectsRestartedInstanceAndProviderDenialCancels(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	startFlow := func() string {
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/mcp/oauth/login", strings.NewReader(`{"server_url":"https://mcp.example.test"}`))
		request.Header.Set("Origin", "https://portal.example.test")
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		var body struct {
			State string `json:"state"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
			t.Fatalf("OAuth start failed: %d %s", response.Code, response.Body.String())
		}
		return body.State
	}
	state := startFlow()
	instances.mu.Lock()
	instances.route.InstanceID = "2.1.29:9999:1700000001"
	instances.route.Status.UserHostPID = 9999
	instances.route.Status.StartedAtUnix = 1_700_000_001
	instances.mu.Unlock()
	callback := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/callback?state="+url.QueryEscape(state)+"&code=code-for-old-instance", nil)
	callback.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, callback)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("restarted instance callback status=%d body=%s", response.Code, response.Body.String())
	}
	instances.mu.Lock()
	if len(instances.oauthCompletes) != 0 {
		instances.mu.Unlock()
		t.Fatal("old instance flow completed on a restarted UserHost")
	}
	instances.route.InstanceID = "2.1.29:1234:1700000000"
	instances.route.Status.UserHostPID = 1234
	instances.route.Status.StartedAtUnix = 1_700_000_000
	instances.mu.Unlock()

	deniedState := startFlow()
	denied := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/callback?state="+url.QueryEscape(deniedState)+"&error=access_denied&error_description=must-not-echo", nil)
	denied.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	deniedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusOK || strings.Contains(deniedResponse.Body.String(), "must-not-echo") {
		t.Fatalf("provider denial was mishandled: status=%d body=%s", deniedResponse.Code, deniedResponse.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.oauthCancels) != 1 || instances.oauthCancels[0].InstanceID != instances.route.InstanceID || instances.oauthCancels[0].ServerURL != "https://mcp.example.test" ||
		!validPortalOAuthToken(instances.oauthCancels[0].FlowID, 32) {
		t.Fatalf("provider denial did not cancel the bound flow: %+v", instances.oauthCancels)
	}
}

func TestMcpOAuthCancelAndExpiredCallbackNeverComplete(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	startFlow := func() string {
		request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/mcp/oauth/login", strings.NewReader(`{"server_url":"https://mcp.example.test"}`))
		request.Header.Set("Origin", "https://portal.example.test")
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		var body struct {
			State string `json:"state"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
			t.Fatalf("OAuth start failed: %d %s", response.Code, response.Body.String())
		}
		return body.State
	}
	cancelledState := startFlow()
	cancelRequest := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/mcp/oauth/cancel", strings.NewReader(`{"state":"`+cancelledState+`"}`))
	cancelRequest.Header.Set("Origin", "https://portal.example.test")
	cancelRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	cancelResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(cancelResponse, cancelRequest)
	if cancelResponse.Code != http.StatusOK {
		t.Fatalf("OAuth cancel failed: %d %s", cancelResponse.Code, cancelResponse.Body.String())
	}
	instances.mu.Lock()
	if len(instances.oauthCancels) != 1 || instances.oauthCancels[0].ServerURL != "https://mcp.example.test" {
		got := append([]ipc.OAuthCancelRequest(nil), instances.oauthCancels...)
		instances.mu.Unlock()
		t.Fatalf("cancel reached wrong flow: %+v", got)
	}
	instances.mu.Unlock()

	expiredState := startFlow()
	server.now = func() time.Time { return time.Now().Add(portalOAuthFlowTTL + time.Second) }
	expired := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/callback?state="+url.QueryEscape(expiredState)+"&code=too-late", nil)
	expired.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	expiredResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(expiredResponse, expired)
	if expiredResponse.Code != http.StatusBadRequest {
		t.Fatalf("expired callback status=%d body=%s", expiredResponse.Code, expiredResponse.Body.String())
	}
	instances.mu.Lock()
	defer instances.mu.Unlock()
	if len(instances.oauthCompletes) != 0 {
		t.Fatalf("cancelled/expired callback completed %d flows", len(instances.oauthCompletes))
	}
}

func TestOAuthBridgeIsInjectedBeforeRendererAndPopupRequiresSession(t *testing.T) {
	index := []byte(`<!doctype html><html><head><script type="module" src="/assets/app.js"></script></head><body></body></html>`)
	injected := string(injectOAuthBridge(index))
	bridgeAt := strings.Index(injected, `<script src="/portal-mcp-oauth.js"></script>`)
	moduleAt := strings.Index(injected, `<script type="module"`)
	if bridgeAt < 0 || moduleAt < 0 || bridgeAt > moduleAt {
		t.Fatalf("OAuth bridge was not injected before the Renderer module: %s", injected)
	}
	server, data, _ := testServer(t)
	bridgeRequest := httptest.NewRequest(http.MethodGet, "https://portal.example.test/portal-mcp-oauth.js", nil)
	bridgeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(bridgeResponse, bridgeRequest)
	if bridgeResponse.Code != http.StatusOK || !strings.Contains(bridgeResponse.Body.String(), "noopener,noreferrer") ||
		!strings.Contains(bridgeResponse.Body.String(), "BroadcastChannel") || bridgeResponse.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatalf("OAuth bridge response is incomplete: status=%d body=%s", bridgeResponse.Code, bridgeResponse.Body.String())
	}
	channelBytes := make([]byte, 16)
	channel := base64.RawURLEncoding.EncodeToString(channelBytes)
	unauthenticated := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/popup?channel="+channel, nil)
	unauthenticatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated popup status=%d", unauthenticatedResponse.Code)
	}
	token := createPortalSession(t, data)
	authenticated := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/mcp/oauth/popup?channel="+channel, nil)
	authenticated.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	authenticatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(authenticatedResponse, authenticated)
	if authenticatedResponse.Code != http.StatusOK || !strings.Contains(authenticatedResponse.Body.String(), "aionui-mcp-oauth-launch") ||
		!strings.Contains(authenticatedResponse.Header().Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Fatalf("authenticated popup invalid: status=%d csp=%q body=%s", authenticatedResponse.Code, authenticatedResponse.Header().Get("Content-Security-Policy"), authenticatedResponse.Body.String())
	}
}

func TestProxyStreamsResponseBeforeUpstreamCompletes(t *testing.T) {
	firstFlushed := make(chan struct{})
	releaseSecond := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "chunk-one\n")
		w.(http.Flusher).Flush()
		close(firstFlushed)
		<-releaseSecond
		_, _ = io.WriteString(w, "chunk-two\n")
	}))
	defer upstream.Close()
	defer func() {
		select {
		case releaseSecond <- struct{}{}:
		default:
		}
	}()

	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	upstreamURL, _ := url.Parse(upstream.URL)
	port, _ := net.LookupPort("tcp", upstreamURL.Port())
	instances.route = testRoute(port)
	public := httptest.NewServer(server.Handler())
	defer public.Close()
	request, _ := http.NewRequest(http.MethodGet, public.URL+"/api/events", nil)
	request.Header.Set("Cookie", sessionCookie+"="+token)
	response, err := public.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-firstFlushed:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not flush the first response chunk")
	}
	first := make([]byte, len("chunk-one\n"))
	readDone := make(chan error, 1)
	go func() { _, err := io.ReadFull(response.Body, first); readDone <- err }()
	select {
	case err := <-readDone:
		if err != nil || string(first) != "chunk-one\n" {
			t.Fatalf("first streamed chunk=%q err=%v", first, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Portal buffered the response until upstream completion")
	}
	releaseSecond <- struct{}{}
	rest, err := io.ReadAll(response.Body)
	if err != nil || string(rest) != "chunk-two\n" {
		t.Fatalf("remaining stream=%q err=%v", rest, err)
	}
}

func TestProxyStreamsLargeUploadWithoutReadingWholeBodyFirst(t *testing.T) {
	readFirst := make(chan struct{})
	receivedDone := make(chan int64, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first := make([]byte, 16)
		if _, err := io.ReadFull(r.Body, first); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		close(readFirst)
		rest, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedDone <- int64(len(first)) + rest
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	upstreamURL, _ := url.Parse(upstream.URL)
	port, _ := net.LookupPort("tcp", upstreamURL.Port())
	instances.route = testRoute(port)
	public := httptest.NewServer(server.Handler())
	defer public.Close()
	reader, writer := io.Pipe()
	defer writer.CloseWithError(errors.New("test completed"))
	request, _ := http.NewRequest(http.MethodPost, public.URL+"/api/files/upload", reader)
	request.Header.Set("Origin", "https://portal.example.test")
	request.Header.Set("Cookie", sessionCookie+"="+token)
	responseDone := make(chan *http.Response, 1)
	errorDone := make(chan error, 1)
	go func() {
		response, err := public.Client().Do(request)
		if err != nil {
			errorDone <- err
			return
		}
		responseDone <- response
	}()
	if _, err := writer.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readFirst:
	case err := <-errorDone:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("Portal waited for the complete upload before sending bytes upstream")
	}
	const remainder = int64(4 << 20)
	if _, err := io.CopyN(writer, zeroReader{}, remainder); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-responseDone:
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("upload status=%d", response.StatusCode)
		}
	case err := <-errorDone:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("large upload did not complete")
	}
	received := <-receivedDone
	if received != 16+remainder {
		t.Fatalf("upstream received %d bytes, want %d", received, 16+remainder)
	}
}

func TestWebSocketUpgradeUsesSessionSIDAndInternalCookie(t *testing.T) {
	upstreamSeen := make(chan error, 1)
	releaseUpstream := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "aionui-session=internal-A; aionui-csrf-token=csrf-A" || r.Header.Get("Origin") != "http://127.0.0.1:34123" {
			upstreamSeen <- fmt.Errorf("wrong websocket credentials cookie=%q origin=%q", r.Header.Get("Cookie"), r.Header.Get("Origin"))
			return
		}
		upstreamSeen <- nil
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		key := r.Header.Get("Sec-WebSocket-Key")
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		buffer.Write([]byte{0x81, 0x02, 'o', 'k'})
		buffer.Flush()
		<-releaseUpstream
	}))
	defer upstream.Close()
	defer func() {
		select {
		case releaseUpstream <- struct{}{}:
		default:
		}
	}()

	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	upstreamURL, _ := url.Parse(upstream.URL)
	port, _ := net.LookupPort("tcp", upstreamURL.Port())
	instances.route = testRoute(port)
	public := httptest.NewServer(server.Handler())
	defer public.Close()
	publicURL, _ := url.Parse(public.URL)
	connection, err := net.DialTimeout("tcp", publicURL.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	fmt.Fprintf(connection, "GET /ws?sid=%s&port=9 HTTP/1.1\r\nHost: portal.example.test\r\nOrigin: https://portal.example.test\r\nCookie: %s=%s; aionui-session=attacker\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", testSID2, sessionCookie, token)
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("websocket status=%q err=%v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	frame := make([]byte, 4)
	if _, err := io.ReadFull(reader, frame); err != nil || string(frame[2:]) != "ok" {
		t.Fatalf("websocket frame=%v err=%v", frame, err)
	}
	if err := <-upstreamSeen; err != nil {
		t.Fatal(err)
	}
	instances.mu.Lock()
	if instances.webSockets != 1 || len(instances.routeSIDs) != 1 || instances.routeSIDs[0] != testSID1 {
		instances.mu.Unlock()
		t.Fatalf("websocket was not held/routed by the session SID")
	}
	instances.mu.Unlock()
	releaseUpstream <- struct{}{}
	connection.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		instances.mu.Lock()
		webSockets := instances.webSockets
		instances.mu.Unlock()
		if webSockets == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("websocket request count was not released after disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testServer(t *testing.T) (*Server, *store.Store, *fakeInstances) {
	t.Helper()
	return testServerAtRoot(t, t.TempDir())
}

func testServerWithPublicURL(t *testing.T, publicURL string) (*Server, *store.Store, *fakeInstances) {
	t.Helper()
	return testServerWithPublicURLAndOrigins(t, publicURL, nil)
}

func testServerWithPublicURLAndOrigins(t *testing.T, publicURL string, origins []string) (*Server, *store.Store, *fakeInstances) {
	t.Helper()
	return testServerAtRootWithPublicURLAndOrigins(t, t.TempDir(), publicURL, origins)
}

func testServerAtRoot(t *testing.T, root string) (*Server, *store.Store, *fakeInstances) {
	t.Helper()
	return testServerAtRootWithPublicURL(t, root, "https://portal.example.test")
}

func testServerAtRootWithPublicURL(t *testing.T, root, publicURL string) (*Server, *store.Store, *fakeInstances) {
	t.Helper()
	return testServerAtRootWithPublicURLAndOrigins(t, root, publicURL, nil)
}

func testServerAtRootWithPublicURLAndOrigins(t *testing.T, root, publicURL string, origins []string) (*Server, *store.Store, *fakeInstances) {
	t.Helper()
	staticDir := filepath.Join(root, "static")
	if err := os.Mkdir(staticDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("real renderer placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "app.js"), []byte("real static asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(staticDir, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "assets", "index-AbCdEf12.js"), []byte("fingerprinted static asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := store.Open(filepath.Join(root, "portal.db"), filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { data.Close() })
	cfg := config.DefaultPortal()
	cfg.Mode = "test"
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.PublicBaseURL = publicURL
	cfg.BrowserOrigins = append([]string(nil), origins...)
	cfg.ChatForwardURL = ""
	cfg.ChatForwardSecretFile = ""
	cfg.ChatGPTProModels = nil
	cfg.LoginAccountFailures = 5
	cfg.LoginIPFailures = 20
	instances := &fakeInstances{route: instance.Route{Status: ipc.Status{WindowsSID: testSID1, Healthy: true, WebPort: 31001, AionCorePort: 32001,
		Version: "2.1.29", UserHostPID: 1234, StartedAtUnix: 1_700_000_000}, InstanceID: "2.1.29:1234:1700000000"}}
	usage := &fakeUsageService{summary: validUsageSummary()}
	server, err := New(cfg, data, instances, usage, staticDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server, data, instances
}

func loginRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/login", strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://portal.example.test")
	return request
}

func changePasswordRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/auth/password", strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://portal.example.test")
	return request
}

func createPortalSession(t *testing.T, data *store.Store) string {
	t.Helper()
	return createPortalSessionFor(t, data, "portal-alice", testSID1, `SERVER\test1`)
}

func createPortalSessionFor(t *testing.T, data *store.Store, username, sid, windowsUsername string) string {
	t.Helper()
	hash, err := auth.HashPassword([]byte("correct-employee-portal-password"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(context.Background(), username, hash, sid, windowsUsername, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := data.CreateSession(context.Background(), token, user, time.Hour, "192.0.2.10", "test-browser", time.Now()); err != nil {
		t.Fatal(err)
	}
	return token
}

func testRoute(port int) instance.Route {
	return instance.Route{Status: ipc.Status{WindowsSID: testSID1, Healthy: true, WebPort: port, AionCorePort: 34123},
		Auth: ipc.AuthMaterial{CookieHeader: "aionui-session=internal-A; aionui-csrf-token=csrf-A", CSRFToken: "csrf-A"}}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) { return len(buffer), nil }
