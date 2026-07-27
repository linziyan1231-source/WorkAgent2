package portal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const portalTestTenant = "11111111-1111-4111-8111-111111111111"

type portalFixture struct {
	server *Server
	store  *store.Store
	cfg    config.Portal
}

func newPortalFixture(t *testing.T) portalFixture {
	t.Helper()
	root := t.TempDir()
	cfg := config.Portal{
		SchemaVersion: config.PortalSchemaVersion,
		RuntimeUser:   "workagent",
		BrandFile:     filepath.Join(root, "brand.json"), PolicyFile: filepath.Join(root, "policy.json"),
		Listener:      config.Listener{Network: "tcp", Address: "127.0.0.1:42580", PublicOrigin: "https://portal.example.test", TrustedProxyCIDRs: []string{"127.0.0.1/32"}, RequireForwardedHTTPS: true},
		Session:       config.SessionPolicy{CookieName: "__Host-aionui-portal", Secure: true, HTTPOnly: true, SameSite: "strict", IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 43200},
		Paths:         config.PortalPaths{PortalState: filepath.Join(root, "state"), TenantConfigs: filepath.Join(root, "tenants"), TenantData: filepath.Join(root, "users"), RuntimeSockets: filepath.Join(root, "run"), ReleaseRoot: filepath.Join(root, "releases")},
		Runtime:       config.RuntimePolicy{MaxConcurrentInstances: 3, IdleReapSeconds: 900, RequireDedicatedUID: true, RequireReleaseHashes: true},
		Usage:         config.UsagePolicy{QueryTimeoutSeconds: 3, CacheTTLSeconds: 15},
		Observability: config.ObservabilityPolicy{AuditRetentionDays: 365, AuditMinimumEvents: 1000},
	}
	data, err := store.Open(cfg.DatabasePath(), cfg.AuditPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { data.Close() })
	brand := productconfig.Brand{SchemaVersion: 1, BrandID: "workagent", CompanyName: "WorkAgent", PlatformName: "WorkAgent2", PrimaryColor: "#EA3E00", Assets: productconfig.Assets{Logo: "logo.svg", LogoDark: "logo-dark.svg", Favicon: "favicon.svg", AppIcon: "app-icon.svg"}}
	policy := productconfig.Policy{SchemaVersion: 1, PolicyID: "workagent-deny-all-v1", DefaultAction: "deny", Models: []productconfig.Model{}, Aliases: map[string]string{}, Pricing: map[string]productconfig.Price{}, Quotas: map[string]productconfig.Quota{}, ApprovalRequired: true}
	server, err := New(cfg, data, brand, policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	server.now = func() time.Time { return now }
	server.ensureRuntime = func(context.Context, store.User) error { return nil }
	hash, err := auth.HashPassword([]byte("correct horse value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateUser(context.Background(), "alice", hash, portalTestTenant, "workagent_alice", filepath.Join(root, "users", portalTestTenant), true, now); err != nil {
		t.Fatal(err)
	}
	return portalFixture{server: server, store: data, cfg: cfg}
}

func secureRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:45678"
	request.TLS = &tls.ConnectionState{}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", "https://portal.example.test")
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("User-Agent", "portal-test-agent")
	return request
}

func TestLoginSessionAndCSRF(t *testing.T) {
	fixture := newPortalFixture(t)
	recorder := httptest.NewRecorder()
	request := secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value"}`)
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.CSRFToken == "" {
		t.Fatalf("missing CSRF token: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != "__Host-aionui-portal" || cookies[1].Name != "__Host-aionui-portal-csrf" ||
		!cookies[0].Secure || !cookies[0].HttpOnly || !cookies[1].Secure || cookies[1].HttpOnly {
		t.Fatalf("unexpected cookies: %+v", cookies)
	}
	logout := secureRequest(http.MethodPost, "https://portal.example.test/api/logout", "")
	for _, cookie := range cookies {
		logout.AddCookie(cookie)
	}
	rejected := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rejected, logout)
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF was accepted: %d", rejected.Code)
	}
	logout = secureRequest(http.MethodPost, "https://portal.example.test/api/logout", "")
	for _, cookie := range cookies {
		logout.AddCookie(cookie)
	}
	logout.Header.Set("X-CSRF-Token", body.CSRFToken)
	accepted := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(accepted, logout)
	if accepted.Code != http.StatusOK {
		t.Fatalf("valid logout failed: %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestCompatibilityLogoutIsIdempotentWithoutSession(t *testing.T) {
	fixture := newPortalFixture(t)
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodPost, "https://portal.example.test/logout", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("idempotent compatibility logout failed: %d %s", recorder.Code, recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
		t.Fatalf("compatibility logout did not expire Portal cookies: %#v", cookies)
	}
}

func TestProjectCompatibilityEndpointsRejectQueryParametersBeforeRuntimeDispatch(t *testing.T) {
	fixture := newPortalFixture(t)
	for _, test := range []struct {
		method string
		url    string
		body   string
	}{
		{method: http.MethodPost, url: "https://portal.example.test/api/portal/me/projects?unexpected=1", body: `{"name":"project-one"}`},
		{method: http.MethodPatch, url: "https://portal.example.test/api/portal/me/projects?unexpected=1", body: `{"path":"/tmp/project-one","name":"project-two","force":false}`},
	} {
		request := authenticatedPortalRequest(t, fixture, test.method, test.url)
		request.Body = io.NopCloser(strings.NewReader(test.body))
		request.ContentLength = int64(len(test.body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		fixture.server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_PROJECT_REQUEST") {
			t.Fatalf("project compatibility query was accepted: method=%s status=%d body=%s", test.method, recorder.Code, recorder.Body.String())
		}
	}
}

func TestLoginAcceptsAionUIRememberCompatibilityField(t *testing.T) {
	fixture := newPortalFixture(t)
	recorder := httptest.NewRecorder()
	request := secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value","remember":true}`)
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("AionUi remember field was rejected: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestLoginAndSessionFailuresUseWindowsCompatibleJSON(t *testing.T) {
	fixture := newPortalFixture(t)
	tests := []struct {
		name   string
		method string
		target string
		body   string
		status int
	}{
		{name: "malformed login", method: http.MethodPost, target: "https://portal.example.test/login", body: `{"username":`, status: http.StatusBadRequest},
		{name: "invalid credentials", method: http.MethodPost, target: "https://portal.example.test/login", body: `{"username":"alice","password":"wrong password value"}`, status: http.StatusUnauthorized},
		{name: "missing session", method: http.MethodGet, target: "https://portal.example.test/api/auth/user", status: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			fixture.server.Handler().ServeHTTP(recorder, secureRequest(test.method, test.target, test.body))
			var body struct {
				Success *bool `json:"success"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || recorder.Code != test.status || body.Success == nil || *body.Success {
				t.Fatalf("unexpected browser failure: status=%d body=%s err=%v", recorder.Code, recorder.Body.String(), err)
			}
		})
	}
}

func TestAdministratorMasterPasswordImpersonationIsOptionalAndAudited(t *testing.T) {
	fixture := newPortalFixture(t)
	masterPassword := []byte("administrator recovery password")
	masterHash, err := auth.HashPassword(masterPassword)
	if err != nil {
		t.Fatal(err)
	}
	fixture.server.adminMasterHash = masterHash
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"administrator recovery password"}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("administrator impersonation failed: %d %s", recorder.Code, recorder.Body.String())
	}
	audit, err := os.ReadFile(fixture.cfg.AuditPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"action":"portal.admin_impersonation"`) || !strings.Contains(string(audit), `"authentication":"admin_master_password"`) {
		t.Fatalf("administrator impersonation was not distinctly audited: %s", audit)
	}
	change := secureRequest(http.MethodPost, "https://portal.example.test/api/password/change", `{"username":"alice","current_password":"administrator recovery password","new_password":"a new secure password","confirm_password":"a new secure password"}`)
	changeRecorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(changeRecorder, change)
	if changeRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("administrator master password changed a tenant password: %d %s", changeRecorder.Code, changeRecorder.Body.String())
	}
}

func TestLoadAdministratorMasterPasswordHashRejectsUnsafeFile(t *testing.T) {
	password, err := auth.HashPassword([]byte("administrator recovery password"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "admin-master.hash")
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := loadAdminMasterPasswordHash(path); err != nil || loaded != password {
		t.Fatalf("protected master-password hash was rejected: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminMasterPasswordHash(path); err == nil {
		t.Fatal("group-readable master-password hash was accepted")
	}
}

func TestOriginAndForwardedHeaderForgeryAreRejected(t *testing.T) {
	fixture := newPortalFixture(t)
	badOrigin := secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value"}`)
	badOrigin.Header.Set("Origin", "https://attacker.example.test")
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, badOrigin)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("forged origin returned %d", recorder.Code)
	}
	forgedForward := secureRequest(http.MethodGet, "https://portal.example.test/healthz", "")
	forgedForward.Header.Set("X-Forwarded-For", "198.51.100.8")
	recorder = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, forgedForward)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("forwarding metadata from untrusted peer returned %d", recorder.Code)
	}
}

func TestMetricsArePrometheusFormattedAndDirectLoopbackOnly(t *testing.T) {
	fixture := newPortalFixture(t)
	direct := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/internal/metrics", nil)
	direct.RemoteAddr = "127.0.0.1:43100"
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, direct)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "workagent_portal_http_requests_total") {
		t.Fatalf("direct metrics request failed: %d %s", recorder.Code, recorder.Body.String())
	}
	proxied := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/internal/metrics", nil)
	proxied.RemoteAddr = "127.0.0.1:43101"
	proxied.Header.Set("X-Forwarded-Proto", "https")
	recorder = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, proxied)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("proxied metrics request returned %d", recorder.Code)
	}
}

func TestTrustedProxySelectsRightmostUntrustedClient(t *testing.T) {
	fixture := newPortalFixture(t)
	request := httptest.NewRequest(http.MethodGet, "http://portal.internal/healthz", nil)
	request.RemoteAddr = "127.0.0.1:34567"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-For", "198.51.100.9, 127.0.0.1")
	client, trusted, err := fixture.server.clientIP(request)
	if err != nil || !trusted || client != "198.51.100.9" {
		t.Fatalf("unexpected client selection: %s %v %v", client, trusted, err)
	}
}

func TestRootServesWorkAgentAILoginPageWithoutRedirect(t *testing.T) {
	fixture := newPortalFixture(t)
	request := secureRequest(http.MethodGet, "https://portal.example.test/", "")
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "WorkAgent2") || strings.Contains(recorder.Body.String(), "WorkAgent2") {
		t.Fatalf("unexpected login page: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("Permissions-Policy"), "microphone=(self)") {
		t.Fatalf("AionUi microphone permission is disabled: %q", recorder.Header().Get("Permissions-Policy"))
	}
	appRecorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(appRecorder, secureRequest(http.MethodGet, "https://portal.example.test/app.js", ""))
	if appRecorder.Code != http.StatusOK || !strings.Contains(appRecorder.Body.String(), "__Host-aionui-portal-csrf=") || strings.Contains(appRecorder.Body.String(), "__Host-workagent_csrf=") {
		t.Fatalf("unexpected Portal application branding/cookie contract: status=%d body=%q", appRecorder.Code, appRecorder.Body.String())
	}
}

func TestWebSocketUpgradeRequiresExactOrigin(t *testing.T) {
	fixture := newPortalFixture(t)
	request := secureRequest(http.MethodGet, "https://portal.example.test/runtime/ws", "")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Origin", "https://attacker.example.test")
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("forged WebSocket origin returned %d", recorder.Code)
	}
}

func TestSuccessfulLoginFailsClosedWhenAuditLogCannotBeWritten(t *testing.T) {
	fixture := newPortalFixture(t)
	if err := os.Remove(fixture.cfg.AuditPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture.cfg.AuditPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value"}`))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure did not fail closed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	userValue, err := fixture.store.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	count, err := fixture.store.SessionCountForUser(context.Background(), userValue.ID, fixture.server.now())
	if err != nil || count != 0 {
		t.Fatalf("session survived failed audit: count=%d err=%v", count, err)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge > 0 {
			t.Fatalf("active cookie returned after audit failure: %#v", cookie)
		}
	}
}

func TestReadinessReportsEveryRequiredDependency(t *testing.T) {
	fixture := newPortalFixture(t)
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodGet, "https://portal.example.test/readyz", ""))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("deny-all staging reported ready: %d %s", recorder.Code, recorder.Body.String())
	}
	var report struct {
		Ready      bool `json:"ready"`
		Components map[string]struct {
			Ready bool `json:"ready"`
		} `json:"components"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"database", "audit", "brand", "policy", "host", "tenants", "cli_proxy"} {
		if _, ok := report.Components[name]; !ok {
			t.Fatalf("readiness omitted %s: %#v", name, report.Components)
		}
	}
	if report.Ready {
		t.Fatal("not-ready report had ready=true")
	}
}

func TestLoginInvalidatesPreviousBrowserSession(t *testing.T) {
	fixture := newPortalFixture(t)
	userValue, err := fixture.store.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CreateSession(context.Background(), "old-session", "old-csrf", userValue, "192.0.2.10", "portal-test-agent", fixture.server.now(), fixture.server.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value"}`)
	request.AddCookie(&http.Cookie{Name: fixture.cfg.Session.CookieName, Value: "old-session"})
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := fixture.store.SessionByToken(context.Background(), "old-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old session remains valid: %v", err)
	}
}

func TestLoginDoesNotCreateSessionWhenDisabledDuringRuntimeStart(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.server.ensureRuntime = func(ctx context.Context, value store.User) error {
		return fixture.store.SetUserEnabled(ctx, value.Username, false, fixture.server.now())
	}
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value"}`))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("login status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	userValue, err := fixture.store.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	count, err := fixture.store.SessionCountForUser(context.Background(), userValue.ID, fixture.server.now())
	if err != nil || count != 0 {
		t.Fatalf("disabled-during-startup session count=%d err=%v", count, err)
	}
}

func TestPasswordChangeRevokesSessionsAndChangesCredential(t *testing.T) {
	fixture := newPortalFixture(t)
	userValue, err := fixture.store.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CreateSession(context.Background(), "existing-session", "existing-csrf", userValue, "192.0.2.10", "portal-test-agent", fixture.server.now(), fixture.server.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	change := secureRequest(http.MethodPost, "https://portal.example.test/api/password/change", `{"username":"alice","current_password":"correct horse value","new_password":"a different secure value","confirm_password":"a different secure value"}`)
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, change)
	if recorder.Code != http.StatusOK {
		t.Fatalf("password change failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := fixture.store.SessionByToken(context.Background(), "existing-session"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("password change did not revoke session: %v", err)
	}
	oldLogin := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(oldLogin, secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"correct horse value"}`))
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password status=%d", oldLogin.Code)
	}
	newLogin := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(newLogin, secureRequest(http.MethodPost, "https://portal.example.test/api/login", `{"username":"alice","password":"a different secure value"}`))
	if newLogin.Code != http.StatusOK {
		t.Fatalf("new password login failed: %d %s", newLogin.Code, newLogin.Body.String())
	}
}

func TestRuntimeMultipartIsNotRejectedByPortalContentTypeGate(t *testing.T) {
	fixture := newPortalFixture(t)
	request := secureRequest(http.MethodPost, "https://portal.example.test/runtime/upload", "fixture")
	request.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("runtime upload was rejected before authentication: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestRuntimeCompatibilityPrefixCannotReachInternalAuthentication(t *testing.T) {
	fixture := newPortalFixture(t)
	starts := 0
	fixture.server.ensureRuntime = func(context.Context, store.User) error {
		starts++
		return nil
	}

	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/runtime/logout"},
		{method: http.MethodGet, path: "/runtime/api/auth/status"},
		{method: http.MethodPost, path: "/runtime/api/webui/reset-password"},
		{method: http.MethodGet, path: "/api/auth/status"},
	} {
		request := authenticatedPortalRequest(t, fixture, test.method, "https://portal.example.test"+test.path)
		if test.method != http.MethodGet && test.method != http.MethodHead {
			request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "test-csrf-token"})
			request.Header.Set("X-CSRF-Token", "test-csrf-token")
		}
		recorder := httptest.NewRecorder()
		fixture.server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "Internal runtime authentication") {
			t.Fatalf("internal runtime auth path %s returned %d %s", test.path, recorder.Code, recorder.Body.String())
		}
	}
	if starts != 0 {
		t.Fatalf("blocked internal authentication requests started %d tenant runtimes", starts)
	}
}

func TestRootAionUiMultipartIsNotRejectedByPortalContentTypeGate(t *testing.T) {
	fixture := newPortalFixture(t)
	request := secureRequest(http.MethodPost, "https://portal.example.test/api/files/upload", "fixture")
	request.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("AionUi upload was rejected before authentication: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAionUiStreamingBodyPassesSecurityBeforeEOF(t *testing.T) {
	fixture := newPortalFixture(t)
	reader, writer := io.Pipe()
	seen := make(chan string, 1)
	handler := fixture.server.security(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		prefix := make([]byte, 16)
		_, err := io.ReadFull(request.Body, prefix)
		if err != nil {
			seen <- "error: " + err.Error()
			return
		}
		seen <- string(prefix)
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/api/stt/stream", reader)
	request.RemoteAddr = "192.0.2.10:45678"
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Origin", "https://portal.example.test")
	request.Header.Set("Content-Type", "application/octet-stream")
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(done)
	}()
	if _, err := writer.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-seen:
		if got != "0123456789abcdef" {
			t.Fatalf("stream prefix=%q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("security middleware waited for the complete streaming body")
	}
	_ = writer.Close()
	<-done
}

func TestUnauthenticatedClientSettingsReturnChineseWithoutRuntimeStart(t *testing.T) {
	fixture := newPortalFixture(t)
	starts := 0
	fixture.server.ensureRuntime = func(context.Context, store.User) error {
		starts++
		return nil
	}
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodGet, "https://portal.example.test/api/settings/client", ""))
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"language":"zh-CN"}` {
		t.Fatalf("settings response=%d %q", recorder.Code, recorder.Body.String())
	}
	if starts != 0 {
		t.Fatalf("unauthenticated language bootstrap started %d runtimes", starts)
	}
}

func TestExactAPIRootDoesNotRedirect(t *testing.T) {
	fixture := newPortalFixture(t)
	recorder := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(recorder, secureRequest(http.MethodGet, "https://portal.example.test/api", ""))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("exact /api returned %d, want authentication failure without redirect", recorder.Code)
	}
}

func TestRuntimeGateCountsLiveRequestsAndReleasesCapacity(t *testing.T) {
	gate := runtimeGate{active: make(map[string]int)}
	finishA, ok := gate.begin("tenant-a", 1)
	if !ok {
		t.Fatal("first tenant was rejected")
	}
	finishA2, ok := gate.begin("tenant-a", 1)
	if !ok {
		t.Fatal("second request for the active tenant was rejected")
	}
	if _, ok := gate.begin("tenant-b", 1); ok {
		t.Fatal("second live tenant exceeded capacity")
	}
	finishA()
	if _, ok := gate.begin("tenant-b", 1); ok {
		t.Fatal("capacity was released before all tenant requests ended")
	}
	finishA2()
	finishB, ok := gate.begin("tenant-b", 1)
	if !ok {
		t.Fatal("capacity was not released after the final request")
	}
	finishB()
}
