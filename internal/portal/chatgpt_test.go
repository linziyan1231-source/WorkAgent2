package portal

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aionuiportal/internal/chatgptproxy"
)

func TestChatGPTWebDelegatesPortalIdentityAndInjectsBridge(t *testing.T) {
	fixed := time.Now().UTC()
	secret := []byte("portal-chatgpt-test-secret-0123456789abcdef")
	var seen atomic.Bool
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertChatGPTDelegation(t, r, secret, "portal-alice")
		if r.Header.Get("Cookie") != "" {
			t.Fatalf("browser cookie leaked to ChatGPT forwarder: %q", r.Header.Get("Cookie"))
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("HTML forwarder did not request identity encoding: %q", r.Header.Get("Accept-Encoding"))
		}
		if r.Header.Get("Authorization") != "Bearer chatgpt-browser-token" {
			t.Fatalf("ChatGPT browser authorization was removed: %q", r.Header.Get("Authorization"))
		}
		seen.Store(true)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Set-Cookie", "llm_web_session=must-not-reach-browser")
		_, _ = fmt.Fprint(w, "<!doctype html><html><body>ChatGPT</body></html>")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, err := url.Parse(forwarder.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.chatgptTarget = target
	server.chatgptSecret = secret
	server.now = func() time.Time { return fixed }
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt", nil)
	request.Header.Set("Authorization", "Bearer chatgpt-browser-token")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK || !seen.Load() {
		t.Fatalf("ChatGPT entry failed: status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `<script src="/portal-chatgpt-bridge.js"></script>`) {
		t.Fatalf("Portal bridge was not injected: %s", response.Body.String())
	}
	if values := response.Header().Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("forwarder cookie reached the browser: %v", values)
	}
	if policy := response.Header().Get("Referrer-Policy"); policy != "same-origin" {
		t.Fatalf("ChatGPT entry suppressed same-origin routing context: %q", policy)
	}
}

func TestChatGPTMaintenanceRejectsAllProxyPathsWithoutForwarding(t *testing.T) {
	var calls atomic.Int32
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, "must not be reached")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	server.cfg.ChatGPTMaintenanceMode = true
	token := createPortalSession(t, data)

	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt", nil),
		httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt/cdn/assets/sprites-core.svg", nil),
		httptest.NewRequest(http.MethodPost, "https://portal.example.test/chatgpt/backend-api/f/conversation", strings.NewReader(`{}`)),
	}
	for _, request := range requests {
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if request.Method == http.MethodPost {
			request.Header.Set("Origin", "https://portal.example.test")
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), `"code":"CHATGPT_UPGRADING"`) ||
			!strings.Contains(response.Body.String(), `"message":"聊天模式正在升级中"`) {
			t.Fatalf("maintenance response mismatch for %s %s: status=%d body=%s", request.Method, request.URL.Path, response.Code, response.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("maintenance requests reached the forwarder: calls=%d", calls.Load())
	}
}

func TestChatGPTSharedSpriteKeepsImmutableBrowserCachePolicy(t *testing.T) {
	secret := []byte("portal-chatgpt-test-secret-0123456789abcdef")
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertChatGPTDelegation(t, r, secret, "portal-alice")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = fmt.Fprint(w, `<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	server.chatgptSecret = secret
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt/cdn/assets/sprites-core.svg", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK || strings.Contains(response.Header().Get("Cache-Control"), "no-store") ||
		!strings.Contains(response.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("shared sprite cache policy mismatch: status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
}

func TestChatGPTRootRequestUsesAllowedChatPageReferrer(t *testing.T) {
	secret := []byte("portal-chatgpt-test-secret-0123456789abcdef")
	var calls atomic.Int32
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assertChatGPTDelegation(t, r, secret, "portal-alice")
		_, _ = fmt.Fprint(w, "forwarded")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	server.chatgptSecret = secret
	server.origins["http://127.0.0.1:25808"] = struct{}{}
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:25808/backend-api/me", nil)
	request.Header.Set("Referer", "http://127.0.0.1:25808/chatgpt/g/project")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "forwarded" || calls.Load() != 1 {
		t.Fatalf("allowed ChatGPT root request was not forwarded: status=%d body=%q calls=%d", response.Code, response.Body.String(), calls.Load())
	}
	if policy := response.Header().Get("Referrer-Policy"); policy != "same-origin" {
		t.Fatalf("ChatGPT root response suppressed routing context: %q", policy)
	}
}

func TestChatGPTRootRequestRejectsUnlistedReferrer(t *testing.T) {
	var calls atomic.Int32
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, "must not be reached")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/backend-api/me", nil)
	request.Header.Set("Referer", "https://unlisted.example.test/chatgpt/g/project")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if calls.Load() != 0 || response.Body.String() == "must not be reached" {
		t.Fatalf("unlisted ChatGPT referrer reached forwarder: status=%d body=%q calls=%d", response.Code, response.Body.String(), calls.Load())
	}
}

func TestChatGPTProEventsAcceptsShimPrefixedPathWithoutForwarding(t *testing.T) {
	var calls atomic.Int32
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, "must not be reached")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt/api/portal/me/chatgpt/pro-events", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"success":true`) || calls.Load() != 0 {
		t.Fatalf("shim-prefixed Pro events path was not handled by Portal: status=%d body=%q calls=%d", response.Code, response.Body.String(), calls.Load())
	}
}

func TestChatGPTHomeEscapeReturnsToPortalWithoutForwarding(t *testing.T) {
	var calls atomic.Int32
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, "must not be reached")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt/portal-home", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusFound || response.Header().Get("Location") != "/#/chat" || calls.Load() != 0 {
		t.Fatalf("ChatGPT home escape mismatch: status=%d location=%q calls=%d", response.Code, response.Header().Get("Location"), calls.Load())
	}
}

func TestChatGPTProFallbackReturnsQuotaAndCreatesDegradationEvent(t *testing.T) {
	fixed := time.Now().UTC()
	secret := []byte("portal-chatgpt-test-secret-0123456789abcdef")
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertChatGPTDelegation(t, r, secret, "portal-alice")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"type\":\"server_ste_metadata\",\"model_slug\":\"gpt-5-3-mini\"}\n\ndata: {\"type\":\"message_stream_complete\"}\n\ndata: [DONE]\n\n")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	server.chatgptSecret = secret
	server.cfg.ChatGPTProModels = []string{"gpt-5-6-pro"}
	server.now = func() time.Time { return fixed }
	token := createPortalSession(t, data)
	request := chatGPTProRequest(token, "message-fallback", "parent-fallback")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fallback send failed: status=%d body=%s", response.Code, response.Body.String())
	}

	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	quota, err := data.ChatGPTProQuota(context.Background(), user.ID, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if quota.Confirmed != 0 || quota.Pending != 0 || quota.Limit != 7 {
		t.Fatalf("fallback consumed quota: %+v", quota)
	}
	events, err := data.PendingChatGPTProEvents(context.Background(), user.ID, 20)
	if err != nil || len(events) != 1 {
		t.Fatalf("fallback degradation event mismatch: events=%v err=%v", events, err)
	}
}

func TestChatGPTProWeeklyLimitRejectsEighthConfirmedSend(t *testing.T) {
	fixed := time.Now().UTC()
	secret := []byte("portal-chatgpt-test-secret-0123456789abcdef")
	var calls atomic.Int32
	forwarder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"type\":\"server_ste_metadata\",\"model_slug\":\"gpt-5-6-pro\"}\n\ndata: {\"type\":\"message_stream_complete\"}\n\ndata: [DONE]\n\n")
	}))
	defer forwarder.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(forwarder.URL)
	server.chatgptTarget = target
	server.chatgptSecret = secret
	server.cfg.ChatGPTProModels = []string{"gpt-5-6-pro"}
	server.now = func() time.Time { return fixed }
	token := createPortalSession(t, data)
	for index := 1; index <= 8; index++ {
		request := chatGPTProRequest(token, fmt.Sprintf("message-%d", index), fmt.Sprintf("parent-%d", index))
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		want := http.StatusOK
		if index == 8 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("send %d: status=%d want=%d body=%s", index, response.Code, want, response.Body.String())
		}
	}
	if calls.Load() != 7 {
		t.Fatalf("quota rejection reached upstream: calls=%d", calls.Load())
	}
}

func TestChatGPTBridgeContainsRequiredDegradationGuidance(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/portal-chatgpt-bridge.js", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	for _, required := range []string{
		"主界面",
		"workagent-platform-return-icon",
		"MutationObserver",
		"遇到模型降智，请在新的窗口重新发送相关文件和指令并",
		"【将思考程度（Intelligence）切换至“超高”（“Extra High”）】",
		"新的思考程度可能会造成内容生成质量下降",
		"目前处于降智状态，暂不可用，请使用5.6 balanced Extra high。",
		"data-workagent-pro-status-note",
		"syncProStatusNote",
		"findSelectedProButton",
		"button.getAttribute('aria-haspopup')",
		"href.endsWith('#ba3792')",
		"for (const note of notes) note.remove()",
		"/api/portal/me/notifications",
		"workagent-portal-notification-modal",
		"window.addEventListener('focus'",
	} {
		if !strings.Contains(response.Body.String(), required) {
			t.Fatalf("bridge omitted required guidance %q", required)
		}
	}
}

func chatGPTProRequest(token, messageID, parentID string) *http.Request {
	body := fmt.Sprintf(`{"action":"next","model":"gpt-5-6-pro","parent_message_id":%q,"messages":[{"id":%q,"author":{"role":"user"}}]}`, parentID, messageID)
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/chatgpt/backend-api/f/conversation", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://portal.example.test")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	return request
}

func assertChatGPTDelegation(t *testing.T, request *http.Request, secret []byte, wantUser string) {
	t.Helper()
	encoded := request.Header.Get(chatgptproxy.HeaderPortalUser)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || string(decoded) != wantUser {
		t.Fatalf("delegated user mismatch: encoded=%q decoded=%q err=%v", encoded, decoded, err)
	}
	timestamp, err := strconv.ParseInt(request.Header.Get(chatgptproxy.HeaderPortalTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("invalid delegation timestamp: %v", err)
	}
	expected := chatgptproxy.DelegationHeaders(secret, wantUser, request.Method, request.URL.RequestURI(), time.Unix(timestamp, 0))
	if request.Header.Get(chatgptproxy.HeaderPortalSignature) != expected[chatgptproxy.HeaderPortalSignature] {
		t.Fatal("invalid Portal delegation signature")
	}
}
