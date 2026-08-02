package portal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestChatForwardProxyAuthenticatesUserAndStripsBrowserCredentials(t *testing.T) {
	secret := []byte("portal-chatforward-test-secret-0123456789abcdef")
	var gotPath, gotAuthorization, gotCookie, gotAPIKey, gotWindows, gotPortal, gotUser, gotSignature string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotPath, gotAuthorization, gotCookie = request.URL.RequestURI(), request.Header.Get("Authorization"), request.Header.Get("Cookie")
		gotAPIKey, gotWindows = request.Header.Get("X-API-Key"), request.Header.Get("X-Windows-SID")
		gotPortal = request.Header.Get("X-AionUi-Portal-Admin")
		gotUser, gotSignature = request.Header.Get(headerChatForwardUserID), request.Header.Get(headerChatForwardSignature)
		_, _ = writer.Write([]byte("mirror asset"))
	}))
	defer upstream.Close()
	fixture := newPortalFixture(t)
	target, _ := url.Parse(upstream.URL)
	fixture.server.chatForward = &chatForwardBridge{target: target, secret: secret, transport: upstream.Client().Transport.(*http.Transport)}
	request := authenticatedPortalRequest(t, fixture, http.MethodGet, "https://portal.example.test/chatgpt/mirror.js?build=1")
	request.Header.Set("Authorization", "Bearer browser-secret")
	request.Header.Add("Cookie", "foreign=secret")
	request.Header.Set("X-API-Key", "browser-key")
	request.Header.Set("X-Windows-SID", "forged")
	request.Header.Set("X-AionUi-Portal-Admin", "forged")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "mirror asset" || gotPath != "/mirror.js?build=1" || gotAuthorization != "" || gotCookie != "" || gotAPIKey != "" || gotWindows != "" || gotPortal != "" || gotUser == "" || gotSignature == "" {
		t.Fatalf("proxy mismatch status=%d path=%q auth=%q cookie=%q api_key=%q windows=%q portal=%q user=%q signature=%q", response.Code, gotPath, gotAuthorization, gotCookie, gotAPIKey, gotWindows, gotPortal, gotUser, gotSignature)
	}
}

func TestChatForwardCredentialStrippingRejectsAllBrowserIdentityNamespaces(t *testing.T) {
	header := http.Header{
		"Cookie":                  {"secret"},
		"Authorization":           {"secret"},
		"X-Api-Key":               {"secret"},
		"Forwarded":               {"for=203.0.113.7"},
		"X-Forwarded-For":         {"203.0.113.7"},
		"X-Windows-Sid":           {"forged"},
		"X-Workagent-Tenant":            {"forged"},
		"X-Aionui-Portal-Admin":   {"forged"},
		"X-Chatforward-Signature": {"forged"},
		"Accept":                  {"application/json"},
	}
	stripBrowserCredentials(header)
	if len(header) != 1 || header.Get("Accept") != "application/json" {
		t.Fatalf("ChatForward credential stripping left unsafe headers: %#v", header)
	}
}

func TestPortalRuntimeReverseProxyDoesNotReintroduceBrowserIdentity(t *testing.T) {
	var received http.Header
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = request.Header.Clone()
		receivedPath = request.URL.RequestURI()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			rewritePortalRuntimeRequest(request, target, "api/events", "11111111-1111-4111-8111-111111111111")
		},
		Transport: upstream.Client().Transport,
	}
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/events?cursor=1", nil)
	request.RemoteAddr = "192.0.2.10:45678"
	request.Header.Set("Cookie", "portal=secret")
	request.Header.Set("Authorization", "Bearer browser-secret")
	request.Header.Set("Forwarded", "for=203.0.113.7")
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	request.Header.Set("X-WorkAgent-Control", "forged")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || receivedPath != "/api/events?cursor=1" {
		t.Fatalf("unexpected runtime proxy response: status=%d path=%q", recorder.Code, receivedPath)
	}
	if received.Get("Cookie") != "" || received.Get("Authorization") != "" || received.Get("Forwarded") != "" || received.Get("X-Forwarded-For") != "" || received.Get("X-WorkAgent-Control") != "" {
		t.Fatalf("browser identity reached UserHost: %#v", received)
	}
	if received.Get("X-WorkAgent-Tenant") != "11111111-1111-4111-8111-111111111111" || received.Get("X-WorkAgent-User-Request") != "1" {
		t.Fatalf("Portal runtime binding is missing: %#v", received)
	}
}

func TestChatForwardSignedQuotaRequestIsReplaySafe(t *testing.T) {
	secret := []byte("portal-chatforward-test-secret-0123456789abcdef")
	fixture := newPortalFixture(t)
	fixture.server.chatForward = &chatForwardBridge{secret: secret}
	fixture.server.cfg.ChatForward = configChatForwardForTest()
	userValue, err := fixture.store.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.server.now()
	payload := map[string]any{"user_id": userValue.ID, "request_body": `{"action":"next","conversation_id":"conversation-1","messages":[{"id":"message-1","author":{"role":"user"}}],"model":"gpt-5-6-pro"}`}
	request := signedChatForwardRequest(t, secret, now, "/internal/chatforward/quota/reserve", payload)
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"allowed":true`) {
		t.Fatalf("signed reservation failed: status=%d body=%s", response.Code, response.Body.String())
	}
	replay := signedChatForwardRequest(t, secret, now, "/internal/chatforward/quota/reserve", payload)
	replayed := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(replayed, replay)
	if replayed.Code != http.StatusForbidden {
		t.Fatalf("replayed reservation was accepted: status=%d body=%s", replayed.Code, replayed.Body.String())
	}
}

func TestChatForwardHMACContractMatchesWindowsVector(t *testing.T) {
	secret := []byte("chatforward-test-secret-0123456789-abcdef")
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	headers := chatForwardDelegationHeaders(secret, 42, http.MethodGet, "/ws?role=mirror&clientId=client-123", now)
	if headers[headerChatForwardTimestamp] != "1784635200" || headers[headerChatForwardSignature] != "XoRBB8FCtBSCrD0MLO-LW3-rsKbuSGEA7VX18xy6S-U" {
		t.Fatalf("delegation vector mismatch: %#v", headers)
	}
}

func configChatForwardForTest() config.ChatForwardService {
	return config.ChatForwardService{Enabled: true, Endpoint: "http://127.0.0.1:3210", CredentialFile: "/tmp/not-used", ProModels: []string{"gpt-5-6-pro"}, WeeklyProLimit: 1,
		MaxPairs: 3, ExtensionProtocol: "quota-v1", QuotaProtection: true, SourceAssetProxy: true}
}

func TestChatForwardReadinessRequiresCurrentCapacityQuotaAndAssetCapabilities(t *testing.T) {
	body := `{"ok":true,"controllerOnline":true,"sourceOnline":false,"mirrorCount":1,"activePairs":1,"connectedPairs":0,"maxPairs":3,"quotaProtection":true,"extensionProtocol":"quota-v1","quotaChecks":4,"sourceAssetProxy":true,"sourceAssetRequests":3,"sourceAssetCacheHits":2,"sourceAssetCacheEntries":1,"sourceAssetCacheBytes":1024}`
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected health request: %s accept=%q", request.URL.RequestURI(), request.Header.Get("Accept"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(body))
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	service := configChatForwardForTest()
	server := &Server{chatForward: &chatForwardBridge{target: target, secret: []byte("chatforward-test-secret-0123456789"), transport: upstream.Client().Transport.(*http.Transport), expected: service}}
	if err := server.checkChatForward(context.Background()); err != nil {
		t.Fatalf("current ChatForward health rejected: %v", err)
	}
	body = `{"ok":true,"controllerOnline":false,"sourceOnline":false,"mirrorCount":0,"activePairs":0,"connectedPairs":0,"maxPairs":3,"quotaProtection":true,"extensionProtocol":"quota-v1","quotaChecks":0,"sourceAssetProxy":true,"sourceAssetRequests":0,"sourceAssetCacheHits":0,"sourceAssetCacheEntries":0,"sourceAssetCacheBytes":0}`
	if err := server.checkChatForward(context.Background()); err == nil {
		t.Fatal("ChatForward health without its Chromium controller was accepted")
	}
	body = `{"ok":true,"controllerOnline":true,"sourceOnline":true,"mirrorCount":0,"activePairs":0,"connectedPairs":0,"maxPairs":3,"quotaProtection":true,"extensionProtocol":"quota-v1","quotaChecks":0,"sourceAssetProxy":true,"sourceAssetRequests":0,"sourceAssetCacheHits":0,"sourceAssetCacheEntries":0,"sourceAssetCacheBytes":0}`
	if err := server.checkChatForward(context.Background()); err == nil {
		t.Fatal("ChatForward health with inconsistent source state was accepted")
	}
	body = `{"ok":true,"mirrorCount":0,"activePairs":0,"maxPairs":3,"quotaProtection":true}`
	if err := server.checkChatForward(context.Background()); err == nil {
		t.Fatal("legacy ChatForward health without extension and asset capabilities was accepted")
	}
	body = `{"ok":true,"controllerOnline":true,"sourceOnline":false,"mirrorCount":4,"activePairs":4,"connectedPairs":0,"maxPairs":3,"quotaProtection":true,"extensionProtocol":"quota-v1","quotaChecks":0,"sourceAssetProxy":true,"sourceAssetRequests":0,"sourceAssetCacheHits":0,"sourceAssetCacheEntries":0,"sourceAssetCacheBytes":0}`
	if err := server.checkChatForward(context.Background()); err == nil {
		t.Fatal("ChatForward health above the three-pair cap was accepted")
	}
	body = `{"ok":true,"ok":true,"controllerOnline":true,"sourceOnline":false,"mirrorCount":0,"activePairs":0,"connectedPairs":0,"maxPairs":3,"quotaProtection":true,"extensionProtocol":"quota-v1","quotaChecks":0,"sourceAssetProxy":true,"sourceAssetRequests":0,"sourceAssetCacheHits":0,"sourceAssetCacheEntries":0,"sourceAssetCacheBytes":0}`
	if err := server.checkChatForward(context.Background()); err == nil {
		t.Fatal("ChatForward health with duplicate JSON keys was accepted")
	}
}

func signedChatForwardRequest(t *testing.T, secret []byte, now time.Time, path string, payload any) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{http.MethodPost, path, timestamp, hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, bytes.NewReader(body))
	request.RemoteAddr = "127.0.0.1:3210"
	request.Header.Set(headerChatForwardTimestamp, timestamp)
	request.Header.Set(headerChatForwardSignature, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}
