package portal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChatForwardProxyAuthenticatesUserAndRewritesPrefix(t *testing.T) {
	secret := []byte("portal-chatforward-test-secret-0123456789abcdef")
	var upstreamRequest *http.Request
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequest = r.Clone(r.Context())
		_, _ = fmt.Fprint(w, "mirror asset")
	}))
	defer bridge.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(bridge.URL)
	server.chatForwardTarget = target
	server.chatForwardSecret = secret
	now := time.Now()
	server.now = func() time.Time { return now }
	token := createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt/mirror.js?build=1", nil)
	request.Header.Set("Authorization", "Bearer browser-secret")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "mirror asset" {
		t.Fatalf("ChatForward asset response mismatch: status=%d body=%q", response.Code, response.Body.String())
	}
	if upstreamRequest == nil || upstreamRequest.URL.RequestURI() != "/mirror.js?build=1" {
		t.Fatalf("ChatForward path was not stripped: %#v", upstreamRequest)
	}
	if upstreamRequest.Header.Get("Cookie") != "" || upstreamRequest.Header.Get("Authorization") != "" {
		t.Fatal("browser credentials leaked to ChatForward")
	}
	assertChatForwardDelegation(t, upstreamRequest, secret, user.ID)
}

func TestChatForwardProxyRejectsUnauthenticatedBrowser(t *testing.T) {
	var calls atomic.Int32
	bridge := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer bridge.Close()
	server, _, _ := testServer(t)
	server.chatForwardTarget, _ = url.Parse(bridge.URL)
	server.chatForwardSecret = []byte("portal-chatforward-test-secret-0123456789abcdef")

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt/", nil))
	if response.Code != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("unauthenticated request status=%d upstream_calls=%d", response.Code, calls.Load())
	}
}

func TestChatForwardRootRedirectsToStablePrefix(t *testing.T) {
	server, data, _ := testServer(t)
	server.chatForwardTarget, _ = url.Parse("http://127.0.0.1:3210")
	server.chatForwardSecret = []byte("portal-chatforward-test-secret-0123456789abcdef")
	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/chatgpt", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "/chatgpt/" {
		t.Fatalf("canonical redirect status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestChatForwardQuotaRejectsUnsignedAndRemoteRequests(t *testing.T) {
	server, _, _ := testServer(t)
	server.chatForwardSecret = []byte("portal-chatforward-test-secret-0123456789abcdef")
	for name, remote := range map[string]string{"unsigned loopback": "127.0.0.1:3210", "signed remote": "192.0.2.20:3210"} {
		t.Run(name, func(t *testing.T) {
			request := signedChatForwardRequest(t, server.chatForwardSecret, time.Now(), "/internal/chatforward/quota/reserve", map[string]any{"user_id": 1, "request_body": `{}`})
			request.RemoteAddr = remote
			if name == "unsigned loopback" {
				request.Header.Del(headerChatForwardSignature)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestChatForwardHMACContractMatchesNodeRuntimeVector(t *testing.T) {
	secret := []byte("chatforward-test-secret-0123456789-abcdef")
	now := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	headers := chatForwardDelegationHeaders(secret, 42, http.MethodGet, "/ws?role=mirror&clientId=client-123", now)
	if headers[headerChatForwardTimestamp] != "1784635200" || headers[headerChatForwardSignature] != "XoRBB8FCtBSCrD0MLO-LW3-rsKbuSGEA7VX18xy6S-U" {
		t.Fatalf("delegation vector mismatch: %#v", headers)
	}

	server, _, _ := testServer(t)
	server.chatForwardSecret = secret
	server.now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test/internal/chatforward/quota/reserve", strings.NewReader(`{"user_id":42}`))
	request.RemoteAddr = "127.0.0.1:3210"
	request.Header.Set(headerChatForwardTimestamp, "1784635200")
	request.Header.Set(headerChatForwardSignature, "eHx8Y6Cc9wJYOdaRqBsyRlbkI_qBbQCCnxtXHCUBmt0")
	body, ok := server.authenticateChatForwardRequest(httptest.NewRecorder(), request, 1024)
	if !ok || string(body) != `{"user_id":42}` {
		t.Fatalf("quota request vector was rejected: ok=%v body=%q", ok, body)
	}
}

func TestChatForwardQuotaConfirmsProAndBlocksNextSendAtLimit(t *testing.T) {
	fixed := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	secret := []byte("portal-chatforward-test-secret-0123456789abcdef")
	server, data, _ := testServer(t)
	server.chatForwardSecret = secret
	server.cfg.ChatGPTProModels = []string{"gpt-5-6-pro"}
	server.now = func() time.Time { return fixed }
	_ = createPortalSession(t, data)
	user, err := data.UserByUsername(context.Background(), "portal-alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.SetChatGPTProWeeklyLimit(context.Background(), user.ID, 1, fixed); err != nil {
		t.Fatal(err)
	}

	first := reserveChatForwardPro(t, server, secret, fixed, user.ID, "message-1", "parent-1")
	if !first.Allowed || !first.Pro || first.LogicalID == "" {
		t.Fatalf("first reservation was not allowed: %+v", first)
	}
	stream := "data: {\"type\":\"server_ste_metadata\",\"model_slug\":\"gpt-5-6-pro\"}\n\ndata: {\"type\":\"message_stream_complete\"}\n\ndata: [DONE]\n\n"
	settle := signedChatForwardRequest(t, secret, fixed, "/internal/chatforward/quota/settle", map[string]any{
		"user_id": user.ID, "logical_id": first.LogicalID, "requested_model": first.RequestedModel,
		"upstream_status": http.StatusOK, "response_body": stream,
	})
	settleResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(settleResponse, settle)
	if settleResponse.Code != http.StatusOK {
		t.Fatalf("settlement status=%d body=%s", settleResponse.Code, settleResponse.Body.String())
	}

	second := reserveChatForwardPro(t, server, secret, fixed, user.ID, "message-2", "parent-2")
	if second.Allowed || second.Code != "chatgpt_pro_quota_exceeded" || second.Used != 1 || second.Limit != 1 {
		t.Fatalf("second reservation was not blocked at the limit: %+v", second)
	}
}

func TestChatForwardFallbackRefundsReservationAndCreatesEvent(t *testing.T) {
	fixed := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	secret := []byte("portal-chatforward-test-secret-0123456789abcdef")
	server, data, _ := testServer(t)
	server.chatForwardSecret = secret
	server.cfg.ChatGPTProModels = []string{"gpt-5-6-pro"}
	server.now = func() time.Time { return fixed }
	_ = createPortalSession(t, data)
	user, _ := data.UserByUsername(context.Background(), "portal-alice")
	reservation := reserveChatForwardPro(t, server, secret, fixed, user.ID, "message-fallback", "parent-fallback")
	stream := "data: {\"type\":\"server_ste_metadata\",\"model_slug\":\"gpt-5-3-mini\"}\n\ndata: {\"type\":\"message_stream_complete\"}\n\ndata: [DONE]\n\n"
	request := signedChatForwardRequest(t, secret, fixed, "/internal/chatforward/quota/settle", map[string]any{
		"user_id": user.ID, "logical_id": reservation.LogicalID, "requested_model": reservation.RequestedModel,
		"upstream_status": http.StatusOK, "response_body": stream,
	})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	quota, err := data.ChatGPTProQuota(context.Background(), user.ID, fixed)
	if err != nil {
		t.Fatal(err)
	}
	events, err := data.PendingChatGPTProEvents(context.Background(), user.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || quota.Confirmed != 0 || quota.Pending != 0 || len(events) != 1 {
		t.Fatalf("fallback result status=%d quota=%+v events=%v", response.Code, quota, events)
	}
}

type quotaReservationResponse struct {
	Allowed        bool   `json:"allowed"`
	Pro            bool   `json:"pro"`
	LogicalID      string `json:"logical_id"`
	RequestedModel string `json:"requested_model"`
	Code           string `json:"code"`
	Used           int    `json:"used"`
	Limit          int    `json:"limit"`
}

func reserveChatForwardPro(t *testing.T, server *Server, secret []byte, now time.Time, userID int64, messageID, parentID string) quotaReservationResponse {
	t.Helper()
	conversation := fmt.Sprintf(`{"action":"next","model":"gpt-5-6-pro","parent_message_id":%q,"messages":[{"id":%q,"author":{"role":"user"}}]}`, parentID, messageID)
	request := signedChatForwardRequest(t, secret, now, "/internal/chatforward/quota/reserve", map[string]any{"user_id": userID, "request_body": conversation})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("reservation status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded quotaReservationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
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
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.test"+path, strings.NewReader(string(body)))
	request.RemoteAddr = "127.0.0.1:3210"
	request.Header.Set(headerChatForwardTimestamp, timestamp)
	request.Header.Set(headerChatForwardSignature, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func assertChatForwardDelegation(t *testing.T, request *http.Request, secret []byte, userID int64) {
	t.Helper()
	timestamp, err := strconv.ParseInt(request.Header.Get(headerChatForwardTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("invalid delegation timestamp: %v", err)
	}
	expected := chatForwardDelegationHeaders(secret, userID, request.Method, request.URL.RequestURI(), time.Unix(timestamp, 0))
	if request.Header.Get(headerChatForwardUserID) != strconv.FormatInt(userID, 10) ||
		request.Header.Get(headerChatForwardSignature) != expected[headerChatForwardSignature] {
		t.Fatal("ChatForward delegation signature mismatch")
	}
}
