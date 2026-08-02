package portal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseNotificationPayloadAcceptsCompatibleShapesAndStableIDs(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		wantTitle   string
		wantMessage string
		wantID      string
	}{
		{name: "wrapped", body: `{"notifications":[{"id":"notice-1","title":"维护提醒","message":"今晚维护"}]}`, contentType: "application/json", wantTitle: "维护提醒", wantMessage: "今晚维护", wantID: "notice-1"},
		{name: "data array", body: `{"data":[{"subject":"提醒","content":"内容"}]}`, contentType: "application/json", wantTitle: "提醒", wantMessage: "内容"},
		{name: "plain text", body: "临时通知", contentType: "text/plain", wantMessage: "临时通知"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, err := parseNotificationPayload([]byte(test.body), test.contentType)
			if err != nil || len(first) != 1 {
				t.Fatalf("parse result=%#v err=%v", first, err)
			}
			second, err := parseNotificationPayload([]byte(test.body), test.contentType)
			if err != nil || len(second) != 1 || first[0].ID != second[0].ID {
				t.Fatalf("notification ID was not stable: first=%#v second=%#v err=%v", first, second, err)
			}
			if first[0].Title != test.wantTitle || first[0].Message != test.wantMessage || (test.wantID != "" && first[0].ID != test.wantID) {
				t.Fatalf("unexpected notification: %#v", first[0])
			}
		})
	}
}

func TestNotificationEndpointUsesFixedServerSource(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/notification" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected notification request: %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"notifications":[{"id":"n-1","message":"<img src=x onerror=alert(1)>"}]}`))
	}))
	defer upstream.Close()

	server, data, _ := testServer(t)
	target, _ := url.Parse(upstream.URL + "/notification")
	server.notificationTarget = target
	server.notificationClient = upstream.Client()
	token := createPortalSession(t, data)

	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/me/notifications", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"n-1"`) || !strings.Contains(response.Body.String(), `\u003cimg`) {
		t.Fatalf("notification response status=%d body=%s", response.Code, response.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected upstream call count: %d", calls.Load())
	}
}

func TestNotificationEndpointFailsClosedWithoutSessionOrHealthySource(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream-secret", http.StatusBadGateway)
	}))
	defer upstream.Close()
	server, data, _ := testServer(t)
	target, _ := url.Parse(upstream.URL + "/notification")
	server.notificationTarget = target
	server.notificationClient = upstream.Client()

	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/me/notifications", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated notification status=%d", unauthorized.Code)
	}

	token := createPortalSession(t, data)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/me/notifications", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "upstream-secret") {
		t.Fatalf("upstream failure leaked details: status=%d body=%s", response.Code, response.Body.String())
	}
}
