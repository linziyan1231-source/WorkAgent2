package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseNotificationPayloadAcceptsCompatibleShapesAndStableIDs(t *testing.T) {
	tests := []struct {
		name, body, contentType, wantTitle, wantMessage, wantID string
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

func TestNotificationSourceAuthenticatesRetriesAndCaches(t *testing.T) {
	const token = "notification-source-token-0123456789"
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/notification" || request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("Cookie") != "" {
			t.Fatalf("unexpected notification request: %s %s auth=%q", request.Method, request.URL.RequestURI(), request.Header.Get("Authorization"))
		}
		if call == 1 {
			http.Error(writer, "private upstream detail", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"notifications":[{"id":"n-1","message":"hello"}]}`))
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL + "/notification")
	source := &notificationSource{target: target, token: []byte(token), client: upstream.Client(), now: time.Now}
	first, err := source.Fetch(context.Background())
	if err != nil || len(first) != 1 || first[0].ID != "n-1" {
		t.Fatalf("notification fetch failed: items=%+v err=%v", first, err)
	}
	second, err := source.Fetch(context.Background())
	if err != nil || len(second) != 1 || calls.Load() != 2 {
		t.Fatalf("notification cache failed: calls=%d items=%+v err=%v", calls.Load(), second, err)
	}
}

func TestNotificationEndpointIsSessionBoundAndRedactsFailures(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "upstream-secret", http.StatusBadRequest)
	}))
	defer upstream.Close()
	fixture := newPortalFixture(t)
	target, _ := url.Parse(upstream.URL)
	fixture.server.notifications = &notificationSource{target: target, token: []byte("notification-source-token-0123456789"), client: upstream.Client(), now: time.Now}

	unauthorized := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(unauthorized, secureRequest(http.MethodGet, "https://portal.example.test/api/portal/me/notifications", ""))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated notification status=%d", unauthorized.Code)
	}
	request := authenticatedPortalRequest(t, fixture, http.MethodGet, "https://portal.example.test/api/portal/me/notifications")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "upstream-secret") {
		t.Fatalf("notification failure leaked details: status=%d body=%s", response.Code, response.Body.String())
	}
}
