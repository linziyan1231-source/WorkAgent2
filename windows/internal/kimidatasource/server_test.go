package kimidatasource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aionuiportal/internal/store"
)

func TestBrokerFiltersSourcesAndEnforcesQuotaBeforeUpstream(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "portal.db")
	auditPath := filepath.Join(root, "audit.jsonl")
	policyStore, err := store.Open(databasePath, auditPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	user, err := policyStore.CreateUser(context.Background(), "broker-user", "hash", "S-1-5-21-1-1201", `SERVER\broker-user`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := policyStore.SetKimiDatasourceGrant(context.Background(), user.ID, true, []string{"arxiv"}, 1, 10, "broker-token", now); err != nil {
		t.Fatal(err)
	}
	if err := policyStore.Close(); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(root, "kimi-code.json")
	if err := os.WriteFile(credentialPath, []byte(`{"access_token":"upstream-token","refresh_token":"refresh-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer upstream-token" {
			t.Fatalf("unexpected upstream authorization")
		}
		w.Header().Set("X-Request-Id", "request-123")
		_ = json.NewEncoder(w).Encode(map[string]string{"text": "arxiv result"})
	}))
	defer upstream.Close()
	server, err := NewServer(Config{ListenAddress: "127.0.0.1:3211", DatabasePath: databasePath, AuditLogPath: auditPath,
		CredentialPath: credentialPath, LogPath: filepath.Join(root, "broker.log"), OAuthHost: "https://auth.kimi.com", APIURL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.client = upstream.Client()

	list := brokerRequest(t, server.Handler(), "broker-token", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"enum":["arxiv"]`) || strings.Contains(list.Body.String(), "scholar") {
		t.Fatalf("filtered tools/list status=%d body=%s", list.Code, list.Body.String())
	}
	denied := brokerRequest(t, server.Handler(), "broker-token", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_data_source_desc","arguments":{"name":"scholar"}}}`)
	if !strings.Contains(denied.Body.String(), "KIMI_DATASOURCE_SOURCE_NOT_ALLOWED") || calls.Load() != 0 {
		t.Fatalf("denied source reached upstream: body=%s calls=%d", denied.Body.String(), calls.Load())
	}
	success := brokerRequest(t, server.Handler(), "broker-token", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_data_source_desc","arguments":{"name":"arxiv"}}}`)
	if !strings.Contains(success.Body.String(), "arxiv result") || !strings.Contains(success.Body.String(), "request-123") || calls.Load() != 1 {
		t.Fatalf("successful call body=%s calls=%d", success.Body.String(), calls.Load())
	}
	exhausted := brokerRequest(t, server.Handler(), "broker-token", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_data_source_desc","arguments":{"name":"arxiv"}}}`)
	if !strings.Contains(exhausted.Body.String(), "KIMI_DATASOURCE_DAILY_QUOTA_EXCEEDED") || calls.Load() != 1 {
		t.Fatalf("exhausted call reached upstream: body=%s calls=%d", exhausted.Body.String(), calls.Load())
	}
	unauthorized := brokerRequest(t, server.Handler(), "wrong-token", `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status=%d", unauthorized.Code)
	}
}

func TestCredentialExpiryAcceptsKimiFormats(t *testing.T) {
	threshold := time.Unix(1_783_968_000, 0)
	tests := []struct {
		name string
		raw  string
		soon bool
	}{
		{name: "fractional unix seconds", raw: `1783968468.6851072`, soon: false},
		{name: "unix milliseconds", raw: `1783968468685`, soon: false},
		{name: "quoted unix seconds", raw: `"1783968468.6851072"`, soon: false},
		{name: "RFC3339", raw: `"2026-07-13T18:47:48Z"`, soon: false},
		{name: "expired", raw: `1783967000`, soon: true},
		{name: "malformed refreshes safely", raw: `"not-a-time"`, soon: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := credentialDocument{ExpiresAt: json.RawMessage(test.raw)}
			if got := credentialExpiresSoon(document, threshold); got != test.soon {
				t.Fatalf("credentialExpiresSoon()=%t, want %t", got, test.soon)
			}
		})
	}
}

func brokerRequest(t *testing.T, handler http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:3211/mcp", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
