package userhost

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aionuiportal/internal/ipc"
)

func TestOAuthManagerCompletesPKCEAndUpsertsRealAionCoreSchema(t *testing.T) {
	dbPath := createOAuthDatabase(t, true)
	now := time.Unix(1_700_000_000, 0)
	state := oauthTestToken(1, 32)
	redirectURI := "http://134.175.110.121:25808/api/mcp/oauth/callback"
	var tokenCalls atomic.Int32
	var expectedChallenge string
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"authorization_endpoint":%q,"token_endpoint":%q,"issuer":%q}`, server.URL+"/authorize", server.URL+"/token", server.URL)
		case "/token":
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			verifier := r.Form.Get("code_verifier")
			hash := sha256.Sum256([]byte(verifier))
			if got := base64.RawURLEncoding.EncodeToString(hash[:]); got != expectedChallenge {
				t.Errorf("PKCE challenge mismatch: got %q want %q", got, expectedChallenge)
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "real-shaped-code" ||
				r.Form.Get("client_id") != "aionui" || r.Form.Get("redirect_uri") != redirectURI || len(verifier) != 43 {
				t.Errorf("wrong token exchange form: %#v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-for-user-one","refresh_token":"refresh-for-user-one","token_type":"Bearer","expires_in":3600,"scope":"mcp"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	seedDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seedDB.Exec(`UPDATE oauth_tokens SET server_url=? WHERE server_url='placeholder'`, server.URL); err != nil {
		seedDB.Close()
		t.Fatal(err)
	}
	seedDB.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	manager := newOAuthManager(dbPath, client, func() time.Time { return now }, true)
	result, err := manager.start(context.Background(), ipc.OAuthStartRequest{ServerURL: server.URL, State: state, RedirectURI: redirectURI})
	if err != nil {
		t.Fatal(err)
	}
	if !validOAuthToken(result.FlowID, 32) {
		t.Fatalf("invalid flow ID: %q", result.FlowID)
	}
	authorizationURL, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizationURL.Query()
	expectedChallenge = query.Get("code_challenge")
	if authorizationURL.Path != "/authorize" || query.Get("state") != state || query.Get("client_id") != "aionui" ||
		query.Get("redirect_uri") != redirectURI || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || expectedChallenge == "" {
		t.Fatalf("wrong authorization URL: %s", result.AuthorizationURL)
	}
	if err := manager.complete(context.Background(), ipc.OAuthCompleteRequest{FlowID: result.FlowID, ServerURL: server.URL, Code: "real-shaped-code"}); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token endpoint calls=%d, want 1", tokenCalls.Load())
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var access, refresh, tokenType string
	var expires, created, updated int64
	if err := db.QueryRow(`SELECT access_token,refresh_token,token_type,expires_at,created_at,updated_at FROM oauth_tokens WHERE server_url=?`, server.URL).
		Scan(&access, &refresh, &tokenType, &expires, &created, &updated); err != nil {
		t.Fatal(err)
	}
	if access != "access-for-user-one" || refresh != "refresh-for-user-one" || tokenType != "bearer" ||
		expires != now.Add(time.Hour).UnixMilli() || created != 111 || updated != now.UnixMilli() {
		t.Fatalf("wrong persisted token metadata: access=%q refresh=%q type=%q expires=%d created=%d updated=%d", access, refresh, tokenType, expires, created, updated)
	}
	if err := manager.complete(context.Background(), ipc.OAuthCompleteRequest{FlowID: result.FlowID, ServerURL: server.URL, Code: "replay-code"}); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("OAuth flow replay was accepted: %v", err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("replay reached token endpoint: calls=%d", tokenCalls.Load())
	}
}

func TestOAuthManagerExpiresAndCancelsFlowsBeforeTokenExchange(t *testing.T) {
	dbPath := createOAuthDatabase(t, false)
	now := time.Unix(1_700_000_000, 0)
	var tokenCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			fmt.Fprintf(w, `{"authorization_endpoint":%q,"token_endpoint":%q}`, server.URL+"/authorize", server.URL+"/token")
			return
		}
		if r.URL.Path == "/token" {
			tokenCalls.Add(1)
			_, _ = w.Write([]byte(`{"access_token":"unexpected","token_type":"Bearer"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	manager := newOAuthManager(dbPath, server.Client(), func() time.Time { return now }, true)
	start := func(seed byte) ipc.OAuthResult {
		result, err := manager.start(context.Background(), ipc.OAuthStartRequest{ServerURL: server.URL, State: oauthTestToken(seed, 32), RedirectURI: "https://portal.example.test/api/mcp/oauth/callback"})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	expired := start(2)
	now = now.Add(oauthFlowTTL)
	if err := manager.complete(context.Background(), ipc.OAuthCompleteRequest{FlowID: expired.FlowID, ServerURL: server.URL, Code: "expired-code"}); err == nil {
		t.Fatal("expired OAuth flow was accepted")
	}
	now = now.Add(time.Second)
	cancelled := start(3)
	if err := manager.cancel(ipc.OAuthCancelRequest{FlowID: cancelled.FlowID, ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if err := manager.complete(context.Background(), ipc.OAuthCompleteRequest{FlowID: cancelled.FlowID, ServerURL: server.URL, Code: "cancelled-code"}); err == nil {
		t.Fatal("cancelled OAuth flow was accepted")
	}
	if tokenCalls.Load() != 0 {
		t.Fatalf("expired/cancelled flow reached token endpoint %d times", tokenCalls.Load())
	}
}

func TestOAuthManagerRejectsPrivateServerAndUnknownDatabaseSchema(t *testing.T) {
	manager := newOAuthManager(filepath.Join(t.TempDir(), "missing.db"), nil, time.Now, false)
	_, err := manager.start(context.Background(), ipc.OAuthStartRequest{
		ServerURL: "https://127.0.0.1:9443", State: oauthTestToken(4, 32), RedirectURI: "https://portal.example.test/api/mcp/oauth/callback",
	})
	if err == nil || !strings.Contains(err.Error(), "public HTTPS") {
		t.Fatalf("private OAuth server URL was accepted: %v", err)
	}
	dbPath := createOAuthDatabase(t, false)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE oauth_tokens ADD COLUMN unexpected TEXT`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	expires := time.Now().Add(time.Hour).UnixMilli()
	if err := persistOAuthToken(context.Background(), dbPath, "https://mcp.example.test", "must-not-store", "", &expires, time.Now()); err == nil || !strings.Contains(err.Error(), "unsupported AionCore oauth_tokens schema") {
		t.Fatalf("unknown OAuth schema was accepted: %v", err)
	}
	db, _ = sql.Open("sqlite", dbPath)
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM oauth_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unknown schema was mutated: count=%d err=%v", count, err)
	}
}

func createOAuthDatabase(t *testing.T, existing bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aionui-backend.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE oauth_tokens (
 server_url TEXT PRIMARY KEY NOT NULL,
 access_token TEXT NOT NULL,
 refresh_token TEXT,
 token_type TEXT NOT NULL DEFAULT 'bearer',
 expires_at INTEGER,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	if existing {
		if _, err := db.Exec(`INSERT INTO oauth_tokens(server_url,access_token,refresh_token,token_type,expires_at,created_at,updated_at)
 VALUES('placeholder','old-access',NULL,'bearer',NULL,111,111)`); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func oauthTestToken(seed byte, size int) string {
	value := make([]byte, size)
	for index := range value {
		value[index] = seed
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
