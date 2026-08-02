package userhost

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	_ "modernc.org/sqlite"
)

func TestOAuthManagerUsesPKCEAndPersistsTokenOnce(t *testing.T) {
	var providerURL string
	var expectedChallenge string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]string{"authorization_endpoint": providerURL + "/authorize", "token_endpoint": providerURL + "/token"})
	})
	mux.HandleFunc("POST /token", func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil || request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("code") != "one-time-code" || request.Form.Get("client_id") != "aionui" {
			http.Error(writer, "invalid exchange", http.StatusBadRequest)
			return
		}
		digest := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(digest[:]) != expectedChallenge {
			http.Error(writer, "invalid PKCE verifier", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": "access-value", "refresh_token": "refresh-value", "token_type": "Bearer", "expires_in": 3600})
	})
	provider := httptest.NewTLSServer(mux)
	defer provider.Close()
	providerURL = provider.URL
	client := provider.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(rootPath, "data", "aionui-backend.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE oauth_tokens(server_url TEXT PRIMARY KEY,access_token TEXT NOT NULL,refresh_token TEXT,token_type TEXT NOT NULL,expires_at INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	database.Close()
	if err := os.Chmod(databasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	now := time.Unix(1_800_000_000, 0).UTC()
	manager := newOAuthManager(root, "data/aionui-backend.db", "https://portal.example.test", client, func() time.Time { return now }, true)
	stateBytes, _ := randomOAuthTokenBytes(32)
	state := string(stateBytes)
	clear(stateBytes)
	started, err := manager.start(context.Background(), oauthStartRequest{ServerURL: providerURL, State: state, RedirectURI: "https://portal.example.test/api/mcp/oauth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := url.Parse(started.AuthorizationURL)
	if err != nil || authorization.Query().Get("state") != state || authorization.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("invalid authorization URL: %s err=%v", started.AuthorizationURL, err)
	}
	expectedChallenge = authorization.Query().Get("code_challenge")
	if err := manager.complete(context.Background(), oauthCompleteRequest{FlowID: started.FlowID, ServerURL: providerURL, Code: "one-time-code"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.complete(context.Background(), oauthCompleteRequest{FlowID: started.FlowID, ServerURL: providerURL, Code: "one-time-code"}); err == nil {
		t.Fatal("OAuth flow replay was accepted")
	}
	database, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var access, refresh, tokenType string
	if err := database.QueryRow(`SELECT access_token,refresh_token,token_type FROM oauth_tokens WHERE server_url=?`, providerURL).Scan(&access, &refresh, &tokenType); err != nil {
		t.Fatal(err)
	}
	if access != "access-value" || refresh != "refresh-value" || tokenType != "bearer" {
		t.Fatal("OAuth token was not persisted exactly")
	}
}

func TestOAuthPublicDialRejectsPrivateAndDocumentationAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "192.0.2.20", "198.51.100.8", "203.0.113.9", "::1", "2001:db8::1"} {
		if !forbiddenOAuthIP(net.ParseIP(value)) {
			t.Fatalf("OAuth address %s was accepted", value)
		}
	}
}
