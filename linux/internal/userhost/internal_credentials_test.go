package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	_ "modernc.org/sqlite"
)

func createInternalCredentialFixture(t *testing.T) (string, *projectfs.Root) {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(rootPath, "data", "aionui-backend.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT NOT NULL,email TEXT,password_hash TEXT NOT NULL,avatar_path TEXT,jwt_secret TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,last_login INTEGER)`,
		`CREATE TABLE system_settings(id INTEGER PRIMARY KEY,language TEXT NOT NULL,updated_at INTEGER NOT NULL)`,
		`INSERT INTO users VALUES('system_default_user','internal-admin',NULL,'old-hash',NULL,'persistent-provider-secret',1,1,NULL)`,
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return databasePath, root
}

func TestRotateBackendCredentialPreservesProviderSecretAndChangesPassword(t *testing.T) {
	databasePath, root := createInternalCredentialFixture(t)
	uid := uint32(os.Getuid())
	username, first, err := rotateBackendCredential(context.Background(), root, "data/aionui-backend.db", uid, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	_, second, err := rotateBackendCredential(context.Background(), root, "data/aionui-backend.db", uid, time.Unix(1_700_000_001, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second)
	if username != "internal-admin" || string(first) == string(second) {
		t.Fatal("internal identity was changed or password was reused")
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var hash, jwt, language string
	if err := database.QueryRow(`SELECT password_hash,jwt_secret FROM users WHERE id='system_default_user'`).Scan(&hash, &jwt); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT language FROM system_settings WHERE id=1`).Scan(&language); err != nil {
		t.Fatal(err)
	}
	if jwt != "persistent-provider-secret" || language != "zh-CN" || bcrypt.CompareHashAndPassword([]byte(hash), second) != nil {
		t.Fatal("credential rotation did not preserve the encryption secret or persist the new login")
	}
}

func TestRotateBackendCredentialRejectsSymlink(t *testing.T) {
	_, root := createInternalCredentialFixture(t)
	if err := os.Symlink(filepath.Join(root.Path(), "data", "aionui-backend.db"), filepath.Join(root.Path(), "data", "linked.db")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotateBackendCredential(context.Background(), root, "data/linked.db", uint32(os.Getuid()), time.Now()); err == nil {
		t.Fatal("symlinked internal database was accepted")
	}
}

func TestAuthenticateBackendReturnsOnlyManagedCookies(t *testing.T) {
	const password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	runtimeToken := []byte(strings.Repeat("A", workAgentRuntimeTokenTextBytes))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/status", func(writer http.ResponseWriter, _ *http.Request) {
		http.SetCookie(writer, &http.Cookie{Name: "unrelated", Value: "do-not-forward", Path: "/"})
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "needs_setup": false, "is_authenticated": false})
	})
	mux.HandleFunc("POST /login", func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["username"] != "internal-admin" || body["password"] != password || request.Header.Get("Origin") == "" {
			http.Error(writer, "bad login", http.StatusBadRequest)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "aionui-session", Value: "session-value", Path: "/"})
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "user": map[string]string{"id": "system_default_user", "username": "internal-admin"}})
	})
	mux.HandleFunc("GET /api/auth/user", func(writer http.ResponseWriter, request *http.Request) {
		if cookie, err := request.Cookie("aionui-session"); err != nil || cookie.Value != "session-value" {
			http.Error(writer, "missing session", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "user": map[string]string{"id": "system_default_user", "username": "internal-admin"}})
	})
	mux.HandleFunc("GET /api/system/info", func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "data": map[string]string{
			"cache_dir": "/tenant/data", "work_dir": "/tenant/data", "log_dir": "/tenant/logs", "platform": "linux", "arch": "x64",
		}})
	})
	mux.HandleFunc("GET /api/agents/management", func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "data": []map[string]string{{"id": "aion"}}})
	})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(workAgentRuntimeHeader) != string(runtimeToken) {
			http.Error(writer, "missing runtime token", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(writer, request)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	material, err := authenticateBackend(context.Background(), base, server.Client().Transport, "internal-admin", []byte(password), backendSystemInfo{
		CacheDir: "/tenant/data", WorkDir: "/tenant/data", LogDir: "/tenant/logs", Platform: "linux", Arch: "x64",
	}, runtimeToken)
	if err != nil {
		t.Fatal(err)
	}
	if material.CookieHeader != "aionui-session=session-value" || strings.Contains(material.CookieHeader, "unrelated") {
		t.Fatalf("unexpected internal cookie material: %q", material.CookieHeader)
	}
}
