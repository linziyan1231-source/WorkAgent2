package userhost

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func fakeAionServer(t *testing.T, password string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "needs_setup": false, "is_authenticated": false})
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("x-csrf-token") != "" || r.Header.Get("Origin") == "" || body["username"] != "admin" || body["password"] != password {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "aionui-session", Value: "session-value", Path: "/", HttpOnly: true})
		json.NewEncoder(w).Encode(map[string]any{"success": true, "user": map[string]any{"id": "system_default_user", "username": "admin"}, "token": "must-not-escape"})
	})
	mux.HandleFunc("/api/auth/user", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "user": map[string]any{"id": "system_default_user", "username": "admin"}})
	})
	mux.HandleFunc("/api/system/info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"cache_dir": `C:\Users\worker\AionUiPortal\data`, "work_dir": `C:\Users\worker\AionUiPortal\data`, "log_dir": `C:\Users\worker\AionUiPortal\logs`, "platform": "win32", "arch": "x64"}})
	})
	mux.HandleFunc("/api/agents/management", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": []any{map[string]any{"id": "aion"}}})
	})
	return httptest.NewServer(mux)
}

func clientForServer(t *testing.T, server *httptest.Server) *aionClient {
	t.Helper()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	client, err := newAionClient(port)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestInternalAuthenticationKeepsCookiesServerSide(t *testing.T) {
	server := fakeAionServer(t, "internal-pass")
	defer server.Close()
	client := clientForServer(t, server)
	material, err := client.authenticate(context.Background(), "admin", []byte("internal-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if material.CSRFToken != "" || material.CookieHeader != "aionui-session=session-value" || strings.Contains(material.CookieHeader, "must-not-escape") {
		t.Fatalf("unexpected internal material: %+v", material)
	}
	if err := client.validateAuthenticatedAPIs(context.Background(), "admin", systemInfo{CacheDir: `C:\Users\worker\AionUiPortal\data`, WorkDir: `C:\Users\worker\AionUiPortal\data`, LogDir: `C:\Users\worker\AionUiPortal\logs`}); err != nil {
		t.Fatal(err)
	}
}

func TestInternalAuthenticationMakesOneLoginAttempt(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/status" {
			json.NewEncoder(w).Encode(map[string]any{"success": true, "needs_setup": false})
			return
		}
		if r.URL.Path == "/login" {
			attempts++
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer server.Close()
	client := clientForServer(t, server)
	if _, err := client.authenticate(context.Background(), "admin", []byte("wrong")); err == nil {
		t.Fatal("failed internal login unexpectedly succeeded")
	}
	if attempts != 1 {
		t.Fatalf("login attempts=%d, want exactly 1", attempts)
	}
}

func TestControlJSONRejectsTrailingAndOversizedResponses(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"trailing": func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"success":true} {}`)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"success":true,"padding":"`+strings.Repeat("x", maxControlResponse)+`"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client := clientForServer(t, server)
			var response struct {
				Success bool `json:"success"`
			}
			if err := client.getJSON(context.Background(), "/", &response); err == nil {
				t.Fatal("invalid control response was accepted")
			}
		})
	}
}
