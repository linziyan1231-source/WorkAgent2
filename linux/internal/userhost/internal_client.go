package userhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxBackendControlResponse = 2 * 1024 * 1024

type backendAuthMaterial struct {
	CookieHeader string
	CSRFToken    string
}

type backendSystemInfo struct {
	CacheDir string `json:"cache_dir"`
	WorkDir  string `json:"work_dir"`
	LogDir   string `json:"log_dir"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

func authenticateBackend(ctx context.Context, base *url.URL, transport http.RoundTripper, username string, password []byte, expected backendSystemInfo, runtimeToken []byte) (backendAuthMaterial, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return backendAuthMaterial{}, err
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	var status struct {
		Success         bool `json:"success"`
		NeedsSetup      bool `json:"needs_setup"`
		IsAuthenticated bool `json:"is_authenticated"`
	}
	if err := backendClientJSON(ctx, client, base, http.MethodGet, "/api/auth/status", nil, &status, "", runtimeToken); err != nil {
		return backendAuthMaterial{}, fmt.Errorf("read internal authentication status: %w", err)
	}
	if !status.Success || status.NeedsSetup {
		return backendAuthMaterial{}, errors.New("internal backend authentication is not initialized")
	}
	body := make([]byte, 0, len(username)+len(password)+64)
	body = append(body, `{"username":`...)
	body = strconv.AppendQuote(body, username)
	body = append(body, `,"password":"`...)
	body = append(body, password...)
	body = append(body, `","remember":false}`...)
	defer clear(body)
	csrf := backendCookie(jar, base, "aionui-csrf-token")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/login", bytes.NewReader(body))
	if err != nil {
		return backendAuthMaterial{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", base.String())
	setWorkAgentRuntimeHeader(request, runtimeToken)
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		return backendAuthMaterial{}, errors.New("internal backend login request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxBackendControlResponse+1))
	if err != nil || len(responseBody) > maxBackendControlResponse || response.StatusCode != http.StatusOK {
		clear(responseBody)
		return backendAuthMaterial{}, fmt.Errorf("internal backend login returned HTTP %d", response.StatusCode)
	}
	defer clear(responseBody)
	var login struct {
		Success bool `json:"success"`
		User    struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(&login); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !login.Success || login.User.ID == "" || login.User.Username != username {
		return backendAuthMaterial{}, errors.New("internal backend login response was invalid")
	}
	if backendCookie(jar, base, "aionui-session") == "" {
		return backendAuthMaterial{}, errors.New("internal backend login did not establish a session")
	}
	material := backendAuthMaterial{CookieHeader: backendCookieHeader(jar, base), CSRFToken: backendCookie(jar, base, "aionui-csrf-token")}
	var current struct {
		Success bool `json:"success"`
		User    struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := backendClientJSON(ctx, client, base, http.MethodGet, "/api/auth/user", nil, &current, "", runtimeToken); err != nil || !current.Success || current.User.ID == "" || current.User.Username != username {
		return backendAuthMaterial{}, errors.New("internal authenticated user verification failed")
	}
	var system struct {
		Success bool              `json:"success"`
		Data    backendSystemInfo `json:"data"`
	}
	if err := backendClientJSON(ctx, client, base, http.MethodGet, "/api/system/info", nil, &system, "", runtimeToken); err != nil {
		return backendAuthMaterial{}, fmt.Errorf("verify internal system directories: %w", err)
	}
	if !system.Success || !sameBackendPath(system.Data.CacheDir, expected.CacheDir) || !sameBackendPath(system.Data.WorkDir, expected.WorkDir) || !sameBackendPath(system.Data.LogDir, expected.LogDir) || system.Data.Platform != expected.Platform || system.Data.Arch != expected.Arch {
		return backendAuthMaterial{}, fmt.Errorf("internal system directory/platform contract mismatch: %+v", system.Data)
	}
	var agents struct {
		Success bool             `json:"success"`
		Data    []map[string]any `json:"data"`
	}
	if err := backendClientJSON(ctx, client, base, http.MethodGet, "/api/agents/management", nil, &agents, "", runtimeToken); err != nil || !agents.Success || len(agents.Data) == 0 {
		return backendAuthMaterial{}, errors.New("Renderer-critical agent management API is unavailable")
	}
	return material, nil
}

func sameBackendPath(actual, expected string) bool {
	return actual != "" && expected != "" && filepath.Clean(actual) == filepath.Clean(expected)
}

func backendClientJSON(ctx context.Context, client *http.Client, base *url.URL, method, requestPath string, source, destination any, csrf string, runtimeToken []byte) error {
	var body io.Reader
	var payload []byte
	if source != nil {
		var err error
		payload, err = json.Marshal(source)
		if err != nil {
			return err
		}
		defer clear(payload)
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, base.String()+requestPath, body)
	if err != nil {
		return err
	}
	setWorkAgentRuntimeHeader(request, runtimeToken)
	if source != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", base.String())
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("internal backend request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBackendControlResponse+1))
	if err != nil || len(data) > maxBackendControlResponse {
		clear(data)
		return errors.New("internal backend response exceeded its limit")
	}
	defer clear(data)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("internal backend returned HTTP %d", response.StatusCode)
	}
	if destination == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("internal backend returned invalid JSON")
	}
	return nil
}

func backendCookie(jar http.CookieJar, base *url.URL, name string) string {
	for _, cookie := range jar.Cookies(base) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func backendCookieHeader(jar http.CookieJar, base *url.URL) string {
	cookies := jar.Cookies(base)
	sort.Slice(cookies, func(left, right int) bool { return cookies[left].Name < cookies[right].Name })
	values := make([]string, 0, 2)
	for _, cookie := range cookies {
		if (cookie.Name == "aionui-session" || cookie.Name == "aionui-csrf-token") && cookie.Value != "" && !strings.ContainsAny(cookie.Value, ";\r\n") {
			values = append(values, cookie.Name+"="+cookie.Value)
		}
	}
	return strings.Join(values, "; ")
}
