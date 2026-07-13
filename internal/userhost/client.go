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
	"sort"
	"strconv"
	"strings"
	"time"

	"aionuiportal/internal/ipc"
)

const maxControlResponse = 2 * 1024 * 1024

type aionClient struct {
	base   *url.URL
	client *http.Client
}

type systemInfo struct {
	CacheDir string `json:"cache_dir"`
	WorkDir  string `json:"work_dir"`
	LogDir   string `json:"log_dir"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

func newAionClient(port int) (*aionClient, error) {
	base, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &aionClient{base: base, client: &http.Client{Jar: jar, Timeout: 15 * time.Second}}, nil
}

func (a *aionClient) authenticate(ctx context.Context, username string, password []byte) (ipc.AuthMaterial, error) {
	var status struct {
		Success         bool `json:"success"`
		NeedsSetup      bool `json:"needs_setup"`
		IsAuthenticated bool `json:"is_authenticated"`
	}
	if err := a.getJSON(ctx, "/api/auth/status", &status); err != nil {
		return ipc.AuthMaterial{}, fmt.Errorf("read internal auth status: %w", err)
	}
	if !status.Success || status.NeedsSetup {
		return ipc.AuthMaterial{}, errors.New("internal AionUi authentication is not initialized")
	}
	csrf := a.cookie("aionui-csrf-token")
	body := make([]byte, 0, len(username)+len(password)+64)
	body = append(body, `{"username":`...)
	body = strconv.AppendQuote(body, username)
	body = append(body, `,"password":"`...)
	body = append(body, password...)
	body = append(body, `","remember":false}`...)
	defer zero(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base.String()+"/login", bytes.NewReader(body))
	if err != nil {
		return ipc.AuthMaterial{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", a.base.String())
	if csrf != "" {
		req.Header.Set("x-csrf-token", csrf)
	}
	response, err := a.client.Do(req)
	if err != nil {
		return ipc.AuthMaterial{}, fmt.Errorf("internal AionUi login request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxControlResponse+1))
	if err != nil {
		return ipc.AuthMaterial{}, err
	}
	defer zero(responseBody)
	if len(responseBody) > maxControlResponse || response.StatusCode != http.StatusOK {
		return ipc.AuthMaterial{}, fmt.Errorf("internal AionUi login returned HTTP %d", response.StatusCode)
	}
	var login struct {
		Success bool `json:"success"`
		User    struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := json.Unmarshal(responseBody, &login); err != nil || !login.Success || login.User.ID == "" || login.User.Username != username {
		return ipc.AuthMaterial{}, errors.New("internal AionUi login response was invalid")
	}
	session := a.cookie("aionui-session")
	csrf = a.cookie("aionui-csrf-token")
	if session == "" {
		return ipc.AuthMaterial{}, errors.New("internal AionUi login did not establish a session")
	}
	return ipc.AuthMaterial{CookieHeader: a.cookieHeader(), CSRFToken: csrf}, nil
}

func (a *aionClient) validateAuthenticatedAPIs(ctx context.Context, expectedUsername string, expected systemInfo) error {
	var user struct {
		Success bool `json:"success"`
		User    struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := a.getJSON(ctx, "/api/auth/user", &user); err != nil || !user.Success || user.User.ID == "" || user.User.Username != expectedUsername {
		return errors.New("authenticated user API did not return the internal system user")
	}
	var infoResponse struct {
		Success bool       `json:"success"`
		Data    systemInfo `json:"data"`
	}
	if err := a.getJSON(ctx, "/api/system/info", &infoResponse); err != nil {
		return fmt.Errorf("system info API: %w", err)
	}
	got := infoResponse.Data
	if !infoResponse.Success || !samePath(got.CacheDir, expected.CacheDir) || !samePath(got.WorkDir, expected.WorkDir) ||
		!samePath(got.LogDir, expected.LogDir) || got.Platform != "win32" || got.Arch != "x64" {
		return fmt.Errorf("AionCore directory/platform contract mismatch: got %+v", got)
	}
	var agents struct {
		Success bool             `json:"success"`
		Data    []map[string]any `json:"data"`
	}
	if err := a.getJSON(ctx, "/api/agents/management", &agents); err != nil || !agents.Success || len(agents.Data) == 0 {
		return errors.New("Renderer-critical agent management API is unavailable")
	}
	return nil
}

func (a *aionClient) getJSON(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base.String()+path, nil)
	if err != nil {
		return err
	}
	response, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", path, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxControlResponse+1))
	if err != nil {
		return fmt.Errorf("read GET %s: %w", path, err)
	}
	if len(body) > maxControlResponse {
		return fmt.Errorf("GET %s exceeded the %d-byte control response limit", path, maxControlResponse)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode GET %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode GET %s: trailing JSON value", path)
	}
	return nil
}

func (a *aionClient) cookie(name string) string {
	for _, cookie := range a.client.Jar.Cookies(a.base) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func (a *aionClient) cookieHeader() string {
	cookies := a.client.Jar.Cookies(a.base)
	sort.Slice(cookies, func(i, j int) bool { return cookies[i].Name < cookies[j].Name })
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie.Name == "aionui-session" || cookie.Name == "aionui-csrf-token" {
			parts = append(parts, cookie.Name+"="+cookie.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func samePath(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, `\/`), strings.TrimRight(b, `\/`))
}
