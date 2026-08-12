package kimidatasource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"aionuiportal/internal/store"
	"golang.org/x/sys/windows"
)

const (
	defaultOAuthHost = "https://auth.kimi.com"
	defaultAPIURL    = "https://api.kimi.com/coding/v1/tools"
	clientID         = "17e5f671-d194-4dfb-9706-5516cb48c098"
	protocolVersion  = "2025-06-18"
	maxRequestBytes  = 2 << 20
	maxResponseBytes = 8 << 20
)

type Config struct {
	ListenAddress  string `json:"listen_address"`
	DatabasePath   string `json:"database_path"`
	AuditLogPath   string `json:"audit_log_path"`
	CredentialPath string `json:"credential_path"`
	LogPath        string `json:"log_path"`
	OAuthHost      string `json:"oauth_host,omitempty"`
	APIURL         string `json:"api_url,omitempty"`
	OutboundProxy  string `json:"outbound_proxy_url,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	if !filepath.IsAbs(path) {
		return cfg, errors.New("Kimi datasource broker config path must be absolute")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read Kimi datasource broker config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode Kimi datasource broker config: %w", err)
	}
	if cfg.OAuthHost == "" {
		cfg.OAuthHost = defaultOAuthHost
	}
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if !strings.HasPrefix(c.ListenAddress, "127.0.0.1:") {
		return errors.New("Kimi datasource broker must listen on 127.0.0.1")
	}
	for name, value := range map[string]string{
		"database_path":   c.DatabasePath,
		"audit_log_path":  c.AuditLogPath,
		"credential_path": c.CredentialPath,
		"log_path":        c.LogPath,
	} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	for name, value := range map[string]string{"oauth_host": c.OAuthHost, "api_url": c.APIURL} {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%s must be an absolute HTTPS URL without credentials or fragment", name)
		}
	}
	if c.OutboundProxy != "" {
		proxy, err := url.Parse(c.OutboundProxy)
		if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Hostname() == "" || proxy.User != nil {
			return errors.New("outbound_proxy_url must be an HTTP or HTTPS URL without credentials")
		}
	}
	return nil
}

type Server struct {
	cfg        Config
	store      *store.Store
	client     *http.Client
	logger     *log.Logger
	logFile    *os.File
	credential credentialManager
}

func NewServer(cfg Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	policyStore, err := store.Open(cfg.DatabasePath, cfg.AuditLogPath)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.OutboundProxy != "" {
		proxyURL, _ := url.Parse(cfg.OutboundProxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		policyStore.Close()
		return nil, fmt.Errorf("open Kimi datasource broker log: %w", err)
	}
	return &Server{
		cfg:        cfg,
		store:      policyStore,
		client:     &http.Client{Transport: transport, Timeout: 35 * time.Second},
		logger:     log.New(logFile, "", log.LstdFlags|log.LUTC),
		logFile:    logFile,
		credential: credentialManager{path: cfg.CredentialPath, oauthHost: cfg.OAuthHost, client: &http.Client{Transport: transport, Timeout: 30 * time.Second}},
	}, nil
}

func (s *Server) Close() error {
	storeErr := s.store.Close()
	logErr := s.logFile.Close()
	if storeErr != nil {
		return storeErr
	}
	return logErr
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/mcp", s.handleMCP)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok","service":"professional-datasource-broker"}`)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r.Header.Get("Authorization"))
	grant, userID, err := s.store.KimiDatasourceGrantForToken(r.Context(), token, time.Now())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes+1))
	var request rpcRequest
	if err := decoder.Decode(&request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: request.ID, Error: &rpcError{Code: -32600, Message: "Invalid Request"}})
		return
	}
	if request.Method == "notifications/initialized" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	response := rpcResponse{JSONRPC: "2.0", ID: request.ID}
	switch request.Method {
	case "initialize":
		response.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "workagent2-professional-datasource", "version": "1.0.0"},
		}
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		response.Result = map[string]any{"tools": tools(grant.AllowedSources)}
	case "tools/call":
		result, source, callErr := s.callTool(r.Context(), token, request.Params)
		if callErr != nil {
			response.Result = toolError(callErr)
			s.logger.Printf("user_id=%d source=%s outcome=denied error=%q", userID, source, callErr.Error())
		} else {
			response.Result = result
			s.logger.Printf("user_id=%d source=%s outcome=success", userID, source)
		}
	default:
		response.Error = &rpcError{Code: -32601, Message: "Method not found"}
	}
	writeRPC(w, response)
}

func (s *Server) callTool(ctx context.Context, token string, raw json.RawMessage) (any, string, error) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, "", errors.New("invalid tool parameters")
	}
	var method, source string
	switch params.Name {
	case "get_data_source_desc":
		method = params.Name
		source, _ = params.Arguments["name"].(string)
	case "call_data_source_tool":
		method = params.Name
		source, _ = params.Arguments["data_source_name"].(string)
	default:
		return nil, "", fmt.Errorf("unknown tool %q", params.Name)
	}
	if source == "" {
		return nil, "", errors.New("data source is required")
	}
	if _, _, err := s.store.ReserveKimiDatasourceCall(ctx, token, source, time.Now()); err != nil {
		return nil, source, err
	}
	upstream, trace, err := s.callUpstream(ctx, method, params.Arguments)
	if err != nil {
		return nil, source, err
	}
	text := responseText(upstream)
	if trace != "" {
		text += "\n\n[professional-datasource] request-id: " + trace
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}, source, nil
}

func (s *Server) callUpstream(ctx context.Context, method string, params map[string]any) (any, string, error) {
	return s.callUpstreamAttempt(ctx, method, params, true)
}

func (s *Server) callUpstreamAttempt(ctx context.Context, method string, params map[string]any, mayRefresh bool) (any, string, error) {
	token, err := s.credential.accessToken(ctx)
	if err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(map[string]any{"method": method, "params": params})
	if err != nil {
		return nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.APIURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Msh-Platform", "workagent2")
	request.Header.Set("X-Msh-Version", "1.0.0")
	request.Header.Set("X-Msh-Os-Version", runtime.GOOS+"/"+runtime.GOARCH)
	callID, err := randomID()
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("X-Msh-Tool-Call-Id", callID)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("Kimi datasource request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read Kimi datasource response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, "", errors.New("Kimi datasource response exceeded 8 MiB")
	}
	if response.StatusCode == http.StatusUnauthorized && mayRefresh {
		if _, refreshErr := s.credential.forceRefresh(ctx); refreshErr != nil {
			return nil, response.Header.Get("X-Request-Id"), refreshErr
		}
		return s.callUpstreamAttempt(ctx, method, params, false)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.Header.Get("X-Request-Id"), fmt.Errorf("Kimi datasource returned HTTP %d", response.StatusCode)
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		result = string(data)
	}
	return result, firstHeader(response.Header, "X-Request-Id", "X-Trace-Id", "X-Msh-Request-Id"), nil
}

func tools(sources []string) []map[string]any {
	return []map[string]any{
		{
			"name":        "get_data_source_desc",
			"description": "Get the current API documentation for one authorized Kimi data source before calling it.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string", "enum": sources}}, "required": []string{"name"}},
		},
		{
			"name":        "call_data_source_tool",
			"description": "Call one authorized Kimi data source using an API name and parameters returned by get_data_source_desc.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
				"data_source_name": map[string]any{"type": "string", "enum": sources},
				"api_name":         map[string]string{"type": "string"},
				"params":           map[string]string{"type": "object"},
			}, "required": []string{"data_source_name", "api_name", "params"}},
		},
	}
}

func responseText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if object, ok := value.(map[string]any); ok {
		for _, key := range []string{"text", "content", "result"} {
			if text, ok := object[key].(string); ok {
				return text
			}
		}
	}
	data, _ := json.MarshalIndent(value, "", "  ")
	return string(data)
}

func toolError(err error) map[string]any {
	message := err.Error()
	switch {
	case errors.Is(err, store.ErrKimiDatasourceDisabled):
		message = "KIMI_DATASOURCE_DISABLED"
	case errors.Is(err, store.ErrKimiDatasourceSourceDenied):
		message = "KIMI_DATASOURCE_SOURCE_NOT_ALLOWED"
	case errors.Is(err, store.ErrKimiDatasourceDailyExceeded):
		message = "KIMI_DATASOURCE_DAILY_QUOTA_EXCEEDED"
	case errors.Is(err, store.ErrKimiDatasourceMonthlyExceeded):
		message = "KIMI_DATASOURCE_MONTHLY_QUOTA_EXCEEDED"
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": message}}, "isError": true}
}

func bearerToken(value string) string {
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func writeRPC(w http.ResponseWriter, response rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func firstHeader(header http.Header, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

type credentialManager struct {
	mu        sync.Mutex
	path      string
	oauthHost string
	client    *http.Client
}

type credentialDocument struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	Scope        string          `json:"scope,omitempty"`
	ExpiresAt    json.RawMessage `json:"expires_at,omitempty"`
	Expired      string          `json:"expired,omitempty"`
}

func (m *credentialManager) accessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	document, raw, err := m.read()
	if err != nil {
		return "", err
	}
	if credentialExpiresSoon(document, time.Now().Add(5*time.Minute)) {
		return m.refreshLocked(ctx, document, raw)
	}
	return document.AccessToken, nil
}

func (m *credentialManager) forceRefresh(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	document, raw, err := m.read()
	if err != nil {
		return "", err
	}
	return m.refreshLocked(ctx, document, raw)
}

func (m *credentialManager) read() (credentialDocument, map[string]any, error) {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return credentialDocument{}, nil, fmt.Errorf("read Kimi datasource credential: %w", err)
	}
	var document credentialDocument
	var raw map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return document, nil, fmt.Errorf("decode Kimi datasource credential: %w", err)
	}
	_ = json.Unmarshal(data, &raw)
	if document.AccessToken == "" || document.RefreshToken == "" {
		return document, nil, errors.New("Kimi datasource credential requires access_token and refresh_token")
	}
	return document, raw, nil
}

func (m *credentialManager) refreshLocked(ctx context.Context, document credentialDocument, raw map[string]any) (string, error) {
	form := url.Values{"client_id": {clientID}, "grant_type": {"refresh_token"}, "refresh_token": {document.RefreshToken}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(m.oauthHost, "/")+"/api/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("refresh Kimi datasource credential: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read Kimi refresh response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Kimi refresh token was rejected with HTTP %d", response.StatusCode)
	}
	var refreshed struct {
		AccessToken  string  `json:"access_token"`
		RefreshToken string  `json:"refresh_token"`
		TokenType    string  `json:"token_type"`
		Scope        string  `json:"scope"`
		ExpiresIn    float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &refreshed); err != nil || refreshed.AccessToken == "" {
		return "", errors.New("Kimi refresh response did not contain an access token")
	}
	raw["access_token"] = refreshed.AccessToken
	if refreshed.RefreshToken != "" {
		raw["refresh_token"] = refreshed.RefreshToken
	}
	if refreshed.TokenType != "" {
		raw["token_type"] = refreshed.TokenType
	}
	if refreshed.Scope != "" {
		raw["scope"] = refreshed.Scope
	}
	if refreshed.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(refreshed.ExpiresIn * float64(time.Second)))
		raw["expires_at"] = expiresAt.Unix()
		raw["expired"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if err := atomicWriteJSON(m.path, raw); err != nil {
		return "", err
	}
	return refreshed.AccessToken, nil
}

func credentialExpiresSoon(document credentialDocument, threshold time.Time) bool {
	if len(document.ExpiresAt) > 0 && string(document.ExpiresAt) != "null" {
		expires, err := parseCredentialExpiry(document.ExpiresAt)
		return err != nil || !expires.After(threshold)
	}
	if document.Expired != "" {
		expires, err := time.Parse(time.RFC3339, document.Expired)
		return err != nil || !expires.After(threshold)
	}
	return false
}

func parseCredentialExpiry(raw json.RawMessage) (time.Time, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return time.Time{}, errors.New("empty Kimi credential expiry")
	}
	if strings.HasPrefix(value, `"`) {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return time.Time{}, fmt.Errorf("decode Kimi credential expiry: %w", err)
		}
		if parsed, err := time.Parse(time.RFC3339, text); err == nil {
			return parsed, nil
		}
		value = text
	}
	stamp, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse Kimi credential expiry: %w", err)
	}
	if stamp > 1_000_000_000_000 {
		stamp /= 1000
	}
	seconds := int64(stamp)
	nanoseconds := int64((stamp - float64(seconds)) * float64(time.Second))
	return time.Unix(seconds, nanoseconds), nil
}

func atomicWriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".kimi-datasource-credential-*.tmp")
	if err != nil {
		return fmt.Errorf("create Kimi credential temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace Kimi credential: %w", err)
	}
	return nil
}
