package userhost

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"aionuiportal/internal/ipc"
)

const (
	oauthFlowTTL          = 2 * time.Minute
	oauthOperationTimeout = 12 * time.Second
	maxPendingOAuthFlows  = 8
	maxOAuthDocumentBytes = 256 * 1024
	maxOAuthTokenBytes    = 128 * 1024
)

var (
	expectedOAuthTokenColumns = []string{"server_url", "access_token", "refresh_token", "token_type", "expires_at", "created_at", "updated_at"}
	blockedOAuthPrefixes      = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

type pendingOAuthFlow struct {
	serverURL   string
	tokenURL    string
	redirectURI string
	verifier    []byte
	expiresAt   time.Time
}

type oauthManager struct {
	dbPath       string
	client       *http.Client
	now          func() time.Time
	allowPrivate bool

	mu      sync.Mutex
	pending map[string]pendingOAuthFlow
}

type oauthMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type oauthTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
}

func newOAuthManager(dbPath string, client *http.Client, now func() time.Time, allowPrivate bool) *oauthManager {
	if client == nil {
		client = secureOAuthHTTPClient()
	}
	if now == nil {
		now = time.Now
	}
	return &oauthManager{dbPath: dbPath, client: client, now: now, allowPrivate: allowPrivate, pending: make(map[string]pendingOAuthFlow)}
}

func secureOAuthHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialPublicOAuthAddress,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func dialPublicOAuthAddress(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("OAuth endpoint address is invalid")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("OAuth endpoint DNS resolution failed")
	}
	for _, candidate := range addresses {
		if forbiddenOAuthAddress(candidate.IP) {
			return nil, errors.New("OAuth endpoint resolved to a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
}

func forbiddenOAuthAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return true
	}
	for _, prefix := range blockedOAuthPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (m *oauthManager) start(ctx context.Context, request ipc.OAuthStartRequest) (ipc.OAuthResult, error) {
	if !validOAuthToken(request.State, 32) {
		return ipc.OAuthResult{}, errors.New("OAuth state is invalid")
	}
	serverURL := strings.TrimSpace(request.ServerURL)
	server, err := validateOAuthHTTPSURL(serverURL, false, m.allowPrivate)
	if err != nil {
		return ipc.OAuthResult{}, errors.New("MCP server URL must be a public HTTPS URL without credentials, query, or fragment")
	}
	if err := validateOAuthRedirectURI(request.RedirectURI); err != nil {
		return ipc.OAuthResult{}, err
	}
	m.mu.Lock()
	m.purgeExpiredLocked(m.now())
	full := len(m.pending) >= maxPendingOAuthFlows
	m.mu.Unlock()
	if full {
		return ipc.OAuthResult{}, errors.New("too many pending OAuth flows")
	}

	operationCtx, cancel := context.WithTimeout(ctx, oauthOperationTimeout)
	defer cancel()
	metadata, err := m.discover(operationCtx, server.String())
	if err != nil {
		return ipc.OAuthResult{}, err
	}
	authorizationURL, err := validateOAuthHTTPSURL(metadata.AuthorizationEndpoint, true, m.allowPrivate)
	if err != nil {
		return ipc.OAuthResult{}, errors.New("OAuth authorization endpoint is invalid")
	}
	tokenURL, err := validateOAuthHTTPSURL(metadata.TokenEndpoint, true, m.allowPrivate)
	if err != nil {
		return ipc.OAuthResult{}, errors.New("OAuth token endpoint is invalid")
	}
	if err := ensurePublicOAuthHost(operationCtx, authorizationURL.Hostname(), m.allowPrivate); err != nil {
		return ipc.OAuthResult{}, err
	}
	if err := ensurePublicOAuthHost(operationCtx, tokenURL.Hostname(), m.allowPrivate); err != nil {
		return ipc.OAuthResult{}, err
	}

	verifier, err := randomBase64(32)
	if err != nil {
		return ipc.OAuthResult{}, err
	}
	stored := false
	defer func() {
		if !stored {
			zero(verifier)
		}
	}()
	flowBytes, err := randomBase64(32)
	if err != nil {
		return ipc.OAuthResult{}, err
	}
	flowID := string(flowBytes)
	zero(flowBytes)

	challengeHash := sha256.Sum256(verifier)
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", "aionui")
	query.Set("redirect_uri", request.RedirectURI)
	query.Set("state", request.State)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challengeHash[:]))
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()

	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeExpiredLocked(now)
	if len(m.pending) >= maxPendingOAuthFlows {
		return ipc.OAuthResult{}, errors.New("too many pending OAuth flows")
	}
	if _, exists := m.pending[flowID]; exists {
		return ipc.OAuthResult{}, errors.New("OAuth flow identifier collision")
	}
	m.pending[flowID] = pendingOAuthFlow{serverURL: serverURL, tokenURL: tokenURL.String(), redirectURI: request.RedirectURI, verifier: verifier, expiresAt: now.Add(oauthFlowTTL)}
	stored = true
	return ipc.OAuthResult{AuthorizationURL: authorizationURL.String(), FlowID: flowID}, nil
}

func (m *oauthManager) complete(ctx context.Context, request ipc.OAuthCompleteRequest) error {
	if !validOAuthToken(request.FlowID, 32) {
		return errors.New("OAuth flow identifier is invalid")
	}
	if len(request.Code) == 0 || len(request.Code) > 16*1024 || strings.IndexByte(request.Code, 0) >= 0 {
		return errors.New("OAuth authorization code is invalid")
	}
	flow, ok := m.take(request.FlowID)
	if !ok {
		return errors.New("OAuth flow is missing, expired, or already used")
	}
	defer zero(flow.verifier)
	if request.ServerURL != flow.serverURL {
		return errors.New("OAuth flow did not match the bound MCP server")
	}

	operationCtx, cancel := context.WithTimeout(ctx, oauthOperationTimeout)
	defer cancel()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {request.Code},
		"redirect_uri":  {flow.redirectURI},
		"client_id":     {"aionui"},
		"code_verifier": {string(flow.verifier)},
	}
	httpRequest, err := http.NewRequestWithContext(operationCtx, http.MethodPost, flow.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("create OAuth token request")
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := m.client.Do(httpRequest)
	if err != nil {
		return errors.New("OAuth token exchange request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("OAuth token endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := readLimitedOAuthBody(response.Body)
	if err != nil {
		return err
	}
	var token oauthTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return errors.New("OAuth token endpoint returned invalid JSON")
	}
	if token.AccessToken == "" || len(token.AccessToken) > maxOAuthTokenBytes || len(token.RefreshToken) > maxOAuthTokenBytes || !strings.EqualFold(token.TokenType, "bearer") {
		return errors.New("OAuth token response is incomplete or unsupported")
	}
	expiresAt, err := parseOAuthExpiry(token.ExpiresIn, m.now())
	if err != nil {
		return err
	}
	return persistOAuthToken(operationCtx, m.dbPath, flow.serverURL, token.AccessToken, token.RefreshToken, expiresAt, m.now())
}

func (m *oauthManager) cancel(request ipc.OAuthCancelRequest) error {
	if !validOAuthToken(request.FlowID, 32) {
		return errors.New("OAuth flow identifier is invalid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, ok := m.pending[request.FlowID]
	if ok {
		if flow.serverURL != request.ServerURL {
			return errors.New("OAuth flow did not match the bound MCP server")
		}
		delete(m.pending, request.FlowID)
		zero(flow.verifier)
	}
	return nil
}

func (m *oauthManager) take(flowID string) (pendingOAuthFlow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.purgeExpiredLocked(now)
	flow, ok := m.pending[flowID]
	if !ok {
		return pendingOAuthFlow{}, false
	}
	delete(m.pending, flowID)
	return flow, true
}

func (m *oauthManager) purgeExpiredLocked(now time.Time) {
	for flowID, flow := range m.pending {
		if !flow.expiresAt.After(now) {
			delete(m.pending, flowID)
			zero(flow.verifier)
		}
	}
}

func (m *oauthManager) discover(ctx context.Context, serverURL string) (oauthMetadata, error) {
	base := strings.TrimRight(serverURL, "/")
	for _, suffix := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		metadata, err := m.fetchMetadata(ctx, base+suffix)
		if err == nil {
			return metadata, nil
		}
	}
	return oauthMetadata{}, errors.New("OAuth discovery failed for the MCP server")
}

func (m *oauthManager) fetchMetadata(ctx context.Context, endpoint string) (oauthMetadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return oauthMetadata{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return oauthMetadata{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return oauthMetadata{}, errors.New("OAuth metadata endpoint returned a non-success status")
	}
	body, err := readLimitedOAuthBody(response.Body)
	if err != nil {
		return oauthMetadata{}, err
	}
	var metadata oauthMetadata
	if err := json.Unmarshal(body, &metadata); err != nil || metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" {
		return oauthMetadata{}, errors.New("OAuth metadata is invalid")
	}
	return metadata, nil
}

func readLimitedOAuthBody(body io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(body, maxOAuthDocumentBytes+1))
	if err != nil {
		return nil, errors.New("read OAuth response")
	}
	if len(value) > maxOAuthDocumentBytes {
		return nil, errors.New("OAuth response exceeded the size limit")
	}
	return value, nil
}

func validateOAuthHTTPSURL(raw string, allowQuery, allowPrivate bool) (*url.URL, error) {
	if raw == "" || len(raw) > 4096 || strings.TrimSpace(raw) != raw || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, errors.New("invalid OAuth URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid OAuth URL")
	}
	if !allowQuery && (parsed.RawQuery != "" || parsed.ForceQuery) {
		return nil, errors.New("invalid OAuth URL")
	}
	if strings.Contains(parsed.Hostname(), "%") {
		return nil, errors.New("invalid OAuth URL")
	}
	if literal := net.ParseIP(parsed.Hostname()); literal != nil && !allowPrivate && forbiddenOAuthAddress(literal) {
		return nil, errors.New("non-public OAuth URL")
	}
	return parsed, nil
}

func validateOAuthRedirectURI(raw string) error {
	if raw == "" || len(raw) > 4096 || strings.TrimSpace(raw) != raw || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return errors.New("OAuth redirect URI must be the configured HTTP or HTTPS Portal callback")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != "/api/mcp/oauth/callback" || parsed.RawPath != "" {
		return errors.New("OAuth redirect URI must be the configured HTTP or HTTPS Portal callback")
	}
	return nil
}

func ensurePublicOAuthHost(ctx context.Context, host string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return errors.New("OAuth endpoint DNS resolution failed")
	}
	for _, address := range addresses {
		if forbiddenOAuthAddress(address.IP) {
			return errors.New("OAuth endpoint resolved to a non-public address")
		}
	}
	return nil
}

func validOAuthToken(value string, bytes int) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	defer zero(decoded)
	return len(decoded) == bytes
}

func parseOAuthExpiry(raw json.RawMessage, now time.Time) (*int64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	value := strings.Trim(string(raw), `"`)
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 || seconds > int64((10*365*24*time.Hour)/time.Second) {
		return nil, errors.New("OAuth token expiry is invalid")
	}
	expires := now.UnixMilli() + seconds*1000
	return &expires, nil
}

func persistOAuthToken(ctx context.Context, dbPath, serverURL, accessToken, refreshToken string, expiresAt *int64, now time.Time) error {
	if !filepath.IsAbs(dbPath) {
		return errors.New("AionCore database path must be absolute")
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return fmt.Errorf("inspect AionCore database: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("AionCore database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return errors.New("open AionCore database for OAuth token storage")
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return errors.New("begin AionCore OAuth token transaction")
	}
	defer tx.Rollback()
	columns, err := tableColumns(ctx, tx, "oauth_tokens")
	if err != nil {
		return err
	}
	if len(columns) != len(expectedOAuthTokenColumns) {
		return fmt.Errorf("unsupported AionCore oauth_tokens schema: got %v", columns)
	}
	for index := range columns {
		if columns[index] != expectedOAuthTokenColumns[index] {
			return fmt.Errorf("unsupported AionCore oauth_tokens schema: got %v", columns)
		}
	}
	var refresh any
	if refreshToken != "" {
		refresh = refreshToken
	}
	var expiry any
	if expiresAt != nil {
		expiry = *expiresAt
	}
	stamp := now.UnixMilli()
	result, err := tx.ExecContext(ctx, `INSERT INTO oauth_tokens(server_url,access_token,refresh_token,token_type,expires_at,created_at,updated_at)
 VALUES(?,?,?,'bearer',?,?,?)
 ON CONFLICT(server_url) DO UPDATE SET access_token=excluded.access_token,refresh_token=excluded.refresh_token,
 token_type=excluded.token_type,expires_at=excluded.expires_at,updated_at=excluded.updated_at`,
		serverURL, accessToken, refresh, expiry, stamp, stamp)
	if err != nil {
		return errors.New("write AionCore OAuth token")
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("AionCore OAuth token write did not affect exactly one row")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit AionCore OAuth token")
	}
	return nil
}
