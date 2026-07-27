package userhost

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

const (
	oauthFlowTTL          = 2 * time.Minute
	oauthOperationTimeout = 12 * time.Second
	maxOAuthFlows         = 8
	maxOAuthDocument      = 256 * 1024
	maxOAuthToken         = 128 * 1024
)

var (
	oauthTokenColumns  = []string{"server_url", "access_token", "refresh_token", "token_type", "expires_at", "created_at", "updated_at"}
	blockedOAuthRanges = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	}
)

type oauthStartRequest struct {
	ServerURL   string `json:"server_url"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
}

type oauthCompleteRequest struct {
	FlowID    string `json:"flow_id"`
	ServerURL string `json:"server_url"`
	Code      string `json:"code"`
}

type oauthCancelRequest struct {
	FlowID    string `json:"flow_id"`
	ServerURL string `json:"server_url"`
}

type oauthStartResult struct {
	AuthorizationURL string `json:"authorization_url"`
	FlowID           string `json:"flow_id"`
}

type oauthFlow struct {
	serverURL   string
	tokenURL    string
	redirectURI string
	verifier    []byte
	expiresAt   time.Time
}

type oauthManager struct {
	root         *projectfs.Root
	databasePath string
	portalOrigin string
	client       *http.Client
	now          func() time.Time
	allowPrivate bool
	mu           sync.Mutex
	flows        map[string]oauthFlow
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

func newOAuthManager(root *projectfs.Root, databasePath, portalOrigin string, client *http.Client, now func() time.Time, allowPrivate bool) *oauthManager {
	if client == nil {
		client = secureOAuthClient("")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &oauthManager{root: root, databasePath: databasePath, portalOrigin: strings.TrimSuffix(portalOrigin, "/"), client: client, now: now, allowPrivate: allowPrivate, flows: make(map[string]oauthFlow)}
}

func (h *Host) oauthStart(writer http.ResponseWriter, request *http.Request) {
	if h.oauth == nil {
		http.Error(writer, "OAuth is unavailable", http.StatusServiceUnavailable)
		return
	}
	var body oauthStartRequest
	if err := decodeJSON(request, &body, 32*1024); err != nil {
		http.Error(writer, "invalid OAuth request", http.StatusBadRequest)
		return
	}
	result, err := h.oauth.start(request.Context(), body)
	if err != nil {
		h.logger.Printf("OAuth start rejected: %v", err)
		http.Error(writer, "OAuth authorization could not be started", http.StatusBadGateway)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *Host) oauthComplete(writer http.ResponseWriter, request *http.Request) {
	if h.oauth == nil {
		http.Error(writer, "OAuth is unavailable", http.StatusServiceUnavailable)
		return
	}
	var body oauthCompleteRequest
	if err := decodeJSON(request, &body, 32*1024); err != nil {
		http.Error(writer, "invalid OAuth request", http.StatusBadRequest)
		return
	}
	if err := h.oauth.complete(request.Context(), body); err != nil {
		h.logger.Printf("OAuth completion rejected: %v", err)
		http.Error(writer, "OAuth authorization could not be completed", http.StatusBadGateway)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"success": true})
}

func (h *Host) oauthCancel(writer http.ResponseWriter, request *http.Request) {
	if h.oauth == nil {
		http.Error(writer, "OAuth is unavailable", http.StatusServiceUnavailable)
		return
	}
	var body oauthCancelRequest
	if err := decodeJSON(request, &body, 16*1024); err != nil || h.oauth.cancel(body) != nil {
		http.Error(writer, "invalid OAuth cancellation", http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"success": true})
}

func secureOAuthClient(outboundProxy string) *http.Client {
	var proxy func(*http.Request) (*url.URL, error)
	dialContext := dialPublicOAuth
	if outboundProxy != "" {
		proxyURL, err := url.Parse(outboundProxy)
		if err == nil {
			proxy = http.ProxyURL(proxyURL)
			dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
			dialContext = dialer.DialContext
		}
	}
	transport := &http.Transport{
		Proxy: proxy, DialContext: dialContext, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second, ExpectContinueTimeout: time.Second, IdleConnTimeout: 30 * time.Second, DisableCompression: true,
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func dialPublicOAuth(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("OAuth endpoint address is invalid")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("OAuth endpoint DNS resolution failed")
	}
	for _, candidate := range addresses {
		if forbiddenOAuthIP(candidate.IP) {
			return nil, errors.New("OAuth endpoint resolved to a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
}

func forbiddenOAuthIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return true
	}
	for _, prefix := range blockedOAuthRanges {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (m *oauthManager) start(ctx context.Context, request oauthStartRequest) (oauthStartResult, error) {
	if !validOAuthToken(request.State, 32) {
		return oauthStartResult{}, errors.New("OAuth state is invalid")
	}
	server, err := validateOAuthURL(strings.TrimSpace(request.ServerURL), false, m.allowPrivate)
	if err != nil {
		return oauthStartResult{}, errors.New("MCP server must be a public HTTPS URL without query or credentials")
	}
	if !m.allowPrivate {
		if err := ensurePublicOAuthHost(ctx, server.Hostname()); err != nil {
			return oauthStartResult{}, err
		}
	}
	expectedRedirect := m.portalOrigin + "/api/mcp/oauth/callback"
	if request.RedirectURI != expectedRedirect {
		return oauthStartResult{}, errors.New("OAuth redirect URI does not match the configured Portal")
	}
	m.mu.Lock()
	m.purgeLocked(m.now())
	full := len(m.flows) >= maxOAuthFlows
	m.mu.Unlock()
	if full {
		return oauthStartResult{}, errors.New("too many pending OAuth flows")
	}
	operation, cancel := context.WithTimeout(ctx, oauthOperationTimeout)
	defer cancel()
	metadata, err := m.discover(operation, server.String())
	if err != nil {
		return oauthStartResult{}, err
	}
	authorization, err := validateOAuthURL(metadata.AuthorizationEndpoint, true, m.allowPrivate)
	if err != nil {
		return oauthStartResult{}, errors.New("OAuth authorization endpoint is invalid")
	}
	token, err := validateOAuthURL(metadata.TokenEndpoint, true, m.allowPrivate)
	if err != nil {
		return oauthStartResult{}, errors.New("OAuth token endpoint is invalid")
	}
	if !m.allowPrivate {
		if err := ensurePublicOAuthHost(operation, authorization.Hostname()); err != nil {
			return oauthStartResult{}, err
		}
		if err := ensurePublicOAuthHost(operation, token.Hostname()); err != nil {
			return oauthStartResult{}, err
		}
	}
	verifier, err := randomOAuthTokenBytes(32)
	if err != nil {
		return oauthStartResult{}, err
	}
	flowValue, err := randomOAuthTokenBytes(32)
	if err != nil {
		clear(verifier)
		return oauthStartResult{}, err
	}
	flowID := string(flowValue)
	clear(flowValue)
	challenge := sha256.Sum256(verifier)
	query := authorization.Query()
	query.Set("response_type", "code")
	query.Set("client_id", "aionui")
	query.Set("redirect_uri", expectedRedirect)
	query.Set("state", request.State)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	authorization.RawQuery = query.Encode()
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(now)
	if len(m.flows) >= maxOAuthFlows {
		clear(verifier)
		return oauthStartResult{}, errors.New("too many pending OAuth flows")
	}
	if _, duplicate := m.flows[flowID]; duplicate {
		clear(verifier)
		return oauthStartResult{}, errors.New("OAuth flow identifier collision")
	}
	m.flows[flowID] = oauthFlow{serverURL: server.String(), tokenURL: token.String(), redirectURI: expectedRedirect, verifier: verifier, expiresAt: now.Add(oauthFlowTTL)}
	return oauthStartResult{AuthorizationURL: authorization.String(), FlowID: flowID}, nil
}

func (m *oauthManager) complete(ctx context.Context, request oauthCompleteRequest) error {
	if !validOAuthToken(request.FlowID, 32) || request.Code == "" || len(request.Code) > 16*1024 || strings.IndexByte(request.Code, 0) >= 0 {
		return errors.New("OAuth completion payload is invalid")
	}
	flow, ok := m.take(request.FlowID)
	if !ok {
		return errors.New("OAuth flow is missing, expired, or already consumed")
	}
	defer clear(flow.verifier)
	if request.ServerURL != flow.serverURL {
		return errors.New("OAuth flow target changed")
	}
	operation, cancel := context.WithTimeout(ctx, oauthOperationTimeout)
	defer cancel()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {request.Code}, "redirect_uri": {flow.redirectURI}, "client_id": {"aionui"}, "code_verifier": {string(flow.verifier)}}
	httpRequest, err := http.NewRequestWithContext(operation, http.MethodPost, flow.tokenURL, strings.NewReader(form.Encode()))
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
	payload, err := readOAuthBody(response.Body)
	if err != nil {
		return err
	}
	defer clear(payload)
	var token oauthTokenResponse
	if err := json.Unmarshal(payload, &token); err != nil || token.AccessToken == "" || len(token.AccessToken) > maxOAuthToken || len(token.RefreshToken) > maxOAuthToken || !strings.EqualFold(token.TokenType, "bearer") {
		return errors.New("OAuth token response is invalid")
	}
	defer func() { token.AccessToken, token.RefreshToken = "", "" }()
	expiresAt, err := oauthExpiry(token.ExpiresIn, m.now())
	if err != nil {
		return err
	}
	return m.persistToken(operation, flow.serverURL, token.AccessToken, token.RefreshToken, expiresAt)
}

func (m *oauthManager) cancel(request oauthCancelRequest) error {
	if !validOAuthToken(request.FlowID, 32) {
		return errors.New("invalid OAuth flow identifier")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	flow, found := m.flows[request.FlowID]
	if !found {
		return nil
	}
	if flow.serverURL != request.ServerURL {
		return errors.New("OAuth cancellation target changed")
	}
	delete(m.flows, request.FlowID)
	clear(flow.verifier)
	return nil
}

func (m *oauthManager) take(flowID string) (oauthFlow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.purgeLocked(now)
	flow, found := m.flows[flowID]
	if !found || !flow.expiresAt.After(now) {
		return oauthFlow{}, false
	}
	delete(m.flows, flowID)
	return flow, true
}

func (m *oauthManager) purgeLocked(now time.Time) {
	for id, flow := range m.flows {
		if !flow.expiresAt.After(now) {
			delete(m.flows, id)
			clear(flow.verifier)
		}
	}
}

func (m *oauthManager) discover(ctx context.Context, server string) (oauthMetadata, error) {
	base := strings.TrimRight(server, "/")
	for _, suffix := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+suffix, nil)
		request.Header.Set("Accept", "application/json")
		response, err := m.client.Do(request)
		if err != nil {
			continue
		}
		payload, readErr := readOAuthBody(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
			clear(payload)
			continue
		}
		var metadata oauthMetadata
		decodeErr := json.Unmarshal(payload, &metadata)
		clear(payload)
		if decodeErr == nil && metadata.AuthorizationEndpoint != "" && metadata.TokenEndpoint != "" {
			return metadata, nil
		}
	}
	return oauthMetadata{}, errors.New("OAuth discovery failed")
}

func (m *oauthManager) persistToken(ctx context.Context, serverURL, accessToken, refreshToken string, expiresAt *int64) error {
	file, err := m.root.Open(m.databasePath, unix.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open OAuth token database")
	}
	info, statErr := file.Stat()
	file.Close()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("OAuth token database is not protected")
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(m.root.Path(), m.databasePath)) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return errors.New("open OAuth token database")
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return errors.New("begin OAuth token transaction")
	}
	defer transaction.Rollback()
	columns, err := sqliteOAuthColumns(ctx, transaction)
	if err != nil || !slices.Equal(columns, oauthTokenColumns) {
		return errors.New("OAuth token database schema is unsupported")
	}
	var refresh, expiry any
	if refreshToken != "" {
		refresh = refreshToken
	}
	if expiresAt != nil {
		expiry = *expiresAt
	}
	stamp := m.now().UnixMilli()
	result, err := transaction.ExecContext(ctx, `INSERT INTO oauth_tokens(server_url,access_token,refresh_token,token_type,expires_at,created_at,updated_at) VALUES(?,?,?,'bearer',?,?,?) ON CONFLICT(server_url) DO UPDATE SET access_token=excluded.access_token,refresh_token=excluded.refresh_token,token_type=excluded.token_type,expires_at=excluded.expires_at,updated_at=excluded.updated_at`, serverURL, accessToken, refresh, expiry, stamp, stamp)
	if err != nil {
		return errors.New("write OAuth token")
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("OAuth token write did not affect exactly one row")
	}
	if err := transaction.Commit(); err != nil {
		return errors.New("commit OAuth token")
	}
	return nil
}

func sqliteOAuthColumns(ctx context.Context, transaction *sql.Tx) ([]string, error) {
	rows, err := transaction.QueryContext(ctx, `PRAGMA table_info(oauth_tokens)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func validateOAuthURL(raw string, queryAllowed, privateAllowed bool) (*url.URL, error) {
	if raw == "" || len(raw) > 4096 || strings.TrimSpace(raw) != raw || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, errors.New("invalid OAuth URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" || (!queryAllowed && (parsed.RawQuery != "" || parsed.ForceQuery)) || strings.Contains(parsed.Hostname(), "%") {
		return nil, errors.New("invalid OAuth URL")
	}
	if literal := net.ParseIP(parsed.Hostname()); literal != nil && !privateAllowed && forbiddenOAuthIP(literal) {
		return nil, errors.New("OAuth URL is not public")
	}
	return parsed, nil
}

func ensurePublicOAuthHost(ctx context.Context, host string) error {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return errors.New("OAuth endpoint DNS resolution failed")
	}
	for _, address := range addresses {
		if forbiddenOAuthIP(address.IP) {
			return errors.New("OAuth endpoint resolved to a non-public address")
		}
	}
	return nil
}

func randomOAuthTokenBytes(size int) ([]byte, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(size))
	base64.RawURLEncoding.Encode(encoded, raw)
	return encoded, nil
}

func validOAuthToken(value string, size int) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	defer clear(decoded)
	return err == nil && len(decoded) == size
}

func readOAuthBody(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maxOAuthDocument+1))
	if err != nil || len(payload) > maxOAuthDocument {
		clear(payload)
		return nil, errors.New("OAuth response exceeded its limit")
	}
	return payload, nil
}

func oauthExpiry(raw json.RawMessage, now time.Time) (*int64, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
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
