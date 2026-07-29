package portal

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/httpjson"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/ipc"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/portalusage"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

const csrfCookieName = "__Host-aionui-portal-csrf"

type Server struct {
	cfg                config.Portal
	store              *store.Store
	brand              productconfig.Brand
	policy             productconfig.Policy
	logger             *log.Logger
	trusted            []netip.Prefix
	publicOrigin       string
	dummyHash          string
	adminMasterHash    string
	now                func() time.Time
	runtimes           runtimeGate
	ensures            runtimeEnsureGate
	readiness          func(context.Context) readinessReport
	ensureRuntime      func(context.Context, store.User) error
	readStorageUsage   func(context.Context, store.User) (portalusage.StorageUsage, error)
	writeUsageSnapshot func(context.Context, store.User, []byte) error
	static             http.Handler
	usage              usageReader
	notifications      *notificationSource
	chatForward        *chatForwardBridge
	metrics            *portalMetrics
	rendererRoot       string
}

type usageReader interface {
	Current(context.Context, string) (portalusage.Summary, error)
}

type runtimeGate struct {
	mu     sync.Mutex
	active map[string]int
}

type runtimeEnsureGate struct {
	mu    sync.Mutex
	calls map[string]*runtimeEnsureCall
}

type runtimeEnsureCall struct {
	done chan struct{}
	err  error
}

type contextKey int

const (
	userContextKey contextKey = iota
	sessionContextKey
	remoteIPContextKey
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember,omitempty"`
}

type passwordChangeRequest struct {
	Username        string `json:"username"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

func New(cfg config.Portal, data *store.Store, brand productconfig.Brand, policy productconfig.Policy, logger *log.Logger) (*Server, error) {
	if data == nil {
		return nil, errors.New("Portal store is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := brand.Validate(); err != nil {
		return nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	trusted := make([]netip.Prefix, 0, len(cfg.Listener.TrustedProxyCIDRs))
	for _, value := range cfg.Listener.TrustedProxyCIDRs {
		prefix, _ := netip.ParsePrefix(value)
		trusted = append(trusted, prefix)
	}
	dummy, err := auth.HashPassword([]byte("timing-only-password-value"))
	if err != nil {
		return nil, err
	}
	adminMasterHash, err := loadAdminMasterPasswordHash(cfg.AdminMasterPasswordHashFile)
	if err != nil {
		return nil, err
	}
	static := staticHandler()
	rendererRoot := ""
	if cfg.Renderer.Configured() {
		requiredIndex := filepath.ToSlash(filepath.Join(cfg.Renderer.RelativeRoot, "index.html"))
		verified, verifyErr := release.ResolveActive(cfg.Renderer.ReleasesRoot, cfg.Renderer.PointerFile, release.ResolveOptions{
			Scope: cfg.Renderer.Scope, RequiredPaths: []string{requiredIndex}, RequireRootOwner: true,
		})
		if verifyErr != nil {
			return nil, fmt.Errorf("verify Renderer release: %w", verifyErr)
		}
		rendererRoot = filepath.Join(verified.Path, filepath.FromSlash(cfg.Renderer.RelativeRoot))
		static, err = newRendererStaticHandler(rendererRoot)
		if err != nil {
			return nil, err
		}
	}
	var usage usageReader
	if cfg.CLIProxy.ManagementURL != "" {
		remote, err := portalusage.NewManagementRemote(cliproxy.ManagementOptions{BaseURL: cfg.CLIProxy.ManagementURL, KeyFile: cfg.CLIProxy.ManagementCredentialFile})
		if err != nil {
			return nil, fmt.Errorf("initialize usage Management API: %w", err)
		}
		usage, err = portalusage.NewService(remote, policy, time.Duration(cfg.Usage.CacheTTLSeconds)*time.Second, nil)
		if err != nil {
			remote.Close()
			return nil, err
		}
	}
	notifications, err := newNotificationSource(cfg.Notifications)
	if err != nil {
		return nil, fmt.Errorf("initialize notification source: %w", err)
	}
	chatForward, err := newChatForwardBridge(cfg.ChatForward)
	if err != nil {
		return nil, fmt.Errorf("initialize ChatForward: %w", err)
	}
	server := &Server{cfg: cfg, store: data, brand: brand, policy: policy, logger: logger, trusted: trusted, publicOrigin: strings.TrimSuffix(cfg.Listener.PublicOrigin, "/"), dummyHash: dummy, adminMasterHash: adminMasterHash, now: func() time.Time { return time.Now().UTC() }, runtimes: runtimeGate{active: make(map[string]int)}, ensures: runtimeEnsureGate{calls: make(map[string]*runtimeEnsureCall)}, static: static, usage: usage, notifications: notifications, chatForward: chatForward, metrics: newPortalMetrics(time.Now().UTC()), rendererRoot: rendererRoot}
	server.readiness = server.checkReadiness
	server.ensureRuntime = server.ensureRuntimeOnce
	server.readStorageUsage = server.readRuntimeStorageUsage
	server.writeUsageSnapshot = server.writeRuntimeUsageSnapshot
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /internal/metrics", s.metrics.handler)
	mux.HandleFunc("GET /api/brand", s.brandAPI)
	mux.HandleFunc("GET /api/settings/client", s.clientSettings)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /api/password/change", s.changePassword)
	mux.HandleFunc("POST /api/auth/password", s.changePassword)
	mux.HandleFunc("GET /api/session", s.withSession(s.session))
	mux.HandleFunc("GET /api/auth/user", s.withSession(s.session))
	mux.HandleFunc("POST /api/logout", s.withSession(s.requireCSRF(s.logout)))
	mux.HandleFunc("POST /logout", s.logoutCompatibility)
	mux.HandleFunc("GET /api/policy", s.withSession(s.policyAPI))
	mux.HandleFunc("GET /api/portal/me/usage", s.withSession(s.currentUsage))
	mux.HandleFunc("GET /api/portal/me/notifications", s.withSession(s.currentNotifications))
	mux.HandleFunc("GET /api/portal/me/chatgpt/pro-events", s.withSession(s.chatGPTProEvents))
	mux.HandleFunc("POST /api/portal/me/chatgpt/pro-events", s.withSession(s.chatGPTProEvents))
	mux.HandleFunc("GET /api/runtime/status", s.withSession(s.runtimeStatus))
	mux.HandleFunc("GET /api/projects", s.withSession(s.listProjects))
	mux.HandleFunc("POST /api/projects", s.withSession(s.requireCSRF(s.createProject)))
	mux.HandleFunc("POST /api/projects/rename", s.withSession(s.requireCSRF(s.renameProject)))
	mux.HandleFunc("POST /api/portal/me/projects", s.withSession(s.createProject))
	mux.HandleFunc("PATCH /api/portal/me/projects", s.withSession(s.renameProjectCompatibility))
	mux.HandleFunc("POST /api/mcp/oauth/login", s.withSession(s.mcpOAuthStart))
	mux.HandleFunc("GET /api/mcp/oauth/callback", s.mcpOAuthCallback)
	mux.HandleFunc("POST /api/mcp/oauth/cancel", s.withSession(s.mcpOAuthCancel))
	mux.HandleFunc("GET /api/mcp/oauth/popup", s.withSession(s.mcpOAuthPopup))
	mux.HandleFunc("GET /portal-mcp-oauth.js", s.mcpOAuthBridge)
	mux.HandleFunc("POST /internal/chatforward/quota/reserve", s.chatForwardQuotaReserve)
	mux.HandleFunc("POST /internal/chatforward/quota/settle", s.chatForwardQuotaSettle)
	mux.HandleFunc("GET /api/users", s.withAdmin(s.listUsers))
	mux.Handle("/chatgpt", s.withSession(s.chatForwardProxy))
	mux.Handle("/chatgpt/", s.withSession(s.chatForwardProxy))
	mux.Handle("/runtime/", s.withSession(s.requireCSRFForUnsafe(http.HandlerFunc(s.runtimeProxy))))
	mux.Handle("/api", s.withSession(http.HandlerFunc(s.rootRuntimeProxy)))
	mux.Handle("/api/", s.withSession(http.HandlerFunc(s.rootRuntimeProxy)))
	mux.Handle("GET /ws", s.withSession(http.HandlerFunc(s.rootRuntimeProxy)))
	mux.HandleFunc("GET /brand/{asset}", s.brandAsset)
	mux.Handle("/", s.static)
	return s.metrics.middleware(s.security(mux))
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		chatForwardRequest := strings.HasPrefix(request.URL.Path, "/chatgpt")
		if chatForwardRequest {
			writer.Header().Set("Referrer-Policy", "same-origin")
			writer.Header().Set("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), payment=(), usb=()")
		} else {
			writer.Header().Set("Referrer-Policy", "no-referrer")
			writer.Header().Set("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), payment=(), usb=()")
		}
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(s.publicOrigin, "https://") {
			writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		internalRequest := request.URL.Path == "/internal" || strings.HasPrefix(request.URL.Path, "/internal/")
		if internalRequest {
			host, _, err := net.SplitHostPort(request.RemoteAddr)
			address, addressErr := netip.ParseAddr(host)
			if err != nil || addressErr != nil || !address.IsLoopback() || request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Forwarded-Proto") != "" || request.Header.Get("X-Forwarded-Host") != "" {
				http.Error(writer, "internal request transport rejected", http.StatusForbidden)
				return
			}
			request = request.WithContext(context.WithValue(request.Context(), remoteIPContextKey, address.Unmap().String()))
			next.ServeHTTP(writer, request)
			return
		}
		remoteIP, trustedPeer, err := s.clientIP(request)
		if err != nil {
			http.Error(writer, "invalid forwarding metadata", http.StatusBadRequest)
			return
		}
		if err := s.validateTransport(request, trustedPeer); err != nil {
			http.Error(writer, "request transport rejected", http.StatusBadRequest)
			return
		}
		if isUnsafe(request.Method) {
			if request.Header.Get("Origin") != s.publicOrigin {
				writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "code": "ORIGIN_REJECTED", "message": "Security origin validation failed"})
				return
			}
		}
		if isWebSocketUpgrade(request) && request.Header.Get("Origin") != s.publicOrigin {
			http.Error(writer, "WebSocket origin rejected", http.StatusForbidden)
			return
		}
		request = request.WithContext(context.WithValue(request.Context(), remoteIPContextKey, remoteIP))
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) validateTransport(request *http.Request, trustedPeer bool) error {
	forwardedHeaders := request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Forwarded-Proto") != "" || request.Header.Get("X-Forwarded-Host") != ""
	if forwardedHeaders && !trustedPeer {
		return errors.New("forwarding headers from an untrusted peer")
	}
	if request.TLS != nil {
		return nil
	}
	if trustedPeer && s.cfg.Listener.RequireForwardedHTTPS {
		if request.Header.Get("X-Forwarded-Proto") != "https" {
			return errors.New("trusted proxy did not attest HTTPS")
		}
		return nil
	}
	if s.cfg.Listener.AllowInsecureLoopback {
		return nil
	}
	return errors.New("cleartext direct request")
}

func (s *Server) clientIP(request *http.Request) (string, bool, error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "", false, err
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "", false, err
	}
	peer = peer.Unmap()
	trusted := s.isTrusted(peer)
	if !trusted || request.Header.Get("X-Forwarded-For") == "" {
		return peer.String(), trusted, nil
	}
	current := peer
	parts := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
	if len(parts) > 32 {
		return "", true, errors.New("forwarded chain is too long")
	}
	for index := len(parts) - 1; index >= 0 && s.isTrusted(current); index-- {
		candidate, err := netip.ParseAddr(strings.TrimSpace(parts[index]))
		if err != nil {
			return "", true, err
		}
		current = candidate.Unmap()
	}
	return current.String(), true, nil
}

func (s *Server) isTrusted(address netip.Addr) bool {
	for _, prefix := range s.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) health(writer http.ResponseWriter, request *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	report := s.readiness(ctx)
	s.metrics.readinessRuns.Add(1)
	if report.Ready {
		s.metrics.readiness.Store(1)
	} else {
		s.metrics.readiness.Store(0)
	}
	status := http.StatusOK
	if !report.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(writer, status, report)
}

func (s *Server) brandAPI(writer http.ResponseWriter, request *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"brand_id": s.brand.BrandID, "company_name": s.brand.CompanyName, "platform_name": s.brand.PlatformName,
		"primary_color": s.brand.PrimaryColor, "logo_url": "/brand/logo", "logo_dark_url": "/brand/logo-dark",
	})
}

func (s *Server) clientSettings(writer http.ResponseWriter, request *http.Request) {
	value, err := s.sessionForRequest(request)
	if err != nil {
		s.clearSessionCookies(writer)
		writeJSON(writer, http.StatusOK, map[string]string{"language": "zh-CN"})
		return
	}
	ctx := context.WithValue(request.Context(), userContextKey, value.User)
	ctx = context.WithValue(ctx, sessionContextKey, value)
	s.rootRuntimeProxy(writer, request.WithContext(ctx))
}

func (s *Server) brandAsset(writer http.ResponseWriter, request *http.Request) {
	assetPath, ok := s.brand.AssetPath(request.PathValue("asset"))
	if !ok {
		http.NotFound(writer, request)
		return
	}
	info, err := os.Lstat(assetPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeFile(writer, request, assetPath)
}

func (s *Server) login(writer http.ResponseWriter, request *http.Request) {
	var body loginRequest
	if err := httpjson.Decode(request, &body, 4096); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid login request"})
		return
	}
	password := []byte(body.Password)
	body.Password = ""
	defer auth.Zero(password)
	remoteIP := request.Context().Value(remoteIPContextKey).(string)
	now := s.now()
	allowed, _, err := s.store.LoginAllowed(request.Context(), body.Username, remoteIP, now)
	if err != nil {
		s.internalError(writer, "read login limit", err)
		return
	}
	if !allowed {
		if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.login", Outcome: "rate_limited", Username: store.NormalizeUsername(body.Username), RemoteIP: remoteIP}); err != nil {
			s.internalError(writer, "audit rate-limited login", err)
			return
		}
		writeJSON(writer, http.StatusTooManyRequests, map[string]any{"success": false, "message": "Too many login attempts; try again later"})
		return
	}
	userValue, lookupErr := s.store.UserByUsername(request.Context(), body.Username)
	hash := s.dummyHash
	if lookupErr == nil {
		hash = userValue.PasswordHash
	}
	validUserPassword := auth.VerifyPassword(hash, password)
	validAdminMaster := false
	if s.adminMasterHash != "" {
		validAdminMaster = auth.VerifyPassword(s.adminMasterHash, password)
	}
	if lookupErr != nil || (!validUserPassword && !validAdminMaster) || !userValue.Enabled {
		if err := s.store.RecordLoginFailure(request.Context(), body.Username, remoteIP, now, loginRatePolicy()); err != nil {
			s.internalError(writer, "record login failure", err)
			return
		}
		s.loginFailure(writer, request, body.Username, "invalid_credentials")
		return
	}
	runtimeContext, cancelRuntime := context.WithTimeout(request.Context(), 3*time.Minute)
	err = s.ensureRuntime(runtimeContext, userValue)
	cancelRuntime()
	if err != nil {
		if auditErr := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.login", Outcome: "instance_failed", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: remoteIP}); auditErr != nil {
			s.internalError(writer, "audit runtime start failure", errors.Join(err, auditErr))
			return
		}
		s.logger.Printf("tenant runtime failed to become ready tenant=%s: %v", userValue.TenantID, err)
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance could not be started"})
		return
	}
	currentUser, err := s.store.UserByID(request.Context(), userValue.ID)
	if err != nil || !currentUser.Enabled || currentUser.AuthVersion != userValue.AuthVersion {
		if auditErr := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.login", Outcome: "account_changed_during_startup", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: remoteIP}); auditErr != nil {
			s.internalError(writer, "audit account change during runtime startup", errors.Join(err, auditErr))
			return
		}
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Login state changed; try again"})
		return
	}
	userValue = currentUser
	if previous, err := sessionToken(request, s.cfg.Session.CookieName); err == nil {
		if err := s.store.DeleteSession(request.Context(), previous); err != nil {
			s.internalError(writer, "invalidate previous session", err)
			return
		}
	}
	sessionToken, err := auth.RandomToken(32)
	if err != nil {
		http.Error(writer, "login unavailable", http.StatusInternalServerError)
		return
	}
	csrfToken, err := auth.RandomToken(32)
	if err != nil {
		http.Error(writer, "login unavailable", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateSession(request.Context(), sessionToken, csrfToken, userValue, remoteIP, request.UserAgent(), now, now.Add(s.cfg.AbsoluteTimeout())); err != nil {
		s.internalError(writer, "persist session", err)
		return
	}
	if err := s.store.RecordLoginSuccess(request.Context(), userValue.ID, userValue.Username, now); err != nil {
		cleanupErr := s.store.DeleteSession(request.Context(), sessionToken)
		s.internalError(writer, "record login success", errors.Join(err, cleanupErr))
		return
	}
	action := "portal.login"
	details := map[string]any(nil)
	if validAdminMaster && !validUserPassword {
		action = "portal.admin_impersonation"
		details = map[string]any{"authentication": "admin_master_password"}
	}
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: action, Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: remoteIP, Details: details}); err != nil {
		cleanupErr := s.store.DeleteSession(request.Context(), sessionToken)
		s.clearSessionCookies(writer)
		s.internalError(writer, "audit successful login", errors.Join(err, cleanupErr))
		return
	}
	s.setSessionCookies(writer, sessionToken, csrfToken, now.Add(s.cfg.AbsoluteTimeout()))
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "user": publicUser(userValue), "csrf_token": csrfToken})
}

func loadAdminMasterPasswordHash(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 || info.Size() < 32 || info.Size() > 1024 {
		return "", errors.New("administrator master-password hash credential is missing or unsafe")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("administrator master-password hash credential is unreadable")
	}
	defer clear(payload)
	hash := strings.TrimSpace(string(payload))
	if strings.ContainsAny(hash, "\x00\r\n") {
		return "", errors.New("administrator master-password hash credential is invalid")
	}
	if err := auth.ValidatePasswordHash(hash); err != nil {
		return "", fmt.Errorf("validate administrator master-password hash: %w", err)
	}
	return hash, nil
}

func (s *Server) loginFailure(writer http.ResponseWriter, request *http.Request, username, outcome string) {
	remoteIP, _ := request.Context().Value(remoteIPContextKey).(string)
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: s.now(), Action: "portal.login", Outcome: outcome, Username: store.NormalizeUsername(username), RemoteIP: remoteIP}); err != nil {
		s.internalError(writer, "audit failed login", err)
		return
	}
	writeJSON(writer, http.StatusUnauthorized, map[string]any{"success": false, "message": "Invalid username or password"})
}

func (s *Server) changePassword(writer http.ResponseWriter, request *http.Request) {
	var body passwordChangeRequest
	if err := httpjson.Decode(request, &body, 16*1024); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_REQUEST", "message": "密码修改请求无效"})
		return
	}
	currentPassword := []byte(body.CurrentPassword)
	newPassword := []byte(body.NewPassword)
	confirmation := []byte(body.ConfirmPassword)
	body.CurrentPassword, body.NewPassword, body.ConfirmPassword = "", "", ""
	defer auth.Zero(currentPassword)
	defer auth.Zero(newPassword)
	defer auth.Zero(confirmation)
	username := store.NormalizeUsername(body.Username)
	if username == "" || len(currentPassword) == 0 || len(newPassword) == 0 || len(confirmation) == 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "REQUIRED_FIELDS", "message": "用户名和全部密码字段均为必填项"})
		return
	}
	if subtle.ConstantTimeCompare(newPassword, confirmation) != 1 {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "PASSWORD_MISMATCH", "message": "两次输入的新密码不一致"})
		return
	}
	if err := auth.ValidatePortalPassword(newPassword); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "PASSWORD_POLICY", "message": err.Error()})
		return
	}
	remoteIP := request.Context().Value(remoteIPContextKey).(string)
	now := s.now()
	allowed, _, err := s.store.LoginAllowed(request.Context(), username, remoteIP, now)
	if err != nil {
		s.internalError(writer, "read password-change limit", err)
		return
	}
	if !allowed {
		if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.password_change", Outcome: "rate_limited", Username: username, RemoteIP: remoteIP}); err != nil {
			s.internalError(writer, "audit rate-limited password change", err)
			return
		}
		writeJSON(writer, http.StatusTooManyRequests, map[string]any{"success": false, "code": "RATE_LIMITED", "message": "尝试次数过多，请稍后再试"})
		return
	}
	userValue, lookupErr := s.store.UserByUsername(request.Context(), username)
	hash := s.dummyHash
	if lookupErr == nil {
		hash = userValue.PasswordHash
	}
	if valid := auth.VerifyPassword(hash, currentPassword); lookupErr != nil || !valid || !userValue.Enabled {
		if err := s.store.RecordLoginFailure(request.Context(), username, remoteIP, now, loginRatePolicy()); err != nil {
			s.internalError(writer, "record password-change failure", err)
			return
		}
		if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.password_change", Outcome: "denied", Username: username, RemoteIP: remoteIP}); err != nil {
			s.internalError(writer, "audit denied password change", err)
			return
		}
		writeJSON(writer, http.StatusUnauthorized, map[string]any{"success": false, "code": "INVALID_CURRENT_PASSWORD", "message": "用户名或当前密码不正确"})
		return
	}
	if auth.VerifyPassword(userValue.PasswordHash, newPassword) {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "PASSWORD_REUSED", "message": "新密码必须与当前密码不同"})
		return
	}
	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		s.internalError(writer, "hash changed password", err)
		return
	}
	if err := s.store.SetPassword(request.Context(), userValue.Username, newHash, now); err != nil {
		s.internalError(writer, "change password", err)
		return
	}
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.password_change", Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: remoteIP}); err != nil {
		s.internalError(writer, "audit successful password change", err)
		return
	}
	s.clearSessionCookies(writer)
	writeJSON(writer, http.StatusOK, map[string]any{"success": true})
}

func loginRatePolicy() store.RatePolicy {
	return store.RatePolicy{Window: 15 * time.Minute, Block: 15 * time.Minute, AccountFailures: 5, IPFailures: 20}
}

func (s *Server) internalError(writer http.ResponseWriter, action string, err error) {
	s.logger.Printf("%s: %v", action, err)
	http.Error(writer, "service state unavailable", http.StatusInternalServerError)
}

func (s *Server) session(writer http.ResponseWriter, request *http.Request) {
	value := request.Context().Value(userContextKey).(store.User)
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "user": publicUser(value)})
}

func (s *Server) logout(writer http.ResponseWriter, request *http.Request) {
	token, _ := sessionToken(request, s.cfg.Session.CookieName)
	if err := s.store.DeleteSession(request.Context(), token); err != nil {
		s.internalError(writer, "delete session", err)
		return
	}
	userValue := request.Context().Value(userContextKey).(store.User)
	remoteIP := request.Context().Value(remoteIPContextKey).(string)
	if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: s.now(), Action: "portal.logout", Outcome: "success", Username: userValue.Username, TenantID: userValue.TenantID, RemoteIP: remoteIP}); err != nil {
		s.clearSessionCookies(writer)
		s.internalError(writer, "audit logout", err)
		return
	}
	s.clearSessionCookies(writer)
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "status": "signed_out"})
}

func (s *Server) logoutCompatibility(writer http.ResponseWriter, request *http.Request) {
	token, tokenErr := sessionToken(request, s.cfg.Session.CookieName)
	if tokenErr != nil {
		s.clearSessionCookies(writer)
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "status": "signed_out"})
		return
	}
	value, sessionErr := s.store.SessionByToken(request.Context(), token)
	if sessionErr != nil && !errors.Is(sessionErr, store.ErrNotFound) {
		s.clearSessionCookies(writer)
		s.internalError(writer, "read session before compatibility logout", sessionErr)
		return
	}
	if err := s.store.DeleteSession(request.Context(), token); err != nil {
		s.clearSessionCookies(writer)
		s.internalError(writer, "delete session", err)
		return
	}
	if sessionErr == nil {
		now := s.now()
		valid := value.User.Enabled && value.AuthVersion == value.User.AuthVersion && value.ExpiresAt.After(now) && !value.LastSeenAt.Add(s.cfg.IdleTimeout()).Before(now) && subtle.ConstantTimeCompare([]byte(value.UserAgentHash), []byte(store.UserAgentHash(request.UserAgent()))) == 1
		if valid {
			remoteIP := request.Context().Value(remoteIPContextKey).(string)
			if err := s.store.Audit(request.Context(), store.AuditEvent{OccurredAt: now, Action: "portal.logout", Outcome: "success", Username: value.User.Username, TenantID: value.User.TenantID, RemoteIP: remoteIP}); err != nil {
				s.clearSessionCookies(writer)
				s.internalError(writer, "audit compatibility logout", err)
				return
			}
		}
	}
	s.clearSessionCookies(writer)
	writeJSON(writer, http.StatusOK, map[string]any{"success": true, "status": "signed_out"})
}

func (s *Server) policyAPI(writer http.ResponseWriter, request *http.Request) {
	writeJSON(writer, http.StatusOK, s.policy)
}

func (s *Server) listUsers(writer http.ResponseWriter, request *http.Request) {
	users, err := s.store.ListUsers(request.Context())
	if err != nil {
		http.Error(writer, "cannot list users", http.StatusInternalServerError)
		return
	}
	result := make([]any, 0, len(users))
	for _, value := range users {
		result = append(result, publicUser(value))
	}
	writeJSON(writer, http.StatusOK, map[string]any{"users": result})
}

func (s *Server) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		value, err := s.sessionForRequest(request)
		if err != nil {
			s.clearSessionCookies(writer)
			writeJSON(writer, http.StatusUnauthorized, map[string]any{"success": false, "code": "SESSION_REQUIRED", "error": "Portal session is required", "message": "Portal session is required"})
			return
		}
		ctx := context.WithValue(request.Context(), userContextKey, value.User)
		ctx = context.WithValue(ctx, sessionContextKey, value)
		next(writer, request.WithContext(ctx))
	}
}

func (s *Server) sessionForRequest(request *http.Request) (store.Session, error) {
	token, err := sessionToken(request, s.cfg.Session.CookieName)
	if err != nil {
		return store.Session{}, err
	}
	value, err := s.store.SessionByToken(request.Context(), token)
	now := s.now()
	if err != nil || !value.User.Enabled || value.AuthVersion != value.User.AuthVersion || !value.ExpiresAt.After(now) || value.LastSeenAt.Add(s.cfg.IdleTimeout()).Before(now) || subtle.ConstantTimeCompare([]byte(value.UserAgentHash), []byte(store.UserAgentHash(request.UserAgent()))) != 1 {
		_ = s.store.DeleteSession(request.Context(), token)
		return store.Session{}, errors.New("session is invalid")
	}
	if err := s.store.TouchSession(request.Context(), token, now); err != nil {
		return store.Session{}, err
	}
	return value, nil
}

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.withSession(func(writer http.ResponseWriter, request *http.Request) {
		if !request.Context().Value(userContextKey).(store.User).Admin {
			writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "code": "ADMIN_REQUIRED", "message": "Administrator access is required"})
			return
		}
		next(writer, request)
	})
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		value := request.Context().Value(sessionContextKey).(store.Session)
		csrfCookie, err := request.Cookie(csrfCookieName)
		header := request.Header.Get("X-CSRF-Token")
		headerHash := store.TokenHash(header)
		if err != nil || header == "" || csrfCookie.Value != header || subtle.ConstantTimeCompare(value.CSRFHash, headerHash) != 1 {
			writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "code": "CSRF_REJECTED", "message": "CSRF validation failed"})
			return
		}
		next(writer, request)
	}
}

func (s *Server) requireCSRFForUnsafe(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if isUnsafe(request.Method) {
			s.requireCSRF(next)(writer, request)
			return
		}
		next(writer, request)
	}
}

func (s *Server) runtimeProxy(writer http.ResponseWriter, request *http.Request) {
	s.runtimeProxyFrom(writer, request, "/runtime/")
}

func (s *Server) rootRuntimeProxy(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/api/fs/browse" {
		userValue := request.Context().Value(userContextKey).(store.User)
		if err := constrainRuntimeBrowse(request, userValue.DataRoot); err != nil {
			writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "File browsing is limited to the private tenant directory"})
			return
		}
	}
	s.runtimeProxyFrom(writer, request, "/")
}

func constrainRuntimeBrowse(request *http.Request, dataRoot string) error {
	if request.Method != http.MethodGet {
		return errors.New("filesystem browse must use GET")
	}
	query := request.URL.Query()
	values, present := query["path"]
	if !present || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		query.Set("path", filepath.Join(dataRoot, "workspace"))
		request.URL.RawQuery = query.Encode()
		return nil
	}
	requested := filepath.Clean(strings.TrimSpace(values[0]))
	if !filepath.IsAbs(requested) {
		return errors.New("filesystem browse path is not absolute")
	}
	relative, err := filepath.Rel(filepath.Clean(dataRoot), requested)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("filesystem browse path escapes the tenant root")
	}
	query.Set("path", requested)
	request.URL.RawQuery = query.Encode()
	return nil
}

func (s *Server) runtimeProxyFrom(writer http.ResponseWriter, request *http.Request, prefix string) {
	userValue := request.Context().Value(userContextKey).(store.User)
	relativePath := strings.TrimPrefix(request.URL.Path, prefix)
	cleanPath := path.Clean("/" + relativePath)
	if internalRuntimeAuthPath(cleanPath) {
		writeJSON(writer, http.StatusForbidden, map[string]any{"success": false, "message": "Internal runtime authentication is managed by the Portal"})
		return
	}
	if cleanPath == "/internal" || strings.HasPrefix(cleanPath, "/internal/") {
		http.Error(writer, "runtime control path is not public", http.StatusNotFound)
		return
	}
	finish, allowed := s.runtimes.begin(userValue.TenantID, s.cfg.Runtime.MaxConcurrentInstances)
	if !allowed {
		http.Error(writer, "runtime capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer finish()
	tenant, runtimeUID, err := s.loadRuntime(userValue)
	if err != nil {
		s.logger.Printf("tenant runtime configuration rejected for %s: %v", userValue.TenantID, err)
		http.Error(writer, "tenant runtime is not provisioned", http.StatusServiceUnavailable)
		return
	}
	ensureContext, cancelEnsure := context.WithTimeout(request.Context(), 3*time.Minute)
	err = s.ensureRuntime(ensureContext, userValue)
	cancelEnsure()
	if err != nil {
		s.logger.Printf("tenant runtime could not be prepared tenant=%s: %v", userValue.TenantID, err)
		http.Error(writer, "tenant runtime is unavailable", http.StatusServiceUnavailable)
		return
	}
	target, _ := url.Parse("http://userhost")
	proxy := &httputil.ReverseProxy{Rewrite: func(proxyRequest *httputil.ProxyRequest) {
		rewritePortalRuntimeRequest(proxyRequest, target, relativePath, userValue.TenantID)
	}}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return ipc.DialContext(ctx, tenant.SocketPath, ipc.DialOptions{ExpectedRuntimeUID: runtimeUID, ExpectedSocketUID: tenant.PortalUID, SystemdActivation: tenant.SocketActivation})
		},
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
	}
	proxy.Transport = transport
	defer transport.CloseIdleConnections()
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("Set-Cookie")
		response.Header.Del("WWW-Authenticate")
		if location := response.Header.Get("Location"); location != "" {
			parsed, parseErr := url.Parse(location)
			if parseErr == nil {
				rewrite := false
				if parsed.IsAbs() {
					address, addressErr := netip.ParseAddr(parsed.Hostname())
					rewrite = addressErr == nil && address.IsLoopback() && (parsed.Scheme == "http" || parsed.Scheme == "https")
				} else if strings.HasPrefix(parsed.Path, "/") {
					rewrite = true
				}
				if rewrite {
					public, _ := url.Parse(s.publicOrigin)
					parsed.Scheme, parsed.Host = public.Scheme, public.Host
					if prefix != "/" {
						parsed.Path = strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(parsed.Path, "/")
					}
					response.Header.Set("Location", parsed.String())
				}
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(response http.ResponseWriter, proxied *http.Request, proxyErr error) {
		s.logger.Printf("tenant runtime unavailable for %s: %v", userValue.TenantID, proxyErr)
		http.Error(response, "tenant runtime unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(writer, request)
}

// AionUi's login session belongs exclusively to UserHost. Exposing any of
// these routes through either the root compatibility proxy or /runtime would
// let a browser blacklist the internal JWT (notably via POST /logout) and
// strand the tenant until its service is restarted.
func internalRuntimeAuthPath(cleanPath string) bool {
	return cleanPath == "/login" || cleanPath == "/logout" || cleanPath == "/qr-login" ||
		cleanPath == "/api/auth" || strings.HasPrefix(cleanPath, "/api/auth/") ||
		cleanPath == "/api/webui" || strings.HasPrefix(cleanPath, "/api/webui/")
}

func rewritePortalRuntimeRequest(proxyRequest *httputil.ProxyRequest, target *url.URL, relativePath, tenantID string) {
	proxyRequest.SetURL(target)
	outbound := proxyRequest.Out
	outbound.URL.Path = "/" + relativePath
	outbound.URL.RawPath = ""
	outbound.Host = "userhost"
	stripBrowserCredentials(outbound.Header)
	outbound.Header.Set("X-WorkAgent-Tenant", tenantID)
	outbound.Header.Set("X-WorkAgent-User-Request", "1")
}

func (s *Server) loadRuntime(userValue store.User) (config.Tenant, uint32, error) {
	path := filepath.Join(s.cfg.Paths.TenantConfigs, userValue.TenantID+".json")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return config.Tenant{}, 0, errors.New("tenant configuration is missing or unsafe")
	}
	tenant, err := config.LoadTenant(path)
	if err != nil {
		return config.Tenant{}, 0, err
	}
	if err := admin.VerifyTenantConfigPath(s.cfg, tenant, path); err != nil {
		return config.Tenant{}, 0, fmt.Errorf("tenant configuration protection is invalid: %w", err)
	}
	if tenant.TenantID != userValue.TenantID || tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
		return config.Tenant{}, 0, errors.New("tenant identity does not match the Portal database")
	}
	if strings.TrimSuffix(tenant.PortalOrigin, "/") != s.publicOrigin {
		return config.Tenant{}, 0, errors.New("tenant Portal origin does not match the active Portal")
	}
	if uint32(os.Geteuid()) != tenant.PortalUID {
		return config.Tenant{}, 0, errors.New("tenant Portal UID does not match the running Portal")
	}
	account, err := user.Lookup(tenant.RuntimeUser)
	if err != nil {
		return config.Tenant{}, 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 || uint32(uid) == tenant.PortalUID {
		return config.Tenant{}, 0, errors.New("runtime account UID is invalid")
	}
	return tenant, uint32(uid), nil
}

func (g *runtimeGate) begin(tenantID string, maximum int) (func(), bool) {
	g.mu.Lock()
	if g.active[tenantID] == 0 && len(g.active) >= maximum {
		g.mu.Unlock()
		return nil, false
	}
	g.active[tenantID]++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.active[tenantID]--
			if g.active[tenantID] == 0 {
				delete(g.active, tenantID)
			}
		})
	}, true
}

func (s *Server) setSessionCookies(writer http.ResponseWriter, sessionToken, csrfToken string, expires time.Time) {
	mode := http.SameSiteStrictMode
	if strings.EqualFold(s.cfg.Session.SameSite, "lax") {
		mode = http.SameSiteLaxMode
	}
	http.SetCookie(writer, &http.Cookie{Name: s.cfg.Session.CookieName, Value: sessionToken, Path: "/", Secure: true, HttpOnly: true, SameSite: mode, Expires: expires, MaxAge: s.cfg.Session.AbsoluteTimeoutSeconds})
	http.SetCookie(writer, &http.Cookie{Name: csrfCookieName, Value: csrfToken, Path: "/", Secure: true, HttpOnly: false, SameSite: mode, Expires: expires, MaxAge: s.cfg.Session.AbsoluteTimeoutSeconds})
}

func (s *Server) clearSessionCookies(writer http.ResponseWriter) {
	mode := http.SameSiteStrictMode
	if strings.EqualFold(s.cfg.Session.SameSite, "lax") {
		mode = http.SameSiteLaxMode
	}
	for _, name := range []string{s.cfg.Session.CookieName, csrfCookieName} {
		http.SetCookie(writer, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: name == s.cfg.Session.CookieName, SameSite: mode, MaxAge: -1, Expires: time.Unix(1, 0)})
	}
}

func sessionToken(request *http.Request, name string) (string, error) {
	cookie, err := request.Cookie(name)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 256 {
		return "", errors.New("session cookie is missing")
	}
	return cookie.Value, nil
}

func publicUser(value store.User) map[string]any {
	return map[string]any{"id": strconv.FormatInt(value.ID, 10), "username": value.Username, "tenant_id": value.TenantID, "enabled": value.Enabled, "admin": value.Admin, "created_at": value.CreatedAt, "last_login_at": value.LastLoginAt}
}

func isUnsafe(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func isWebSocketUpgrade(request *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, value := range strings.Split(request.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(value), "upgrade") {
			return true
		}
	}
	return false
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func staticHandler() http.Handler {
	root, _ := fs.Sub(staticFiles, "ui")
	files := http.FileServer(http.FS(root))
	index, _ := fs.ReadFile(root, "index.html")
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		clean := path.Clean("/" + request.URL.Path)
		if clean == "/" {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = writer.Write(index)
			return
		}
		files.ServeHTTP(writer, request)
	})
}
