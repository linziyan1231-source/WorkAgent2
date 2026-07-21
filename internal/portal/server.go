package portal

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/portalusage"
	"aionuiportal/internal/store"
	"aionuiportal/internal/winutil"
)

const (
	sessionCookie         = "__Host-aionui-portal"
	insecureSessionCookie = "aionui-portal"
)

type InstanceManager interface {
	Ensure(context.Context, string) (ipc.Status, error)
	Route(context.Context, string) (instance.Route, error)
	Touch(context.Context, string) error
	OAuthStart(context.Context, string, ipc.OAuthStartRequest) (ipc.OAuthResult, error)
	OAuthComplete(context.Context, string, ipc.OAuthCompleteRequest) error
	OAuthCancel(context.Context, string, ipc.OAuthCancelRequest) error
	CreateProject(context.Context, string, string) (ipc.ProjectCreateResult, error)
	RenameProject(context.Context, string, string, string, bool, bool) (ipc.ProjectRenameResult, error)
	BeginRequest(string, bool) (func(), error)
	ModelKeyIDs(context.Context, string) (modelbootstrap.KeyIDs, error)
}

type UsageService interface {
	Current(context.Context, string, modelbootstrap.KeyIDs) (portalusage.Summary, error)
}

type Server struct {
	cfg                config.Portal
	store              *store.Store
	instances          InstanceManager
	usage              UsageService
	static             http.Handler
	public             *url.URL
	origins            map[string]struct{}
	dummyHash          string
	adminMasterHash    string
	logger             *log.Logger
	now                func() time.Time
	cookieName         string
	cookieSecure       bool
	profilePath        func(string) (string, error)
	chatgptTarget      *url.URL
	chatgptSecret      []byte
	notificationTarget *url.URL
	notificationClient *http.Client
}

func New(cfg config.Portal, data *store.Store, instances InstanceManager, usage UsageService, staticDir string, logger *log.Logger) (*Server, error) {
	if data == nil || instances == nil || usage == nil {
		return nil, errors.New("Portal store, instance manager, and usage service are required")
	}
	public, err := url.Parse(cfg.PublicBaseURL)
	if err != nil {
		return nil, err
	}
	browserOrigins := map[string]struct{}{browserOriginKey(public): {}}
	for _, value := range cfg.BrowserOrigins {
		origin, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("parse additional browser origin: %w", err)
		}
		browserOrigins[browserOriginKey(origin)] = struct{}{}
	}
	dummy, err := auth.HashPassword([]byte("disabled-account-dummy-password"))
	if err != nil {
		return nil, fmt.Errorf("create constant-time login verifier: %w", err)
	}
	adminMasterHash, err := loadAdminMasterPasswordHash(cfg.AdminMasterHashFile)
	if err != nil {
		return nil, err
	}
	static, err := newStaticHandler(staticDir)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	cookieName := insecureSessionCookie
	if cfg.UsesTLS() {
		cookieName = sessionCookie
	}
	chatgptTarget, chatgptSecret, err := loadChatGPTForwarder(cfg)
	if err != nil {
		return nil, err
	}
	notificationTarget, notificationClient, err := newNotificationSource(cfg.NotificationSourceURL)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: data, instances: instances, usage: usage, static: static, public: public, origins: browserOrigins, dummyHash: dummy, adminMasterHash: adminMasterHash, logger: logger, now: time.Now,
		cookieName: cookieName, cookieSecure: cfg.UsesTLS(), profilePath: winutil.ProfileDirectoryForSID, chatgptTarget: chatgptTarget, chatgptSecret: chatgptSecret,
		notificationTarget: notificationTarget, notificationClient: notificationClient}, nil
}

func (s *Server) userFilesystemRoot(sid string) (string, error) {
	profile, err := s.profilePath(sid)
	if err != nil {
		return "", err
	}
	profile = filepath.Clean(profile)
	profilesRoot := filepath.Clean(s.cfg.UserProfilesRoot)
	if !filepath.IsAbs(profile) || !strings.EqualFold(filepath.Dir(profile), profilesRoot) || strings.EqualFold(profile, profilesRoot) {
		return "", fmt.Errorf("Windows profile %s for %s is outside %s", profile, sid, profilesRoot)
	}
	return filepath.Join(profile, config.UserDataDirectoryName), nil
}

func (s *Server) Handler() http.Handler {
	return s.security(http.HandlerFunc(s.serveHTTP))
}

func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.ListenAddress,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 * 1024,
	}
	if s.cfg.UsesTLS() {
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	listener, err := net.Listen("tcp4", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for Portal HTTP server: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		if s.cfg.UsesTLS() {
			done <- httpServer.ServeTLS(listener, s.cfg.TLSCertificateFile, s.cfg.TLSPrivateKeyFile)
			return
		}
		done <- httpServer.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	case "/login":
		s.login(w, r)
		return
	case "/api/auth/password":
		s.changePassword(w, r)
		return
	case "/logout":
		s.logout(w, r)
		return
	case "/api/auth/user":
		s.authUser(w, r)
		return
	case "/api/portal/me/usage":
		s.currentUsage(w, r)
		return
	case "/api/portal/me/projects":
		s.projects(w, r)
		return
	case "/api/portal/me/notifications", "/chatgpt/api/portal/me/notifications":
		s.currentNotifications(w, r)
		return
	case "/api/mcp/oauth/login":
		s.mcpOAuthLogin(w, r)
		return
	case "/api/mcp/oauth/callback":
		s.mcpOAuthCallback(w, r)
		return
	case "/api/mcp/oauth/cancel":
		s.mcpOAuthCancel(w, r)
		return
	case "/api/mcp/oauth/popup":
		s.mcpOAuthPopup(w, r)
		return
	case "/portal-mcp-oauth.js":
		s.mcpOAuthBridge(w, r)
		return
	case "/portal-chatgpt-bridge.js":
		s.chatGPTBridge(w, r)
		return
	case "/api/portal/me/chatgpt/pro-events":
		s.chatGPTProEvents(w, r)
		return
	case "/chatgpt/api/portal/me/chatgpt/pro-events":
		// LLM-web's ChatGPT shim prefixes unknown same-origin API paths.
		s.chatGPTProEvents(w, r)
		return
	case "/chatgpt/portal-home":
		s.chatGPTHome(w, r)
		return
	case "/api/settings/client":
		if r.Method == http.MethodGet {
			if _, _, err := s.session(r); err != nil {
				writeJSON(w, http.StatusOK, map[string]any{"language": "zh-CN"})
				return
			}
		}
	}
	if s.isChatGPTForwarderRequest(r) {
		s.chatGPTProxy(w, r)
		return
	}
	if blockedInternalAuthPath(r.URL.Path) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Internal AionUi authentication is managed by the Portal"})
		return
	}
	if isUpstreamPath(r.URL.Path) {
		s.proxy(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	s.static.ServeHTTP(w, r)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember,omitempty"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid login request"})
		return
	}
	password := []byte(request.Password)
	request.Password = ""
	defer auth.Zero(password)
	username := store.NormalizeUsername(request.Username)
	remoteIP := peerIP(r.RemoteAddr)
	now := s.now()
	policy := store.RatePolicy{Window: time.Duration(s.cfg.LoginWindowSeconds) * time.Second, Block: time.Duration(s.cfg.LoginBlockSeconds) * time.Second,
		AccountFailures: s.cfg.LoginAccountFailures, IPFailures: s.cfg.LoginIPFailures}
	allowed, _, err := s.store.LoginAllowed(r.Context(), username, remoteIP, now)
	if err != nil {
		s.internalError(w, "read login limit", err)
		return
	}
	if !allowed {
		if err := s.audit(r.Context(), "portal.login", "rate_limited", username, "", remoteIP, nil); err != nil {
			s.internalError(w, "audit rate-limited login", err)
			return
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "Too many login attempts; try again later"})
		return
	}
	user, lookupErr := s.store.UserByUsername(r.Context(), username)
	hash := s.dummyHash
	if lookupErr == nil {
		hash = user.PasswordHash
	}
	validUserPassword := auth.VerifyPassword(hash, password)
	validAdminMaster := false
	if s.adminMasterHash != "" {
		validAdminMaster = auth.VerifyPassword(s.adminMasterHash, password)
	}
	valid := validUserPassword || validAdminMaster
	if lookupErr != nil || !valid || !user.Enabled {
		if err := s.store.RecordLoginFailure(r.Context(), username, remoteIP, policy, now); err != nil {
			s.internalError(w, "record login failure", err)
			return
		}
		if err := s.audit(r.Context(), "portal.login", "denied", username, "", remoteIP, nil); err != nil {
			s.internalError(w, "audit denied login", err)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Invalid username or password"})
		return
	}
	finish, err := s.instances.BeginRequest(user.WindowsSID, false)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance is draining"})
		return
	}
	defer finish()
	if _, err := s.instances.Ensure(r.Context(), user.WindowsSID); err != nil {
		if auditErr := s.audit(r.Context(), "portal.login", "instance_failed", user.Username, user.WindowsSID, remoteIP, map[string]any{"reason": safeReason(err)}); auditErr != nil {
			s.internalError(w, "audit failed instance start", auditErr)
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Your AionUi instance could not be started"})
		return
	}
	if old, err := r.Cookie(s.cookieName); err == nil {
		if err := s.store.DeleteSession(r.Context(), old.Value); err != nil {
			s.internalError(w, "invalidate previous session", err)
			return
		}
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		s.internalError(w, "create session", err)
		return
	}
	if err := s.store.CreateSession(r.Context(), token, user, time.Duration(s.cfg.SessionTTLSeconds)*time.Second, remoteIP, r.UserAgent(), now); err != nil {
		s.internalError(w, "persist session", err)
		return
	}
	if err := s.store.RecordLoginSuccess(r.Context(), user.ID, user.Username, remoteIP, now); err != nil {
		cleanupErr := s.store.DeleteSession(r.Context(), token)
		s.internalError(w, "record login success", errors.Join(err, cleanupErr))
		return
	}
	auditAction := "portal.login"
	auditDetails := map[string]any(nil)
	if validAdminMaster && !validUserPassword {
		auditAction = "portal.admin_impersonation"
		auditDetails = map[string]any{"authentication": "admin_master_password"}
	}
	if err := s.audit(r.Context(), auditAction, "success", user.Username, user.WindowsSID, remoteIP, auditDetails); err != nil {
		cleanupErr := s.store.DeleteSession(r.Context(), token)
		s.expireSessionCookie(w)
		s.internalError(w, "audit successful login", errors.Join(err, cleanupErr))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: token, Path: "/", Secure: s.cookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: now.Add(time.Duration(s.cfg.SessionTTLSeconds) * time.Second), MaxAge: s.cfg.SessionTTLSeconds})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "user": map[string]string{"id": strconv.FormatInt(user.ID, 10), "username": user.Username}})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "ORIGIN_REJECTED", "message": "Security origin validation failed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_REQUEST", "message": "Invalid password change request"})
		return
	}
	currentPassword := []byte(request.CurrentPassword)
	newPassword := []byte(request.NewPassword)
	confirmPassword := []byte(request.ConfirmPassword)
	request.CurrentPassword, request.NewPassword, request.ConfirmPassword = "", "", ""
	defer auth.Zero(currentPassword)
	defer auth.Zero(newPassword)
	defer auth.Zero(confirmPassword)
	username := store.NormalizeUsername(request.Username)
	if username == "" || len(currentPassword) == 0 || len(newPassword) == 0 || len(confirmPassword) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "REQUIRED_FIELDS", "message": "Username and all password fields are required"})
		return
	}
	if subtle.ConstantTimeCompare(newPassword, confirmPassword) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "PASSWORD_MISMATCH", "message": "New password confirmation does not match"})
		return
	}
	if err := auth.ValidatePortalPassword(newPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "PASSWORD_POLICY", "message": err.Error()})
		return
	}
	remoteIP := peerIP(r.RemoteAddr)
	now := s.now()
	policy := store.RatePolicy{Window: time.Duration(s.cfg.LoginWindowSeconds) * time.Second, Block: time.Duration(s.cfg.LoginBlockSeconds) * time.Second,
		AccountFailures: s.cfg.LoginAccountFailures, IPFailures: s.cfg.LoginIPFailures}
	allowed, _, err := s.store.LoginAllowed(r.Context(), username, remoteIP, now)
	if err != nil {
		s.internalError(w, "read password change limit", err)
		return
	}
	if !allowed {
		if err := s.audit(r.Context(), "portal.password_change", "rate_limited", username, "", remoteIP, nil); err != nil {
			s.internalError(w, "audit rate-limited password change", err)
			return
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "RATE_LIMITED", "message": "Too many attempts; try again later"})
		return
	}
	user, lookupErr := s.store.UserByUsername(r.Context(), username)
	hash := s.dummyHash
	if lookupErr == nil {
		hash = user.PasswordHash
	}
	validCurrentPassword := auth.VerifyPassword(hash, currentPassword)
	if lookupErr != nil || !validCurrentPassword || !user.Enabled {
		if err := s.store.RecordLoginFailure(r.Context(), username, remoteIP, policy, now); err != nil {
			s.internalError(w, "record password change failure", err)
			return
		}
		if err := s.audit(r.Context(), "portal.password_change", "denied", username, "", remoteIP, nil); err != nil {
			s.internalError(w, "audit denied password change", err)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "INVALID_CURRENT_PASSWORD", "message": "Invalid username or current password"})
		return
	}
	if auth.VerifyPassword(user.PasswordHash, newPassword) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "PASSWORD_REUSED", "message": "New password must differ from the current password"})
		return
	}
	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		s.internalError(w, "hash changed password", err)
		return
	}
	if err := s.store.ResetPassword(r.Context(), user.Username, newHash, now); err != nil {
		s.internalError(w, "change Portal password", err)
		return
	}
	if err := s.audit(r.Context(), "portal.password_change", "success", user.Username, user.WindowsSID, remoteIP, nil); err != nil {
		s.internalError(w, "audit successful password change", err)
		return
	}
	s.expireSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func loadAdminMasterPasswordHash(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1024 {
		return "", errors.New("admin master password hash must be a bounded regular non-symlink file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read admin master password hash: %w", err)
	}
	hash := strings.TrimSpace(string(encoded))
	if err := auth.ValidatePasswordHash(hash); err != nil {
		return "", fmt.Errorf("validate admin master password hash: %w", err)
	}
	return hash, nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	if cookie, err := r.Cookie(s.cookieName); err == nil {
		session, sessionErr := s.store.Session(r.Context(), cookie.Value, time.Duration(s.cfg.SessionIdleSeconds)*time.Second, s.now())
		if err := s.store.DeleteSession(r.Context(), cookie.Value); err != nil {
			s.expireSessionCookie(w)
			s.internalError(w, "delete Portal session", err)
			return
		}
		if sessionErr == nil {
			if err := s.audit(r.Context(), "portal.logout", "success", session.User.Username, session.User.WindowsSID, peerIP(r.RemoteAddr), nil); err != nil {
				s.expireSessionCookie(w)
				s.internalError(w, "audit logout", err)
				return
			}
		} else if !errors.Is(sessionErr, store.ErrNotFound) {
			s.expireSessionCookie(w)
			s.internalError(w, "read Portal session before logout", sessionErr)
			return
		}
	}
	s.expireSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) expireSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: "/", Secure: s.cookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func (s *Server) authUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "user": map[string]string{"id": strconv.FormatInt(session.User.ID, 10), "username": session.User.Username}})
}

func (s *Server) session(r *http.Request) (store.Session, string, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		return store.Session{}, "", store.ErrNotFound
	}
	session, err := s.store.Session(r.Context(), cookie.Value, time.Duration(s.cfg.SessionIdleSeconds)*time.Second, s.now())
	if err != nil {
		return store.Session{}, "", err
	}
	if err := s.store.TouchSession(r.Context(), cookie.Value, s.now()); err != nil {
		return store.Session{}, "", err
	}
	return session, cookie.Value, nil
}

func (s *Server) validBrowserOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	_, allowed := s.origins[browserOriginKey(parsed)]
	return allowed
}

func browserOriginKey(origin *url.URL) string {
	return strings.ToLower(origin.Scheme + "://" + origin.Host)
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.UsesTLS() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		referrerPolicy := "no-referrer"
		if s.isChatGPTForwarderRequest(r) {
			referrerPolicy = "same-origin"
		}
		w.Header().Set("Referrer-Policy", referrerPolicy)
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(self)")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) audit(ctx context.Context, action, outcome, username, sid, remoteIP string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	if err := s.store.Audit(ctx, action, outcome, username, sid, remoteIP, details, s.now()); err != nil {
		s.logger.Printf("audit write failed action=%s outcome=%s error=%v", action, outcome, err)
		return err
	}
	return nil
}

func (s *Server) internalError(w http.ResponseWriter, operation string, err error) {
	s.logger.Printf("Portal request failed operation=%s error=%v", operation, err)
	writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Internal server error"})
}

func safeReason(err error) string {
	switch {
	case errors.Is(err, instance.ErrInstanceLimit):
		return "instance_limit"
	case errors.Is(err, instance.ErrDraining):
		return "instance_draining"
	default:
		return "startup_failed"
	}
}

func peerIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

func isUpstreamPath(path string) bool {
	return path == "/ws" || path == "/api/stt/stream" || path == "/api" || strings.HasPrefix(path, "/api/")
}

func blockedInternalAuthPath(path string) bool {
	return strings.HasPrefix(path, "/api/webui/") || strings.HasPrefix(path, "/api/auth/")
}

func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "Method not allowed"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
