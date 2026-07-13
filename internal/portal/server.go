package portal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/instance"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/store"
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
	BeginRequest(string, bool) (func(), error)
}

type Server struct {
	cfg          config.Portal
	store        *store.Store
	instances    InstanceManager
	static       http.Handler
	public       *url.URL
	dummyHash    string
	logger       *log.Logger
	now          func() time.Time
	cookieName   string
	cookieSecure bool
}

func New(cfg config.Portal, data *store.Store, instances InstanceManager, staticDir string, logger *log.Logger) (*Server, error) {
	if data == nil || instances == nil {
		return nil, errors.New("Portal store and instance manager are required")
	}
	public, err := url.Parse(cfg.PublicBaseURL)
	if err != nil {
		return nil, err
	}
	dummy, err := auth.HashPassword([]byte("disabled-account-dummy-password"))
	if err != nil {
		return nil, fmt.Errorf("create constant-time login verifier: %w", err)
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
	return &Server{cfg: cfg, store: data, instances: instances, static: static, public: public, dummyHash: dummy, logger: logger, now: time.Now,
		cookieName: cookieName, cookieSecure: cfg.UsesTLS()}, nil
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
	case "/logout":
		s.logout(w, r)
		return
	case "/api/auth/user":
		s.authUser(w, r)
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
	valid := auth.VerifyPassword(hash, password)
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
	if err := s.audit(r.Context(), "portal.login", "success", user.Username, user.WindowsSID, remoteIP, nil); err != nil {
		cleanupErr := s.store.DeleteSession(r.Context(), token)
		s.expireSessionCookie(w)
		s.internalError(w, "audit successful login", errors.Join(err, cleanupErr))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: token, Path: "/", Secure: s.cookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: now.Add(time.Duration(s.cfg.SessionTTLSeconds) * time.Second), MaxAge: s.cfg.SessionTTLSeconds})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "user": map[string]string{"id": strconv.FormatInt(user.ID, 10), "username": user.Username}})
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
	return parsed.User == nil && parsed.Opaque == "" && strings.EqualFold(parsed.Scheme, s.public.Scheme) &&
		strings.EqualFold(parsed.Host, s.public.Host) && parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.UsesTLS() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
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
