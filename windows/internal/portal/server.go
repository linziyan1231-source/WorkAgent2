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
	"aionuiportal/internal/provisionipc"
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
	ResolveProject(context.Context, string, string) (ipc.ProjectResolveResult, error)
	ListProjects(context.Context, string) (ipc.ProjectListResult, error)
	ProvisionSharedProject(context.Context, string, ipc.SharedProjectRequest) (ipc.SharedProjectResult, error)
	FinishSharedProjectProvisioning(context.Context, string, ipc.SharedProjectRequest, bool) error
	RunSharedAgent(context.Context, string, ipc.SharedAgentRequest) (ipc.SharedAgentResult, error)
	StopSharedAgent(context.Context, string, ipc.SharedAgentStopRequest) error
	InstallSharedAgentCredential(context.Context, string, ipc.SharedAgentCredentialRequest) error
	VerifySharedAgentCredential(context.Context, string, string) (bool, error)
	SharedFile(context.Context, string, ipc.SharedFileRequest) (ipc.SharedFileResult, error)
	TransferSharedProject(context.Context, string, ipc.SharedTransferRequest) error
	FinishSharedProjectTransfer(context.Context, string, ipc.SharedTransferRequest, bool) error
	RelocateSharedProjectConversations(context.Context, string, ipc.SharedConversationRelocateRequest) error
	UpdateSharedProjectACL(context.Context, string, ipc.SharedProjectRequest) error
	BeginRequest(string, bool) (func(), error)
	ModelKeyIDs(context.Context, string) (modelbootstrap.KeyIDs, error)
	StorageUsage(context.Context, string) (ipc.StorageUsage, error)
	WriteUsageSnapshot(context.Context, string, []byte) error
	Stop(context.Context, string) error
	Restart(context.Context, string) error
}

type UsageService interface {
	Current(context.Context, string, modelbootstrap.KeyIDs) (portalusage.Summary, error)
	CurrentMany(context.Context, []string) (map[string]portalusage.Summary, error)
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
	chatForwardTarget  *url.URL
	chatForwardSecret  []byte
	notificationTarget *url.URL
	notificationClient *http.Client
	skillMarketRoot    string
	provision          func(context.Context, provisionipc.Request, func(provisionipc.Progress)) (provisionipc.Response, error)
	provisionJobs      provisionJobStore
	sharedEvents       *sharedEventHub
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
	chatForwardTarget, chatForwardSecret, err := loadChatForward(cfg)
	if err != nil {
		return nil, err
	}
	notificationTarget, notificationClient, err := newNotificationSource(cfg.NotificationSourceURL)
	if err != nil {
		return nil, err
	}
	skillMarketRoot := filepath.Join(filepath.Dir(cfg.DatabasePath), "skill-market")
	if err := os.MkdirAll(skillMarketRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create skill market storage: %w", err)
	}
	return &Server{cfg: cfg, store: data, instances: instances, usage: usage, static: static, public: public, origins: browserOrigins, dummyHash: dummy, adminMasterHash: adminMasterHash, logger: logger, now: time.Now,
		cookieName: cookieName, cookieSecure: cfg.UsesTLS(), profilePath: winutil.ProfileDirectoryForSID, chatForwardTarget: chatForwardTarget, chatForwardSecret: chatForwardSecret,
		notificationTarget: notificationTarget, notificationClient: notificationClient, provision: provisionipc.CallWithProgress,
		skillMarketRoot: skillMarketRoot,
		provisionJobs:   provisionJobStore{items: make(map[string]provisionJob)},
		sharedEvents:    newSharedEventHub()}, nil
}

func (s *Server) userFilesystemRoot(sid string) (string, error) {
	if s.cfg.UserDataRoot != "" {
		return filepath.Join(filepath.Clean(s.cfg.UserDataRoot), sid), nil
	}
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
	if isCollaborationAPIPath(r.URL.Path) && !s.requireCollaborationEnabled(w, r) {
		return
	}
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
	case "/api/portal/me/profile":
		s.profile(w, r)
		return
	case "/api/portal/me/restart-service":
		s.restartCurrentUserService(w, r)
		return
	case "/api/portal/me/projects":
		s.projects(w, r)
		return
	case "/api/portal/shared-projects":
		s.sharedProjects(w, r)
		return
	case "/api/portal/shared-projects/hidden":
		s.sharedProjectHidden(w, r)
		return
	case "/api/portal/shared-projects/transfer":
		s.sharedProjectTransfer(w, r)
		return
	case "/api/portal/shared-conversations":
		s.sharedConversations(w, r)
		return
	case "/api/portal/shared-runtime-options":
		s.sharedRuntimeOptions(w, r)
		return
	case "/api/portal/shared-events":
		s.sharedEventStream(w, r)
		return
	case "/api/portal/shared-files":
		s.sharedFiles(w, r)
		return
	case "/api/portal/shared-messages":
		s.sharedMessages(w, r)
		return
	case "/api/portal/shared-users":
		s.sharedUsers(w, r)
		return
	case "/api/portal/shared-invites":
		s.sharedInvites(w, r)
		return
	case "/api/portal/shared-invites/accept":
		s.acceptSharedInvite(w, r)
		return
	case "/api/portal/shared-invites/decline":
		s.declineSharedInvite(w, r)
		return
	case "/api/portal/shared-invite-links":
		s.sharedInviteLinks(w, r)
		return
	case "/api/portal/shared-invite-links/accept":
		s.acceptSharedInviteLink(w, r)
		return
	case "/api/portal/shared-members":
		s.sharedMembers(w, r)
		return
	case "/api/portal/shared-members/leave":
		s.leaveSharedProject(w, r)
		return
	case "/api/portal/me/notifications":
		s.currentNotifications(w, r)
		return
	case "/api/portal/skill-market":
		s.skillMarket(w, r)
		return
	case "/api/portal/skill-market/download":
		s.downloadMarketSkill(w, r)
		return
	case "/api/portal/skill-market/install":
		s.installMarketSkill(w, r)
		return
	case "/api/portal/admin/users":
		s.adminUsers(w, r)
		return
	case "/api/portal/admin/users/usage":
		s.adminUserUsage(w, r)
		return
	case "/api/portal/admin/user-jobs":
		s.adminUserJob(w, r)
		return
	case "/api/portal/admin/users/disable":
		s.disableUser(w, r)
		return
	case "/api/portal/admin/users/enable":
		s.enableUser(w, r)
		return
	case "/api/portal/admin/users/reset-password":
		s.resetUserPassword(w, r)
		return
	case "/api/portal/admin/users/kimi-datasource":
		s.setUserKimiDatasource(w, r)
		return
	case "/internal/chatforward/quota/reserve":
		s.chatForwardQuotaReserve(w, r)
		return
	case "/internal/chatforward/quota/settle":
		s.chatForwardQuotaSettle(w, r)
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
	case "/api/portal/me/chatgpt/pro-events":
		s.chatGPTProEvents(w, r)
		return
	case "/api/settings/client":
		if r.Method == http.MethodGet {
			if _, _, err := s.session(r); err != nil {
				writeJSON(w, http.StatusOK, map[string]any{"language": "zh-CN"})
				return
			}
		}
	}
	if s.isChatForwardRequest(r) {
		s.chatForwardProxy(w, r)
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
	if !user.Admin {
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
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "user": authUserPayload(user)})
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
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "user": authUserPayload(session.User)})
}

func authUserPayload(user store.User) map[string]any {
	return map[string]any{
		"id": strconv.FormatInt(user.ID, 10), "username": user.Username, "display_name": user.DisplayName, "admin": user.Admin,
		"collaboration_enabled": user.CollaborationEnabled, "collaboration_capable": !user.Admin,
	}
}

func isCollaborationAPIPath(path string) bool {
	switch path {
	case "/api/portal/shared-projects",
		"/api/portal/shared-projects/hidden",
		"/api/portal/shared-projects/transfer",
		"/api/portal/shared-conversations",
		"/api/portal/shared-runtime-options",
		"/api/portal/shared-events",
		"/api/portal/shared-files",
		"/api/portal/shared-messages",
		"/api/portal/shared-users",
		"/api/portal/shared-invites",
		"/api/portal/shared-invites/accept",
		"/api/portal/shared-invites/decline",
		"/api/portal/shared-invite-links",
		"/api/portal/shared-invite-links/accept",
		"/api/portal/shared-members",
		"/api/portal/shared-members/leave":
		return true
	default:
		return false
	}
}

func (s *Server) requireCollaborationEnabled(w http.ResponseWriter, r *http.Request) bool {
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return false
	}
	if session.User.Admin || !session.User.CollaborationEnabled {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"success": false,
			"code":    "COLLABORATION_DISABLED",
			"message": "User collaboration is disabled in your profile",
		})
		return false
	}
	return true
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	if r.Method == http.MethodGet {
		users, err := s.store.ListManagedUsers(r.Context())
		if err != nil {
			s.internalError(w, "list managed users", err)
			return
		}
		items := make([]map[string]any, len(users))
		for index, user := range users {
			grant, err := s.store.KimiDatasourceGrantForUser(r.Context(), user.ID, s.now())
			if err != nil {
				s.internalError(w, "read managed user Kimi datasource grant", err)
				return
			}
			items[index] = managedUserPayload(user, grant)
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "users": items, "kimi_datasource_sources": store.KimiDatasourceSources})
		return
	}
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
		Username       string `json:"username"`
		PortalPassword string `json:"portal_password"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid account request"})
		return
	}
	password := []byte(request.PortalPassword)
	request.PortalPassword = ""
	defer auth.Zero(password)
	if err := winutil.ValidateLocalUsername(request.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	if err := auth.ValidatePortalPassword(password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	s.startProvisionJob(w, request.Username, password, session.User.Username, peerIP(r.RemoteAddr))
}

func (s *Server) adminUserUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	if r.URL.RawQuery != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Managed resource usage does not accept query parameters"})
		return
	}
	users, err := s.store.ListManagedUsers(r.Context())
	if err != nil {
		s.internalError(w, "list managed users for resource usage", err)
		return
	}
	usageCtx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.UsageQueryTimeoutSecs)*time.Second)
	defer cancel()
	items, err := s.managedUsersUsage(usageCtx, users)
	if err != nil {
		s.logger.Print("Administrator resource usage unavailable")
		if errors.Is(usageCtx.Err(), context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]any{"success": false, "message": "Resource usage request timed out"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Resource usage is unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "users": items})
}

func managedUserPayload(user store.User, grant store.KimiDatasourceGrant) map[string]any {
	item := map[string]any{"username": user.Username, "windows_username": user.WindowsUsername, "windows_sid": user.WindowsSID, "enabled": user.Enabled,
		"display_name": user.DisplayName, "collaboration_enabled": user.CollaborationEnabled,
		"created_at": user.CreatedAt.UTC().Format(time.RFC3339), "kimi_datasource": grant}
	if user.LastLoginAt != nil {
		item["last_login_at"] = user.LastLoginAt.UTC().Format(time.RFC3339)
	}
	return item
}

func (s *Server) setUserKimiDatasource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		Username       string   `json:"username"`
		Enabled        bool     `json:"enabled"`
		AllowedSources []string `json:"allowed_sources"`
		DailyLimit     int      `json:"daily_limit"`
		MonthlyLimit   int      `json:"monthly_limit"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid Kimi datasource policy request"})
		return
	}
	user, err := s.store.UserByUsername(r.Context(), request.Username)
	if err != nil || user.Admin {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Managed user was not found"})
		return
	}
	normalized, err := store.NormalizeKimiDatasourceSources(request.AllowedSources)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	if err := store.ValidateKimiDatasourceLimits(request.DailyLimit, request.MonthlyLimit); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	nonce, err := auth.RandomToken(18)
	if err != nil {
		s.internalError(w, "create Kimi datasource policy nonce", err)
		return
	}
	requestCtx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	response, err := s.provision(requestCtx, provisionipc.Request{Command: "set-kimi-datasource", Username: user.Username, Enabled: request.Enabled,
		AllowedSources: normalized, DailyLimit: request.DailyLimit, MonthlyLimit: request.MonthlyLimit, Nonce: nonce}, nil)
	if err != nil || response.KimiDatasource == nil {
		s.logger.Printf("Administrator Kimi datasource policy update failed username=%s", user.Username)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "Kimi datasource policy update failed"})
		return
	}
	if err := s.audit(r.Context(), "portal.admin.user.kimi_datasource", "success", user.Username, user.WindowsSID, peerIP(r.RemoteAddr), map[string]any{
		"actor": session.User.Username, "enabled": request.Enabled, "allowed_sources": normalized, "daily_limit": request.DailyLimit, "monthly_limit": request.MonthlyLimit,
	}); err != nil {
		s.internalError(w, "audit administrator Kimi datasource policy", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "kimi_datasource": response.KimiDatasource})
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var request struct {
		Username string `json:"username"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid disable request"})
		return
	}
	user, err := s.store.UserByUsername(r.Context(), request.Username)
	if err != nil || user.Admin {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Managed user was not found"})
		return
	}
	if err := s.store.SetUserEnabled(r.Context(), user.Username, false, s.now()); err != nil {
		s.internalError(w, "disable managed user", err)
		return
	}
	if err := s.instances.Stop(r.Context(), user.WindowsSID); err != nil && !isUnavailableInstance(err) {
		s.internalError(w, "stop disabled user", err)
		return
	}
	if err := s.audit(r.Context(), "portal.admin.user.disable", "success", user.Username, user.WindowsSID, peerIP(r.RemoteAddr), map[string]any{"actor": session.User.Username}); err != nil {
		s.internalError(w, "audit administrator user disable", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) enableUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var request struct {
		Username string `json:"username"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid enable request"})
		return
	}
	user, err := s.store.UserByUsername(r.Context(), request.Username)
	if err != nil || user.Admin {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Managed user was not found"})
		return
	}
	if !user.Enabled {
		if err := s.store.SetUserEnabled(r.Context(), user.Username, true, s.now()); err != nil {
			s.internalError(w, "enable managed user", err)
			return
		}
		if err := s.audit(r.Context(), "portal.admin.user.enable", "success", user.Username, user.WindowsSID, peerIP(r.RemoteAddr), map[string]any{"actor": session.User.Username}); err != nil {
			s.internalError(w, "audit administrator user enable", err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.validBrowserOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Security origin validation failed"})
		return
	}
	session, _, err := s.session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "Portal session is required"})
		return
	}
	if !session.User.Admin {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Administrator access is required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		Username       string `json:"username"`
		PortalPassword string `json:"portal_password"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid password reset request"})
		return
	}
	password := []byte(request.PortalPassword)
	request.PortalPassword = ""
	defer auth.Zero(password)
	if err := auth.ValidatePortalPassword(password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": err.Error()})
		return
	}
	user, err := s.store.UserByUsername(r.Context(), request.Username)
	if err != nil || user.Admin {
		writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Managed user was not found"})
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.internalError(w, "hash managed user password", err)
		return
	}
	if err := s.store.ResetPassword(r.Context(), user.Username, hash, s.now()); err != nil {
		s.internalError(w, "reset managed user password", err)
		return
	}
	if err := s.audit(r.Context(), "portal.admin.user.reset_password", "success", user.Username, user.WindowsSID, peerIP(r.RemoteAddr), map[string]any{"actor": session.User.Username}); err != nil {
		s.internalError(w, "audit administrator password reset", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func isUnavailableInstance(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "pipe") && (strings.Contains(message, "not found") || strings.Contains(message, "cannot find") || strings.Contains(message, "找不到"))
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
		if s.isChatForwardRequest(r) {
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
