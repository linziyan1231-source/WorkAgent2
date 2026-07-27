package userhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/ipc"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/sdnotify"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"
)

type Host struct {
	cfg             config.Tenant
	uid             uint32
	listener        net.Listener
	backend         *exec.Cmd
	aionCorePID     int
	aionCorePort    uint16
	aionCoreHealth  []string
	backendURL      *url.URL
	proxy           *httputil.ReverseProxy
	transport       *http.Transport
	auth            backendAuthMaterial
	runtimeToken    []byte
	dataRoot        *projectfs.Root
	workspace       *projectfs.Root
	capacity        *capacityLease
	runtimeLock     *servicelock.Lock
	logger          *log.Logger
	startedAt       time.Time
	releaseID       string
	releaseRoot     string
	mu              sync.RWMutex
	ready           bool
	lastActivity    atomic.Int64
	requests        atomic.Int64
	webSockets      atomic.Int64
	handlers        sync.WaitGroup
	backendDone     chan error
	bootstrap       chan *bootstrapOperation
	bootstrapMu     sync.Mutex
	projectRenameMu sync.Mutex
	oauth           *oauthManager
}

type bootstrapOperation struct {
	bundle modelbootstrap.Bundle
	done   chan error
}

type Status struct {
	TenantID         string         `json:"tenant_id"`
	RuntimeUser      string         `json:"runtime_user"`
	RuntimeUID       uint32         `json:"runtime_uid"`
	ReleaseID        string         `json:"release_id"`
	Ready            bool           `json:"ready"`
	BackendPID       int            `json:"backend_pid,omitempty"`
	AionCorePID      int            `json:"aioncore_pid,omitempty"`
	AionCorePort     uint16         `json:"aioncore_port,omitempty"`
	StartedAt        time.Time      `json:"started_at"`
	LastActivity     time.Time      `json:"last_activity"`
	ActiveRequests   int64          `json:"active_requests"`
	ActiveWebSockets int64          `json:"active_websockets"`
	CapacitySlot     int            `json:"capacity_slot"`
	Activity         ActivityStatus `json:"activity"`
}

func New(cfg config.Tenant, listener net.Listener, logger *log.Logger) (*Host, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if listener == nil {
		return nil, errors.New("UserHost listener is required")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	uid, err := verifyRuntimeIdentity(cfg)
	if err != nil {
		return nil, err
	}
	if err := verifyDataRoot(cfg.DataRoot, uid); err != nil {
		return nil, err
	}
	runtimeLock, err := servicelock.AcquireShared(filepath.Join(cfg.DataRoot, ".runtime.lock"), uid)
	if err != nil {
		return nil, fmt.Errorf("acquire tenant runtime lock: %w", err)
	}
	keepRuntimeLock := false
	defer func() {
		if !keepRuntimeLock {
			_ = runtimeLock.Close()
		}
	}()
	requiredPaths := []string{cfg.Backend.Executable}
	requiredPaths = append(requiredPaths, cfg.Backend.RequiredReleaseFiles...)
	if cfg.Backend.Migration.Enabled {
		requiredPaths = append(requiredPaths, cfg.Backend.Migration.Executable)
	}
	if cfg.Backend.AgentCLI.BinDirectory != "" {
		requiredPaths = append(requiredPaths, cfg.Backend.AgentCLI.CodexExecutable, cfg.Backend.AgentCLI.KimiExecutable, cfg.Backend.AgentCLI.PythonExecutable)
	}
	verifiedRelease, err := release.ResolveActive(cfg.Release.ReleasesRoot, cfg.Release.PointerFile, cfg.Release.PublicKeyFile, release.ResolveOptions{
		Scope: cfg.Release.Scope, RequiredPaths: requiredPaths, RequireRootOwner: true, RequiredComponents: release.RequiredComponentsForScope(cfg.Release.Scope),
	})
	if err != nil {
		return nil, fmt.Errorf("verify runtime release: %w", err)
	}
	aionCoreHealth, err := expectedAionCoreHealthVersions(verifiedRelease.Manifest)
	if err != nil {
		return nil, err
	}
	cfg.Backend.Executable = filepath.Join(verifiedRelease.Path, filepath.FromSlash(cfg.Backend.Executable))
	if cfg.Backend.Migration.Enabled {
		cfg.Backend.Migration.Executable = filepath.Join(verifiedRelease.Path, filepath.FromSlash(cfg.Backend.Migration.Executable))
	}
	if cfg.Backend.AgentCLI.BinDirectory != "" {
		cfg.Backend.AgentCLI.BinDirectory = filepath.Join(verifiedRelease.Path, filepath.FromSlash(cfg.Backend.AgentCLI.BinDirectory))
		cfg.Backend.AgentCLI.CodexExecutable = filepath.Join(verifiedRelease.Path, filepath.FromSlash(cfg.Backend.AgentCLI.CodexExecutable))
		cfg.Backend.AgentCLI.KimiExecutable = filepath.Join(verifiedRelease.Path, filepath.FromSlash(cfg.Backend.AgentCLI.KimiExecutable))
		cfg.Backend.AgentCLI.PythonExecutable = filepath.Join(verifiedRelease.Path, filepath.FromSlash(cfg.Backend.AgentCLI.PythonExecutable))
	}
	dataRoot, err := projectfs.OpenRoot(cfg.DataRoot)
	if err != nil {
		return nil, err
	}
	if err := dataRoot.ValidatePrivateOwner(uid); err != nil {
		dataRoot.Close()
		return nil, err
	}
	for _, directory := range []string{"workspace", "home", "home/.kimi-code", "tmp", "cache", "config", "config/codex", "data", "logs", "credentials"} {
		if err := dataRoot.EnsureDirectory(directory, 0o700); err != nil {
			dataRoot.Close()
			return nil, fmt.Errorf("prepare private tenant directory %s: %w", directory, err)
		}
	}
	workingRelative, err := filepath.Rel(cfg.DataRoot, cfg.Backend.WorkingDirectory)
	if err != nil {
		dataRoot.Close()
		return nil, fmt.Errorf("resolve backend working directory: %w", err)
	}
	if workingRelative != "." {
		if err := dataRoot.EnsureDirectory(workingRelative, 0o700); err != nil {
			dataRoot.Close()
			return nil, fmt.Errorf("prepare backend working directory: %w", err)
		}
	}
	if cfg.Backend.Migration.Enabled {
		migrationWorkingRelative, err := filepath.Rel(cfg.DataRoot, cfg.Backend.Migration.WorkingDirectory)
		if err != nil {
			dataRoot.Close()
			return nil, fmt.Errorf("resolve migration working directory: %w", err)
		}
		if migrationWorkingRelative != "." {
			if err := dataRoot.EnsureDirectory(migrationWorkingRelative, 0o700); err != nil {
				dataRoot.Close()
				return nil, fmt.Errorf("prepare migration working directory: %w", err)
			}
		}
	}
	workspacePath := filepath.Join(cfg.DataRoot, "workspace")
	workspace, err := projectfs.OpenRoot(workspacePath)
	if err != nil {
		dataRoot.Close()
		return nil, err
	}
	capacity, err := acquireCapacity(cfg.Capacity.SlotDirectory, cfg.Capacity.MaxInstances)
	if err != nil {
		workspace.Close()
		dataRoot.Close()
		return nil, err
	}
	runtimeToken, err := generateWorkAgentRuntimeToken()
	if err != nil {
		capacity.Close()
		workspace.Close()
		dataRoot.Close()
		return nil, err
	}
	host := &Host{cfg: cfg, uid: uid, listener: listener, dataRoot: dataRoot, workspace: workspace, capacity: capacity, runtimeLock: runtimeLock, logger: logger, startedAt: time.Now().UTC(), releaseID: verifiedRelease.Manifest.ReleaseID, releaseRoot: verifiedRelease.Path, aionCoreHealth: aionCoreHealth, runtimeToken: runtimeToken, backendDone: make(chan error, 1), bootstrap: make(chan *bootstrapOperation, 1)}
	if cfg.Backend.InternalAuth.Enabled {
		relativeDatabase, err := filepath.Rel(cfg.DataRoot, cfg.Backend.InternalAuth.DatabasePath)
		if err != nil {
			clear(runtimeToken)
			capacity.Close()
			workspace.Close()
			dataRoot.Close()
			return nil, err
		}
		host.oauth = newOAuthManager(dataRoot, relativeDatabase, cfg.PortalOrigin, secureOAuthClient(cfg.OutboundProxyURL), nil, false)
	}
	host.lastActivity.Store(time.Now().UTC().UnixNano())
	keepRuntimeLock = true
	return host, nil
}

func (h *Host) Run(ctx context.Context) error {
	defer h.runtimeLock.Close()
	defer h.dataRoot.Close()
	defer h.workspace.Close()
	defer h.capacity.Close()
	requestContext, cancelRequests := context.WithCancel(context.Background())
	server := &http.Server{
		Handler:           h.routes(),
		BaseContext:       func(net.Listener) context.Context { return requestContext },
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}
	defer h.finishRun(server, cancelRequests)
	serverError := make(chan error, 1)
	go func() { serverError <- server.Serve(h.listener) }()
	var initial *bootstrapOperation
	if h.cfg.Backend.RequireModelBootstrap {
		bundle, found, err := h.loadStartupModelBundle()
		if err != nil {
			return fmt.Errorf("inspect applied model configuration: %w", err)
		}
		if !found {
			timer := time.NewTimer(time.Duration(h.cfg.Backend.ModelBootstrapTimeoutSeconds) * time.Second)
			defer timer.Stop()
			select {
			case initial = <-h.bootstrap:
			case <-ctx.Done():
				return ctx.Err()
			case err := <-serverError:
				return err
			case <-timer.C:
				return errors.New("model bootstrap was not supplied before the startup deadline")
			}
		} else {
			initial = &bootstrapOperation{bundle: bundle, done: make(chan error, 1)}
		}
	}
	if initial != nil {
		if state, migrated, err := h.applyCodexModelDefaults(); err != nil {
			h.finishBootstrap(initial, err)
			return fmt.Errorf("migrate Codex model defaults: %w", err)
		} else if migrated {
			initial.bundle.State = state
			h.logger.Printf("set Codex defaults model=%s reasoning=%s before runtime startup", modelbootstrap.DefaultCodexModel, modelbootstrap.DefaultCodexReasoningEffort)
		}
		if state, migrated, err := h.applyKimiModelDefaults(); err != nil {
			h.finishBootstrap(initial, err)
			return fmt.Errorf("migrate Kimi model defaults: %w", err)
		} else if migrated {
			initial.bundle.State = state
			h.logger.Printf("set Kimi defaults model=%s thinking=true efforts=low,high,max before runtime startup", modelbootstrap.DefaultKimiModel)
		}
		if err := h.writeCLIModelConfiguration(initial.bundle); err != nil {
			h.finishBootstrap(initial, err)
			return fmt.Errorf("configure model clients: %w", err)
		}
	}
	if err := h.probeAgentCLIs(ctx); err != nil {
		h.finishBootstrap(initial, err)
		return fmt.Errorf("verify bundled Agent CLI runtime: %w", err)
	}
	if err := h.startBackend(ctx); err != nil {
		h.finishBootstrap(initial, err)
		return err
	}
	if initial != nil {
		if err := h.completeModelBootstrap(ctx, initial.bundle); err != nil {
			h.finishBootstrap(initial, err)
			return err
		}
		if state, migrated, err := h.applyCodexModelDefaults(); err != nil {
			h.finishBootstrap(initial, err)
			return fmt.Errorf("finalize Codex model defaults: %w", err)
		} else if migrated {
			initial.bundle.State = state
			h.logger.Printf("set Codex defaults model=%s reasoning=%s", modelbootstrap.DefaultCodexModel, modelbootstrap.DefaultCodexReasoningEffort)
		}
		if state, migrated, err := h.applyKimiModelDefaults(); err != nil {
			h.finishBootstrap(initial, err)
			return fmt.Errorf("finalize Kimi model defaults: %w", err)
		} else if migrated {
			initial.bundle.State = state
			h.logger.Printf("set Kimi defaults model=%s thinking=true efforts=low,high,max", modelbootstrap.DefaultKimiModel)
		}
		h.finishBootstrap(initial, nil)
	}
	h.setReady(true)
	_ = sdnotify.Notify("READY=1\nSTATUS=WorkAgent2 tenant runtime is ready")
	go sdnotify.Watchdog(ctx)
	idleTicker := time.NewTicker(minDuration(30*time.Second, time.Duration(h.cfg.IdleReapSeconds)*time.Second/4))
	defer idleTicker.Stop()
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case backendErr := <-h.backendDone:
			h.setReady(false)
			if backendErr == nil {
				return errors.New("tenant backend exited unexpectedly")
			}
			return fmt.Errorf("tenant backend exited: %w", backendErr)
		case <-idleTicker.C:
			if h.idleEligible(ctx) {
				h.logger.Printf("tenant runtime reached its idle deadline")
				return nil
			}
		case <-healthTicker.C:
			if err := h.verifyBackendOwnership(ctx); err != nil {
				h.setReady(false)
				return fmt.Errorf("tenant runtime process verification failed: %w", err)
			}
		case err := <-serverError:
			if errors.Is(err, http.ErrServerClosed) || ipc.IsClosed(err) {
				return nil
			}
			return err
		case operation := <-h.bootstrap:
			err := h.applyLiveModelBootstrap(ctx, operation.bundle)
			h.finishBootstrap(operation, err)
		}
	}
}

// finishRun is the only Run-exit path that destroys the in-memory transport
// credential. It first prevents new accepts, cancels every request context,
// stops the backend (which tears down hijacked WebSocket tunnels), and waits
// for every UserHost handler to return. Only then may the shared token bytes be
// zeroed without racing a proxy Rewrite or an internal backend health call.
func (h *Host) finishRun(server *http.Server, cancelRequests context.CancelFunc) {
	h.setReady(false)
	_ = sdnotify.Notify("STOPPING=1\nSTATUS=WorkAgent2 tenant runtime is stopping")
	cancelRequests()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
	}
	cancel()
	h.stopBackend()
	h.handlers.Wait()
	h.mu.Lock()
	clear(h.runtimeToken)
	h.runtimeToken = nil
	h.proxy = nil
	h.transport = nil
	h.backendURL = nil
	h.auth = backendAuthMaterial{}
	h.mu.Unlock()
}

func (h *Host) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/status", h.statusHandler)
	mux.HandleFunc("GET /internal/model-bootstrap", h.modelBootstrapStatus)
	mux.HandleFunc("POST /internal/model-bootstrap", h.modelBootstrapApply)
	mux.HandleFunc("POST /internal/oauth/start", h.oauthStart)
	mux.HandleFunc("POST /internal/oauth/complete", h.oauthComplete)
	mux.HandleFunc("POST /internal/oauth/cancel", h.oauthCancel)
	mux.HandleFunc("GET /internal/storage-usage", h.storageUsageHandler)
	mux.HandleFunc("POST /internal/usage-snapshot", h.usageSnapshotHandler)
	mux.HandleFunc("GET /internal/projects", h.listProjects)
	mux.HandleFunc("POST /internal/projects", h.createProject)
	mux.HandleFunc("POST /internal/projects/rename", h.renameProject)
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "healthy"})
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if !h.isReady(request.Context()) {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/", h.proxyRequest)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		h.handlers.Add(1)
		defer h.handlers.Done()
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Cache-Control", "no-store")
		if request.Header.Get("X-WorkAgent-Tenant") != h.cfg.TenantID {
			http.Error(writer, "tenant binding rejected", http.StatusForbidden)
			return
		}
		internal := request.URL.Path == "/internal" || strings.HasPrefix(request.URL.Path, "/internal/")
		if internal && request.Header.Get("X-WorkAgent-Control") != "portal-v1" {
			http.Error(writer, "runtime control authentication rejected", http.StatusForbidden)
			return
		}
		userRequest := request.Header.Get("X-WorkAgent-User-Request") == "1" && !internal
		webSocket := userRequest && isWebSocketUpgrade(request)
		if userRequest {
			h.requests.Add(1)
			if webSocket {
				h.webSockets.Add(1)
			}
			h.touchActivity()
			defer func() {
				h.touchActivity()
				h.requests.Add(-1)
				if webSocket {
					h.webSockets.Add(-1)
				}
			}()
		}
		request.Header.Del("X-WorkAgent-Tenant")
		request.Header.Del("X-WorkAgent-User-Request")
		request.Header.Del("X-WorkAgent-Control")
		mux.ServeHTTP(writer, request)
	})
}

func (h *Host) proxyRequest(writer http.ResponseWriter, request *http.Request) {
	h.mu.RLock()
	proxy := h.proxy
	ready := h.ready
	h.mu.RUnlock()
	if proxy == nil || !ready {
		http.Error(writer, "tenant runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	proxy.ServeHTTP(writer, request)
}

func (h *Host) startBackend(ctx context.Context) error {
	if h.cfg.Backend.InternalAuth.Enabled {
		relativeDatabase, err := filepath.Rel(h.cfg.DataRoot, h.cfg.Backend.InternalAuth.DatabasePath)
		if err != nil {
			return err
		}
		if err := recoverProjectRenameState(ctx, h.workspace, h.dataRoot, relativeDatabase, h.uid); err != nil {
			return fmt.Errorf("recover interrupted project rename: %w", err)
		}
	}
	if h.cfg.Backend.Migration.Enabled {
		if err := h.runMigration(ctx); err != nil {
			return err
		}
	}
	if h.cfg.Backend.InternalAuth.Enabled {
		if _, err := applyInitialAgentDefaults(ctx, h.cfg.Backend.InternalAuth.DatabasePath, filepath.Join(h.cfg.DataRoot, "config", agentDefaultsMarkerName), h.uid, time.Now().UTC()); err != nil {
			return fmt.Errorf("initialize AionUi agent defaults: %w", err)
		}
		if applied, err := applyCodexAssistantDefaults(ctx, h.cfg.Backend.InternalAuth.DatabasePath, filepath.Join(h.cfg.DataRoot, "config", codexAssistantDefaultsMarkerName), h.uid, time.Now().UTC()); err != nil {
			return fmt.Errorf("initialize managed Codex assistant defaults: %w", err)
		} else if applied {
			h.logger.Printf("set managed Codex assistant defaults model=%s reasoning=%s permission=agent-full-access", modelbootstrap.DefaultCodexModel, modelbootstrap.DefaultCodexReasoningEffort)
		}
	}
	var internalUsername string
	var internalPassword []byte
	if h.cfg.Backend.InternalAuth.Enabled {
		relativeDatabase, err := filepath.Rel(h.cfg.DataRoot, h.cfg.Backend.InternalAuth.DatabasePath)
		if err != nil {
			return err
		}
		internalUsername, internalPassword, err = rotateBackendCredential(ctx, h.dataRoot, relativeDatabase, h.uid, time.Now().UTC())
		if err != nil {
			return err
		}
		defer clear(internalPassword)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("reserve backend address: %w", err)
	}
	address := listener.Addr().String()
	listener.Close()
	arguments := make([]string, len(h.cfg.Backend.Arguments))
	for index, argument := range h.cfg.Backend.Arguments {
		arguments[index] = expandArgument(argument, address, h.cfg.DataRoot, h.releaseRoot)
	}
	command := exec.CommandContext(ctx, h.cfg.Backend.Executable, arguments...)
	command.Dir = h.cfg.Backend.WorkingDirectory
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Env = h.runtimeEnvironment(address, true)
	logFile, err := openBoundedLog(h.dataRoot, "logs/backend.log")
	if err != nil {
		return err
	}
	command.Stdout, command.Stderr = logFile, logFile
	if err := startRuntimeCommand(command, h.runtimeToken); err != nil {
		logFile.Close()
		return fmt.Errorf("start tenant backend: %w", err)
	}
	if err := verifyBackendExecutable(command.Process.Pid, h.cfg.Backend.Executable); err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		logFile.Close()
		return err
	}
	h.mu.Lock()
	h.backend = command
	h.mu.Unlock()
	go func() {
		waitErr := command.Wait()
		_ = logFile.Close()
		h.setReady(false)
		h.backendDone <- waitErr
	}()
	backendURL, _ := url.Parse("http://" + address)
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
	}
	proxy := &httputil.ReverseProxy{}
	proxy.Transport = transport
	proxy.FlushInterval = -1
	proxy.Rewrite = func(proxyRequest *httputil.ProxyRequest) {
		h.mu.RLock()
		auth := h.auth
		h.mu.RUnlock()
		rewriteBackendProxyRequest(proxyRequest, backendURL, auth, h.runtimeToken)
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del("Set-Cookie")
		response.Header.Del("WWW-Authenticate")
		return nil
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		h.logger.Printf("backend request failed: %v", proxyErr)
		http.Error(writer, "tenant runtime unavailable", http.StatusBadGateway)
	}
	h.mu.Lock()
	h.backendURL = backendURL
	h.transport = transport
	h.proxy = proxy
	h.mu.Unlock()
	deadline := time.Now().Add(time.Duration(h.cfg.Backend.StartupTimeoutSeconds) * time.Second)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		request, requestBuildErr := http.NewRequestWithContext(ctx, http.MethodGet, backendURL.String()+h.cfg.Backend.HealthPath, nil)
		if requestBuildErr != nil {
			return requestBuildErr
		}
		setWorkAgentRuntimeHeader(request, h.runtimeToken)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				if err := verifyBackendProcess(address, command.Process.Pid, h.cfg.Backend.Executable); err != nil {
					return fmt.Errorf("verify backend listener ownership: %w", err)
				}
				if h.cfg.Backend.ActivityProbe == "aionui" {
					corePID, corePort, err := verifyAionCoreProcess(command.Process.Pid, h.cfg.Backend.Migration.Executable)
					if err != nil {
						return fmt.Errorf("verify AionCore child process: %w", err)
					}
					if err := checkAionCoreHealth(ctx, corePort, h.aionCoreHealth, h.runtimeToken); err != nil {
						return fmt.Errorf("verify AionCore health: %w", err)
					}
					h.mu.Lock()
					h.aionCorePID, h.aionCorePort = corePID, corePort
					h.mu.Unlock()
				}
				if h.cfg.Backend.InternalAuth.Enabled {
					auth, err := authenticateBackend(ctx, backendURL, transport, internalUsername, internalPassword, backendSystemInfo{
						CacheDir: filepath.Join(h.cfg.DataRoot, "data"),
						WorkDir:  filepath.Join(h.cfg.DataRoot, "workspace"),
						LogDir:   filepath.Join(h.cfg.DataRoot, "logs"),
						Platform: "linux",
						Arch:     "x64",
					}, h.runtimeToken)
					if err != nil {
						return fmt.Errorf("authenticate internal backend: %w", err)
					}
					h.mu.Lock()
					h.auth = auth
					h.mu.Unlock()
				}
				if h.cfg.Backend.ActivityProbe == "aionui" {
					prompt, err := loadWorkAgentAssistantPrompt(h.releaseRoot)
					if err != nil {
						return err
					}
					changed, brandingErr := applyWorkAgentBranding(ctx, h.dataRoot, "data/aionui-backend.db", prompt, h.uid, time.Now().UTC())
					clear(prompt)
					if brandingErr != nil {
						return fmt.Errorf("apply WorkAgent2 runtime branding: %w", brandingErr)
					}
					if changed {
						h.logger.Printf("converged the built-in assistant, snapshots, and product skills to WorkAgent2")
					}
				}
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("tenant backend did not become healthy before the startup deadline")
}

func stripRuntimeCredentials(header http.Header) {
	for name := range header {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" || lower == "x-csrf-token" || lower == "x-api-key" || lower == "forwarded" ||
			strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-windows-") || strings.HasPrefix(lower, "x-workagent-") ||
			strings.HasPrefix(lower, "x-aionui-portal-") || strings.HasPrefix(lower, "x-chatforward-") || strings.HasPrefix(lower, "x-workagent-") {
			delete(header, name)
		}
	}
}

func rewriteBackendProxyRequest(proxyRequest *httputil.ProxyRequest, backendURL *url.URL, auth backendAuthMaterial, runtimeToken []byte) {
	proxyRequest.SetURL(backendURL)
	request := proxyRequest.Out
	stripRuntimeCredentials(request.Header)
	if auth.CookieHeader != "" {
		request.Header.Set("Cookie", auth.CookieHeader)
	}
	if auth.CSRFToken != "" {
		request.Header.Set("X-CSRF-Token", auth.CSRFToken)
	}
	request.Header.Set("Origin", backendURL.String())
	request.Header.Del("Referer")
	setWorkAgentRuntimeHeader(request, runtimeToken)
}

func (h *Host) runtimeEnvironment(address string, includeRuntimeAuth bool) []string {
	pathValue := "/usr/bin:/bin"
	if h.cfg.Backend.AgentCLI.BinDirectory != "" {
		pathValue = h.cfg.Backend.AgentCLI.BinDirectory + ":" + pathValue
	}
	environment := []string{
		"HOME=" + filepath.Join(h.cfg.DataRoot, "home"),
		"LANG=C.UTF-8",
		"PATH=" + pathValue,
		"TMPDIR=" + filepath.Join(h.cfg.DataRoot, "tmp"),
		"XDG_CACHE_HOME=" + filepath.Join(h.cfg.DataRoot, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(h.cfg.DataRoot, "config"),
		"XDG_DATA_HOME=" + filepath.Join(h.cfg.DataRoot, "data"),
		"AIONUI_DATA_DIR=" + filepath.Join(h.cfg.DataRoot, "data"),
		"AIONUI_LOG_DIR=" + filepath.Join(h.cfg.DataRoot, "logs"),
		"AIONUI_CACHE_DIR=" + filepath.Join(h.cfg.DataRoot, "cache"),
		"AIONUI_WORK_DIR=" + filepath.Join(h.cfg.DataRoot, "workspace"),
		"AIONUI_BUILTIN_ASSISTANTS_PATH=" + filepath.Join(h.releaseRoot, "workagent-builtin-assistants"),
		"WORKAGENT_BACKEND_ADDRESS=" + address,
		"CODEX_HOME=" + filepath.Join(h.cfg.DataRoot, "config", "codex"),
		"KIMI_CODE_HOME=" + filepath.Join(h.cfg.DataRoot, "home", ".kimi-code"),
		"KIMI_CODE_NO_AUTO_UPDATE=1",
		"PYTHONDONTWRITEBYTECODE=1",
		"WORKAGENT_MODEL_BOOTSTRAP_MARKER=" + filepath.Join(h.cfg.DataRoot, modelBootstrapMarkerPath),
	}
	if includeRuntimeAuth {
		environment = append(environment,
			workAgentTenantEnvironment+"="+h.cfg.TenantID,
			workAgentRuntimeFDEnvironment+"="+workAgentRuntimeFDText,
		)
	}
	for key, value := range h.cfg.Backend.Environment {
		environment = append(environment, key+"="+expandArgument(value, address, h.cfg.DataRoot, h.releaseRoot))
	}
	if h.cfg.OutboundProxyURL != "" {
		environment = append(environment,
			"HTTP_PROXY="+h.cfg.OutboundProxyURL,
			"HTTPS_PROXY="+h.cfg.OutboundProxyURL,
			"NO_PROXY=127.0.0.1,localhost,::1",
		)
	}
	return environment
}

func (h *Host) stopBackend() {
	h.mu.RLock()
	backend := h.backend
	transport := h.transport
	h.mu.RUnlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
	if backend == nil || backend.Process == nil {
		return
	}
	_ = syscall.Kill(-backend.Process.Pid, syscall.SIGTERM)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := backend.Process.Signal(syscall.Signal(0)); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-backend.Process.Pid, syscall.SIGKILL)
}

func verifyRuntimeIdentity(cfg config.Tenant) (uint32, error) {
	account, err := user.Lookup(cfg.RuntimeUser)
	if err != nil {
		return 0, fmt.Errorf("lookup runtime account: %w", err)
	}
	parsed, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || parsed == 0 {
		return 0, errors.New("runtime account must have a non-root numeric UID")
	}
	uid := uint32(parsed)
	if uint32(os.Getuid()) != uid || uint32(os.Geteuid()) != uid {
		return 0, fmt.Errorf("UserHost is running as UID %d instead of dedicated UID %d", os.Geteuid(), uid)
	}
	if uid == cfg.PortalUID {
		return 0, errors.New("Portal and tenant runtime must use different UIDs")
	}
	return uid, nil
}

func verifyDataRoot(path string, expectedUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect tenant data root: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("tenant data root must be a real 0700 directory owned by the runtime UID")
	}
	return nil
}

func expandArgument(value, address, dataRoot, releaseRoot string) string {
	value = strings.ReplaceAll(value, "{listen_address}", address)
	if host, port, err := net.SplitHostPort(address); err == nil {
		value = strings.ReplaceAll(value, "{listen_host}", host)
		value = strings.ReplaceAll(value, "{listen_port}", port)
	}
	value = strings.ReplaceAll(value, "{data_root}", dataRoot)
	return strings.ReplaceAll(value, "{release_root}", releaseRoot)
}

func (h *Host) statusHandler(writer http.ResponseWriter, request *http.Request) {
	h.mu.RLock()
	ready := h.ready
	backend := h.backend
	corePID, corePort := h.aionCorePID, h.aionCorePort
	h.mu.RUnlock()
	pid := 0
	if backend != nil && backend.Process != nil {
		pid = backend.Process.Pid
	}
	if ready && h.verifyBackendOwnership(request.Context()) != nil {
		ready = false
	}
	activityContext, cancel := context.WithTimeout(request.Context(), 750*time.Millisecond)
	defer cancel()
	activity, err := h.probeActivity(activityContext)
	if err != nil {
		activity = ActivityStatus{Known: false}
	}
	slot := 0
	if h.capacity != nil {
		slot = h.capacity.index
	}
	writeJSON(writer, http.StatusOK, Status{TenantID: h.cfg.TenantID, RuntimeUser: h.cfg.RuntimeUser, RuntimeUID: h.uid, ReleaseID: h.releaseID, Ready: ready, BackendPID: pid, AionCorePID: corePID, AionCorePort: corePort, StartedAt: h.startedAt, LastActivity: time.Unix(0, h.lastActivity.Load()).UTC(), ActiveRequests: h.requests.Load(), ActiveWebSockets: h.webSockets.Load(), CapacitySlot: slot, Activity: activity})
}

func (h *Host) listProjects(writer http.ResponseWriter, request *http.Request) {
	entries, err := h.workspace.ReadDir(".")
	if err != nil {
		http.Error(writer, "cannot list projects", http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && projectfs.ValidProjectName(entry.Name()) && h.workspace.ValidateDirectory(entry.Name(), h.uid) == nil {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	writeJSON(writer, http.StatusOK, map[string]any{"projects": names})
}

func (h *Host) createProject(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(request, &body, 16*1024); err != nil || !projectfs.ValidProjectName(body.Name) {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_PROJECT_NAME"})
		return
	}
	if err := h.workspace.CreateDirectory(body.Name, 0o700); err != nil {
		status, code := http.StatusServiceUnavailable, "PROJECT_CREATE_FAILED"
		if errors.Is(err, os.ErrExist) {
			status, code = http.StatusConflict, "PROJECT_EXISTS"
		}
		h.logger.Printf("project creation rejected tenant=%s code=%s", h.cfg.TenantID, code)
		writeJSON(writer, status, map[string]any{"success": false, "code": code})
		return
	}
	if err := h.workspace.ValidateDirectory(body.Name, h.uid); err != nil {
		cleanupErr := os.Remove(filepath.Join(h.workspace.Path(), body.Name))
		h.logger.Printf("project creation verification failed tenant=%s: %v", h.cfg.TenantID, errors.Join(err, cleanupErr))
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "PROJECT_CREATE_FAILED"})
		return
	}
	h.touchActivity()
	writeJSON(writer, http.StatusCreated, map[string]string{"path": filepath.Join(h.workspace.Path(), body.Name)})
}

func (h *Host) renameProject(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		OldName    string `json:"old_name"`
		NewName    string `json:"new_name"`
		Force      bool   `json:"force,omitempty"`
		LegacyRoot bool   `json:"legacy_root,omitempty"`
	}
	if err := decodeJSON(request, &body, 16*1024); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"success": false, "code": "INVALID_PROJECT_NAME"})
		return
	}
	operationContext, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	result, code, err := h.renameProjectOperation(operationContext, body.OldName, body.NewName, body.Force, body.LegacyRoot)
	if err != nil {
		status := http.StatusServiceUnavailable
		switch code {
		case "INVALID_PROJECT_NAME":
			status = http.StatusBadRequest
		case "PROJECT_NOT_FOUND":
			status = http.StatusNotFound
		case "PROJECT_EXISTS", "PROJECT_IN_USE", "PROJECT_FORCE_STOP_FAILED":
			status = http.StatusConflict
		}
		h.logger.Printf("project rename rejected tenant=%s code=%s", h.cfg.TenantID, code)
		writeJSON(writer, status, map[string]any{"success": false, "code": code})
		return
	}
	h.touchActivity()
	writeJSON(writer, http.StatusOK, result)
}

func (h *Host) setReady(value bool) {
	h.mu.Lock()
	h.ready = value
	h.mu.Unlock()
}

func (h *Host) isReady(ctx context.Context) bool {
	h.mu.RLock()
	ready := h.ready
	h.mu.RUnlock()
	return ready && h.verifyBackendOwnership(ctx) == nil
}

func (h *Host) verifyBackendOwnership(ctx context.Context) error {
	h.mu.RLock()
	backend := h.backend
	backendURL := h.backendURL
	h.mu.RUnlock()
	if backend == nil || backend.Process == nil || backendURL == nil {
		return errors.New("backend is unavailable")
	}
	if err := verifyBackendProcess(backendURL.Host, backend.Process.Pid, h.cfg.Backend.Executable); err != nil {
		return err
	}
	if h.cfg.Backend.ActivityProbe == "aionui" {
		pid, port, err := verifyAionCoreProcess(backend.Process.Pid, h.cfg.Backend.Migration.Executable)
		if err != nil {
			return err
		}
		h.mu.RLock()
		expectedPID, expectedPort := h.aionCorePID, h.aionCorePort
		h.mu.RUnlock()
		if pid != expectedPID || port != expectedPort {
			return errors.New("AionCore process identity changed after startup")
		}
		if err := checkAionCoreHealth(ctx, port, h.aionCoreHealth, h.runtimeToken); err != nil {
			return err
		}
	}
	return nil
}

func expectedAionCoreHealthVersions(manifest release.Manifest) ([]string, error) {
	for _, component := range manifest.Components {
		if component.Name != "aioncore" {
			continue
		}
		full := strings.TrimPrefix(component.Version, "v")
		if full == "" {
			return nil, errors.New("runtime release has an invalid AionCore version")
		}
		versions := []string{full}
		if index := strings.Index(full, "-editfork."); index > 0 {
			versions = append(versions, full[:index])
		}
		return versions, nil
	}
	return nil, errors.New("runtime release does not declare AionCore")
}

func (h *Host) touchActivity() { h.lastActivity.Store(time.Now().UTC().UnixNano()) }

func (h *Host) idleEligible(parent context.Context) bool {
	last := time.Unix(0, h.lastActivity.Load())
	if time.Since(last) < time.Duration(h.cfg.IdleReapSeconds)*time.Second || h.requests.Load() != 0 || h.webSockets.Load() != 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	activity, err := h.probeActivity(ctx)
	if err != nil || !activity.Known {
		h.logger.Printf("tenant activity is unknown; idle reap deferred: %v", err)
		return false
	}
	if activity.Active {
		h.touchActivity()
		return false
	}
	return h.requests.Load() == 0 && h.webSockets.Load() == 0
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

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func decodeJSON(request *http.Request, destination any, maximum int64) error {
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > maximum {
		clear(payload)
		return errors.New("request body is too large")
	}
	defer clear(payload)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
