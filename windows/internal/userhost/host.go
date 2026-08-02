package userhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/config"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/release"
	"aionuiportal/internal/winutil"
	"golang.org/x/sys/windows"
)

type privateDirs struct {
	Profile      string
	Data         string
	Config       string
	Credentials  string
	OAuth        string
	Workspace    string
	Cache        string
	Logs         string
	Temp         string
	Runtime      string
	AppData      string
	LocalAppData string
}

type Host struct {
	cfg     config.UserHost
	release release.Verified
	dirs    privateDirs
	job     *winutil.Job
	sandbox *winutil.RestrictedToken
	log     *privateLog
	oauth   *oauthManager

	mu           sync.RWMutex
	status       ipc.Status
	auth         ipc.AuthMaterial
	client       *aionClient
	web          *exec.Cmd
	webDone      chan error
	stop         chan struct{}
	stopOnce     sync.Once
	previousStat winutil.JobStats
	previousAt   time.Time

	storageMu      sync.Mutex
	storageUsage   ipc.StorageUsage
	storageUsageAt time.Time
}

func Run(ctx context.Context, cfg config.UserHost) error {
	h := &Host{cfg: cfg, stop: make(chan struct{})}
	return h.run(ctx)
}

func (h *Host) run(ctx context.Context) error {
	startupBegan := time.Now()
	identity, err := winutil.RequireIdentity(h.cfg.WindowsSID, true)
	if err != nil {
		return err
	}
	whoamiCtx, cancelWhoami := context.WithTimeout(ctx, 10*time.Second)
	err = winutil.VerifyWhoamiSID(whoamiCtx, h.cfg.WindowsSID)
	cancelWhoami()
	if err != nil {
		return err
	}
	windowsProfile, err := winutil.ProfileDirectoryForSID(h.cfg.WindowsSID)
	if err != nil {
		return err
	}
	if !samePath(windowsProfile, h.cfg.WindowsProfile) {
		return fmt.Errorf("registered Windows profile %s does not match configured profile %s", windowsProfile, h.cfg.WindowsProfile)
	}
	expectedDataRoot := filepath.Join(windowsProfile, config.UserDataDirectoryName)
	if !samePath(expectedDataRoot, h.cfg.DataRoot) {
		return fmt.Errorf("configured data root %s does not match SID profile data root %s", h.cfg.DataRoot, expectedDataRoot)
	}
	verified, err := release.VerifyCurrentFast(h.cfg.CurrentReleaseFile, h.cfg.ReleasesRoot, h.cfg.SupportedAionCore)
	if err != nil {
		return fmt.Errorf("verify shared AionUi release: %w", err)
	}
	h.release = verified
	h.dirs, err = ensurePrivateDirs(h.cfg.DataRoot)
	if err != nil {
		return err
	}
	if _, err := applyInitialCLILanguageDefaults(h.dirs); err != nil {
		return err
	}
	if err := winutil.VerifyTreeACL(h.cfg.DataRoot, winutil.PrivateTreePolicy(h.cfg.WindowsSID)); err != nil {
		return fmt.Errorf("verify private user tree before sandbox launch: %w", err)
	}
	if err := winutil.RequireCurrentTokenOutsideCodexSandboxGroup(); err != nil {
		return err
	}
	h.sandbox, err = winutil.NewCurrentUserRestrictedToken(h.cfg.WindowsSID)
	if err != nil {
		return fmt.Errorf("create per-user process sandbox: %w", err)
	}
	defer h.sandbox.Close()
	h.oauth = newOAuthManager(filepath.Join(h.dirs.Data, "aionui-backend.db"), nil, time.Now, false)
	h.log, err = openPrivateLog(h.dirs.Logs)
	if err != nil {
		return fmt.Errorf("open UserHost log: %w", err)
	}
	defer h.log.Close()
	h.log.Printf("UserHost starting sid=%s account=%s\\%s release=%s", identity.SID, identity.Domain, identity.Username, verified.Manifest.Version)
	h.log.Printf("Startup release verification mode=fast prelaunch_elapsed_ms=%d", time.Since(startupBegan).Milliseconds())
	h.job, err = winutil.NewJob("AionUiWeb-"+h.cfg.WindowsSID, winutil.JobLimits{
		MemoryBytes: h.cfg.Limits.MemoryBytes, CPUPercent: h.cfg.Limits.CPUPercent, ActiveProcesses: h.cfg.Limits.ActiveProcesses,
	})
	if err != nil {
		return err
	}
	if err := h.job.AssignCurrentProcess(); err != nil {
		return err
	}
	now := time.Now()
	h.status = ipc.Status{WindowsSID: h.cfg.WindowsSID, State: "starting", UserHostPID: uint32(os.Getpid()), Version: verified.Manifest.Version,
		StartedAtUnix: now.Unix(), LastActivityUnix: now.Unix(), Activity: ipc.Activity{Known: false, Active: true, Reason: "startup in progress", CheckedAtUnix: now.Unix()}}
	sddl, err := ipc.SDDL(h.cfg.WindowsSID, h.cfg.PortalServiceSID)
	if err != nil {
		return err
	}
	pipe, err := ipc.Listen(ctx, h.cfg.PipeName, sddl, h.handleIPC)
	if err != nil {
		return err
	}
	defer pipe.Close()
	if err := h.initialize(ctx); err != nil {
		h.setFailure(err)
		h.log.Printf("startup failed: %v", err)
		return err
	}
	h.log.Printf("UserHost healthy web_pid=%d core_pid=%d web_port=%d core_port=%d", h.status.WebPID, h.status.AionCorePID, h.status.WebPort, h.status.AionCorePort)
	if err := h.monitor(ctx); err != nil {
		h.log.Printf("runtime failed: %v", err)
		return err
	}
	return nil
}

func (h *Host) initialize(ctx context.Context) error {
	corePath := filepath.Join(h.release.Path, "bundled-aioncore", "win32-x64", "aioncore.exe")
	webPath := filepath.Join(h.release.Path, "aionui-web.exe")
	staticPath := filepath.Join(h.release.Path, "static")
	env := h.environment()
	phaseStarted := time.Now()
	agentVersions, err := agentcli.Probe(ctx, agentcli.BinFromAionReleases(h.cfg.ReleasesRoot), env, h.sandbox.Apply)
	if err != nil {
		return fmt.Errorf("verify shared agent CLIs: %w", err)
	}
	h.log.Printf("Shared agent CLIs verified codex=%s kimi=%s python=%s elapsed_ms=%d", agentVersions.Codex, agentVersions.Kimi, agentVersions.Python, time.Since(phaseStarted).Milliseconds())
	phaseStarted = time.Now()
	kimiConfigMigrated, err := h.initializeKimiCodeConfig(ctx, env)
	if err != nil {
		return err
	}
	h.log.Printf("Startup phase completed phase=kimi-config elapsed_ms=%d changed=%t", time.Since(phaseStarted).Milliseconds(), kimiConfigMigrated)
	if kimiConfigMigrated {
		h.log.Printf("Copied the legacy Kimi configuration to the private Kimi Code home; the legacy configuration was preserved for rollback")
	}
	phaseStarted = time.Now()
	pendingModels, err := h.preparePendingModelBootstrap(ctx, env)
	if err != nil {
		return err
	}
	h.log.Printf("Startup phase completed phase=model-bootstrap-prepare elapsed_ms=%d pending=%t", time.Since(phaseStarted).Milliseconds(), pendingModels != nil)
	// Keep catalog setup after the pending API-key login and before the bundle is
	// completed so a first-start user follows the same exact picker policy.
	phaseStarted = time.Now()
	codexCatalogApplied, err := h.applyManagedCodexModelCatalog(ctx, env, agentVersions.Codex)
	if err != nil {
		return err
	}
	h.log.Printf("Startup phase completed phase=codex-catalog elapsed_ms=%d catalog_fetched=%t", time.Since(phaseStarted).Milliseconds(), codexCatalogApplied)
	if codexCatalogApplied {
		h.log.Printf("Initialized Codex CLI with the exact three-model GPT-5.6 catalog")
	}
	phaseStarted = time.Now()
	kimiThinkingApplied, err := h.applyKimiThinkingDefault(ctx, env)
	if err != nil {
		return err
	}
	h.log.Printf("Startup phase completed phase=kimi-defaults elapsed_ms=%d changed=%t", time.Since(phaseStarted).Milliseconds(), kimiThinkingApplied)
	if kimiThinkingApplied {
		h.log.Printf("Initialized Kimi for Coding with thinking enabled")
	}
	migrationPort, err := selectLoopbackPort(h.cfg.MigrationPortStart, h.cfg.MigrationPortTries)
	if err != nil {
		return fmt.Errorf("select migration port: %w", err)
	}
	phaseStarted = time.Now()
	if err := h.runMigrations(ctx, corePath, migrationPort, env); err != nil {
		return err
	}
	h.log.Printf("Startup phase completed phase=aioncore-migrations elapsed_ms=%d", time.Since(phaseStarted).Milliseconds())
	dbPath := filepath.Join(h.dirs.Data, "aionui-backend.db")
	brandingApplied, err := applyWorkAgentBranding(ctx, dbPath, h.dirs.Data, filepath.Join(h.dirs.Config, workagentBrandingMarkerName), time.Now())
	if err != nil {
		return err
	}
	if brandingApplied {
		h.log.Printf("Updated the built-in WorkAgent AI assistant, prompt, and skill bindings")
	}
	if pendingModels == nil {
		codexModelDefaultsApplied, err := applyCodexModelDefaults(h.cfg.DataRoot, h.dirs)
		if err != nil {
			return err
		}
		if codexModelDefaultsApplied {
			h.log.Printf("Set the Codex default model to %s with %s reasoning before runtime startup", modelbootstrap.DefaultCodexModel, modelbootstrap.DefaultCodexReasoningEffort)
		}
	}
	agentDefaultsApplied, err := applyInitialAgentDefaults(ctx, dbPath, filepath.Join(h.dirs.Config, agentDefaultsMarkerName), time.Now())
	if err != nil {
		return err
	}
	if agentDefaultsApplied {
		h.log.Printf("Initialized AionUi agents with Aion CLI, Codex, and Kimi enabled and Aion CLI defaulting to YOLO")
	}
	codexAssistantDefaultsApplied, err := applyCodexAssistantDefaults(ctx, dbPath, filepath.Join(h.dirs.Config, codexAssistantDefaultsMarkerName), time.Now())
	if err != nil {
		return err
	}
	if codexAssistantDefaultsApplied {
		h.log.Printf("Set managed Codex assistant defaults to %s, %s reasoning, and full access", modelbootstrap.DefaultCodexModel, modelbootstrap.DefaultCodexReasoningEffort)
	}
	username, password, err := rotateInternalCredentials(ctx, dbPath, time.Now())
	if err != nil {
		return err
	}
	defer zero(password)
	webPort, err := selectLoopbackPort(h.cfg.WebPort, h.cfg.WebPortTries)
	if err != nil {
		return fmt.Errorf("select internal Web port: %w", err)
	}
	cmd := exec.Command(webPath, "start", "--port", fmt.Sprint(webPort), "--data-dir", h.dirs.Data, "--work-dir", h.dirs.Workspace, "--log-dir", h.dirs.Logs,
		"--static-dir", staticPath, "--backend-bin", corePath, "--no-open")
	cmd.Dir = h.dirs.Workspace
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := h.sandbox.Apply(cmd); err != nil {
		return fmt.Errorf("sandbox aionui-web.exe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start shared aionui-web.exe: %w", err)
	}
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	h.web = cmd
	h.webDone = make(chan error, 1)
	go func() { h.webDone <- cmd.Wait() }()
	go h.log.CopyRedacted("[aionui-web stdout]", stdout)
	go h.log.CopyRedacted("[aionui-web stderr]", stderr)
	h.mu.Lock()
	h.status.WebPID = uint32(cmd.Process.Pid)
	h.status.WebPort = webPort
	h.mu.Unlock()
	startupCtx, cancel := context.WithTimeout(ctx, time.Duration(h.cfg.StartupSeconds)*time.Second)
	defer cancel()
	client, material, err := h.waitForAuthentication(startupCtx, webPort, username, password)
	if err != nil {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			h.stopCommand(cmd, h.webDone, 5*time.Second)
		}
		return err
	}
	h.client, h.auth = client, material
	if err := h.applyPendingModelBootstrap(startupCtx, pendingModels); err != nil {
		h.stopCommand(cmd, h.webDone, 5*time.Second)
		return err
	}
	codexModelDefaultsApplied, err := applyCodexModelDefaults(h.cfg.DataRoot, h.dirs)
	if err != nil {
		h.stopCommand(cmd, h.webDone, 5*time.Second)
		return err
	}
	if codexModelDefaultsApplied {
		h.log.Printf("Set the Codex default model to %s with %s reasoning", modelbootstrap.DefaultCodexModel, modelbootstrap.DefaultCodexReasoningEffort)
	}
	if err := h.enforceManagedProviderPolicy(startupCtx); err != nil {
		h.stopCommand(cmd, h.webDone, 5*time.Second)
		return err
	}
	corePID, corePort, checks, err := h.verifyCompleteHealth(startupCtx, corePath, webPort, uint32(cmd.Process.Pid), username)
	if err != nil {
		h.stopCommand(cmd, h.webDone, 5*time.Second)
		return err
	}
	if err := h.sandbox.VerifyProcess(corePID, h.cfg.WindowsSID); err != nil {
		h.stopCommand(cmd, h.webDone, 5*time.Second)
		return err
	}
	checks = append(checks, "per-user-restricted-token")
	checks = append(checks, "codex-cli", "kimi-cli")
	if pendingModels != nil {
		checks = append(checks, "codex-api-key", "kimi-api-key", "aion-model-providers")
	}
	stats, err := h.job.Stats()
	if err != nil {
		return err
	}
	h.previousStat, h.previousAt = stats, time.Now()
	h.mu.Lock()
	h.status.State = "healthy"
	h.status.Healthy = true
	h.status.AionCorePID = corePID
	h.status.AionCorePort = corePort
	h.status.ProcessCount = stats.ProcessCount
	h.status.MemoryBytes = stats.MemoryBytes
	h.status.Checks = checks
	h.status.Activity = ipc.Activity{Known: false, Active: true, Reason: "activity has not yet been probed", CheckedAtUnix: time.Now().Unix()}
	h.mu.Unlock()
	return nil
}

func (h *Host) runMigrations(ctx context.Context, corePath string, port int, env []string) error {
	cmd := exec.Command(corePath, "--port", fmt.Sprint(port), "--data-dir", h.dirs.Data, "--work-dir", h.dirs.Workspace,
		"--log-dir", h.dirs.Logs, "--managed-resources-mode", "bundled")
	cmd.Dir = h.dirs.Workspace
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := h.sandbox.Apply(cmd); err != nil {
		return fmt.Errorf("sandbox AionCore migration process: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start AionCore migration process: %w", err)
	}
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	go h.log.CopyRedacted("[migration stdout]", stdout)
	go h.log.CopyRedacted("[migration stderr]", stderr)
	deadline, cancel := context.WithTimeout(ctx, time.Duration(h.cfg.StartupSeconds)*time.Second)
	defer cancel()
	if err := waitCoreHealth(deadline, port, h.release.Manifest.AionCoreVersion, done); err != nil {
		h.stopCommand(cmd, done, 3*time.Second)
		return fmt.Errorf("AionCore migrations did not become healthy: %w", err)
	}
	if err := h.stopCommand(cmd, done, time.Duration(h.cfg.ShutdownSeconds)*time.Second); err != nil {
		return fmt.Errorf("stop AionCore migration process: %w", err)
	}
	return nil
}

func (h *Host) waitForAuthentication(ctx context.Context, port int, username string, password []byte) (*aionClient, ipc.AuthMaterial, error) {
	client, err := newAionClient(port)
	if err != nil {
		return nil, ipc.AuthMaterial{}, err
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		var status struct {
			Success    bool `json:"success"`
			NeedsSetup bool `json:"needs_setup"`
		}
		err := client.getJSON(ctx, "/api/auth/status", &status)
		if err == nil && status.Success {
			if status.NeedsSetup {
				return nil, ipc.AuthMaterial{}, errors.New("internal AionUi still requires setup after offline credential rotation")
			}
			material, authErr := client.authenticate(ctx, username, password)
			if authErr != nil {
				return nil, ipc.AuthMaterial{}, fmt.Errorf("single internal login attempt failed: %w", authErr)
			}
			return client, material, nil
		}
		last = err
		select {
		case <-ctx.Done():
			return nil, ipc.AuthMaterial{}, fmt.Errorf("internal authentication timeout: %w (last error: %v)", ctx.Err(), last)
		case webErr := <-h.webDone:
			return nil, ipc.AuthMaterial{}, fmt.Errorf("aionui-web exited during startup: %v", webErr)
		case <-ticker.C:
		}
	}
}

func (h *Host) verifyCompleteHealth(ctx context.Context, corePath string, webPort int, webPID uint32, username string) (uint32, int, []string, error) {
	if err := winutil.VerifyLoopbackListener(webPID, webPort); err != nil {
		return 0, 0, nil, err
	}
	if inside, err := h.job.ContainsPID(webPID); err != nil || !inside {
		return 0, 0, nil, errors.New("aionui-web is not in the expected Job Object")
	}
	processes, err := h.job.Processes()
	if err != nil {
		return 0, 0, nil, err
	}
	var cores []winutil.ProcessInfo
	for _, process := range processes {
		if strings.EqualFold(process.ImageName, "aioncore.exe") {
			cores = append(cores, process)
		}
	}
	if len(cores) != 1 || !samePath(cores[0].ImagePath, corePath) {
		return 0, 0, nil, fmt.Errorf("expected one shared-release aioncore process, found %+v", cores)
	}
	corePID := cores[0].PID
	listeners, err := winutil.TCPListeners()
	if err != nil {
		return 0, 0, nil, err
	}
	corePort := 0
	for _, listener := range listeners {
		if listener.PID != corePID {
			continue
		}
		if !listener.Address.Equal(net.IPv4(127, 0, 0, 1)) || corePort != 0 {
			return 0, 0, nil, errors.New("aioncore does not have exactly one loopback-only listener")
		}
		corePort = listener.Port
	}
	if corePort == 0 {
		return 0, 0, nil, errors.New("aioncore listener was not found")
	}
	if err := checkCoreHealth(ctx, corePort, h.release.Manifest.AionCoreVersion); err != nil {
		return 0, 0, nil, err
	}
	if inside, err := h.job.ContainsPID(corePID); err != nil || !inside {
		return 0, 0, nil, errors.New("aioncore is not in the expected Job Object")
	}
	if err := h.client.validateAuthenticatedAPIs(ctx, username, systemInfo{CacheDir: h.dirs.Data, WorkDir: h.dirs.Workspace, LogDir: h.dirs.Logs, Platform: "win32", Arch: "x64"}); err != nil {
		return 0, 0, nil, err
	}
	return corePID, corePort, []string{"sid", "whoami-user", "release-integrity", "job-object", "web-process", "aioncore-process", "loopback-bindings", "aioncore-health", "internal-auth", "auth-user-api", "system-dirs", "renderer-api", "not-frontend-only"}, nil
}

func waitCoreHealth(ctx context.Context, port int, expectedVersion string, done <-chan error) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if err := checkCoreHealth(ctx, port, expectedVersion); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last health error: %v)", ctx.Err(), last)
		case err := <-done:
			return fmt.Errorf("process exited before health: %v", err)
		case <-ticker.C:
		}
	}
}

const coreHealthTransientFailureThreshold = 3

type coreHealthError struct {
	transient bool
	err       error
}

func (e *coreHealthError) Error() string { return e.err.Error() }
func (e *coreHealthError) Unwrap() error { return e.err }

func isTransientCoreHealthError(err error) bool {
	var healthErr *coreHealthError
	return errors.As(err, &healthErr) && healthErr.transient
}

func coreHealthMonitorDecision(consecutive int, err error) (int, bool) {
	if !isTransientCoreHealthError(err) {
		return 0, true
	}
	consecutive++
	return consecutive, consecutive >= coreHealthTransientFailureThreshold
}

func checkCoreHealth(ctx context.Context, port int, expectedVersion string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/health", port), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return &coreHealthError{transient: true, err: err}
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return &coreHealthError{transient: true, err: fmt.Errorf("AionCore health returned HTTP %d", response.StatusCode)}
	}
	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	decodeErr := json.NewDecoder(response.Body).Decode(&health)
	if response.StatusCode != http.StatusOK || decodeErr != nil || health.Status != "ok" || health.Version != strings.TrimPrefix(expectedVersion, "v") {
		return fmt.Errorf("unexpected AionCore health response: HTTP %d status=%q version=%q", response.StatusCode, health.Status, health.Version)
	}
	return nil
}

func (h *Host) monitor(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	consecutiveHealthFailures := 0
	for {
		select {
		case <-ctx.Done():
			h.log.Printf("UserHost shutdown requested reason=context cancelled")
			h.shutdown("context cancelled")
			h.log.Printf("UserHost shutdown completed reason=context cancelled")
			return nil
		case <-h.stop:
			h.log.Printf("UserHost shutdown requested reason=stop requested")
			h.shutdown("stop requested")
			h.log.Printf("UserHost shutdown completed reason=stop requested")
			return nil
		case err := <-h.webDone:
			failure := fmt.Errorf("aionui-web exited unexpectedly: %v", err)
			h.setFailure(failure)
			return failure
		case now := <-ticker.C:
			stats, err := h.job.Stats()
			if err != nil {
				h.setFailure(fmt.Errorf("Job Object accounting failed: %w", err))
				return err
			}
			cpu := winutil.CPUPercent(h.previousStat, stats, now.Sub(h.previousAt))
			h.previousStat, h.previousAt = stats, now
			h.mu.Lock()
			h.status.ProcessCount, h.status.MemoryBytes, h.status.CPUPercent = stats.ProcessCount, stats.MemoryBytes, cpu
			h.mu.Unlock()
			if err := checkCoreHealth(ctx, h.snapshot().AionCorePort, h.release.Manifest.AionCoreVersion); err != nil {
				var fail bool
				consecutiveHealthFailures, fail = coreHealthMonitorDecision(consecutiveHealthFailures, err)
				if !fail {
					h.log.Printf("AionCore health monitor transient failure consecutive=%d threshold=%d error=%v", consecutiveHealthFailures, coreHealthTransientFailureThreshold, err)
					continue
				}
				h.setFailure(fmt.Errorf("AionCore health monitor failed: %w", err))
				return err
			}
			if consecutiveHealthFailures != 0 {
				h.log.Printf("AionCore health monitor recovered after transient_failures=%d", consecutiveHealthFailures)
				consecutiveHealthFailures = 0
			}
		}
	}
}

func (h *Host) shutdown(reason string) {
	h.mu.Lock()
	h.status.State, h.status.Healthy, h.status.FailureReason = "draining", false, reason
	h.auth = ipc.AuthMaterial{}
	h.mu.Unlock()
	if h.web != nil {
		if err := h.stopCommand(h.web, h.webDone, time.Duration(h.cfg.ShutdownSeconds)*time.Second); err != nil {
			h.log.Printf("graceful Web shutdown failed: %v", err)
			h.job.Terminate(2)
		}
	}
}

func (h *Host) stopCommand(cmd *exec.Cmd, done <-chan error, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	signalErr := winutil.SignalProcessGroup(uint32(cmd.Process.Pid))
	if signalErr != nil {
		h.log.Printf("graceful signal failed for pid=%d; forcing only this process: %v", cmd.Process.Pid, signalErr)
		cmd.Process.Kill()
	}
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return errors.New("process did not exit after forced termination")
		}
		return errors.New("process exceeded graceful shutdown timeout")
	}
}

func (h *Host) handleIPC(ctx context.Context, request ipc.Request) ipc.Response {
	switch request.Command {
	case "status":
		status := h.snapshot()
		return ipc.Response{OK: true, Status: &status}
	case "auth":
		h.mu.RLock()
		defer h.mu.RUnlock()
		if !h.status.Healthy || h.auth.CookieHeader == "" {
			return ipc.Response{OK: false, ErrorCode: "INSTANCE_NOT_HEALTHY", ErrorMessage: "internal authentication is unavailable"}
		}
		auth := h.auth
		return ipc.Response{OK: true, Auth: &auth}
	case "model_key_ids":
		ids, err := modelbootstrap.AppliedKeyIDs(h.cfg.DataRoot, h.cfg.WindowsSID)
		if errors.Is(err, modelbootstrap.ErrAppliedMarkerMissing) {
			return ipc.Response{OK: false, ErrorCode: "MODEL_MARKER_MISSING", ErrorMessage: "applied model mapping is unavailable"}
		}
		if err != nil {
			return ipc.Response{OK: false, ErrorCode: "MODEL_MARKER_INVALID", ErrorMessage: "applied model mapping is invalid"}
		}
		responseIDs := ipc.ModelKeyIDs{CodexKeyID: ids.CodexKeyID, KimiKeyID: ids.KimiKeyID}
		return ipc.Response{OK: true, ModelKeyIDs: &responseIDs}
	case "storage_usage":
		usage, err := h.currentStorageUsage(ctx)
		if err != nil {
			return ipc.Response{OK: false, ErrorCode: "STORAGE_USAGE_UNAVAILABLE", ErrorMessage: "private storage usage is unavailable"}
		}
		return ipc.Response{OK: true, StorageUsage: &usage}
	case "usage_snapshot":
		if len(request.UsageSnapshot) == 0 || len(request.UsageSnapshot) > 64*1024 || !json.Valid(request.UsageSnapshot) {
			return ipc.Response{OK: false, ErrorCode: "INVALID_USAGE_SNAPSHOT", ErrorMessage: "usage snapshot is invalid"}
		}
		var snapshot struct {
			AsOf      string `json:"as_of"`
			Providers []struct {
				Kind string `json:"kind"`
			} `json:"providers"`
		}
		if err := json.Unmarshal(request.UsageSnapshot, &snapshot); err != nil || snapshot.AsOf == "" || len(snapshot.Providers) != 2 || snapshot.Providers[0].Kind == snapshot.Providers[1].Kind {
			return ipc.Response{OK: false, ErrorCode: "INVALID_USAGE_SNAPSHOT", ErrorMessage: "usage snapshot is invalid"}
		}
		if err := writePrivateFileAtomic(filepath.Join(h.dirs.Data, "quota-summary.json"), request.UsageSnapshot); err != nil {
			return ipc.Response{OK: false, ErrorCode: "USAGE_SNAPSHOT_WRITE_FAILED", ErrorMessage: "usage snapshot could not be saved"}
		}
		return ipc.Response{OK: true}
	case "touch":
		h.mu.Lock()
		h.status.LastActivityUnix = time.Now().Unix()
		h.mu.Unlock()
		return ipc.Response{OK: true}
	case "activity":
		activityCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		activity := h.probeActivity(activityCtx)
		h.mu.Lock()
		h.status.Activity = activity
		status := h.status
		status.Checks = append([]string(nil), h.status.Checks...)
		h.mu.Unlock()
		return ipc.Response{OK: true, Status: &status}
	case "oauth_start":
		if request.OAuthStart == nil || !h.validOAuthInstance(request.OAuthStart.InstanceID) || h.oauth == nil {
			return ipc.Response{OK: false, ErrorCode: "INVALID_OAUTH_FLOW", ErrorMessage: "OAuth start request did not match this healthy UserHost instance"}
		}
		result, err := h.oauth.start(ctx, *request.OAuthStart)
		if err != nil {
			return ipc.Response{OK: false, ErrorCode: "OAUTH_START_FAILED", ErrorMessage: err.Error()}
		}
		h.touchActivity()
		return ipc.Response{OK: true, OAuth: &result}
	case "oauth_complete":
		if request.OAuthComplete == nil || !h.validOAuthInstance(request.OAuthComplete.InstanceID) || h.oauth == nil {
			return ipc.Response{OK: false, ErrorCode: "INVALID_OAUTH_FLOW", ErrorMessage: "OAuth completion request did not match this healthy UserHost instance"}
		}
		if err := h.oauth.complete(ctx, *request.OAuthComplete); err != nil {
			return ipc.Response{OK: false, ErrorCode: "OAUTH_COMPLETE_FAILED", ErrorMessage: err.Error()}
		}
		h.touchActivity()
		return ipc.Response{OK: true}
	case "oauth_cancel":
		if request.OAuthCancel == nil || !h.validOAuthInstance(request.OAuthCancel.InstanceID) || h.oauth == nil {
			return ipc.Response{OK: false, ErrorCode: "INVALID_OAUTH_FLOW", ErrorMessage: "OAuth cancellation request did not match this healthy UserHost instance"}
		}
		if err := h.oauth.cancel(*request.OAuthCancel); err != nil {
			return ipc.Response{OK: false, ErrorCode: "OAUTH_CANCEL_FAILED", ErrorMessage: err.Error()}
		}
		return ipc.Response{OK: true}
	case "project_create":
		if request.ProjectCreate == nil {
			return ipc.Response{OK: false, ErrorCode: "INVALID_PROJECT_REQUEST", ErrorMessage: "project creation request is missing"}
		}
		result, code, err := h.createProject(*request.ProjectCreate)
		if err != nil {
			return ipc.Response{OK: false, ErrorCode: code, ErrorMessage: err.Error()}
		}
		h.touchActivity()
		return ipc.Response{OK: true, ProjectCreate: &result}
	case "project_rename":
		if request.ProjectRename == nil {
			return ipc.Response{OK: false, ErrorCode: "INVALID_PROJECT_REQUEST", ErrorMessage: "project rename request is missing"}
		}
		result, code, err := h.renameProject(ctx, *request.ProjectRename)
		if err != nil {
			return ipc.Response{OK: false, ErrorCode: code, ErrorMessage: err.Error()}
		}
		h.touchActivity()
		return ipc.Response{OK: true, ProjectRename: &result}
	case "stop":
		h.stopOnce.Do(func() { close(h.stop) })
		return ipc.Response{OK: true}
	default:
		return ipc.Response{OK: false, ErrorCode: "UNKNOWN_COMMAND", ErrorMessage: "unsupported UserHost command"}
	}
}

func (h *Host) validOAuthInstance(instanceID string) bool {
	status := h.snapshot()
	return status.Healthy && instanceID != "" && instanceID == fmt.Sprintf("%s:%d:%d", status.Version, status.UserHostPID, status.StartedAtUnix)
}

func (h *Host) touchActivity() {
	h.mu.Lock()
	h.status.LastActivityUnix = time.Now().Unix()
	h.mu.Unlock()
}

func (h *Host) snapshot() ipc.Status {
	h.mu.RLock()
	defer h.mu.RUnlock()
	status := h.status
	status.Checks = append([]string(nil), h.status.Checks...)
	return status
}

const userStorageLimitBytes = uint64(20 * 1024 * 1024 * 1024)
const storageUsageCacheTTL = 5 * time.Minute

func (h *Host) currentStorageUsage(ctx context.Context) (ipc.StorageUsage, error) {
	h.storageMu.Lock()
	defer h.storageMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ipc.StorageUsage{}, err
	}
	now := time.Now()
	if h.storageUsage.MeasuredAt != "" && now.Sub(h.storageUsageAt) < storageUsageCacheTTL {
		return h.storageUsage, nil
	}
	usage, err := measureStorageUsage(ctx, h.cfg.DataRoot)
	if err != nil {
		return ipc.StorageUsage{}, err
	}
	h.storageUsage = usage
	h.storageUsageAt = now
	return usage, nil
}

func measureStorageUsage(ctx context.Context, root string) (ipc.StorageUsage, error) {
	var used uint64
	err := filepath.WalkDir(root, accumulateStorageEntry(ctx, &used))
	if err != nil {
		return ipc.StorageUsage{}, err
	}
	remaining := uint64(0)
	if used < userStorageLimitBytes {
		remaining = userStorageLimitBytes - used
	}
	return ipc.StorageUsage{
		LimitBytes:     userStorageLimitBytes,
		UsedBytes:      used,
		RemainingBytes: remaining,
		MeasuredAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func accumulateStorageEntry(ctx context.Context, used *uint64) fs.WalkDirFunc {
	return func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// WalkDir does not normally follow symbolic links, but Windows directory
		// junctions are reparse points that may otherwise require resolving an
		// inaccessible target before Info can return. Skip them from the cheap
		// DirEntry type metadata first, then retain the attribute check below for
		// other Windows reparse-point forms.
		if entry.Type()&fs.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok && data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 {
			return nil
		}
		size := uint64(info.Size())
		if ^uint64(0)-*used < size {
			return errors.New("private storage usage overflowed")
		}
		*used += size
		return nil
	}
}

func (h *Host) setFailure(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.State, h.status.Healthy, h.status.FailureReason = "failed", false, err.Error()
	h.auth = ipc.AuthMaterial{}
}

func ensurePrivateDirs(root string) (privateDirs, error) {
	d := privateDirs{Profile: filepath.Join(root, "profile"), Data: filepath.Join(root, "data"), Config: filepath.Join(root, "config"),
		Credentials: filepath.Join(root, "credentials"), OAuth: filepath.Join(root, "oauth"), Workspace: filepath.Join(root, "workspace"),
		Cache: filepath.Join(root, "cache"), Logs: filepath.Join(root, "logs"), Temp: filepath.Join(root, "temp"), Runtime: filepath.Join(root, "runtime")}
	d.AppData, d.LocalAppData = filepath.Join(d.Profile, "AppData", "Roaming"), filepath.Join(d.Profile, "AppData", "Local")
	for _, path := range []string{d.Profile, d.Data, d.Config, d.Credentials, d.OAuth, d.Workspace, d.Cache, d.Logs, d.Temp, d.Runtime,
		d.AppData, d.LocalAppData, filepath.Join(d.Config, "codex"), filepath.Join(d.Config, "claude"), filepath.Join(d.Config, "gemini")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return privateDirs{}, fmt.Errorf("create private directory %s: %w", path, err)
		}
	}
	return d, nil
}

func (h *Host) environment() []string {
	overrides := map[string]string{
		"HOME": h.dirs.Profile, "USERPROFILE": h.dirs.Profile, "APPDATA": h.dirs.AppData, "LOCALAPPDATA": h.dirs.LocalAppData,
		"TEMP": h.dirs.Temp, "TMP": h.dirs.Temp, "AIONUI_DATA_DIR": h.dirs.Data, "AIONUI_LOG_DIR": h.dirs.Logs,
		"AIONUI_CACHE_DIR": h.dirs.Cache, "AIONUI_WORK_DIR": h.dirs.Workspace,
		"AIONUI_BUILTIN_ASSISTANTS_PATH":   filepath.Join(h.release.Path, "workagent-builtin-assistants"),
		"CODEX_HOME":                       filepath.Join(h.dirs.Config, "codex"),
		"KIMI_CODE_HOME":                   filepath.Join(h.dirs.Profile, ".kimi-code"),
		"KIMI_CODE_NO_AUTO_UPDATE":         "1",
		agentcli.PerUserSandboxEnvironment: "1",
		"CLAUDE_CONFIG_DIR":                filepath.Join(h.dirs.Config, "claude"), "GEMINI_CLI_HOME": filepath.Join(h.dirs.Config, "gemini"),
		"XDG_CONFIG_HOME": h.dirs.Config, "XDG_CACHE_HOME": h.dirs.Cache, "XDG_DATA_HOME": h.dirs.Data,
		"npm_config_cache": filepath.Join(h.dirs.Cache, "npm"), "BUN_INSTALL_CACHE_DIR": filepath.Join(h.dirs.Cache, "bun"),
	}
	if h.cfg.OutboundProxyURL != "" {
		overrides["HTTP_PROXY"] = h.cfg.OutboundProxyURL
		overrides["HTTPS_PROXY"] = h.cfg.OutboundProxyURL
		overrides["NO_PROXY"] = "127.0.0.1,localhost,::1"
	}
	result := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key := entry
		if index := strings.IndexByte(entry, '='); index >= 0 {
			key = entry[:index]
		}
		upperKey := strings.ToUpper(key)
		if isSensitiveEnvironmentName(upperKey) || isOutboundProxyEnvironmentName(upperKey) {
			continue
		}
		replaced := false
		for overrideKey := range overrides {
			if strings.EqualFold(overrideKey, key) {
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return agentcli.PrependPath(result, agentcli.BinFromAionReleases(h.cfg.ReleasesRoot))
}

func isOutboundProxyEnvironmentName(name string) bool {
	switch name {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
		return true
	default:
		return false
	}
}

func isSensitiveEnvironmentName(name string) bool {
	for _, fragment := range []string{"PASSWORD", "PASSWD", "TOKEN", "SECRET", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE_KEY"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func selectLoopbackPort(start, attempts int) (int, error) {
	for i := 0; i < attempts; i++ {
		port := start + i
		if port > 65535 {
			break
		}
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		listener.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no loopback port available in bounded range %d..%d", start, start+attempts-1)
}

func init() {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		panic("AionUiUserHost requires Windows amd64")
	}
}
