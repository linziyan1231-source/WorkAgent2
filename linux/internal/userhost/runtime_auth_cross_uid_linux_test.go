package userhost

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

// This opt-in test uses the real release binaries and a second kernel UID. It
// is intentionally not a mock and is run during release qualification with:
//
//	WORKAGENT_RUNTIME_AUTH_RUNTIME_ROOT=/absolute/release/root go test \
//	  ./internal/userhost -run TestRealRuntimeAuthRejectsCrossUIDDirectAccess
//
// The release root is not copied or modified. No service is installed or
// started. The default victim is this root test process; the attacker is an
// otherwise-unused numeric UID, which still proves the loopback cross-UID
// boundary without mutating system accounts.
func TestRealRuntimeAuthRejectsCrossUIDDirectAccess(t *testing.T) {
	if os.Getenv("WORKAGENT_RUNTIME_AUTH_RUNTIME_ROOT") == "" {
		t.Skip("real runtime release was not supplied")
	}
	if os.Geteuid() != 0 {
		t.Skip("real cross-UID runtime test requires root")
	}
	runtimeRoot, err := filepath.Abs(os.Getenv("WORKAGENT_RUNTIME_AUTH_RUNTIME_ROOT"))
	if err != nil || runtimeRoot != filepath.Clean(runtimeRoot) {
		t.Fatal("runtime release root must be an absolute canonical path")
	}
	aionUI := filepath.Join(runtimeRoot, "bin", "aionui-web")
	aionCore := filepath.Join(runtimeRoot, "bin", "aioncore")
	staticRoot := filepath.Join(runtimeRoot, "static")
	for _, path := range []string{aionUI, aionCore, filepath.Join(staticRoot, "index.html")} {
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("real runtime input is unavailable: %s", path)
		}
	}

	token, err := generateWorkAgentRuntimeToken()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	tenantID := "11111111-1111-4111-8111-111111111111"
	root := t.TempDir()
	for _, name := range []string{"data", "logs", "work", "home", "tmp", "cache", "config"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	logs := &lockedBoundedBuffer{maximum: 2 * 1024 * 1024}
	command := exec.Command(
		aionUI, "start", "--port", "0", "--no-open",
		"--data-dir", filepath.Join(root, "data"),
		"--log-dir", filepath.Join(root, "logs"),
		"--work-dir", filepath.Join(root, "work"),
		"--static-dir", staticRoot,
		"--backend-bin", aionCore,
	)
	command.Dir = filepath.Join(root, "work")
	command.Env = []string{
		"HOME=" + filepath.Join(root, "home"),
		"LANG=C.UTF-8",
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + filepath.Join(root, "tmp"),
		"XDG_CACHE_HOME=" + filepath.Join(root, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(root, "config"),
		"AIONUI_OPEN_BROWSER=0",
		workAgentTenantEnvironment + "=" + tenantID,
		workAgentRuntimeFDEnvironment + "=" + workAgentRuntimeFDText,
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = logs, logs
	if err := startRuntimeCommand(command, token); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
	}()

	frontendPattern := regexp.MustCompile(`(?m)^  Local  : http://127\.0\.0\.1:([1-9][0-9]*)/?$`)
	backendPattern := regexp.MustCompile(`(?m)^\[aioncore\] AIONCORE_LISTENING \{"host":"127\.0\.0\.1","port":([1-9][0-9]*)\}`)
	deadline := time.Now().Add(60 * time.Second)
	var frontendPort, backendPort uint64
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			command.Process = nil
			t.Fatalf("AionUi exited before readiness: %v\n%s", err, redactRuntimeTestLog(logs.String(), token))
		default:
		}
		content := logs.Bytes()
		frontend := frontendPattern.FindSubmatch(content)
		backend := backendPattern.FindSubmatch(content)
		if len(frontend) == 2 && len(backend) == 2 && bytes.Contains(content, []byte("AionUi WebUI is ready")) {
			frontendPort, _ = strconv.ParseUint(string(frontend[1]), 10, 16)
			backendPort, _ = strconv.ParseUint(string(backend[1]), 10, 16)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if frontendPort == 0 || backendPort == 0 {
		t.Fatalf("AionUi did not become ready\n%s", redactRuntimeTestLog(logs.String(), token))
	}

	corePID, verifiedPort, err := verifyAionCoreProcess(command.Process.Pid, aionCore)
	if err != nil || uint64(verifiedPort) != backendPort {
		t.Fatalf("real AionCore child identity is invalid: pid=%d port=%d err=%v", corePID, verifiedPort, err)
	}
	processes := []struct {
		name           string
		pid            int
		markersVisible bool
	}{
		{name: "AionUi", pid: command.Process.Pid, markersVisible: true},
		{name: "AionCore", pid: corePID},
	}
	for _, process := range processes {
		name, pid := process.name, process.pid
		visible, readErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
		if readErr != nil {
			t.Fatalf("read %s environment: %v", name, readErr)
		}
		tenantMarker := bytes.Contains(visible, []byte(workAgentTenantEnvironment+"="+tenantID+"\x00"))
		fdMarker := bytes.Contains(visible, []byte(workAgentRuntimeFDEnvironment+"="+workAgentRuntimeFDText+"\x00"))
		anyTenantMarker := bytes.Contains(visible, []byte(workAgentTenantEnvironment+"="))
		anyFDMarker := bytes.Contains(visible, []byte(workAgentRuntimeFDEnvironment+"="))
		secretName := bytes.Contains(visible, []byte(workAgentRuntimeEnvironment+"="))
		secretValue := bytes.Contains(visible, token)
		clear(visible)
		if process.markersVisible && (!tenantMarker || !fdMarker) {
			t.Fatalf("%s initial environment did not retain the exact non-secret possession markers in /proc", name)
		}
		if !process.markersVisible && (anyTenantMarker || anyFDMarker) {
			t.Fatalf("%s did not byte-scrub the non-secret possession markers from /proc", name)
		}
		if secretName || secretValue {
			t.Fatalf("%s retained secret WorkAgent bootstrap material in /proc", name)
		}
		arguments, readErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
		if readErr != nil {
			t.Fatalf("read %s arguments: %v", name, readErr)
		}
		if bytes.Contains(arguments, token) {
			clear(arguments)
			t.Fatalf("%s retained the runtime token in argv", name)
		}
		clear(arguments)
	}

	attackerUID := uint32(65532)
	if attackerUID == uint32(os.Geteuid()) {
		attackerUID--
	}
	frontendURL := "http://127.0.0.1:" + strconv.FormatUint(frontendPort, 10)
	backendURL := "http://127.0.0.1:" + strconv.FormatUint(backendPort, 10)
	for name, check := range map[string]struct{ target, header string }{
		"frontend missing": {target: frontendURL + "/"},
		"frontend wrong":   {target: frontendURL + "/", header: strings.Repeat("B", workAgentRuntimeTokenTextBytes)},
		"core missing":     {target: backendURL + "/health"},
		"core wrong":       {target: backendURL + "/health", header: strings.Repeat("B", workAgentRuntimeTokenTextBytes)},
	} {
		if status := curlStatusAsUID(t, attackerUID, check.target, check.header); status != http.StatusForbidden {
			t.Fatalf("%s returned HTTP %d instead of 403", name, status)
		}
	}

	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	if status := runtimeRequestStatus(t, client, backendURL+"/health", token); status != http.StatusOK {
		t.Fatalf("authenticated core health returned HTTP %d", status)
	}
	if status := runtimeRequestStatus(t, client, backendURL+"/api/settings", token); status != http.StatusUnauthorized {
		t.Fatalf("runtime token bypassed AionCore JWT authentication: HTTP %d", status)
	}
	if status := runtimeRequestStatus(t, client, frontendURL+"/api/settings", token); status != http.StatusUnauthorized {
		t.Fatalf("runtime token bypassed proxied JWT authentication: HTTP %d", status)
	}

	target, _ := url.Parse(frontendURL)
	proxy := &httputil.ReverseProxy{
		Transport: http.DefaultTransport,
		Rewrite: func(request *httputil.ProxyRequest) {
			rewriteBackendProxyRequest(request, target, backendAuthMaterial{}, token)
		},
	}
	host := &Host{cfg: config.Tenant{TenantID: tenantID}, proxy: proxy, ready: true, runtimeToken: token}
	userHost := httptest.NewServer(host.routes())
	defer userHost.Close()
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, userHost.URL+"/", nil)
	request.Header.Set("X-WorkAgent-Tenant", tenantID)
	request.Header.Set("X-WorkAgent-User-Request", "1")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("UserHost-authenticated frontend path returned HTTP %d", response.StatusCode)
	}
}

type lockedBoundedBuffer struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	maximum int
}

func (b *lockedBoundedBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(payload) > b.maximum {
		return 0, fmt.Errorf("runtime output exceeded %d bytes", b.maximum)
	}
	return b.buffer.Write(payload)
}

func (b *lockedBoundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

func (b *lockedBoundedBuffer) String() string { return string(b.Bytes()) }

func redactRuntimeTestLog(value string, token []byte) string {
	return strings.ReplaceAll(value, string(token), "[REDACTED]")
}

func curlStatusAsUID(t *testing.T, uid uint32, target, token string) int {
	t.Helper()
	arguments := []string{"--noproxy", "*", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", "5"}
	if token != "" {
		arguments = append(arguments, "--header", workAgentRuntimeHeader+": "+token)
	}
	arguments = append(arguments, target)
	command := exec.Command("/usr/bin/curl", arguments...)
	command.Env = []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, NoSetGroups: true}}
	output, err := command.Output()
	if err != nil {
		t.Fatalf("cross-UID request failed: %v", err)
	}
	status, err := strconv.Atoi(string(output))
	if err != nil {
		t.Fatalf("cross-UID request returned invalid status %q", output)
	}
	return status
}

func runtimeRequestStatus(t *testing.T, client *http.Client, target string, token []byte) int {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	setWorkAgentRuntimeHeader(request, token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	response.Body.Close()
	return response.StatusCode
}
