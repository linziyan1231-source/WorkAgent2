package userhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

func TestAionUiRuntimeEnvironmentUsesPrivateTenantAndVerifiedReleasePaths(t *testing.T) {
	dataRoot := filepath.Join(t.TempDir(), "tenant")
	releaseRoot := filepath.Join(t.TempDir(), "release")
	token := []byte(strings.Repeat("A", workAgentRuntimeTokenTextBytes))
	host := &Host{cfg: config.Tenant{TenantID: "11111111-1111-4111-8111-111111111111", DataRoot: dataRoot, OutboundProxyURL: "http://127.0.0.1:7897"}, releaseRoot: releaseRoot, runtimeToken: token}
	environment := make(map[string]string)
	for _, entry := range host.runtimeEnvironment("127.0.0.1:43123", true) {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("invalid environment entry %q", entry)
		}
		environment[name] = value
	}
	want := map[string]string{
		"AIONUI_DATA_DIR":                filepath.Join(dataRoot, "data"),
		"AIONUI_LOG_DIR":                 filepath.Join(dataRoot, "logs"),
		"AIONUI_CACHE_DIR":               filepath.Join(dataRoot, "cache"),
		"AIONUI_WORK_DIR":                filepath.Join(dataRoot, "workspace"),
		"AIONUI_BUILTIN_ASSISTANTS_PATH": filepath.Join(releaseRoot, "workagent-builtin-assistants"),
		"CODEX_HOME":                     filepath.Join(dataRoot, "config", "codex"),
		"KIMI_CODE_HOME":                 filepath.Join(dataRoot, "home", ".kimi-code"),
		"WORKAGENT_BACKEND_ADDRESS":      "127.0.0.1:43123",
		"WORKAGENT_TENANT_ID":            host.cfg.TenantID,
		"WORKAGENT_RUNTIME_FD":           "3",
		"HTTP_PROXY":                     "http://127.0.0.1:7897",
		"HTTPS_PROXY":                    "http://127.0.0.1:7897",
		"NO_PROXY":                       "127.0.0.1,localhost,::1",
	}
	probeEnvironment := make(map[string]bool)
	for _, entry := range host.runtimeEnvironment("127.0.0.1:1", false) {
		name, _, _ := strings.Cut(entry, "=")
		probeEnvironment[name] = true
	}
	if probeEnvironment[workAgentTenantEnvironment] || probeEnvironment[workAgentRuntimeFDEnvironment] || probeEnvironment[workAgentRuntimeEnvironment] {
		t.Fatal("Agent CLI probe received the broad runtime transport credential")
	}
	if _, found := environment[workAgentRuntimeEnvironment]; found {
		t.Fatal("AionUi runtime environment contained the removed broad token variable")
	}
	for name, expected := range want {
		if environment[name] != expected {
			t.Fatalf("%s=%q want %q", name, environment[name], expected)
		}
	}
	argument := expandArgument("{release_root}/bin/aioncore:{listen_host}:{listen_port}:{data_root}", "127.0.0.1:43123", dataRoot, releaseRoot)
	if argument != filepath.Join(releaseRoot, "bin", "aioncore")+":127.0.0.1:43123:"+dataRoot {
		t.Fatalf("expanded argument=%q", argument)
	}
}

func TestRuntimeCredentialStrippingRejectsAllBrowserIdentityNamespaces(t *testing.T) {
	header := http.Header{
		"Cookie":                      {"secret"},
		"Authorization":               {"secret"},
		"X-Api-Key":                   {"secret"},
		"Forwarded":                   {"for=203.0.113.7"},
		"X-Forwarded-For":             {"203.0.113.7"},
		"X-Windows-Sid":               {"forged"},
		"X-WorkAgent-Tenant":                {"forged"},
		"X-Aionui-Portal-Admin":       {"forged"},
		"X-Chatforward-Signature":     {"forged"},
		"X-WorkAgent-Runtime-Token":   {"forged"},
		"X-WorkAgent-Cron-Capability": {"forged"},
		"Accept":                      {"application/json"},
	}
	stripRuntimeCredentials(header)
	if len(header) != 1 || header.Get("Accept") != "application/json" {
		t.Fatalf("runtime credential stripping left unsafe headers: %#v", header)
	}
}

func TestBackendReverseProxyDoesNotReintroduceForwardingIdentity(t *testing.T) {
	runtimeToken := []byte(strings.Repeat("A", workAgentRuntimeTokenTextBytes))
	var received http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = request.Header.Clone()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			rewriteBackendProxyRequest(request, target, backendAuthMaterial{CookieHeader: "aion-session=internal", CSRFToken: "internal-csrf"}, runtimeToken)
		},
		Transport: upstream.Client().Transport,
	}
	request := httptest.NewRequest(http.MethodGet, "http://userhost/api/events", nil)
	request.RemoteAddr = "192.0.2.10:45678"
	request.Header.Set("Cookie", "browser=secret")
	request.Header.Set("Authorization", "Bearer browser-secret")
	request.Header.Set("Forwarded", "for=203.0.113.7")
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	request.Header.Set("X-WorkAgent-Tenant", "forged")
	request.Header.Set("X-WorkAgent-Runtime-Token", "forged")
	request.Header.Set("X-WorkAgent-Cron-Capability", "forged")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("unexpected proxy response: %d", recorder.Code)
	}
	if received.Get("Authorization") != "" || received.Get("Forwarded") != "" || received.Get("X-Forwarded-For") != "" || received.Get("X-WorkAgent-Tenant") != "" || received.Get("X-WorkAgent-Cron-Capability") != "" {
		t.Fatalf("browser identity reached AionUi: %#v", received)
	}
	if received.Get("Cookie") != "aion-session=internal" || received.Get("X-CSRF-Token") != "internal-csrf" || received.Get("Origin") != upstream.URL || received.Get(workAgentRuntimeHeader) != string(runtimeToken) {
		t.Fatalf("internal AionUi authentication contract changed: %#v", received)
	}
}

func TestProcListenerAddressAcceptsOnlyLoopback(t *testing.T) {
	for _, value := range []string{"0100007F", "00000000000000000000000001000000"} {
		if !procAddressIsLoopback(value) {
			t.Fatalf("loopback address rejected: %s", value)
		}
	}
	for _, value := range []string{"00000000", "010200C0", "not-hex"} {
		if procAddressIsLoopback(value) {
			t.Fatalf("non-loopback address accepted: %s", value)
		}
	}
}

func TestAionCoreHealthIsBoundToSignedComponentVersion(t *testing.T) {
	runtimeToken := []byte(strings.Repeat("A", workAgentRuntimeTokenTextBytes))
	versions, err := expectedAionCoreHealthVersions(release.Manifest{Components: []release.Component{{Name: "aioncore", Version: "v0.1.42-editfork.4"}}})
	if err != nil || len(versions) != 2 || versions[0] != "0.1.42-editfork.4" || versions[1] != "0.1.42" {
		t.Fatalf("unexpected health versions: %v err=%v", versions, err)
	}
	version := "0.1.42"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get(workAgentRuntimeHeader) != string(runtimeToken) {
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]string{"status": "ok", "version": version})
	}))
	defer server.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.ParseUint(portText, 10, 16)
	if err := checkAionCoreHealth(context.Background(), uint16(port), versions, runtimeToken); err != nil {
		t.Fatalf("signed AionCore version was rejected: %v", err)
	}
	version = "0.1.41"
	if err := checkAionCoreHealth(context.Background(), uint16(port), versions, runtimeToken); err == nil {
		t.Fatal("wrong AionCore health version was accepted")
	}
}

func TestGeneratedWorkAgentRuntimeTokenIsCanonicalAndFresh(t *testing.T) {
	first, err := generateWorkAgentRuntimeToken()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	second, err := generateWorkAgentRuntimeToken()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second)
	if !validWorkAgentRuntimeToken(first) || !validWorkAgentRuntimeToken(second) || string(first) == string(second) {
		t.Fatal("runtime transport credentials were not fresh canonical 32-byte base64url values")
	}
	for _, invalid := range [][]byte{nil, []byte(strings.Repeat("A", 42)), []byte(strings.Repeat("A", 42) + "="), []byte(strings.Repeat("A", 42) + "+")} {
		if validWorkAgentRuntimeToken(invalid) {
			t.Fatal("malformed runtime transport credential was accepted")
		}
	}
}

func TestRuntimeCommandDoesNotRetainBootstrapEnvironment(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=TestRuntimeSocketChildHelper")
	command.Env = []string{
		"GO_WANT_RUNTIME_SOCKET_HELPER=1",
		workAgentTenantEnvironment + "=11111111-1111-4111-8111-111111111111",
		workAgentRuntimeFDEnvironment + "=" + workAgentRuntimeFDText,
	}
	retainedSlice := command.Env
	token := []byte(strings.Repeat("A", workAgentRuntimeTokenTextBytes))
	if err := startRuntimeCommand(command, token); err != nil {
		t.Fatal(err)
	}
	if command.Env != nil || retainedSlice[0] != "" || retainedSlice[1] != "" || retainedSlice[2] != "" {
		t.Fatal("started command retained its runtime bootstrap environment")
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSocketChildHelper(t *testing.T) {
	if os.Getenv("GO_WANT_RUNTIME_SOCKET_HELPER") != "1" {
		return
	}
	frame := make([]byte, 64)
	defer clear(frame)
	n, err := syscall.Read(workAgentRuntimeChildFD, frame)
	if err != nil || n != workAgentRuntimeFrameBytes || !bytes.Equal(frame[:len(workAgentRuntimeFrameMagic)], workAgentRuntimeFrameMagic[:]) || binary.BigEndian.Uint16(frame[len(workAgentRuntimeFrameMagic):]) != workAgentRuntimeTokenBytes {
		os.Exit(41)
	}
	second := make([]byte, 1)
	defer clear(second)
	n, err = syscall.Read(workAgentRuntimeChildFD, second)
	if err != nil || n != 0 {
		os.Exit(42)
	}
	pollDescriptors := []unix.PollFd{{Fd: workAgentRuntimeChildFD, Events: unix.POLLRDHUP}}
	ready, err := unix.Poll(pollDescriptors, 0)
	if err != nil || ready != 1 || pollDescriptors[0].Revents&(unix.POLLHUP|unix.POLLRDHUP) == 0 {
		os.Exit(43)
	}
	if err := syscall.Close(workAgentRuntimeChildFD); err != nil {
		os.Exit(44)
	}
}
