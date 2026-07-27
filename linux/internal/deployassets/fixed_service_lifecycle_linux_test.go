package deployassets

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

type fixedHelperFixture struct {
	helper     string
	target     string
	marker     string
	locks      []string
	names      string
	oauthNames string
	targetFile string
}

func replaceHelperFixtureText(t *testing.T, payload *string, old, replacement string) {
	t.Helper()
	if !strings.Contains(*payload, old) {
		t.Fatalf("helper fixture source omitted %q", old)
	}
	*payload = strings.Replace(*payload, old, replacement, 1)
}

func newFixedHelperFixture(t *testing.T, targetBody string) fixedHelperFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact production lock ownership is root-only")
	}
	root := t.TempDir()
	fixture := fixedHelperFixture{
		helper:     filepath.Join(root, "workagent-fixed-root-exec-v1"),
		target:     filepath.Join(root, "target"),
		marker:     filepath.Join(root, "signal-forwarded"),
		locks:      []string{filepath.Join(root, "catalog.lock"), filepath.Join(root, "control.lock"), filepath.Join(root, "shared.lock"), filepath.Join(root, "migration.lock"), filepath.Join(root, "oauth.lock")},
		names:      "workagent-config-lock:workagent-control-release-lock:workagent-shared-release-lock:workagent-cliproxy-migration-lock",
		oauthNames: "workagent-config-lock:workagent-control-release-lock:workagent-shared-release-lock:workagent-cliproxy-migration-lock:workagent-cliproxy-oauth-lock",
		targetFile: targetBody,
	}
	for _, path := range fixture.locks {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(fixture.target, []byte(targetBody), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.target, 0o700); err != nil {
		t.Fatal(err)
	}

	payload := repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	replaceHelperFixtureText(t, &payload, "readonly catalog_lock=/run/workagent/release-config.lock", "readonly catalog_lock="+fixture.locks[0])
	replaceHelperFixtureText(t, &payload, "readonly control_lock=/opt/workagent/control.lock", "readonly control_lock="+fixture.locks[1])
	replaceHelperFixtureText(t, &payload, "readonly shared_lock=/opt/workagent/shared.lock", "readonly shared_lock="+fixture.locks[2])
	replaceHelperFixtureText(t, &payload, "readonly cliproxy_migration_lock=/run/workagent/cliproxy-migration.lock", "readonly cliproxy_migration_lock="+fixture.locks[3])
	replaceHelperFixtureText(t, &payload, "readonly cliproxy_oauth_lock=/run/workagent/cliproxy-oauth.lock", "readonly cliproxy_oauth_lock="+fixture.locks[4])
	replaceHelperFixtureText(t, &payload,
		"expected_command=(/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml)",
		"expected_command=("+fixture.target+")",
	)
	groupBlock := `  group_record=$(/usr/bin/getent group cliproxyapi 2>/dev/null || true)
  [[ -n $group_record && $group_record != *$'\n'* ]] || fail "CLIProxy group identity is unavailable"
  IFS=: read -r group_name _group_password group_gid _group_members <<< "$group_record"
  [[ $group_name == cliproxyapi && $group_gid =~ ^[1-9][0-9]*$ ]] || fail "CLIProxy group identity is invalid"
  migration_shape=0:$group_gid:640:1:0
  oauth_shape=$migration_shape`
	replaceHelperFixtureText(t, &payload, groupBlock, "  migration_shape=0:0:600:1:0\n  oauth_shape=$migration_shape")
	if err := os.WriteFile(fixture.helper, []byte(payload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.helper, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f fixedHelperFixture) command(t *testing.T, names string) (*exec.Cmd, []*os.File) {
	t.Helper()
	files := make([]*os.File, 0, 4)
	for _, path := range f.locks[:4] {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	command := exec.Command("/bin/bash", "-c", `export LISTEN_PID=$$; exec "$@"`, "workagent-fixed-root-test", f.helper, "cliproxyapi", f.target)
	command.Env = append(os.Environ(), "LISTEN_FDS=4", "LISTEN_FDNAMES="+names)
	command.ExtraFiles = files
	return command, files
}

func closeFixtureFiles(t *testing.T, files []*os.File) {
	t.Helper()
	for _, file := range files {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func exclusiveLockAvailable(t *testing.T, path string) bool {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		if unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN); unlockErr != nil {
			t.Fatal(unlockErr)
		}
		return true
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false
	}
	t.Fatalf("probe exclusive lock %s: %v", path, err)
	return false
}

func waitCommand(t *testing.T, command *exec.Cmd, timeout time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		<-done
		t.Fatal("lifecycle helper did not exit before timeout")
		return nil
	}
}

func TestFixedRootLifecycleSupervisorRetainsLocksAndForwardsSignal(t *testing.T) {
	fixture := newFixedHelperFixture(t, fmt.Sprintf(`#!/bin/bash
for fd in 3 4 5 6; do
  [[ ! -e /proc/self/fd/$fd ]] || exit 91
done
trap '/usr/bin/touch %s; exit 42' TERM
printf 'ready\n'
while :; do /bin/sleep 1; done
`, fixtureSafePathPlaceholder))
	// Build the target again now that its fixture-specific marker is known.
	target := strings.Replace(fixture.targetFile, fixtureSafePathPlaceholder, fixture.marker, 1)
	if err := os.WriteFile(fixture.target, []byte(target), 0o700); err != nil {
		t.Fatal(err)
	}

	command, files := fixture.command(t, fixture.names)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	closeFixtureFiles(t, files)
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("target did not reach the lock-held boundary: %q stderr=%s", line, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = waitCommand(t, command, 5*time.Second)
		t.Fatalf("target readiness timed out: %s", stderr.String())
	}

	if !exclusiveLockAvailable(t, fixture.locks[0]) {
		t.Fatal("catalog lock remained held after the helper started its child")
	}
	for _, path := range fixture.locks[1:4] {
		if exclusiveLockAvailable(t, path) {
			t.Fatalf("lifecycle lock was not retained after the child closed all descriptors: %s", path)
		}
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = waitCommand(t, command, 8*time.Second)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 {
		t.Fatalf("signal-forwarded child status was not propagated: err=%v stderr=%s", err, stderr.String())
	}
	if _, err := os.Stat(fixture.marker); err != nil {
		t.Fatalf("TERM was not forwarded to the child: %v", err)
	}
	for _, path := range fixture.locks[:4] {
		if !exclusiveLockAvailable(t, path) {
			t.Fatalf("lifecycle lock remained held after supervisor exit: %s", path)
		}
	}
}

const fixtureSafePathPlaceholder = "FIXTURE_SIGNAL_MARKER"

func TestFixedRootLifecycleSupervisorPropagatesStatusAndRejectsBadEvidence(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		fixture := newFixedHelperFixture(t, "#!/bin/bash\nexit 37\n")
		command, files := fixture.command(t, fixture.names)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		closeFixtureFiles(t, files)
		err := waitCommand(t, command, 5*time.Second)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 {
			t.Fatalf("child status was not propagated: err=%v stderr=%s", err, stderr.String())
		}
	})

	t.Run("descriptor names", func(t *testing.T) {
		fixture := newFixedHelperFixture(t, "#!/bin/bash\nexit 0\n")
		command, files := fixture.command(t, "wrong:names")
		output, err := command.CombinedOutput()
		closeFixtureFiles(t, files)
		if err == nil || !strings.Contains(string(output), "exact named lifecycle descriptors") {
			t.Fatalf("bad descriptor names were not rejected: err=%v output=%s", err, output)
		}
	})

	t.Run("inode metadata", func(t *testing.T) {
		fixture := newFixedHelperFixture(t, "#!/bin/bash\nexit 0\n")
		if err := os.Chmod(fixture.locks[1], 0o644); err != nil {
			t.Fatal(err)
		}
		command, files := fixture.command(t, fixture.names)
		output, err := command.CombinedOutput()
		closeFixtureFiles(t, files)
		if err == nil || !strings.Contains(string(output), "unsafe inode shape") {
			t.Fatalf("bad descriptor metadata was not rejected: err=%v output=%s", err, output)
		}
	})
}

func assertFixedRootProfileRetainsCatalogLockThroughChildExit(t *testing.T, profile, expectedCommand string, descriptorCount int, extraEnvironment ...string) {
	t.Helper()
	fixture := newFixedHelperFixture(t, `#!/bin/bash
for fd in 3 4 5 6 7; do
  [[ ! -e /proc/self/fd/$fd ]] || exit 91
done
printf 'ready\n'
trap 'exit 0' TERM INT HUP
while :; do /bin/sleep 1; done
`)
	payload, err := os.ReadFile(fixture.helper)
	if err != nil {
		t.Fatal(err)
	}
	helper := string(payload)
	replaceHelperFixtureText(t, &helper, expectedCommand, "expected_command=("+fixture.target+")")
	if err := os.WriteFile(fixture.helper, []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}

	files := make([]*os.File, 0, descriptorCount)
	for _, path := range fixture.locks[:descriptorCount] {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	names := "workagent-config-lock:workagent-control-release-lock"
	if descriptorCount == 4 {
		names = fixture.names
	} else if descriptorCount == 5 {
		names = fixture.oauthNames
	}
	command := exec.Command("/bin/bash", "-c", `export LISTEN_PID=$$; exec "$@"`, "workagent-fixed-root-retaining-test", fixture.helper, profile, fixture.target)
	command.Env = append(os.Environ(), "LISTEN_FDS="+fmt.Sprint(descriptorCount), "LISTEN_FDNAMES="+names)
	command.Env = append(command.Env, extraEnvironment...)
	command.ExtraFiles = files
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	closeFixtureFiles(t, files)
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			_ = command.Process.Kill()
			_ = waitCommand(t, command, 5*time.Second)
			t.Fatalf("%s did not reach its lock-held child boundary: %q stderr=%s", profile, line, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = waitCommand(t, command, 5*time.Second)
		t.Fatalf("%s child readiness timed out: %s", profile, stderr.String())
	}
	for _, path := range fixture.locks[:descriptorCount] {
		if exclusiveLockAvailable(t, path) {
			t.Fatalf("%s supervisor released a lifecycle lock before child exit: %s", profile, path)
		}
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitCommand(t, command, 8*time.Second); err != nil {
		t.Fatalf("%s child did not exit cleanly: %v stderr=%s", profile, err, stderr.String())
	}
	for _, path := range fixture.locks[:descriptorCount] {
		if !exclusiveLockAvailable(t, path) {
			t.Fatalf("%s lifecycle lock remained after child exit: %s", profile, path)
		}
	}
}

func TestFixedRootCatalogDependentProfilesRetainCatalogLockThroughChildExit(t *testing.T) {
	t.Run("backup", func(t *testing.T) {
		assertFixedRootProfileRetainsCatalogLockThroughChildExit(t,
			"backup",
			`expected_command=(/opt/workagent/control/bin/workagent-backup create --portal-config /etc/workagent/portal.json --config /etc/workagent/backup.json --quiesce-systemd)`,
			2,
		)
	})
	credentialDirectory := "/run/credentials/workagent-cliproxy-oauth-doctor-12345678-1234-1234-1234-123456789abc.service"
	for _, test := range []struct {
		name        string
		profile     string
		expected    string
		environment []string
	}{
		{
			name:     "Codex OAuth",
			profile:  "cliproxy-oauth-codex",
			expected: `expected_command=(/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml --codex-device-login --no-browser)`,
		},
		{
			name:     "Kimi OAuth",
			profile:  "cliproxy-oauth-kimi",
			expected: `expected_command=(/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml --kimi-login --no-browser)`,
		},
		{
			name:        "doctor",
			profile:     "cliproxy-oauth-doctor",
			expected:    `expected_command=(/opt/workagent/control/bin/workagent-cliproxy doctor --portal-config /etc/workagent/portal.json --credential "$credential_directory/cliproxy-management-key" --wait 30s)`,
			environment: []string{"CREDENTIALS_DIRECTORY=" + credentialDirectory},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptorCount := 4
			if test.profile != "cliproxy-oauth-doctor" {
				descriptorCount = 5
			}
			assertFixedRootProfileRetainsCatalogLockThroughChildExit(t, test.profile, test.expected, descriptorCount, test.environment...)
		})
	}
}

func newOAuthWriterFixture(t *testing.T) fixedHelperFixture {
	t.Helper()
	fixture := newFixedHelperFixture(t, `#!/bin/bash
for fd in 3 4 5 6 7; do
  [[ ! -e /proc/self/fd/$fd ]] || exit 91
done
printf 'ready\n'
trap 'exit 0' TERM INT HUP
while :; do /bin/sleep 1; done
`)
	payload, err := os.ReadFile(fixture.helper)
	if err != nil {
		t.Fatal(err)
	}
	helper := string(payload)
	for _, expected := range []string{
		`expected_command=(/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml --codex-device-login --no-browser)`,
		`expected_command=(/opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml --kimi-login --no-browser)`,
	} {
		replaceHelperFixtureText(t, &helper, expected, "expected_command=("+fixture.target+")")
	}
	if err := os.WriteFile(fixture.helper, []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f fixedHelperFixture) oauthCommand(t *testing.T, profile, names string) (*exec.Cmd, []*os.File) {
	t.Helper()
	files := make([]*os.File, 0, 5)
	for _, path := range f.locks {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	command := exec.Command("/bin/bash", "-c", `export LISTEN_PID=$$; exec "$@"`, "workagent-oauth-writer-test", f.helper, profile, f.target)
	command.Env = append(os.Environ(), "LISTEN_FDS=5", "LISTEN_FDNAMES="+names)
	command.ExtraFiles = files
	return command, files
}

func startOAuthWriterFixture(t *testing.T, fixture fixedHelperFixture, profile string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	command, files := fixture.oauthCommand(t, profile, fixture.oauthNames)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		closeFixtureFiles(t, files)
		t.Fatal(err)
	}
	closeFixtureFiles(t, files)
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			_ = command.Process.Kill()
			_ = waitCommand(t, command, 5*time.Second)
			t.Fatalf("%s did not reach the OAuth writer boundary: %q stderr=%s", profile, line, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = waitCommand(t, command, 5*time.Second)
		t.Fatalf("%s OAuth writer boundary timed out: %s", profile, stderr.String())
	}
	return command, stderr
}

func TestFixedRootOAuthWriterRejectsConcurrentProviderFlows(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  string
		second string
	}{
		{name: "duplicate Codex", first: "cliproxy-oauth-codex", second: "cliproxy-oauth-codex"},
		{name: "duplicate Kimi", first: "cliproxy-oauth-kimi", second: "cliproxy-oauth-kimi"},
		{name: "Codex then Kimi", first: "cliproxy-oauth-codex", second: "cliproxy-oauth-kimi"},
		{name: "Kimi then Codex", first: "cliproxy-oauth-kimi", second: "cliproxy-oauth-codex"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOAuthWriterFixture(t)
			first, firstStderr := startOAuthWriterFixture(t, fixture, test.first)
			if exclusiveLockAvailable(t, fixture.locks[4]) {
				_ = first.Process.Kill()
				_ = waitCommand(t, first, 5*time.Second)
				t.Fatal("first OAuth supervisor did not retain its exclusive writer lock")
			}

			second, files := fixture.oauthCommand(t, test.second, fixture.oauthNames)
			output, err := second.CombinedOutput()
			closeFixtureFiles(t, files)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 75 ||
				!strings.Contains(string(output), "another CLIProxy OAuth authorization flow is active") ||
				strings.Contains(string(output), "ready") {
				_ = first.Process.Kill()
				_ = waitCommand(t, first, 5*time.Second)
				t.Fatalf("concurrent OAuth flow was not rejected before child start: err=%v output=%s first-stderr=%s", err, output, firstStderr.String())
			}

			if err := first.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			if err := waitCommand(t, first, 8*time.Second); err != nil {
				t.Fatalf("first OAuth supervisor did not exit cleanly: %v stderr=%s", err, firstStderr.String())
			}
			if !exclusiveLockAvailable(t, fixture.locks[4]) {
				t.Fatal("OAuth writer lock remained held after the first child exited")
			}
		})
	}
}

func TestFixedRootOAuthWriterRejectsDescriptorDrift(t *testing.T) {
	t.Run("exact descriptor names", func(t *testing.T) {
		fixture := newOAuthWriterFixture(t)
		command, files := fixture.oauthCommand(t, "cliproxy-oauth-codex", fixture.names+":wrong-oauth-name")
		output, err := command.CombinedOutput()
		closeFixtureFiles(t, files)
		if err == nil || !strings.Contains(string(output), "exact named lifecycle descriptors") {
			t.Fatalf("wrong OAuth descriptor name was not rejected: err=%v output=%s", err, output)
		}
	})

	t.Run("metadata", func(t *testing.T) {
		fixture := newOAuthWriterFixture(t)
		if err := os.Chmod(fixture.locks[4], 0o640); err != nil {
			t.Fatal(err)
		}
		command, files := fixture.oauthCommand(t, "cliproxy-oauth-kimi", fixture.oauthNames)
		output, err := command.CombinedOutput()
		closeFixtureFiles(t, files)
		if err == nil || !strings.Contains(string(output), "unsafe inode shape") {
			t.Fatalf("OAuth writer metadata drift was not rejected: err=%v output=%s", err, output)
		}
	})

	t.Run("hard link", func(t *testing.T) {
		fixture := newOAuthWriterFixture(t)
		if err := os.Link(fixture.locks[4], fixture.locks[4]+".alias"); err != nil {
			t.Fatal(err)
		}
		command, files := fixture.oauthCommand(t, "cliproxy-oauth-codex", fixture.oauthNames)
		output, err := command.CombinedOutput()
		closeFixtureFiles(t, files)
		if err == nil || !strings.Contains(string(output), "unsafe inode shape") {
			t.Fatalf("hard-linked OAuth writer inode was not rejected: err=%v output=%s", err, output)
		}
	})

	t.Run("path replacement", func(t *testing.T) {
		fixture := newOAuthWriterFixture(t)
		command, files := fixture.oauthCommand(t, "cliproxy-oauth-kimi", fixture.oauthNames)
		replaced := fixture.locks[4] + ".replaced"
		if err := os.Rename(fixture.locks[4], replaced); err != nil {
			closeFixtureFiles(t, files)
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.locks[4], nil, 0o600); err != nil {
			closeFixtureFiles(t, files)
			t.Fatal(err)
		}
		output, err := command.CombinedOutput()
		closeFixtureFiles(t, files)
		if err == nil || (!strings.Contains(string(output), "wrong path") && !strings.Contains(string(output), "no longer matches its path")) {
			t.Fatalf("replaced OAuth writer path was not rejected: err=%v output=%s", err, output)
		}
	})
}

func TestChatForwardLoginAcquiresActivationBeforeCatalogAndRetainsBoth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact root-owned lifecycle locks require root")
	}
	root := t.TempDir()
	activation := filepath.Join(root, "activation.lock")
	catalog := filepath.Join(root, "catalog.lock")
	controlLock := filepath.Join(root, "control.lock")
	sharedLock := filepath.Join(root, "shared.lock")
	locks := []string{activation, catalog, controlLock, sharedLock}
	for _, path := range locks {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	controlRoot := filepath.Join(root, "control")
	sharedRoot := filepath.Join(root, "shared")
	verifier := filepath.Join(controlRoot, "bin", "workagent-release")
	adminGuard := filepath.Join(controlRoot, "bin", "workagent-admin")
	login := filepath.Join(sharedRoot, "chatforward", "integration", "login.sh")
	for _, path := range []string{verifier, adminGuard, login} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(verifier, []byte("#!/bin/bash\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminGuard, []byte("#!/bin/bash\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	loginPayload := `#!/bin/bash
set -u
[[ -e /proc/self/fd/3 ]] || exit 81
for fd in 4 5 6; do [[ ! -e /proc/self/fd/$fd ]] || exit 82; done
/usr/bin/flock --exclusive --nonblock 3 || exit 83
printf 'ready\n'
trap 'exit 0' TERM INT HUP
while :; do /bin/sleep 1; done
`
	if err := os.WriteFile(login, []byte(loginPayload), 0o700); err != nil {
		t.Fatal(err)
	}
	helperPayload := repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	helperPayload = strings.ReplaceAll(helperPayload, "/run/workagent/activation.lock", activation)
	helperPayload = strings.ReplaceAll(helperPayload, "/run/workagent/release-config.lock", catalog)
	helperPayload = strings.ReplaceAll(helperPayload, "/opt/workagent/control.lock", controlLock)
	helperPayload = strings.ReplaceAll(helperPayload, "/opt/workagent/shared.lock", sharedLock)
	helperPayload = strings.ReplaceAll(helperPayload, "/opt/workagent/control", controlRoot)
	helperPayload = strings.ReplaceAll(helperPayload, "/opt/workagent/shared", sharedRoot)
	helper := filepath.Join(root, "workagent-fixed-root-exec-v1")
	if err := os.WriteFile(helper, []byte(helperPayload), 0o700); err != nil {
		t.Fatal(err)
	}
	catalogBlocker, err := os.Open(catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer catalogBlocker.Close()
	if err := unix.Flock(int(catalogBlocker.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	files := make([]*os.File, 0, len(locks))
	for _, path := range locks {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	command := exec.Command("/bin/bash", "-c", `export LISTEN_PID=$$; exec "$@"`, "workagent-chatforward-login-lock-test", helper, "chatforward-login", login)
	command.Env = append(os.Environ(), "LISTEN_FDS=4", "LISTEN_FDNAMES=workagent-activation-lock:workagent-config-lock:workagent-control-release-lock:workagent-shared-release-lock")
	command.ExtraFiles = files
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	closeFixtureFiles(t, files)
	deadline := time.Now().Add(5 * time.Second)
	for exclusiveLockAvailable(t, activation) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exclusiveLockAvailable(t, activation) {
		_ = command.Process.Kill()
		_ = waitCommand(t, command, 5*time.Second)
		t.Fatalf("login helper did not acquire A before waiting on C: %s", stderr.String())
	}
	if err := unix.Flock(int(catalogBlocker.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatalf("login child did not receive only the activation capability: %q stderr=%s", line, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = waitCommand(t, command, 5*time.Second)
		t.Fatalf("login child did not start after C became available: %s", stderr.String())
	}
	for _, path := range locks {
		if exclusiveLockAvailable(t, path) {
			t.Fatalf("login supervisor did not retain lifecycle lock: %s", path)
		}
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitCommand(t, command, 8*time.Second); err != nil {
		t.Fatalf("login supervisor did not exit cleanly: %v stderr=%s", err, stderr.String())
	}
	for _, path := range locks {
		if !exclusiveLockAvailable(t, path) {
			t.Fatalf("login supervisor leaked lifecycle lock: %s", path)
		}
	}
}

const fixedHelperTestRevision = "1111111111111111111111111111111111111111"

type chatForwardHelperFixture struct {
	helper       string
	target       string
	controlRoot  string
	sharedRoot   string
	publicKey    string
	verification string
	childMarker  string
	locks        []string
	names        string
	chrome       string
}

func bashSingleQuoted(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func writeChatForwardFixtureFile(t *testing.T, root, relative, body string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func freezeChatForwardFixtureRoot(t *testing.T, root string) {
	t.Helper()
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o555)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func signChatForwardFixtureRoot(t *testing.T, root, privateKey, scope, componentName string) {
	t.Helper()
	builtAt := time.Unix(1_800_000_000, 0).UTC()
	component := release.Component{Name: componentName, Version: "1.0.0", SourceRevision: fixedHelperTestRevision}
	writeChatForwardFixtureFile(t, root, "sbom.spdx.json", `{"spdxVersion":"SPDX-2.3","documentNamespace":"https://workagent.example.test/spdx/fixed-helper","packages":[{"name":"`+componentName+`"}]}`+"\n", 0o444)
	writeChatForwardFixtureFile(t, root, "provenance.json", `{"schema_version":1,"release_id":"fixed-helper-test","source_revision":"`+fixedHelperTestRevision+`","builder_id":"fixed-helper-test","build_type":"test","invocation_id":"fixed-helper-test","reproducible":true,"materials":[{"uri":"git:workagent-test","revision":"`+fixedHelperTestRevision+`"}]}`+"\n", 0o444)
	writeChatForwardFixtureFile(t, root, "licenses.json", `{"schema_version":1,"approved":true,"reviewed_at":"`+builtAt.Format(time.RFC3339)+`","entries":[{"component":"`+componentName+`","spdx_expression":"LicenseRef-WorkAgent-Test","copyright":"WorkAgent authorized test fixture"}]}`+"\n", 0o444)
	metadata := release.Manifest{
		ReleaseID:                 "fixed-helper-test",
		SourceRevision:            fixedHelperTestRevision,
		BuiltAt:                   builtAt,
		BrandingVersion:           "workagent-test",
		PolicyVersion:             "fixed-helper-test",
		ComponentScope:            scope,
		DataSchemaVersion:         1,
		MinimumReadableDataSchema: 1,
		MaximumReadableDataSchema: 1,
		Components:                []release.Component{component},
		SBOMPath:                  "sbom.spdx.json",
		ProvenancePath:            "provenance.json",
		LicenseReportPath:         "licenses.json",
	}
	manifest, err := release.BuildManifest(root, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.WriteManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err := release.SignManifest(filepath.Join(root, "manifest.json"), filepath.Join(root, "manifest.sig"), privateKey, false); err != nil {
		t.Fatal(err)
	}
	freezeChatForwardFixtureRoot(t, root)
}

func TestFixedRootReleaseVerifierSubprocess(t *testing.T) {
	if os.Getenv("WORKAGENT_FIXED_HELPER_VERIFIER") != "1" {
		return
	}
	fail := func(message string) {
		fmt.Fprintln(os.Stderr, message)
		os.Exit(41)
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) || os.Args[separator+1] != "verify" {
		fail("fixture verifier did not receive the verify subcommand")
	}
	arguments := os.Args[separator+2:]
	root := ""
	publicKey := ""
	scope := ""
	var required []string
	var requiredExecutable []string
	for len(arguments) != 0 {
		if len(arguments) < 2 {
			fail("fixture verifier received an incomplete option")
		}
		name, value := arguments[0], arguments[1]
		arguments = arguments[2:]
		switch name {
		case "--root":
			root = value
		case "--public-key":
			publicKey = value
		case "--scope":
			scope = value
		case "--required":
			required = append(required, value)
		case "--required-executable":
			requiredExecutable = append(requiredExecutable, value)
		default:
			fail("fixture verifier received an unsupported option: " + name)
		}
	}
	contract, err := release.NewConsumerContract(required, requiredExecutable)
	if err != nil {
		fail(err.Error())
	}
	_, err = release.Verify(root, filepath.Join(root, "manifest.json"), release.VerifyOptions{
		RequiredPaths:           contract.RequiredPaths,
		RequiredExecutablePaths: contract.RequiredExecutablePaths,
		RequireRootOwner:        true,
		RequireSignature:        true,
		SignaturePath:           filepath.Join(root, "manifest.sig"),
		PublicKeyPath:           publicKey,
		AllowedScopes:           []string{scope},
	})
	if err != nil {
		fail(err.Error())
	}
	os.Exit(0)
}

func newChatForwardHelperFixture(t *testing.T, realVerifier string) chatForwardHelperFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact signed fixed-root ownership is root-only")
	}
	root := t.TempDir()
	fixture := chatForwardHelperFixture{
		helper:       filepath.Join(root, "workagent-fixed-root-exec-v1"),
		controlRoot:  filepath.Join(root, "control"),
		sharedRoot:   filepath.Join(root, "shared"),
		publicKey:    filepath.Join(root, "trust", "release-signing.pub"),
		verification: filepath.Join(root, "verification-arguments"),
		childMarker:  filepath.Join(root, "child-started"),
		locks: []string{
			filepath.Join(root, "catalog.lock"),
			filepath.Join(root, "control.lock"),
			filepath.Join(root, "shared.lock"),
		},
		names:  "workagent-config-lock:workagent-control-release-lock:workagent-shared-release-lock",
		chrome: filepath.Join(root, "google-chrome-stable"),
	}
	fixture.target = filepath.Join(fixture.controlRoot, "admin", "smoke-chatforward-browser-sandbox")
	for _, path := range fixture.locks {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(fixture.publicKey), 0o755); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(root, "trust", "release-signing.key")
	if err := release.GenerateSigningKey(fixture.publicKey, privateKey); err != nil {
		t.Fatal(err)
	}

	verifierWrapper := `#!/bin/bash
set -euo pipefail
for lifecycle_lock in ` + bashSingleQuoted(fixture.locks[0]) + ` ` + bashSingleQuoted(fixture.locks[1]) + ` ` + bashSingleQuoted(fixture.locks[2]) + `; do
  if /usr/bin/flock --exclusive --nonblock "$lifecycle_lock" /bin/true; then
    printf 'verification ran without lifecycle lock: %s\n' "$lifecycle_lock" >&2
    exit 96
  fi
done
printf '%s\n' "$*" >> ` + bashSingleQuoted(fixture.verification) + `
exec ` + bashSingleQuoted(realVerifier) + ` -test.run '^TestFixedRootReleaseVerifierSubprocess$' -- "$@" >/dev/null
`
	writeChatForwardFixtureFile(t, fixture.controlRoot, "bin/workagent-release", verifierWrapper, 0o555)
	target := `#!/bin/bash
set -u
for inherited_fd in 3 4 5 6; do
  [[ ! -e /proc/self/fd/$inherited_fd ]] || exit 91
done
/usr/bin/flock --exclusive --nonblock ` + bashSingleQuoted(fixture.locks[0]) + ` /bin/true || exit 92
if /usr/bin/flock --exclusive --nonblock ` + bashSingleQuoted(fixture.locks[1]) + ` /bin/true; then exit 93; fi
if /usr/bin/flock --exclusive --nonblock ` + bashSingleQuoted(fixture.locks[2]) + ` /bin/true; then exit 94; fi
/usr/bin/touch ` + bashSingleQuoted(fixture.childMarker) + `
printf 'ready\n'
trap 'exit 0' TERM INT HUP
while :; do /bin/sleep 1; done
`
	writeChatForwardFixtureFile(t, fixture.controlRoot, "admin/smoke-chatforward-browser-sandbox", target, 0o555)
	writeChatForwardFixtureFile(t, fixture.sharedRoot, "chatforward/app/extension/manifest.json", "trusted extension\n", 0o444)
	writeChatForwardFixtureFile(t, fixture.sharedRoot, "chatforward/integration/run-browser.sh", "#!/bin/bash\nexit 0\n", 0o555)
	writeChatForwardFixtureFile(t, fixture.sharedRoot, "chatforward/node/bin/node", "#!/bin/bash\nexit 0\n", 0o555)
	signChatForwardFixtureRoot(t, fixture.controlRoot, privateKey, release.ScopePortal, "workagent-control")
	signChatForwardFixtureRoot(t, fixture.sharedRoot, privateKey, release.ScopeShared, "chatforward")
	if err := os.WriteFile(fixture.chrome, []byte("#!/bin/bash\nexit 0\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.chrome, 0o555); err != nil {
		t.Fatal(err)
	}

	helper := repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	helper = strings.ReplaceAll(helper, "/run/workagent/release-config.lock", fixture.locks[0])
	helper = strings.ReplaceAll(helper, "/opt/workagent/control.lock", fixture.locks[1])
	helper = strings.ReplaceAll(helper, "/opt/workagent/shared.lock", fixture.locks[2])
	helper = strings.ReplaceAll(helper, "/opt/workagent/control", fixture.controlRoot)
	helper = strings.ReplaceAll(helper, "/opt/workagent/shared", fixture.sharedRoot)
	helper = strings.ReplaceAll(helper, "/etc/workagent/trust/release-signing.pub", fixture.publicKey)
	helper = strings.ReplaceAll(helper, "/usr/bin/google-chrome-stable", fixture.chrome)
	if err := os.WriteFile(fixture.helper, []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.helper, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f chatForwardHelperFixture) command(t *testing.T) (*exec.Cmd, []*os.File) {
	t.Helper()
	files := make([]*os.File, 0, len(f.locks))
	for _, path := range f.locks {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	command := exec.Command("/bin/bash", "-c", `export LISTEN_PID=$$; exec "$@"`, "workagent-fixed-root-chat-test", f.helper, "chatforward-smoke", f.target, f.sharedRoot+"/chatforward", f.chrome)
	command.Env = append(os.Environ(), "LISTEN_FDS=3", "LISTEN_FDNAMES="+f.names, "WORKAGENT_FIXED_HELPER_VERIFIER=1")
	command.ExtraFiles = files
	return command, files
}

func TestFixedRootChatForwardVerificationRejectsTamperAndHoldsLocks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact signed fixed-root ownership is root-only")
	}
	realVerifier, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid roots", func(t *testing.T) {
		fixture := newChatForwardHelperFixture(t, realVerifier)
		command, files := fixture.command(t)
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		closeFixtureFiles(t, files)
		ready := make(chan bool, 1)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				if scanner.Text() == "ready" {
					ready <- true
					return
				}
			}
			ready <- false
		}()
		select {
		case ok := <-ready:
			if !ok {
				_ = command.Process.Kill()
				_ = waitCommand(t, command, 5*time.Second)
				t.Fatalf("signed ChatForward child did not start: %s", stderr.String())
			}
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			_ = waitCommand(t, command, 5*time.Second)
			t.Fatalf("signed ChatForward verification timed out: %s", stderr.String())
		}
		verification, err := os.ReadFile(fixture.verification)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(verification), "--root ") != 2 || !strings.Contains(string(verification), "--scope portal") || !strings.Contains(string(verification), "--scope shared") {
			t.Fatalf("helper did not verify both signed roots with closed scopes:\n%s", verification)
		}
		if _, err := os.Stat(fixture.childMarker); err != nil {
			t.Fatalf("child did not prove its post-verification lock boundary: %v", err)
		}
		if !exclusiveLockAvailable(t, fixture.locks[0]) {
			t.Fatal("catalog lock remained held after signed verification")
		}
		for _, path := range fixture.locks[1:] {
			if exclusiveLockAvailable(t, path) {
				t.Fatalf("channel lock was not retained after signed verification: %s", path)
			}
		}
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := waitCommand(t, command, 8*time.Second); err != nil {
			t.Fatalf("verified child did not exit cleanly: %v stderr=%s", err, stderr.String())
		}
		for _, path := range fixture.locks {
			if !exclusiveLockAvailable(t, path) {
				t.Fatalf("lifecycle lock remained after verified child exit: %s", path)
			}
		}
	})

	tests := []struct {
		name        string
		mutate      func(*testing.T, chatForwardHelperFixture)
		wantFailure string
	}{
		{
			name: "tampered manifest",
			mutate: func(t *testing.T, fixture chatForwardHelperFixture) {
				path := filepath.Join(fixture.controlRoot, "manifest.json")
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("\n"); err != nil {
					file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
			wantFailure: "release manifest signature is invalid",
		},
		{
			name: "tampered shared asset",
			mutate: func(t *testing.T, fixture chatForwardHelperFixture) {
				path := filepath.Join(fixture.sharedRoot, "chatforward", "app", "extension", "manifest.json")
				payload, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				payload[0] ^= 1
				if err := os.WriteFile(path, payload, 0o444); err != nil {
					t.Fatal(err)
				}
			},
			wantFailure: "hash mismatch",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newChatForwardHelperFixture(t, realVerifier)
			test.mutate(t, fixture)
			command, files := fixture.command(t)
			output, err := command.CombinedOutput()
			closeFixtureFiles(t, files)
			if err == nil || !strings.Contains(string(output), test.wantFailure) {
				t.Fatalf("tampered signed root was not rejected: err=%v output=%s", err, output)
			}
			if _, statErr := os.Stat(fixture.childMarker); !os.IsNotExist(statErr) {
				t.Fatalf("tampered signed root reached child execution: %v", statErr)
			}
			for _, path := range fixture.locks {
				if !exclusiveLockAvailable(t, path) {
					t.Fatalf("failed verification leaked lifecycle lock: %s", path)
				}
			}
		})
	}
}

type fixedHelperInstallerFixture struct {
	installer   string
	source      string
	destination string
	libexec     string
}

func newFixedHelperInstallerFixture(t *testing.T) fixedHelperInstallerFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact production installer ownership is root-only")
	}
	root := t.TempDir()
	control := filepath.Join(root, "control-plane")
	admin := filepath.Join(control, "admin")
	share := filepath.Join(control, "share", "deploy", "libexec")
	libexec := filepath.Join(root, "libexec")
	runWorkagent := filepath.Join(root, "run", "workagent")
	for _, directory := range []string{admin, share, libexec, runWorkagent} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fixture := fixedHelperInstallerFixture{
		installer:   filepath.Join(admin, "install-fixed-root-exec-v1"),
		source:      filepath.Join(share, "workagent-fixed-root-exec-v1"),
		destination: filepath.Join(libexec, "workagent-fixed-root-exec-v1"),
		libexec:     libexec,
	}
	helper := repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1")
	if err := os.WriteFile(fixture.source, []byte(helper), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.source, 0o555); err != nil {
		t.Fatal(err)
	}
	installLock := filepath.Join(runWorkagent, "fixed-root-exec-v1-install.lock")
	if err := os.WriteFile(installLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(installLock, 0o600); err != nil {
		t.Fatal(err)
	}
	installer := repositoryFile(t, "scripts/install-fixed-root-exec-v1.sh")
	installer = strings.ReplaceAll(installer, "/usr/libexec", libexec)
	installer = strings.ReplaceAll(installer, "/run/workagent", runWorkagent)
	if err := os.WriteFile(fixture.installer, []byte(installer), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.installer, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func runFixedHelperInstaller(f fixedHelperInstallerFixture) ([]byte, error) {
	return exec.Command(f.installer).CombinedOutput()
}

func copyInstallerSource(t *testing.T, fixture fixedHelperInstallerFixture, destination string) {
	t.Helper()
	payload, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, payload, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destination, 0o555); err != nil {
		t.Fatal(err)
	}
}

func writeInstallerPrefixStage(t *testing.T, fixture fixedHelperInstallerFixture, size int, mode os.FileMode) string {
	t.Helper()
	payload, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if size < 0 || size > len(payload) {
		t.Fatalf("invalid fixture prefix size %d for source size %d", size, len(payload))
	}
	stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
	if err := os.WriteFile(stage, payload[:size], mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stage, mode); err != nil {
		t.Fatal(err)
	}
	return stage
}

func assertInstalledHelperFixture(t *testing.T, fixture fixedHelperInstallerFixture) {
	t.Helper()
	source, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.ReadFile(fixture.destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, destination) {
		t.Fatal("installed helper bytes differ from sealed source")
	}
	info, err := os.Stat(fixture.destination)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != 0o555 || stat.Nlink != 1 {
		t.Fatalf("installed helper metadata is unsafe: mode=%o stat=%#v", info.Mode().Perm(), stat)
	}
	stages, err := filepath.Glob(filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 0 {
		t.Fatalf("installer left reserved stages: %v", stages)
	}
}

func TestFixedRootLifecycleInstallerSerializesConcurrentFirstInstall(t *testing.T) {
	fixture := newFixedHelperInstallerFixture(t)
	commands := []*exec.Cmd{exec.Command(fixture.installer), exec.Command(fixture.installer)}
	outputs := make([]bytes.Buffer, len(commands))
	for index, command := range commands {
		command.Stdout = &outputs[index]
		command.Stderr = &outputs[index]
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("concurrent installer %d failed: %v output=%s", index, err, outputs[index].String())
		}
	}
	assertInstalledHelperFixture(t, fixture)
	if output, err := runFixedHelperInstaller(fixture); err != nil {
		t.Fatalf("idempotent installer failed: %v output=%s", err, output)
	}
}

func TestFixedRootLifecycleInstallerReconcilesInterruptionBoundaries(t *testing.T) {
	t.Run("orphan stage", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
		copyInstallerSource(t, fixture, stage)
		if output, err := runFixedHelperInstaller(fixture); err != nil {
			t.Fatalf("orphan resume failed: %v output=%s", err, output)
		}
		assertInstalledHelperFixture(t, fixture)
	})

	t.Run("linked stage", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
		copyInstallerSource(t, fixture, stage)
		if err := os.Link(stage, fixture.destination); err != nil {
			t.Fatal(err)
		}
		if output, err := runFixedHelperInstaller(fixture); err != nil {
			t.Fatalf("linked resume failed: %v output=%s", err, output)
		}
		assertInstalledHelperFixture(t, fixture)
	})

	t.Run("redundant stage", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
		copyInstallerSource(t, fixture, stage)
		copyInstallerSource(t, fixture, fixture.destination)
		if output, err := runFixedHelperInstaller(fixture); err != nil {
			t.Fatalf("redundant stage cleanup failed: %v output=%s", err, output)
		}
		assertInstalledHelperFixture(t, fixture)
	})

	t.Run("ambiguous stages", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		copyInstallerSource(t, fixture, filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH"))
		copyInstallerSource(t, fixture, filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.IJKLMNOP"))
		output, err := runFixedHelperInstaller(fixture)
		if err == nil || !strings.Contains(string(output), "multiple interrupted v1 helper stages are ambiguous") {
			t.Fatalf("ambiguous stages were not rejected: err=%v output=%s", err, output)
		}
	})

	t.Run("conflicting destination", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		if err := os.WriteFile(fixture.destination, []byte("conflict\n"), 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.destination, 0o555); err != nil {
			t.Fatal(err)
		}
		output, err := runFixedHelperInstaller(fixture)
		if err == nil || !strings.Contains(string(output), "conflicting bytes or metadata") {
			t.Fatalf("conflicting destination was not rejected: err=%v output=%s", err, output)
		}
		payload, readErr := os.ReadFile(fixture.destination)
		if readErr != nil || string(payload) != "conflict\n" {
			t.Fatalf("conflicting destination was modified: err=%v payload=%q", readErr, payload)
		}
	})
}

func TestFixedRootLifecycleInstallerRecoversAuthorizedWorkInodesAndRejectsForeignState(t *testing.T) {
	source := []byte(repositoryFile(t, "deploy/libexec/workagent-fixed-root-exec-v1"))
	recoverWorkStage := func(t *testing.T, fixture fixedHelperInstallerFixture, reason string) {
		t.Helper()
		output, err := runFixedHelperInstaller(fixture)
		if err != nil {
			t.Fatalf("%s work stage did not recover: %v output=%s", reason, err, output)
		}
		if !strings.Contains(string(output), "discarded interrupted v1 helper work stage before retry") {
			t.Fatalf("%s work stage was not explicitly reconciled: %s", reason, output)
		}
		assertInstalledHelperFixture(t, fixture)
	}
	boundaries := []int{0, 1, 2, 4095, 4096, 4097, len(source) / 2, len(source) - 1, len(source)}
	seen := make(map[int]bool)
	for _, boundary := range boundaries {
		if boundary < 0 || boundary > len(source) || seen[boundary] {
			continue
		}
		seen[boundary] = true
		t.Run(fmt.Sprintf("mode-0600-prefix-%d", boundary), func(t *testing.T) {
			fixture := newFixedHelperInstallerFixture(t)
			writeInstallerPrefixStage(t, fixture, boundary, 0o600)
			recoverWorkStage(t, fixture, fmt.Sprintf("prefix boundary %d", boundary))
		})
	}

	t.Run("mode transition complete 0555", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		writeInstallerPrefixStage(t, fixture, len(source), 0o555)
		output, err := runFixedHelperInstaller(fixture)
		if err != nil {
			t.Fatalf("complete post-chmod stage did not resume: %v output=%s", err, output)
		}
		if !strings.Contains(string(output), "resumed immutable workagent fixed-root exec v1 installation") {
			t.Fatalf("complete post-chmod stage took an unexpected transition: %s", output)
		}
		assertInstalledHelperFixture(t, fixture)
	})

	reject := func(t *testing.T, fixture fixedHelperInstallerFixture, stage, reason string) {
		t.Helper()
		before, err := os.ReadFile(stage)
		if err != nil {
			t.Fatal(err)
		}
		beforeInfo, err := os.Stat(stage)
		if err != nil {
			t.Fatal(err)
		}
		output, runErr := runFixedHelperInstaller(fixture)
		if runErr == nil || !strings.Contains(string(output), "neither complete nor an authorized work inode") {
			t.Fatalf("%s stage was not rejected: err=%v output=%s", reason, runErr, output)
		}
		after, err := os.ReadFile(stage)
		if err != nil {
			t.Fatalf("%s stage was removed: %v", reason, err)
		}
		afterInfo, err := os.Stat(stage)
		if err != nil {
			t.Fatal(err)
		}
		beforeStat := beforeInfo.Sys().(*syscall.Stat_t)
		afterStat := afterInfo.Sys().(*syscall.Stat_t)
		if !bytes.Equal(before, after) || beforeInfo.Mode().Perm() != afterInfo.Mode().Perm() || beforeStat.Ino != afterStat.Ino || beforeStat.Nlink != afterStat.Nlink || beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid {
			t.Fatalf("%s rejected stage was modified", reason)
		}
	}

	t.Run("non-prefix dirty-data residue", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := writeInstallerPrefixStage(t, fixture, 4096, 0o600)
		payload, err := os.ReadFile(stage)
		if err != nil {
			t.Fatal(err)
		}
		payload[len(payload)-1] ^= 1
		if err := os.WriteFile(stage, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		recoverWorkStage(t, fixture, "non-prefix dirty-data residue")
	})

	t.Run("zero-filled dirty-data residue", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
		if err := os.WriteFile(stage, make([]byte, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o600); err != nil {
			t.Fatal(err)
		}
		recoverWorkStage(t, fixture, "zero-filled dirty-data residue")
	})

	t.Run("hard-linked prefix", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := writeInstallerPrefixStage(t, fixture, 4096, 0o600)
		outside := filepath.Join(filepath.Dir(fixture.libexec), "outside-hardlink")
		if err := os.Link(stage, outside); err != nil {
			t.Fatal(err)
		}
		reject(t, fixture, stage, "hard-linked prefix")
		if info, err := os.Stat(outside); err != nil || info.Sys().(*syscall.Stat_t).Nlink != 2 {
			t.Fatalf("rejection changed the external hard link: info=%v err=%v", info, err)
		}
	})

	t.Run("symbolic-link work name", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		outside := filepath.Join(filepath.Dir(fixture.libexec), "outside-symlink-target")
		if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
		if err := os.Symlink(outside, stage); err != nil {
			t.Fatal(err)
		}
		output, err := runFixedHelperInstaller(fixture)
		if err == nil || !strings.Contains(string(output), "neither complete nor an authorized work inode") {
			t.Fatalf("symbolic-link work name was not rejected: err=%v output=%s", err, output)
		}
		if info, err := os.Lstat(stage); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("rejection changed the symbolic-link work name: info=%v err=%v", info, err)
		}
		if payload, err := os.ReadFile(outside); err != nil || string(payload) != "outside\n" {
			t.Fatalf("rejection changed the symbolic-link target: payload=%q err=%v", payload, err)
		}
	})

	t.Run("unexpected mode", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := writeInstallerPrefixStage(t, fixture, 4096, 0o644)
		reject(t, fixture, stage, "unexpected-mode prefix")
	})

	t.Run("unexpected ownership", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := writeInstallerPrefixStage(t, fixture, 4096, 0o600)
		if err := os.Chown(stage, 1, 1); err != nil {
			t.Fatal(err)
		}
		reject(t, fixture, stage, "wrong-owner prefix")
	})

	t.Run("oversized dirty-metadata residue", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.ABCDEFGH")
		oversized := append(append([]byte(nil), source...), 'x')
		if err := os.WriteFile(stage, oversized, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o600); err != nil {
			t.Fatal(err)
		}
		recoverWorkStage(t, fixture, "oversized dirty-metadata residue")
	})

	t.Run("partial post-chmod mode", func(t *testing.T) {
		fixture := newFixedHelperInstallerFixture(t)
		stage := writeInstallerPrefixStage(t, fixture, 4096, 0o555)
		reject(t, fixture, stage, "partial mode-0555 prefix")
	})
}

func TestFixedRootLifecycleInstallerRecoversAfterSIGKILLDuringSequentialCopy(t *testing.T) {
	fixture := newFixedHelperInstallerFixture(t)
	writer := filepath.Join(filepath.Dir(fixture.libexec), "crash-once-dd")
	state := filepath.Join(filepath.Dir(fixture.libexec), "writer-used")
	marker := filepath.Join(filepath.Dir(fixture.libexec), "partial-written")
	writerPayload := `#!/bin/bash
set -euo pipefail
if [[ ! -e ` + bashSingleQuoted(state) + ` ]]; then
  /usr/bin/touch ` + bashSingleQuoted(state) + `
  source_file=
  destination=
  for argument in "$@"; do
    case "$argument" in
      if=*) source_file=${argument#if=} ;;
      of=*) destination=${argument#of=} ;;
    esac
  done
  [[ -n $source_file && -n $destination ]]
  /usr/bin/dd if="$source_file" of="$destination" bs=1 count=4097 conv=notrunc status=none
  /usr/bin/touch ` + bashSingleQuoted(marker) + `
  while :; do /bin/sleep 1; done
fi
exec /usr/bin/dd "$@"
`
	if err := os.WriteFile(writer, []byte(writerPayload), 0o700); err != nil {
		t.Fatal(err)
	}
	installer, err := os.ReadFile(fixture.installer)
	if err != nil {
		t.Fatal(err)
	}
	ddInvocation := `/usr/bin/dd if="$source_file" of="$temporary" bs=4096 conv=notrunc status=none`
	if strings.Count(string(installer), ddInvocation) != 1 {
		t.Fatalf("fixture could not isolate sequential copy invocation")
	}
	installer = []byte(strings.Replace(string(installer), ddInvocation, bashSingleQuoted(writer)+` if="$source_file" of="$temporary" bs=4096 conv=notrunc status=none`, 1))
	if err := os.WriteFile(fixture.installer, installer, 0o700); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(fixture.installer)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			_ = command.Wait()
			t.Fatalf("sequential copy did not reach the injected crash boundary: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("SIGKILL-injected installer exited successfully")
	}
	stages, err := filepath.Glob(filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 {
		t.Fatalf("SIGKILL did not leave one recoverable reserved stage: %v", stages)
	}
	stageInfo, err := os.Stat(stages[0])
	if err != nil {
		t.Fatal(err)
	}
	stagePayload, err := os.ReadFile(stages[0])
	if err != nil {
		t.Fatal(err)
	}
	sourcePayload, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if stageInfo.Mode().Perm() != 0o600 || len(stagePayload) != 4097 || !bytes.Equal(stagePayload, sourcePayload[:4097]) {
		t.Fatalf("SIGKILL survivor is not the expected exact mode-0600 prefix: mode=%o size=%d", stageInfo.Mode().Perm(), len(stagePayload))
	}
	resumeOutput, err := runFixedHelperInstaller(fixture)
	if err != nil {
		t.Fatalf("installer wedged after SIGKILL: %v output=%s", err, resumeOutput)
	}
	assertInstalledHelperFixture(t, fixture)
}

func TestFixedRootLifecycleInstallerNoReplaceRejectsDestinationDirectoryRace(t *testing.T) {
	fixture := newFixedHelperInstallerFixture(t)
	tracingLink := filepath.Join(filepath.Dir(fixture.libexec), "inject-destination-directory")
	tracingPayload := `#!/bin/bash
set -euo pipefail
[[ $# == 2 ]]
/usr/bin/mkdir -- "$2"
exec /usr/bin/ln -T -- "$1" "$2"
`
	if err := os.WriteFile(tracingLink, []byte(tracingPayload), 0o700); err != nil {
		t.Fatal(err)
	}
	installer, err := os.ReadFile(fixture.installer)
	if err != nil {
		t.Fatal(err)
	}
	linkInvocation := `ln -T -- "$staged" "$destination"`
	if strings.Count(string(installer), linkInvocation) != 1 {
		t.Fatal("fixture could not isolate the no-replace link invocation")
	}
	installer = []byte(strings.Replace(string(installer), linkInvocation, bashSingleQuoted(tracingLink)+` "$staged" "$destination"`, 1))
	if err := os.WriteFile(fixture.installer, installer, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := runFixedHelperInstaller(fixture)
	if err == nil || !strings.Contains(string(output), "versioned destination appeared with conflicting state") {
		t.Fatalf("destination-directory race was not rejected: err=%v output=%s", err, output)
	}
	entries, err := os.ReadDir(fixture.destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("no-replace link created an entry inside the raced destination directory: %v", entries)
	}
	stages, err := filepath.Glob(filepath.Join(fixture.libexec, ".workagent-fixed-root-exec-v1.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 {
		t.Fatalf("failed no-replace publication did not preserve one resumable stage: %v", stages)
	}
	if info, err := os.Stat(stages[0]); err != nil || info.Mode().Perm() != 0o555 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatalf("failed no-replace publication changed the resumable stage: info=%v err=%v", info, err)
	}
}
