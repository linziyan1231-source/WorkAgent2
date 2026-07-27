package userhost

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This live kernel test holds the one-shot credential queued on the victim's
// exact fd 3. A separate sibling with the same UID proves that procfs cannot
// open a socket descriptor and Yama scope 2 rejects pidfd_getfd. Neither
// process receives the token in argv or its environment.
func TestRuntimeSocketRejectsSameUIDSiblingDescriptorTheft(t *testing.T) {
	if strings.TrimSpace(readRuntimeTestFile(t, "/proc/sys/kernel/yama/ptrace_scope")) != "2" {
		t.Skip("requires kernel.yama.ptrace_scope=2")
	}
	token, err := generateWorkAgentRuntimeToken()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	helperExecutable := stageRuntimeSocketTestExecutable(t)

	victim := exec.Command(helperExecutable, "-test.run=^TestRuntimeSocketVictimHelper$")
	victim.Env = []string{
		"GO_WANT_RUNTIME_SOCKET_VICTIM=1",
		workAgentTenantEnvironment + "=11111111-1111-4111-8111-111111111111",
		workAgentRuntimeFDEnvironment + "=" + workAgentRuntimeFDText,
	}
	victim.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() == 0 {
		victim.SysProcAttr.Credential = &syscall.Credential{Uid: 65532, Gid: 65532, NoSetGroups: true}
	}
	if err := startRuntimeCommand(victim, token); err != nil {
		t.Fatal(err)
	}
	victimDone := make(chan error, 1)
	go func() { victimDone <- victim.Wait() }()
	defer func() {
		if victim.Process == nil {
			return
		}
		_ = syscall.Kill(-victim.Process.Pid, syscall.SIGKILL)
		select {
		case <-victimDone:
		case <-time.After(5 * time.Second):
			t.Errorf("runtime socket victim did not exit")
		}
	}()

	for _, name := range []string{"cmdline", "environ"} {
		content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(victim.Process.Pid), name))
		if err != nil {
			t.Fatalf("read victim %s: %v", name, err)
		}
		if bytes.Contains(content, token) || bytes.Contains(content, []byte(workAgentRuntimeEnvironment+"=")) {
			clear(content)
			t.Fatalf("victim exposed runtime token in /proc/%s", name)
		}
		clear(content)
	}

	attacker := exec.Command(
		helperExecutable,
		"-test.run=^TestRuntimeSocketSiblingAttackerHelper$",
		"--",
		strconv.Itoa(victim.Process.Pid),
	)
	attacker.Env = []string{"GO_WANT_RUNTIME_SOCKET_ATTACKER=1"}
	if os.Geteuid() == 0 {
		attacker.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: 65532, Gid: 65532, NoSetGroups: true},
		}
	}
	output, err := attacker.CombinedOutput()
	if err != nil {
		t.Fatalf("same-UID sibling descriptor attack was not rejected: %v\n%s", err, output)
	}
}

func TestRuntimeSocketVictimHelper(t *testing.T) {
	if os.Getenv("GO_WANT_RUNTIME_SOCKET_VICTIM") != "1" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestRuntimeSocketSiblingAttackerHelper(t *testing.T) {
	if os.Getenv("GO_WANT_RUNTIME_SOCKET_ATTACKER") != "1" {
		return
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		t.Fatal("victim PID argument is missing")
	}
	victimPID, err := strconv.Atoi(os.Args[separator+1])
	if err != nil || victimPID <= 0 {
		t.Fatal("victim PID argument is invalid")
	}

	descriptorPath := filepath.Join("/proc", strconv.Itoa(victimPID), "fd", strconv.Itoa(workAgentRuntimeChildFD))
	descriptor, openErr := os.Open(descriptorPath)
	if openErr == nil {
		descriptor.Close()
		t.Fatal("same-UID sibling opened the runtime socket through procfs")
	}
	if !errors.Is(openErr, syscall.ENXIO) {
		t.Fatalf("procfs socket open error=%v want ENXIO", openErr)
	}

	pidfd, err := unix.PidfdOpen(victimPID, 0)
	if err != nil {
		t.Fatalf("pidfd_open victim: %v", err)
	}
	defer unix.Close(pidfd)
	stolen, theftErr := unix.PidfdGetfd(pidfd, workAgentRuntimeChildFD, 0)
	if theftErr == nil {
		unix.Close(stolen)
		t.Fatal("same-UID sibling stole the runtime socket with pidfd_getfd")
	}
	if !errors.Is(theftErr, syscall.EPERM) {
		t.Fatalf("pidfd_getfd error=%v want EPERM", theftErr)
	}
}

func readRuntimeTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("kernel setting is unavailable: %v", err)
	}
	return string(content)
}

func stageRuntimeSocketTestExecutable(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "workagent-runtime-socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	targetPath := filepath.Join(directory, "runtime-socket-test")
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(targetPath, 0o755); err != nil {
		t.Fatal(err)
	}
	return targetPath
}
