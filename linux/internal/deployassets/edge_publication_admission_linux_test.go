//go:build linux

package deployassets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type edgeAdmissionFixture struct {
	helper          string
	journal         string
	permit          string
	activationLock  string
	recoveryJournal string
	recoveryPermit  string
	caddyExecutable string
}

type edgeAdmissionEvidence struct {
	permit         *os.File
	activation     *os.File
	permitStat     syscall.Stat_t
	journalStat    syscall.Stat_t
	permitPayload  []byte
	journalPayload []byte
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (buffer *lockedBuffer) Write(payload []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.Write(payload)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.String()
}

type asyncCommand struct {
	command *exec.Cmd
	output  *lockedBuffer
	done    chan struct{}
	err     error
}

func startAsyncCommand(t *testing.T, command *exec.Cmd) *asyncCommand {
	t.Helper()
	result := &asyncCommand{command: command, output: &lockedBuffer{}, done: make(chan struct{})}
	command.Stdout = result.output
	command.Stderr = result.output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		result.err = command.Wait()
		close(result.done)
	}()
	t.Cleanup(func() {
		select {
		case <-result.done:
			return
		default:
		}
		if command.SysProcAttr != nil && command.SysProcAttr.Setpgid {
			_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
		} else {
			_ = command.Process.Kill()
		}
		select {
		case <-result.done:
		case <-time.After(3 * time.Second):
		}
	})
	return result
}

func (command *asyncCommand) wait(timeout time.Duration) (string, error, bool) {
	select {
	case <-command.done:
		return command.output.String(), command.err, true
	case <-time.After(timeout):
		return command.output.String(), nil, false
	}
}

func (command *asyncCommand) running() bool {
	select {
	case <-command.done:
		return false
	default:
		return true
	}
}

func newEdgeAdmissionFixture(t *testing.T) edgeAdmissionFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact edge publication evidence and Caddy identity fixture are root-owned")
	}
	root := t.TempDir()
	if err := os.Chmod(filepath.Dir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	edgeState := filepath.Join(root, "edge-state")
	edgeRuntime := filepath.Join(root, "edge-runtime")
	activationRuntime := filepath.Join(root, "activation-runtime")
	recoveryState := filepath.Join(root, "recovery-state")
	recoveryRuntime := filepath.Join(root, "recovery-runtime")
	for _, path := range []string{edgeState, edgeRuntime, activationRuntime, recoveryState, recoveryRuntime} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := edgeAdmissionFixture{
		helper:          filepath.Join(root, "workagent-edge-publication-admission-v1"),
		journal:         filepath.Join(edgeState, "publication.json"),
		permit:          filepath.Join(edgeRuntime, "publication.permit"),
		activationLock:  filepath.Join(activationRuntime, "activation.lock"),
		recoveryJournal: filepath.Join(recoveryState, "recovery-activation.json"),
		recoveryPermit:  filepath.Join(recoveryRuntime, "recovery-activation.permit"),
		caddyExecutable: filepath.Join(root, "caddy"),
	}
	if err := os.WriteFile(fixture.activationLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.activationLock, 0o600); err != nil {
		t.Fatal(err)
	}
	sleepPayload, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.caddyExecutable, sleepPayload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.caddyExecutable, 0o755); err != nil {
		t.Fatal(err)
	}
	cgroupPayload, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	cgroup := strings.TrimSuffix(string(cgroupPayload), "\n")
	if cgroup == "" || strings.Contains(cgroup, "\n") {
		t.Skipf("functional watcher fixture requires one unified cgroup-v2 line, got %q", cgroup)
	}
	helper := repositoryFile(t, "deploy/libexec/workagent-edge-publication-admission-v1")
	replacements := map[string]string{
		"readonly activation_lock=/run/workagent/activation.lock":                      "readonly activation_lock=" + bashSingleQuoted(fixture.activationLock),
		"readonly recovery_permit=/run/workagent-backup/recovery-activation.permit":    "readonly recovery_permit=" + bashSingleQuoted(fixture.recoveryPermit),
		"readonly recovery_journal=/var/lib/workagent-backup/recovery-activation.json": "readonly recovery_journal=" + bashSingleQuoted(fixture.recoveryJournal),
		"readonly edge_permit=/run/workagent-edge/publication.permit":                  "readonly edge_permit=" + bashSingleQuoted(fixture.permit),
		"readonly edge_journal=/var/lib/workagent-edge/publication.json":               "readonly edge_journal=" + bashSingleQuoted(fixture.journal),
		"readonly caddy_executable=/usr/bin/caddy":                                     "readonly caddy_executable=" + bashSingleQuoted(fixture.caddyExecutable),
		"readonly caddy_account=caddy":                                                 "readonly caddy_account=nobody",
		"readonly caddy_cgroup='0::/system.slice/caddy.service'":                       "readonly caddy_cgroup=" + bashSingleQuoted(cgroup),
	}
	for old, replacement := range replacements {
		if !strings.Contains(helper, old) {
			t.Fatalf("edge admission helper omitted fixture seam %q", old)
		}
		helper = strings.Replace(helper, old, replacement, 1)
	}
	if err := os.WriteFile(fixture.helper, []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.helper, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func currentEdgeAdmissionBootID(t *testing.T) string {
	t.Helper()
	payload, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	value := strings.TrimSuffix(string(payload), "\n")
	if len(value) != 36 {
		t.Fatalf("unexpected boot ID fixture %q", value)
	}
	return value
}

func exactFileStat(t *testing.T, path string) syscall.Stat_t {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file stat is not a Linux stat_t")
	}
	return *stat
}

func lockEdgeAdmissionFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	return file
}

func (fixture edgeAdmissionFixture) writeEvidence(t *testing.T, bootID string) *edgeAdmissionEvidence {
	t.Helper()
	activation := lockEdgeAdmissionFile(t, fixture.activationLock)
	permit, err := os.OpenFile(fixture.permit, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = activation.Close()
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.permit, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(permit.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	permitStat := exactFileStat(t, fixture.permit)
	journalPayload := []byte(fmt.Sprintf(`{"schema_version":1,"boot_id":%q,"permit_device":%d,"permit_inode":%d}`+"\n", bootID, permitStat.Dev, permitStat.Ino))
	if err := os.WriteFile(fixture.journal, journalPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.journal, 0o600); err != nil {
		t.Fatal(err)
	}
	journalStat := exactFileStat(t, fixture.journal)
	permitPayload := []byte(fmt.Sprintf(`{"schema_version":1,"boot_id":%q,"journal_device":%d,"journal_inode":%d}`+"\n", bootID, journalStat.Dev, journalStat.Ino))
	if _, err := permit.WriteAt(permitPayload, 0); err != nil {
		t.Fatal(err)
	}
	if err := permit.Truncate(int64(len(permitPayload))); err != nil {
		t.Fatal(err)
	}
	if err := permit.Sync(); err != nil {
		t.Fatal(err)
	}
	evidence := &edgeAdmissionEvidence{
		permit: permit, activation: activation, permitStat: permitStat, journalStat: journalStat,
		permitPayload: permitPayload, journalPayload: journalPayload,
	}
	t.Cleanup(func() {
		if evidence.permit != nil {
			_ = unix.Flock(int(evidence.permit.Fd()), unix.LOCK_UN)
			_ = evidence.permit.Close()
		}
		if evidence.activation != nil {
			_ = unix.Flock(int(evidence.activation.Fd()), unix.LOCK_UN)
			_ = evidence.activation.Close()
		}
	})
	return evidence
}

func (evidence *edgeAdmissionEvidence) releasePermit(t *testing.T) {
	t.Helper()
	if evidence.permit == nil {
		return
	}
	if err := unix.Flock(int(evidence.permit.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := evidence.permit.Close(); err != nil {
		t.Fatal(err)
	}
	evidence.permit = nil
}

func (fixture edgeAdmissionFixture) run() ([]byte, error) {
	return exec.Command(fixture.helper).CombinedOutput()
}

func requireEdgeAdmissionBlocked(t *testing.T, output []byte, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("unsafe edge admission was allowed:\n%s", output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("edge admission failure status = %v, want exit 1; output=%s", err, output)
	}
	if !bytes.Contains(output, []byte("workagent-edge-publication-admission-v1:")) {
		t.Fatalf("edge admission failure omitted its stable diagnostic prefix: %s", output)
	}
}

func (fixture edgeAdmissionFixture) startFakeCaddy(t *testing.T) *asyncCommand {
	t.Helper()
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("nobody account is unavailable: %v", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		t.Fatalf("nobody account identity is unsafe: uid=%q gid=%q", account.Uid, account.Gid)
	}
	command := exec.Command(fixture.caddyExecutable, "300")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true}}
	return startAsyncCommand(t, command)
}

func (fixture edgeAdmissionFixture) startWatcher(t *testing.T, caddy *asyncCommand) *asyncCommand {
	t.Helper()
	if caddy.command.Process == nil {
		t.Fatal("fake Caddy has no PID")
	}
	command := exec.Command(fixture.helper, "--watch", strconv.Itoa(caddy.command.Process.Pid))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	watcher := startAsyncCommand(t, command)
	waitForEdgeWatcherDescriptors(t, watcher, fixture.journal, fixture.permit)
	waitForEdgeWatcherChild(t, watcher, "/usr/bin/flock", "native blocking permit-release wait")
	return watcher
}

func waitForEdgeWatcherDescriptors(t *testing.T, watcher *asyncCommand, expected ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !watcher.running() {
			t.Fatalf("edge watcher exited before pinning evidence: %v\n%s", watcher.err, watcher.output.String())
		}
		found := make(map[string]bool, len(expected))
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", watcher.command.Process.Pid))
		if err == nil {
			for _, entry := range entries {
				target, readErr := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", watcher.command.Process.Pid, entry.Name()))
				if readErr == nil {
					found[target] = true
				}
			}
			complete := true
			for _, path := range expected {
				complete = complete && found[path]
			}
			if complete {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("edge watcher did not pin journal and permit:\n%s", watcher.output.String())
}

func waitForEdgeWatcherChild(t *testing.T, watcher *asyncCommand, executable, description string) {
	t.Helper()
	pid := watcher.command.Process.Pid
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", pid, pid)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !watcher.running() {
			t.Fatalf("edge watcher exited before entering its %s: %v\n%s", description, watcher.err, watcher.output.String())
		}
		payload, err := os.ReadFile(childrenPath)
		if err == nil {
			for _, child := range strings.Fields(string(payload)) {
				target, readErr := os.Readlink(filepath.Join("/proc", child, "exe"))
				if readErr == nil && target == executable {
					time.Sleep(25 * time.Millisecond)
					stableTarget, stableErr := os.Readlink(filepath.Join("/proc", child, "exe"))
					if stableErr == nil && stableTarget == executable && watcher.running() {
						return
					}
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("edge watcher did not enter its %s:\n%s", description, watcher.output.String())
}

func requireWatcherFailed(t *testing.T, watcher *asyncCommand) string {
	t.Helper()
	output, err, completed := watcher.wait(5 * time.Second)
	if !completed {
		t.Fatalf("unsafe edge watcher remained blocked:\n%s", output)
	}
	requireEdgeAdmissionBlocked(t, []byte(output), err)
	return output
}

func TestEdgeAdmissionAllowsAbsenceAndRejectsOrphanOrRecoveryEvidence(t *testing.T) {
	fixture := newEdgeAdmissionFixture(t)
	if output, err := fixture.run(); err != nil {
		t.Fatalf("ordinary edge admission failed: %v\n%s", err, output)
	}
	if err := os.WriteFile(fixture.permit, []byte("orphan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run()
	requireEdgeAdmissionBlocked(t, output, err)
	if err := os.Remove(fixture.permit); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.recoveryJournal, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = fixture.run()
	requireEdgeAdmissionBlocked(t, output, err)
}

func TestEdgeAdmissionRequiresCanonicalCurrentCrossBoundExclusiveEvidence(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixture := newEdgeAdmissionFixture(t)
		fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
		if output, err := fixture.run(); err != nil {
			t.Fatalf("valid edge evidence was rejected: %v\n%s", err, output)
		}
	})

	t.Run("other boot", func(t *testing.T) {
		fixture := newEdgeAdmissionFixture(t)
		const otherBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		if currentEdgeAdmissionBootID(t) == otherBoot {
			t.Fatal("other-boot fixture equals current boot")
		}
		fixture.writeEvidence(t, otherBoot)
		output, err := fixture.run()
		requireEdgeAdmissionBlocked(t, output, err)
	})

	t.Run("cross inode mismatch", func(t *testing.T) {
		fixture := newEdgeAdmissionFixture(t)
		evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
		old := fmt.Sprintf(`"permit_inode":%d`, evidence.permitStat.Ino)
		changed := strings.Replace(string(evidence.journalPayload), old, fmt.Sprintf(`"permit_inode":%d`, evidence.permitStat.Ino+1), 1)
		if changed == string(evidence.journalPayload) {
			t.Fatal("cross-inode mismatch fixture did not change the journal")
		}
		if err := os.WriteFile(fixture.journal, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := fixture.run()
		requireEdgeAdmissionBlocked(t, output, err)
	})

	t.Run("empty visible journal", func(t *testing.T) {
		fixture := newEdgeAdmissionFixture(t)
		fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
		if err := os.Truncate(fixture.journal, 0); err != nil {
			t.Fatal(err)
		}
		output, err := fixture.run()
		requireEdgeAdmissionBlocked(t, output, err)
	})

	t.Run("empty visible permit", func(t *testing.T) {
		fixture := newEdgeAdmissionFixture(t)
		evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
		if err := evidence.permit.Truncate(0); err != nil {
			t.Fatal(err)
		}
		output, err := fixture.run()
		requireEdgeAdmissionBlocked(t, output, err)
	})

	t.Run("shared permit owner", func(t *testing.T) {
		fixture := newEdgeAdmissionFixture(t)
		evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
		if err := unix.Flock(int(evidence.permit.Fd()), unix.LOCK_UN); err != nil {
			t.Fatal(err)
		}
		if err := unix.Flock(int(evidence.permit.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		output, err := fixture.run()
		requireEdgeAdmissionBlocked(t, output, err)
	})
}

func TestEdgeWatcherAcceptsJournalFirstCommitOnlyAfterPermitUnlock(t *testing.T) {
	fixture := newEdgeAdmissionFixture(t)
	evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
	caddy := fixture.startFakeCaddy(t)
	watcher := fixture.startWatcher(t, caddy)
	if err := os.Remove(fixture.journal); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if !watcher.running() {
		t.Fatalf("watcher rejected the journal-first durable transition: %v\n%s", watcher.err, watcher.output.String())
	}
	if err := os.Remove(fixture.permit); err != nil {
		t.Fatal(err)
	}
	waitForEdgeWatcherChild(t, watcher, "/usr/bin/flock", "native blocking permit-release wait")
	// Deterministically hold the publisher in the valid unlink-to-close window.
	time.Sleep(500 * time.Millisecond)
	if !watcher.running() {
		t.Fatalf("watcher rejected the valid permit unlink-to-close window: %v\n%s", watcher.err, watcher.output.String())
	}
	evidence.releasePermit(t)
	output, err, completed := watcher.wait(5 * time.Second)
	if !completed || err != nil {
		t.Fatalf("journal-first committed watcher did not succeed: completed=%v err=%v\n%s", completed, err, output)
	}
	if !caddy.running() {
		t.Fatalf("direct watcher unexpectedly killed the proved fake Caddy process: %v\n%s", caddy.err, caddy.output.String())
	}
}

func TestEdgeWatcherFailsWhenPublisherAuthorityDisappears(t *testing.T) {
	fixture := newEdgeAdmissionFixture(t)
	evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
	caddy := fixture.startFakeCaddy(t)
	watcher := fixture.startWatcher(t, caddy)
	evidence.releasePermit(t)
	output := requireWatcherFailed(t, watcher)
	if !strings.Contains(output, "edge publication evidence remained or reappeared after permit release") {
		t.Fatalf("publisher-loss rejection was ambiguous: %s", output)
	}
	if !caddy.running() {
		t.Fatal("the synchronous helper killed Caddy directly instead of reporting failure to systemd")
	}
}

func TestEdgeWatcherRejectsPermitFirstCommitOrdering(t *testing.T) {
	fixture := newEdgeAdmissionFixture(t)
	evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
	caddy := fixture.startFakeCaddy(t)
	watcher := fixture.startWatcher(t, caddy)
	if err := os.Remove(fixture.permit); err != nil {
		t.Fatal(err)
	}
	evidence.releasePermit(t)
	output := requireWatcherFailed(t, watcher)
	if !strings.Contains(output, "edge publication evidence remained or reappeared after permit release") {
		t.Fatalf("permit-first rejection was ambiguous: %s", output)
	}
}

func TestEdgeWatcherRevalidatesNamesAfterBlockingPermitRelease(t *testing.T) {
	fixture := newEdgeAdmissionFixture(t)
	evidence := fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
	caddy := fixture.startFakeCaddy(t)
	watcher := fixture.startWatcher(t, caddy)
	if err := os.Remove(fixture.journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.permit); err != nil {
		t.Fatal(err)
	}
	waitForEdgeWatcherChild(t, watcher, "/usr/bin/flock", "native blocking permit-release wait")
	if err := os.WriteFile(fixture.journal, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if !watcher.running() {
		t.Fatalf("watcher did not block on the still-owned pinned permit: %v\n%s", watcher.err, watcher.output.String())
	}
	evidence.releasePermit(t)
	output := requireWatcherFailed(t, watcher)
	if !strings.Contains(output, "evidence remained or reappeared after permit release") {
		t.Fatalf("post-lock pathname revalidation was ambiguous: %s", output)
	}
}

func TestEdgeWatcherSignalInterruptionFailsClosed(t *testing.T) {
	fixture := newEdgeAdmissionFixture(t)
	fixture.writeEvidence(t, currentEdgeAdmissionBootID(t))
	caddy := fixture.startFakeCaddy(t)
	watcher := fixture.startWatcher(t, caddy)
	if err := unix.Kill(-watcher.command.Process.Pid, unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	output := requireWatcherFailed(t, watcher)
	if !strings.Contains(output, "edge publication watcher was interrupted before commit") {
		t.Fatalf("interrupted watcher failure was ambiguous: %s", output)
	}
	if !caddy.running() {
		t.Fatal("direct signal test unexpectedly terminated fake Caddy outside systemd cleanup")
	}
}
