//go:build linux

package deployassets

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const validCoreAdmissionJournal = `{"schema_version":1,"units":["workagent-tenant-catalog-ready.target","workagent-tenant-config-reconcile.service","cliproxyapi.service","workagent-notification.service","workagent-chatforward.service","workagent-chatforward-browser.service","workagent-portal.service","caddy.service","workagent-backup.service","workagent-backup.timer","workagent-healthcheck.service","workagent-healthcheck.timer"]}` + "\n"

type coreAdmissionFixture struct {
	helper  string
	journal string
	permit  string
	lock    string
}

type coreAdmissionPermit struct {
	SchemaVersion        int    `json:"schema_version"`
	BootID               string `json:"boot_id"`
	JournalDevice        uint64 `json:"journal_device"`
	JournalInode         uint64 `json:"journal_inode"`
	ActivationLockDevice uint64 `json:"activation_lock_device"`
	ActivationLockInode  uint64 `json:"activation_lock_inode"`
}

func newCoreAdmissionFixture(t *testing.T) coreAdmissionFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact core activation evidence is root-owned")
	}
	root := t.TempDir()
	journalParent := filepath.Join(root, "state")
	permitParent := filepath.Join(root, "runtime")
	activationParent := filepath.Join(root, "activation")
	for _, parent := range []string{journalParent, permitParent, activationParent} {
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := coreAdmissionFixture{
		helper:  filepath.Join(root, "workagent-core-activation-admission-v1"),
		journal: filepath.Join(journalParent, "activation.json"),
		permit:  filepath.Join(permitParent, "activation.permit"),
		lock:    filepath.Join(activationParent, "activation.lock"),
	}
	if err := os.WriteFile(fixture.lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.lock, 0o600); err != nil {
		t.Fatal(err)
	}
	payload := repositoryFile(t, "deploy/libexec/workagent-core-activation-admission-v1")
	for old, replacement := range map[string]string{
		"readonly activation_lock=/run/workagent/activation.lock":       "readonly activation_lock=" + bashSingleQuoted(fixture.lock),
		"readonly core_permit=/run/workagent-core/activation.permit":    "readonly core_permit=" + bashSingleQuoted(fixture.permit),
		"readonly core_journal=/var/lib/workagent-core/activation.json": "readonly core_journal=" + bashSingleQuoted(fixture.journal),
	} {
		if !strings.Contains(payload, old) {
			t.Fatalf("core admission helper omitted fixture seam %q", old)
		}
		payload = strings.Replace(payload, old, replacement, 1)
	}
	if err := os.WriteFile(fixture.helper, []byte(payload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.helper, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture coreAdmissionFixture) writeEvidence(t *testing.T, bootID string) {
	t.Helper()
	if err := os.WriteFile(fixture.journal, []byte(validCoreAdmissionJournal), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.journal, 0o600); err != nil {
		t.Fatal(err)
	}
	journalInfo, err := os.Stat(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	lockInfo, err := os.Stat(fixture.lock)
	if err != nil {
		t.Fatal(err)
	}
	journalStat := journalInfo.Sys().(*syscall.Stat_t)
	lockStat := lockInfo.Sys().(*syscall.Stat_t)
	permit := coreAdmissionPermit{
		SchemaVersion: 1, BootID: bootID,
		JournalDevice: uint64(journalStat.Dev), JournalInode: journalStat.Ino,
		ActivationLockDevice: uint64(lockStat.Dev), ActivationLockInode: lockStat.Ino,
	}
	payload, err := json.Marshal(permit)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(fixture.permit, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.permit, 0o600); err != nil {
		t.Fatal(err)
	}
}

func currentCoreAdmissionBootID(t *testing.T) string {
	t.Helper()
	payload, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(payload), "\n")
}

func lockCoreAdmissionFile(t *testing.T, path string, operation int) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(file.Fd()), operation|unix.LOCK_NB); err != nil {
		file.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	})
	return file
}

func runCoreAdmission(fixture coreAdmissionFixture) ([]byte, error) {
	return exec.Command(fixture.helper).CombinedOutput()
}

func requireCoreAdmissionRejected(t *testing.T, output []byte, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("unsafe core admission was allowed:\n%s", output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !bytes.Contains(output, []byte("workagent-core-activation-admission-v1:")) {
		t.Fatalf("core admission failure is not exact: err=%v output=%s", err, output)
	}
}

func TestCoreActivationAdmissionAllowsCleanBootAndExactLiveTransaction(t *testing.T) {
	fixture := newCoreAdmissionFixture(t)
	if output, err := runCoreAdmission(fixture); err != nil {
		t.Fatalf("clean core admission failed: %v\n%s", err, output)
	}
	fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
	lockCoreAdmissionFile(t, fixture.permit, unix.LOCK_EX)
	lockCoreAdmissionFile(t, fixture.lock, unix.LOCK_EX)
	if output, err := runCoreAdmission(fixture); err != nil {
		t.Fatalf("exact live core transaction was rejected: %v\n%s", err, output)
	}
}

func TestCoreActivationAdmissionRejectsStaleOrNonExclusiveAuthority(t *testing.T) {
	t.Run("free locks", func(t *testing.T) {
		fixture := newCoreAdmissionFixture(t)
		fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
		output, err := runCoreAdmission(fixture)
		requireCoreAdmissionRejected(t, output, err)
	})
	t.Run("shared activation owner", func(t *testing.T) {
		fixture := newCoreAdmissionFixture(t)
		fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
		lockCoreAdmissionFile(t, fixture.permit, unix.LOCK_EX)
		lockCoreAdmissionFile(t, fixture.lock, unix.LOCK_SH)
		output, err := runCoreAdmission(fixture)
		requireCoreAdmissionRejected(t, output, err)
	})
	t.Run("previous boot", func(t *testing.T) {
		fixture := newCoreAdmissionFixture(t)
		fixture.writeEvidence(t, "11111111-2222-3333-4444-555555555555")
		lockCoreAdmissionFile(t, fixture.permit, unix.LOCK_EX)
		lockCoreAdmissionFile(t, fixture.lock, unix.LOCK_EX)
		output, err := runCoreAdmission(fixture)
		requireCoreAdmissionRejected(t, output, err)
	})
}

func TestCoreActivationAdmissionRejectsOrphanPermit(t *testing.T) {
	fixture := newCoreAdmissionFixture(t)
	if err := os.WriteFile(fixture.permit, []byte("orphan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := runCoreAdmission(fixture)
	requireCoreAdmissionRejected(t, output, err)
	if !bytes.Contains(output, []byte("orphan core activation permit")) {
		t.Fatalf("orphan permit diagnostic is ambiguous: %s", output)
	}
}

func TestCoreActivationAdmissionRejectsUnsafeMetadataAndParents(t *testing.T) {
	for _, name := range []string{"journal mode", "journal hardlink", "permit hardlink", "unsafe journal parent", "unsafe permit parent"} {
		t.Run(name, func(t *testing.T) {
			fixture := newCoreAdmissionFixture(t)
			fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
			switch name {
			case "journal mode":
				if err := os.Chmod(fixture.journal, 0o644); err != nil {
					t.Fatal(err)
				}
			case "journal hardlink":
				if err := os.Link(fixture.journal, fixture.journal+".link"); err != nil {
					t.Fatal(err)
				}
			case "permit hardlink":
				if err := os.Link(fixture.permit, fixture.permit+".link"); err != nil {
					t.Fatal(err)
				}
			case "unsafe journal parent":
				if err := os.Chmod(filepath.Dir(fixture.journal), 0o755); err != nil {
					t.Fatal(err)
				}
			case "unsafe permit parent":
				if err := os.Chmod(filepath.Dir(fixture.permit), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			output, err := runCoreAdmission(fixture)
			requireCoreAdmissionRejected(t, output, err)
		})
	}
}

func TestCoreActivationAdmissionRejectsReplacedBoundInodes(t *testing.T) {
	t.Run("journal", func(t *testing.T) {
		fixture := newCoreAdmissionFixture(t)
		fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
		if err := os.Rename(fixture.journal, fixture.journal+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.journal, []byte(validCoreAdmissionJournal), 0o600); err != nil {
			t.Fatal(err)
		}
		lockCoreAdmissionFile(t, fixture.permit, unix.LOCK_EX)
		lockCoreAdmissionFile(t, fixture.lock, unix.LOCK_EX)
		output, err := runCoreAdmission(fixture)
		requireCoreAdmissionRejected(t, output, err)
		if !bytes.Contains(output, []byte("not bound to the durable journal")) {
			t.Fatalf("journal inode replacement diagnostic is ambiguous: %s", output)
		}
	})
	t.Run("activation lock", func(t *testing.T) {
		fixture := newCoreAdmissionFixture(t)
		fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
		if err := os.Rename(fixture.lock, fixture.lock+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		lockCoreAdmissionFile(t, fixture.permit, unix.LOCK_EX)
		lockCoreAdmissionFile(t, fixture.lock, unix.LOCK_EX)
		output, err := runCoreAdmission(fixture)
		requireCoreAdmissionRejected(t, output, err)
		if !bytes.Contains(output, []byte("not bound to the activation lock")) {
			t.Fatalf("activation-lock replacement diagnostic is ambiguous: %s", output)
		}
	})
}

func TestCoreActivationAdmissionRejectsNoncanonicalOrMutatedPayloads(t *testing.T) {
	for _, name := range []string{"journal unknown field", "permit unknown field", "permit trailing JSON"} {
		t.Run(name, func(t *testing.T) {
			fixture := newCoreAdmissionFixture(t)
			fixture.writeEvidence(t, currentCoreAdmissionBootID(t))
			switch name {
			case "journal unknown field":
				payload := strings.Replace(validCoreAdmissionJournal, `{"schema_version":1,`, `{"schema_version":1,"unknown":true,`, 1)
				if err := os.WriteFile(fixture.journal, []byte(payload), 0o600); err != nil {
					t.Fatal(err)
				}
			case "permit unknown field":
				payload, err := os.ReadFile(fixture.permit)
				if err != nil {
					t.Fatal(err)
				}
				payload = bytes.Replace(payload, []byte(`{"schema_version":1,`), []byte(`{"schema_version":1,"unknown":true,`), 1)
				if err := os.WriteFile(fixture.permit, payload, 0o600); err != nil {
					t.Fatal(err)
				}
			case "permit trailing JSON":
				file, err := os.OpenFile(fixture.permit, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.WriteString("{}\n")
				if err := errors.Join(writeErr, file.Close()); err != nil {
					t.Fatal(err)
				}
			}
			lockCoreAdmissionFile(t, fixture.permit, unix.LOCK_EX)
			lockCoreAdmissionFile(t, fixture.lock, unix.LOCK_EX)
			output, err := runCoreAdmission(fixture)
			requireCoreAdmissionRejected(t, output, err)
		})
	}
}
