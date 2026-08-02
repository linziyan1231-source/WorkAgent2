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

const validRecoveryAdmissionJournal = `{"schema_version":1,"units":["workagent-tenant-catalog-ready.target","cliproxyapi.service","workagent-notification.service","workagent-chatforward.service","workagent-userhost@11111111-2222-3333-4444-555555555555.service","workagent-userhost@11111111-2222-3333-4444-555555555555.socket","workagent-chatforward-browser.service","workagent-portal.service"]}` + "\n"

type recoveryAdmissionFixture struct {
	helper      string
	journal     string
	permit      string
	installLock string
	lock        string
}

type recoveryAdmissionPermit struct {
	SchemaVersion     int    `json:"schema_version"`
	BootID            string `json:"boot_id"`
	JournalDevice     uint64 `json:"journal_device"`
	JournalInode      uint64 `json:"journal_inode"`
	InstallLockDevice uint64 `json:"install_lock_device"`
	InstallLockInode  uint64 `json:"install_lock_inode"`
}

func newRecoveryAdmissionFixture(t *testing.T) recoveryAdmissionFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact production recovery evidence is root-owned")
	}
	root := t.TempDir()
	journalParent := filepath.Join(root, "backup-state")
	permitParent := filepath.Join(root, "recovery-runtime")
	activationParent := filepath.Join(root, "runtime")
	for _, path := range []string{journalParent, permitParent, activationParent} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := recoveryAdmissionFixture{
		helper:      filepath.Join(root, "workagent-recovery-activation-admission-v1"),
		journal:     filepath.Join(journalParent, "recovery-activation.json"),
		permit:      filepath.Join(permitParent, "recovery-activation.permit"),
		installLock: filepath.Join(permitParent, "recovery-install.lock"),
		lock:        filepath.Join(activationParent, "activation.lock"),
	}
	for _, lockPath := range []string{fixture.installLock, fixture.lock} {
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lockPath, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := repositoryFile(t, "deploy/libexec/workagent-recovery-activation-admission-v1")
	replacements := map[string]string{
		"readonly activation_lock=/run/workagent/activation.lock":                      "readonly activation_lock=" + bashSingleQuoted(fixture.lock),
		"readonly recovery_permit=/run/workagent-backup/recovery-activation.permit":    "readonly recovery_permit=" + bashSingleQuoted(fixture.permit),
		"readonly recovery_install_lock=/run/workagent-backup/recovery-install.lock":   "readonly recovery_install_lock=" + bashSingleQuoted(fixture.installLock),
		"readonly recovery_journal=/var/lib/workagent-backup/recovery-activation.json": "readonly recovery_journal=" + bashSingleQuoted(fixture.journal),
	}
	for old, replacement := range replacements {
		if !strings.Contains(payload, old) {
			t.Fatalf("recovery admission helper omitted fixture seam %q", old)
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

func (fixture recoveryAdmissionFixture) writePermit(t *testing.T) {
	t.Helper()
	bootPayload, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	fixture.writePermitForBoot(t, strings.TrimSuffix(string(bootPayload), "\n"))
}

func (fixture recoveryAdmissionFixture) writePermitForBoot(t *testing.T, bootID string) {
	t.Helper()
	journalInfo, err := os.Stat(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	journalStat := journalInfo.Sys().(*syscall.Stat_t)
	installLockInfo, err := os.Stat(fixture.installLock)
	if err != nil {
		t.Fatal(err)
	}
	installLockStat := installLockInfo.Sys().(*syscall.Stat_t)
	value := recoveryAdmissionPermit{
		SchemaVersion:     2,
		BootID:            bootID,
		JournalDevice:     uint64(journalStat.Dev),
		JournalInode:      journalStat.Ino,
		InstallLockDevice: uint64(installLockStat.Dev),
		InstallLockInode:  installLockStat.Ino,
	}
	payload, err := json.Marshal(value)
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

func (fixture recoveryAdmissionFixture) writeJournal(t *testing.T, payload string) {
	t.Helper()
	if err := os.WriteFile(fixture.journal, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.journal, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture recoveryAdmissionFixture) run() ([]byte, error) {
	return exec.Command(fixture.helper).CombinedOutput()
}

func lockRecoveryAdmissionFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	})
	return file
}

func requireAdmissionBlocked(t *testing.T, output []byte, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("unsafe recovery admission was allowed:\n%s", output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("recovery admission failure status = %v, want exit 1; output=%s", err, output)
	}
	if !bytes.Contains(output, []byte("workagent-recovery-activation-admission-v1:")) {
		t.Fatalf("recovery admission failure omitted its stable diagnostic prefix: %s", output)
	}
}

func TestRecoveryActivationAdmissionAllowsOnlyJournalAndPermitAbsence(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	if err := os.Remove(fixture.lock); err != nil {
		t.Fatal(err)
	}
	if output, err := fixture.run(); err != nil {
		t.Fatalf("journal-absent admission failed: %v\n%s", err, output)
	}
}

func TestRecoveryActivationAdmissionRejectsOrphanPermitWithoutJournal(t *testing.T) {
	for _, name := range []string{"regular unsafe file", "dangling symlink", "directory"} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecoveryAdmissionFixture(t)
			switch name {
			case "regular unsafe file":
				if err := os.WriteFile(fixture.permit, []byte("orphan\n"), 0o666); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(fixture.permit, 0o666); err != nil {
					t.Fatal(err)
				}
			case "dangling symlink":
				if err := os.Symlink(filepath.Join(filepath.Dir(fixture.permit), "missing-permit-target"), fixture.permit); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(fixture.permit, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			output, err := fixture.run()
			requireAdmissionBlocked(t, output, err)
			if !bytes.Contains(output, []byte("orphan recovery activation permit")) {
				t.Fatalf("orphan permit rejection was ambiguous: %s", output)
			}
		})
	}
}

func TestRecoveryActivationAdmissionRejectsUnprovableArtifactAbsence(t *testing.T) {
	for _, name := range []string{"journal parent", "permit parent"} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecoveryAdmissionFixture(t)
			parent := filepath.Dir(fixture.journal)
			if name == "permit parent" {
				parent = filepath.Dir(fixture.permit)
			}
			if err := os.Chmod(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			output, err := fixture.run()
			requireAdmissionBlocked(t, output, err)
			if !bytes.Contains(output, []byte("parent is unsafe")) {
				t.Fatalf("unsafe-parent absence rejection was ambiguous: %s", output)
			}
		})
	}
}

func TestRecoveryActivationAdmissionAllowsOnlyCurrentRecoveryPermitInstallAndActivationLocks(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	fixture.writePermit(t)
	lockRecoveryAdmissionFile(t, fixture.permit)
	lockRecoveryAdmissionFile(t, fixture.installLock)
	lockRecoveryAdmissionFile(t, fixture.lock)
	if output, err := fixture.run(); err != nil {
		t.Fatalf("current recovery's exclusive lock was rejected: %v\n%s", err, output)
	}
}

func TestRecoveryActivationAdmissionBlocksPendingJournalWithFreeActivationLock(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	fixture.writePermit(t)
	lockRecoveryAdmissionFile(t, fixture.permit)
	lockRecoveryAdmissionFile(t, fixture.installLock)
	output, err := fixture.run()
	requireAdmissionBlocked(t, output, err)
	if !bytes.Contains(output, []byte("pending without an active recovery")) {
		t.Fatalf("free-lock rejection was ambiguous: %s", output)
	}
}

func TestRecoveryActivationAdmissionBlocksPendingJournalWithFreeInstallLock(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	fixture.writePermit(t)
	lockRecoveryAdmissionFile(t, fixture.permit)
	lockRecoveryAdmissionFile(t, fixture.lock)
	output, err := fixture.run()
	requireAdmissionBlocked(t, output, err)
	if !bytes.Contains(output, []byte("install lock has no current recovery owner")) {
		t.Fatalf("free install-lock rejection was ambiguous: %s", output)
	}
}

func TestRecoveryActivationAdmissionRejectsGenericActivationHolderWithoutLivePermit(t *testing.T) {
	for _, name := range []string{"reboot permit absent", "SIGKILL permit unlocked"} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecoveryAdmissionFixture(t)
			fixture.writeJournal(t, validRecoveryAdmissionJournal)
			if name == "SIGKILL permit unlocked" {
				fixture.writePermit(t)
			}
			lockRecoveryAdmissionFile(t, fixture.lock)
			output, err := fixture.run()
			requireAdmissionBlocked(t, output, err)
			if !bytes.Contains(output, []byte("permit")) {
				t.Fatalf("generic activation holder was not rejected at the recovery-specific permit: %s", output)
			}
		})
	}
}

func TestRecoveryActivationAdmissionRejectsPermitFromAnotherBoot(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	const otherBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	currentBoot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(currentBoot)) == otherBoot {
		t.Fatal("wrong-boot fixture unexpectedly equals the current boot")
	}
	fixture.writePermitForBoot(t, otherBoot)
	lockRecoveryAdmissionFile(t, fixture.permit)
	lockRecoveryAdmissionFile(t, fixture.installLock)
	lockRecoveryAdmissionFile(t, fixture.lock)
	output, err := fixture.run()
	requireAdmissionBlocked(t, output, err)
	if !bytes.Contains(output, []byte("belongs to another boot")) {
		t.Fatalf("wrong-boot permit rejection was ambiguous: %s", output)
	}
}

func TestRecoveryActivationAdmissionBlocksUnsafeEvidence(t *testing.T) {
	t.Run("permit mode", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		fixture.writeJournal(t, validRecoveryAdmissionJournal)
		fixture.writePermit(t)
		if err := os.Chmod(fixture.permit, 0o640); err != nil {
			t.Fatal(err)
		}
		lockRecoveryAdmissionFile(t, fixture.permit)
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})

	t.Run("permit content", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		fixture.writeJournal(t, validRecoveryAdmissionJournal)
		if err := os.WriteFile(fixture.permit, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.permit, 0o600); err != nil {
			t.Fatal(err)
		}
		lockRecoveryAdmissionFile(t, fixture.permit)
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})

	t.Run("lock mode", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		fixture.writeJournal(t, validRecoveryAdmissionJournal)
		fixture.writePermit(t)
		lockRecoveryAdmissionFile(t, fixture.permit)
		lockRecoveryAdmissionFile(t, fixture.installLock)
		if err := os.Chmod(fixture.lock, 0o640); err != nil {
			t.Fatal(err)
		}
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})

	t.Run("install lock mode", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		fixture.writeJournal(t, validRecoveryAdmissionJournal)
		fixture.writePermit(t)
		lockRecoveryAdmissionFile(t, fixture.permit)
		if err := os.Chmod(fixture.installLock, 0o640); err != nil {
			t.Fatal(err)
		}
		lockRecoveryAdmissionFile(t, fixture.installLock)
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})

	t.Run("journal mode", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		fixture.writeJournal(t, validRecoveryAdmissionJournal)
		if err := os.Chmod(fixture.journal, 0o640); err != nil {
			t.Fatal(err)
		}
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})

	t.Run("journal content", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		fixture.writeJournal(t, "{}\n")
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})

	t.Run("journal symlink", func(t *testing.T) {
		fixture := newRecoveryAdmissionFixture(t)
		target := filepath.Join(filepath.Dir(fixture.journal), "journal-target")
		if err := os.WriteFile(target, []byte(validRecoveryAdmissionJournal), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, fixture.journal); err != nil {
			t.Fatal(err)
		}
		lockRecoveryAdmissionFile(t, fixture.lock)
		output, err := fixture.run()
		requireAdmissionBlocked(t, output, err)
	})
}

func TestRecoveryActivationAdmissionRejectsLockedReplacedPath(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	fixture.writePermit(t)
	lockRecoveryAdmissionFile(t, fixture.permit)
	lockRecoveryAdmissionFile(t, fixture.installLock)
	locked := lockRecoveryAdmissionFile(t, fixture.lock)
	originalInfo, err := locked.Stat()
	if err != nil {
		t.Fatal(err)
	}
	displaced := fixture.lock + ".displaced"
	if err := os.Rename(fixture.lock, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.lock, 0o600); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := os.Stat(fixture.lock)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(originalInfo, replacementInfo) {
		t.Fatal("path replacement fixture did not change the activation inode")
	}
	output, err := fixture.run()
	requireAdmissionBlocked(t, output, err)
	if !bytes.Contains(output, []byte("pending without an active recovery")) {
		t.Fatalf("replacement-path rejection did not prove the canonical inode was free: %s", output)
	}
}

func TestRecoveryActivationAdmissionRejectsSameBootStalePermitWithGenericOwnersAndForeignInstallLock(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	fixture.writePermit(t)
	lockRecoveryAdmissionFile(t, fixture.permit)
	lockRecoveryAdmissionFile(t, fixture.lock)
	originalInfo, err := os.Stat(fixture.installLock)
	if err != nil {
		t.Fatal(err)
	}
	displaced := fixture.installLock + ".displaced"
	if err := os.Rename(fixture.installLock, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.installLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.installLock, 0o600); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := os.Stat(fixture.installLock)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(originalInfo, replacementInfo) {
		t.Fatal("foreign install-lock fixture did not replace the permit-bound inode")
	}
	lockRecoveryAdmissionFile(t, fixture.installLock)
	output, err := fixture.run()
	requireAdmissionBlocked(t, output, err)
	if !bytes.Contains(output, []byte("does not authorize this install lock")) {
		t.Fatalf("foreign install-lock rejection was ambiguous: %s", output)
	}
}

func TestRecoveryActivationAdmissionRejectsLockedReplacedPermitPath(t *testing.T) {
	fixture := newRecoveryAdmissionFixture(t)
	fixture.writeJournal(t, validRecoveryAdmissionJournal)
	fixture.writePermit(t)
	locked := lockRecoveryAdmissionFile(t, fixture.permit)
	originalInfo, err := locked.Stat()
	if err != nil {
		t.Fatal(err)
	}
	displaced := fixture.permit + ".displaced"
	if err := os.Rename(fixture.permit, displaced); err != nil {
		t.Fatal(err)
	}
	fixture.writePermit(t)
	replacementInfo, err := os.Stat(fixture.permit)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(originalInfo, replacementInfo) {
		t.Fatal("path replacement fixture did not change the permit inode")
	}
	lockRecoveryAdmissionFile(t, fixture.lock)
	output, err := fixture.run()
	requireAdmissionBlocked(t, output, err)
	if !bytes.Contains(output, []byte("permit has no current recovery owner")) {
		t.Fatalf("replacement permit pathname was not rejected as unlocked: %s", output)
	}
}
