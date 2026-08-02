//go:build linux

package backup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const recoveryPermitTestBootID = "11111111-2222-4333-8444-555555555555"

type recoveryPermitFixture struct {
	journal string
	permit  string
	install string
}

func newRecoveryPermitFixture(t *testing.T) recoveryPermitFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact recovery permit ownership is root-only")
	}
	root := t.TempDir()
	journalParent := filepath.Join(root, "persistent")
	permitParent := filepath.Join(root, "volatile")
	for _, parent := range []string{journalParent, permitParent} {
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := recoveryPermitFixture{
		journal: filepath.Join(journalParent, filepath.Base(recoveryActivationJournalPath)),
		permit:  filepath.Join(permitParent, filepath.Base(recoveryActivationPermitPath)),
		install: filepath.Join(permitParent, filepath.Base(recoveryInstallLockPath)),
	}
	if err := os.WriteFile(fixture.journal, []byte("durable recovery intent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.journal, 0o600); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture recoveryPermitFixture) acquireInstallLock(t *testing.T) *recoveryInstallLockGuard {
	t.Helper()
	guard, err := acquireRecoveryInstallLockWithParent(fixture.install, recoveryPermitTestParent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })
	return guard
}

func recoveryPermitTestParent(path string) (int, error) {
	return openRootOnlyRecoveryParent(path)
}

func requirePermitLocked(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		t.Fatal("recovery permit was published without its exclusive owner")
	}
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("inspect recovery permit lock: %v", err)
	}
}

func TestRecoveryActivationPermitIsPublishedLockedAndRemovedBeforeRelease(t *testing.T) {
	fixture := newRecoveryPermitFixture(t)
	installLock := fixture.acquireInstallLock(t)
	guard, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
	if err != nil {
		t.Fatal(err)
	}
	requirePermitLocked(t, fixture.permit)
	info, err := os.Lstat(fixture.permit)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || info.Size() <= 0 {
		t.Fatalf("published permit metadata is unsafe: mode=%v stat=%+v", info.Mode(), stat)
	}
	permitFile, err := os.Open(fixture.permit)
	if err != nil {
		t.Fatal(err)
	}
	var permitStat unix.Stat_t
	if err := unix.Fstat(int(permitFile.Fd()), &permitStat); err != nil {
		permitFile.Close()
		t.Fatal(err)
	}
	value, readErr := readRecoveryActivationPermit(permitFile, permitStat)
	if err := permitFile.Close(); readErr != nil || err != nil {
		t.Fatal(errors.Join(readErr, err))
	}
	installIdentity, err := installLock.identity()
	if err != nil {
		t.Fatal(err)
	}
	if value.SchemaVersion != 2 || value.InstallLockDevice != installIdentity.Dev || value.InstallLockInode != installIdentity.Ino {
		t.Fatalf("permit did not bind its actual held install-lock guard: %+v", value)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if err := installLock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fixture.permit); !os.IsNotExist(err) {
		t.Fatalf("permit pathname survived normal release: %v", err)
	}
}

func TestRecoveryActivationPermitRequiresDurableJournal(t *testing.T) {
	fixture := newRecoveryPermitFixture(t)
	installLock := fixture.acquireInstallLock(t)
	if err := os.Remove(fixture.journal); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent); err == nil {
		t.Fatal("recovery permit was created without a durable activation journal")
	}
	if _, err := os.Lstat(fixture.permit); !os.IsNotExist(err) {
		t.Fatalf("failed permit creation published a pathname: %v", err)
	}
}

func TestRecoveryInstallLockGuardRejectsUnsafeInitialInode(t *testing.T) {
	t.Run("nonempty", func(t *testing.T) {
		fixture := newRecoveryPermitFixture(t)
		if err := os.WriteFile(fixture.install, []byte("foreign\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.install, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := acquireRecoveryInstallLockWithParent(fixture.install, recoveryPermitTestParent); err == nil {
			t.Fatal("nonempty recovery install lock was accepted")
		}
	})

	t.Run("multiply linked", func(t *testing.T) {
		fixture := newRecoveryPermitFixture(t)
		if err := os.WriteFile(fixture.install, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.install, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(fixture.install, fixture.install+".alias"); err != nil {
			t.Fatal(err)
		}
		if _, err := acquireRecoveryInstallLockWithParent(fixture.install, recoveryPermitTestParent); err == nil {
			t.Fatal("multiply linked recovery install lock was accepted")
		}
	})
}

func TestRecoveryPermitCreationRejectsReplacedHeldInstallLockPath(t *testing.T) {
	fixture := newRecoveryPermitFixture(t)
	installLock := fixture.acquireInstallLock(t)
	displaced := fixture.install + ".displaced"
	if err := os.Rename(fixture.install, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.install, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.install, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent); err == nil {
		t.Fatal("permit was bound to an install lock held only through a displaced inode")
	}
	if _, err := os.Lstat(fixture.permit); !os.IsNotExist(err) {
		t.Fatalf("rejected permit creation published a pathname: %v", err)
	}
}

func TestRecoveryPermitCreationAuthenticatesExternallyHeldExclusiveLocks(t *testing.T) {
	fixture := newRecoveryPermitFixture(t)
	lockPath := filepath.Join(filepath.Dir(fixture.permit), "authorization.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireRecoveryExclusiveLockHeld(lockPath, recoveryPermitTestParent); err == nil {
		t.Fatal("free authorization lock was accepted as externally held")
	}
	file, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(file.Fd()), unix.LOCK_UN)
	if err := requireRecoveryExclusiveLockHeld(lockPath, recoveryPermitTestParent); err != nil {
		t.Fatalf("externally held authorization lock was rejected: %v", err)
	}
	displaced := lockPath + ".displaced"
	if err := os.Rename(lockPath, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireRecoveryExclusiveLockHeld(lockPath, recoveryPermitTestParent); err == nil {
		t.Fatal("lock held only on a displaced inode authenticated permit creation")
	}
}

func TestRecoveryCanRebuildUnlockedSIGKILLPermit(t *testing.T) {
	fixture := newRecoveryPermitFixture(t)
	installLock := fixture.acquireInstallLock(t)
	guard, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
	if err != nil {
		t.Fatal(err)
	}
	// Model SIGKILL: the descriptor lock disappears without the pathname
	// cleanup method running.
	if err := guard.file.Close(); err != nil {
		t.Fatal(err)
	}
	guard.closed = true
	if err := reconcileStaleRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent); err != nil {
		t.Fatalf("valid unlocked same-boot permit was not reconciled: %v", err)
	}
	if _, err := os.Lstat(fixture.permit); !os.IsNotExist(err) {
		t.Fatalf("stale permit survived reconciliation: %v", err)
	}
	rebuilt, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
	if err != nil {
		t.Fatalf("recovery permit could not be safely rebuilt: %v", err)
	}
	if err := rebuilt.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryPermitReconciliationRejectsUnsafeOrLiveState(t *testing.T) {
	t.Run("live owner", func(t *testing.T) {
		fixture := newRecoveryPermitFixture(t)
		installLock := fixture.acquireInstallLock(t)
		guard, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
		if err != nil {
			t.Fatal(err)
		}
		if err := reconcileStaleRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent); err == nil {
			t.Fatal("live recovery permit was stolen")
		}
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("different journal inode", func(t *testing.T) {
		fixture := newRecoveryPermitFixture(t)
		installLock := fixture.acquireInstallLock(t)
		guard, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.file.Close(); err != nil {
			t.Fatal(err)
		}
		guard.closed = true
		displaced := fixture.journal + ".displaced"
		if err := os.Rename(fixture.journal, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.journal, []byte("different durable recovery intent\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.journal, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reconcileStaleRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent); err == nil {
			t.Fatal("permit bound to another journal inode was removed")
		}
		if _, err := os.Lstat(fixture.permit); err != nil {
			t.Fatalf("rejected permit was removed: %v", err)
		}
	})

	t.Run("different boot", func(t *testing.T) {
		fixture := newRecoveryPermitFixture(t)
		installLock := fixture.acquireInstallLock(t)
		guard, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.file.Close(); err != nil {
			t.Fatal(err)
		}
		guard.closed = true
		if err := reconcileStaleRecoveryActivationPermit(fixture.permit, fixture.journal, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", installLock, recoveryPermitTestParent); err == nil {
			t.Fatal("another boot's permit was removed")
		}
		if _, err := os.Lstat(fixture.permit); err != nil {
			t.Fatalf("different-boot permit was removed: %v", err)
		}
	})

	t.Run("different install lock inode", func(t *testing.T) {
		fixture := newRecoveryPermitFixture(t)
		installLock := fixture.acquireInstallLock(t)
		guard, err := acquireRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, installLock, recoveryPermitTestParent)
		if err != nil {
			t.Fatal(err)
		}
		if err := guard.file.Close(); err != nil {
			t.Fatal(err)
		}
		guard.closed = true
		if err := installLock.Close(); err != nil {
			t.Fatal(err)
		}
		displaced := fixture.install + ".displaced"
		if err := os.Rename(fixture.install, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.install, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.install, 0o600); err != nil {
			t.Fatal(err)
		}
		foreignInstallLock := fixture.acquireInstallLock(t)
		if err := reconcileStaleRecoveryActivationPermit(fixture.permit, fixture.journal, recoveryPermitTestBootID, foreignInstallLock, recoveryPermitTestParent); err == nil {
			t.Fatal("stale permit bound to another install-lock inode was removed")
		}
		if _, err := os.Lstat(fixture.permit); err != nil {
			t.Fatalf("rejected stale permit was removed: %v", err)
		}
	})
}
