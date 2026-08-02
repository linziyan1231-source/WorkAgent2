//go:build linux

package coreactivation

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const testBootID = "11111111-2222-4333-8444-555555555555"

type testFixture struct {
	layout        layout
	root          string
	journalDir    string
	permitDir     string
	activationDir string
	lockFile      *os.File
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact core activation ownership tests require root")
	}
	root := t.TempDir()
	journalDir := filepath.Join(root, "persistent")
	permitDir := filepath.Join(root, "volatile")
	activationDir := filepath.Join(root, "lifecycle")
	for _, directory := range []string{journalDir, permitDir, activationDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bootPath := filepath.Join(root, "boot_id")
	if err := os.WriteFile(bootPath, []byte(testBootID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	activationPath := filepath.Join(activationDir, filepath.Base(ActivationLockPath))
	if err := os.WriteFile(activationPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(activationPath, 0o600); err != nil {
		t.Fatal(err)
	}
	lockFile, err := os.OpenFile(activationPath, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		t.Fatal(err)
	}
	fixture := &testFixture{
		layout: layout{
			journalPath:        filepath.Join(journalDir, filepath.Base(JournalPath)),
			permitPath:         filepath.Join(permitDir, filepath.Base(PermitPath)),
			activationLockPath: activationPath,
			bootIDPath:         bootPath,
			expectedUID:        0,
			expectedGID:        0,
			fsync:              unix.Fsync,
		},
		root:          root,
		journalDir:    journalDir,
		permitDir:     permitDir,
		activationDir: activationDir,
		lockFile:      lockFile,
	}
	fixture.requireOTmpfile(t)
	t.Cleanup(func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		_ = lockFile.Close()
	})
	return fixture
}

func (fixture *testFixture) requireOTmpfile(t *testing.T) {
	t.Helper()
	for _, directory := range []string{fixture.journalDir, fixture.permitDir} {
		parentFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fd, openErr := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
		_ = unix.Close(parentFD)
		if openErr != nil {
			t.Skipf("test filesystem lacks O_TMPFILE support: %v", openErr)
		}
		_ = unix.Close(fd)
	}
}

func (fixture *testFixture) unlockActivation(t *testing.T) {
	t.Helper()
	if err := unix.Flock(int(fixture.lockFile.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func (fixture *testFixture) lockActivation(t *testing.T) {
	t.Helper()
	if err := unix.Flock(int(fixture.lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

func (fixture *testFixture) crashTransaction(t *testing.T, transaction *Transaction) {
	t.Helper()
	if transaction == nil {
		t.Fatal("nil transaction")
	}
	if err := transaction.closeDescriptors(); err != nil {
		t.Fatal(err)
	}
}

func requirePathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s absent: %v", path, err)
	}
}

func requireSafeEvidence(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || info.Size() <= 0 {
		t.Fatalf("unsafe evidence at %s: mode=%v stat=%+v", path, info.Mode(), stat)
	}
	var result unix.Stat_t
	if err := unix.Stat(path, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func requirePermitExclusivelyLocked(t *testing.T, path string) {
	t.Helper()
	probe, err := os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	err = unix.Flock(int(probe.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(probe.Fd()), unix.LOCK_UN)
		t.Fatal("published permit was not already exclusively locked")
	}
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("inspect permit flock: %v", err)
	}
}

func TestCoreActivationExactSchemaAndOrderedUnitContract(t *testing.T) {
	want := []string{
		"workagent-tenant-catalog-ready.target",
		"workagent-tenant-config-reconcile.service",
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
		"caddy.service",
		"workagent-backup.service",
		"workagent-backup.timer",
		"workagent-healthcheck.service",
		"workagent-healthcheck.timer",
	}
	if got := CoreUnits(); !slices.Equal(got, want) {
		t.Fatalf("unexpected unit contract: %#v", got)
	}
	mutated := CoreUnits()
	mutated[0] = "foreign.service"
	if CoreUnits()[0] != want[0] {
		t.Fatal("CoreUnits exposed mutable package state")
	}
	journal := Journal{SchemaVersion: 1, Units: CoreUnits()}
	payload, err := canonicalJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := `{"schema_version":1,"units":["workagent-tenant-catalog-ready.target","workagent-tenant-config-reconcile.service","cliproxyapi.service","workagent-notification.service","workagent-chatforward.service","workagent-chatforward-browser.service","workagent-portal.service","caddy.service","workagent-backup.service","workagent-backup.timer","workagent-healthcheck.service","workagent-healthcheck.timer"]}` + "\n"
	if string(payload) != wantPayload {
		t.Fatalf("journal is not exact canonical JSON:\n%s", payload)
	}

	invalid := []Journal{
		{SchemaVersion: 2, Units: CoreUnits()},
		{SchemaVersion: 1, Units: CoreUnits()[:len(CoreUnits())-1]},
		{SchemaVersion: 1, Units: append(CoreUnits(), "foreign.service")},
	}
	reordered := CoreUnits()
	reordered[0], reordered[1] = reordered[1], reordered[0]
	invalid = append(invalid, Journal{SchemaVersion: 1, Units: reordered})
	for _, value := range invalid {
		if err := validateJournal(value); err == nil {
			t.Fatalf("invalid journal was accepted: %+v", value)
		}
	}
}

func TestAssertCleanDoubleAbsenceAndOrphanRejection(t *testing.T) {
	fixture := newTestFixture(t)
	if err := assertCleanAt(fixture.layout); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.layout.permitPath, []byte("orphan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.layout.permitPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(fixture.layout); err == nil || !strings.Contains(err.Error(), "orphan") {
		t.Fatalf("orphan permit was not specifically rejected: %v", err)
	}
	if err := os.Remove(fixture.layout.permitPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.permitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(fixture.layout); err == nil {
		t.Fatal("non-0700 evidence parent was accepted")
	}
}

func TestBeginPublishesJournalThenLockedBoundPermit(t *testing.T) {
	fixture := newTestFixture(t)
	var observations []string
	fixture.layout.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			journalExists := pathExists(fixture.layout.journalPath)
			permitExists := pathExists(fixture.layout.permitPath)
			switch {
			case sameDirectory(fd, fixture.journalDir) && journalExists && !permitExists:
				observations = append(observations, "journal-published")
			case sameDirectory(fd, fixture.permitDir) && journalExists && permitExists:
				observations = append(observations, "permit-published")
			}
		}
		return unix.Fsync(fd)
	}
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close()
	if len(observations) < 2 || observations[0] != "journal-published" || observations[1] != "permit-published" {
		t.Fatalf("evidence publication order was not journal then permit: %#v", observations)
	}
	if err := transaction.Verify(); err != nil {
		t.Fatal(err)
	}
	journalStat := requireSafeEvidence(t, fixture.layout.journalPath)
	permitStat := requireSafeEvidence(t, fixture.layout.permitPath)
	if journalStat.Ino == permitStat.Ino && journalStat.Dev == permitStat.Dev {
		t.Fatal("journal and permit unexpectedly share an inode")
	}
	requirePermitExclusivelyLocked(t, fixture.layout.permitPath)
	metadata, err := decodePermit(transaction.pending.permitFile, fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	var lockStat unix.Stat_t
	if err := unix.Stat(fixture.layout.activationLockPath, &lockStat); err != nil {
		t.Fatal(err)
	}
	if metadata.SchemaVersion != 1 || metadata.BootID != testBootID || metadata.JournalDevice != journalStat.Dev ||
		metadata.JournalInode != journalStat.Ino || metadata.ActivationLockDevice != lockStat.Dev || metadata.ActivationLockInode != lockStat.Ino {
		t.Fatalf("permit did not bind boot/journal/activation lock: %+v", metadata)
	}
}

func TestTransactionVerifyRejectsActivationLockLossAndPathReplacement(t *testing.T) {
	t.Run("lock released", func(t *testing.T) {
		fixture := newTestFixture(t)
		transaction, err := beginAt(fixture.layout)
		if err != nil {
			t.Fatal(err)
		}
		fixture.unlockActivation(t)
		if err := transaction.Verify(); err == nil {
			t.Fatal("transaction survived loss of caller's exclusive activation lock")
		}
		fixture.lockActivation(t)
		if err := transaction.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("lock pathname replaced", func(t *testing.T) {
		fixture := newTestFixture(t)
		transaction, err := beginAt(fixture.layout)
		if err != nil {
			t.Fatal(err)
		}
		displaced := fixture.layout.activationLockPath + ".displaced"
		if err := os.Rename(fixture.layout.activationLockPath, displaced); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.layout.activationLockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.layout.activationLockPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := transaction.Verify(); err == nil {
			t.Fatal("transaction accepted an activation lock held only on a displaced inode")
		}
		// Verify failure makes Close retain both evidence names.
		if err := transaction.Close(); err == nil {
			t.Fatal("unsafe transaction Close unexpectedly succeeded")
		}
		if !pathExists(fixture.layout.journalPath) || !pathExists(fixture.layout.permitPath) {
			t.Fatal("unsafe close discarded recovery evidence")
		}
	})
}

func TestCloseRemovesPermitButRetainsRollbackJournal(t *testing.T) {
	fixture := newTestFixture(t)
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	requireSafeEvidence(t, fixture.layout.journalPath)
	requirePathAbsent(t, fixture.layout.permitPath)
	pending, err := loadPendingAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil || pending.PermitPresent() {
		t.Fatalf("journal-only pending state was not loaded: %#v", pending)
	}
	if got := pending.Journal(); got.SchemaVersion != 1 || !slices.Equal(got.Units, CoreUnits()) {
		t.Fatalf("wrong pending rollback contract: %+v", got)
	}
	if err := pending.RemoveJournalAfterRollback(); err != nil {
		t.Fatal(err)
	}
	if value, err := loadPendingAt(fixture.layout); err != nil || value != nil {
		t.Fatalf("settled rollback did not produce explicit no-pending result: pending=%#v err=%v", value, err)
	}
}

func TestCommitRemovesPermitBeforeJournalAndFsyncsBoth(t *testing.T) {
	fixture := newTestFixture(t)
	var removalOrder []string
	fixture.layout.fsync = func(fd int) error {
		journalExists := pathExists(fixture.layout.journalPath)
		permitExists := pathExists(fixture.layout.permitPath)
		if sameDirectory(fd, fixture.permitDir) && journalExists && !permitExists {
			removalOrder = append(removalOrder, "permit")
		}
		if sameDirectory(fd, fixture.journalDir) && !journalExists && !permitExists {
			removalOrder = append(removalOrder, "journal")
		}
		return unix.Fsync(fd)
	}
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(removalOrder, []string{"permit", "journal"}) {
		t.Fatalf("commit settlement order was not permit then journal: %#v", removalOrder)
	}
	if err := assertCleanAt(fixture.layout); err != nil {
		t.Fatalf("committed transaction left evidence: %v", err)
	}
}

func TestCrashAfterJournalOnlyIsReplayable(t *testing.T) {
	fixture := newTestFixture(t)
	journalFile, _, err := writeJournal(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := journalFile.close(); err != nil {
		t.Fatal(err)
	}
	requireSafeEvidence(t, fixture.layout.journalPath)
	requirePathAbsent(t, fixture.layout.permitPath)
	pending, err := loadPendingAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil || pending.PermitPresent() {
		t.Fatal("journal-first crash was not recoverable as journal-only evidence")
	}
	if err := pending.RemoveJournalAfterRollback(); err != nil {
		t.Fatal(err)
	}
}

func TestCrashAfterPermitCanReconcileStalePermitAndRollback(t *testing.T) {
	fixture := newTestFixture(t)
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	fixture.crashTransaction(t, transaction)
	requireSafeEvidence(t, fixture.layout.journalPath)
	requireSafeEvidence(t, fixture.layout.permitPath)
	pending, err := loadPendingAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil || !pending.PermitPresent() {
		t.Fatal("stale permit was not exposed to replay")
	}
	if err := pending.RemoveJournalAfterRollback(); err == nil {
		t.Fatal("journal was removed before stale permit reconciliation")
	}
	if err := pending.ReconcileStalePermit(); err != nil {
		t.Fatal(err)
	}
	requirePathAbsent(t, fixture.layout.permitPath)
	if err := pending.RemoveJournalAfterRollback(); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(fixture.layout); err != nil {
		t.Fatal(err)
	}
}

func TestReplayRefusesToStealLivePermit(t *testing.T) {
	fixture := newTestFixture(t)
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := loadPendingAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.ReconcileStalePermit(); err == nil || !strings.Contains(err.Error(), "live") {
		t.Fatalf("live permit was not rejected: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPendingRejectsNoncanonicalAndMismatchedEvidence(t *testing.T) {
	t.Run("noncanonical journal", func(t *testing.T) {
		fixture := newTestFixture(t)
		journal := Journal{SchemaVersion: 1, Units: CoreUnits()}
		payload, err := canonicalJournal(journal)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.Replace(payload, []byte(`{"schema_version":1`), []byte(`{ "schema_version":1`), 1)
		if err := os.WriteFile(fixture.layout.journalPath, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.layout.journalPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPendingAt(fixture.layout); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("noncanonical journal was accepted: %v", err)
		}
	})

	t.Run("permit journal inode binding", func(t *testing.T) {
		fixture := newTestFixture(t)
		transaction, err := beginAt(fixture.layout)
		if err != nil {
			t.Fatal(err)
		}
		fixture.crashTransaction(t, transaction)
		original := fixture.layout.journalPath + ".original"
		if err := os.Rename(fixture.layout.journalPath, original); err != nil {
			t.Fatal(err)
		}
		payload, err := os.ReadFile(original)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.layout.journalPath, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.layout.journalPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPendingAt(fixture.layout); err == nil || !strings.Contains(err.Error(), "binding") {
			t.Fatalf("permit bound to replaced journal inode was accepted: %v", err)
		}
	})

	t.Run("permit boot binding", func(t *testing.T) {
		fixture := newTestFixture(t)
		transaction, err := beginAt(fixture.layout)
		if err != nil {
			t.Fatal(err)
		}
		fixture.crashTransaction(t, transaction)
		if err := os.WriteFile(fixture.layout.bootIDPath, []byte("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPendingAt(fixture.layout); err == nil || !strings.Contains(err.Error(), "binding") {
			t.Fatalf("permit from another boot was accepted: %v", err)
		}
	})
}

func TestCommitFsyncFailuresRetainDurableRollbackEvidence(t *testing.T) {
	t.Run("permit removal fsync", func(t *testing.T) {
		fixture := newTestFixture(t)
		volatileSyncs := 0
		fixture.layout.fsync = func(fd int) error {
			if sameDirectory(fd, fixture.permitDir) {
				volatileSyncs++
				if volatileSyncs == 2 {
					return errors.New("injected permit removal fsync failure")
				}
			}
			return unix.Fsync(fd)
		}
		transaction, err := beginAt(fixture.layout)
		if err != nil {
			t.Fatal(err)
		}
		if err := transaction.Commit(); err == nil {
			t.Fatal("injected permit removal fsync failure was ignored")
		}
		requireSafeEvidence(t, fixture.layout.journalPath)
		requirePathAbsent(t, fixture.layout.permitPath)
		cleanLayout := fixture.layout
		cleanLayout.fsync = unix.Fsync
		pending, err := loadPendingAt(cleanLayout)
		if err != nil {
			t.Fatal(err)
		}
		if err := pending.RemoveJournalAfterRollback(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("journal removal fsync", func(t *testing.T) {
		fixture := newTestFixture(t)
		persistentSyncs := 0
		fixture.layout.fsync = func(fd int) error {
			if sameDirectory(fd, fixture.journalDir) {
				persistentSyncs++
				if persistentSyncs == 2 {
					return errors.New("injected journal removal fsync failure")
				}
			}
			return unix.Fsync(fd)
		}
		transaction, err := beginAt(fixture.layout)
		if err != nil {
			t.Fatal(err)
		}
		if err := transaction.Commit(); err == nil {
			t.Fatal("injected journal removal fsync failure was ignored")
		}
		// Permit-first settlement remains complete, while canonical journal
		// evidence is republished for a conservative rollback/replay.
		requirePathAbsent(t, fixture.layout.permitPath)
		requireSafeEvidence(t, fixture.layout.journalPath)
		cleanLayout := fixture.layout
		cleanLayout.fsync = unix.Fsync
		pending, err := loadPendingAt(cleanLayout)
		if err != nil {
			t.Fatal(err)
		}
		if err := pending.RemoveJournalAfterRollback(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRemoveJournalRollbackFsyncFailureRepublishesEvidence(t *testing.T) {
	fixture := newTestFixture(t)
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	persistentSyncs := 0
	failing := fixture.layout
	failing.fsync = func(fd int) error {
		if sameDirectory(fd, fixture.journalDir) {
			persistentSyncs++
			if persistentSyncs == 1 {
				return errors.New("injected rollback journal fsync failure")
			}
		}
		return unix.Fsync(fd)
	}
	pending, err := loadPendingAt(failing)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.RemoveJournalAfterRollback(); err == nil {
		t.Fatal("injected rollback settlement failure was ignored")
	}
	requireSafeEvidence(t, fixture.layout.journalPath)
	clean, err := loadPendingAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := clean.RemoveJournalAfterRollback(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPendingRequiresExclusiveExactActivationLock(t *testing.T) {
	fixture := newTestFixture(t)
	transaction, err := beginAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.unlockActivation(t)
	if _, err := loadPendingAt(fixture.layout); err == nil {
		t.Fatal("pending evidence was loaded without the exact exclusive activation lock")
	}
	fixture.lockActivation(t)
	pending, err := loadPendingAt(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.RemoveJournalAfterRollback(); err != nil {
		t.Fatal(err)
	}
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func sameDirectory(fd int, path string) bool {
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || unix.Stat(path, &named) != nil {
		return false
	}
	return opened.Dev == named.Dev && opened.Ino == named.Ino
}

func TestLayoutRejectsAliasedOrRelativeControlPaths(t *testing.T) {
	fixture := newTestFixture(t)
	cases := []layout{
		func() layout { value := fixture.layout; value.journalPath = "activation.json"; return value }(),
		func() layout { value := fixture.layout; value.permitPath = value.journalPath; return value }(),
		func() layout {
			value := fixture.layout
			value.activationLockPath = filepath.Join(fixture.activationDir, "wrong.lock")
			return value
		}(),
	}
	for index, value := range cases {
		if err := value.validate(); err == nil {
			t.Fatalf("invalid layout case %d was accepted: %+v", index, value)
		}
	}
}

func TestPermitCanonicalJSONRejectsUnknownOrMissingBindings(t *testing.T) {
	valid := permit{
		SchemaVersion:        1,
		BootID:               testBootID,
		JournalDevice:        1,
		JournalInode:         2,
		ActivationLockDevice: 3,
		ActivationLockInode:  4,
	}
	payload, err := canonicalPermit(valid)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"schema_version":1,"boot_id":%q,"journal_device":1,"journal_inode":2,"activation_lock_device":3,"activation_lock_inode":4}`+"\n", testBootID)
	if string(payload) != want {
		t.Fatalf("permit is not exact canonical JSON: %s", payload)
	}
	invalid := valid
	invalid.ActivationLockInode = 0
	if _, err := canonicalPermit(invalid); err == nil {
		t.Fatal("permit missing an activation-lock binding was accepted")
	}
}

func TestProductionBootIdentitySourceSupportsPinnedVerification(t *testing.T) {
	bootID, err := currentBootID(productionLayout())
	if err != nil {
		t.Fatal(err)
	}
	if len(bootID) != 36 {
		t.Fatalf("unexpected production boot identity: %q", bootID)
	}
}
