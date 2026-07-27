//go:build linux

package fixedroot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type testGuard struct {
	held   *atomic.Bool
	closed atomic.Bool
}

type noopGuard struct{}

func (noopGuard) Close() error { return nil }

func (g *testGuard) Close() error {
	if g == nil || g.closed.Swap(true) {
		return nil
	}
	if !g.held.CompareAndSwap(true, false) {
		return errors.New("test lifecycle guard was not held")
	}
	return nil
}

type testEnvironment struct {
	installer   *installer
	parent      string
	destination string
	held        atomic.Bool
	drained     atomic.Bool
	drainCalls  atomic.Int32
	verifyCalls atomic.Int32
	admitCalls  atomic.Int32
	admittedIDs []string
	historyIDs  []string
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "workagent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	environment := &testEnvironment{parent: parent, destination: filepath.Join(parent, "control")}
	environment.installer = &installer{
		parent: parent, expectedUID: uint32(os.Geteuid()), expectedGID: uint32(os.Getegid()),
		effectiveUID: func() int { return 0 },
		now:          func() time.Time { return time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC) },
		random:       strings.NewReader(strings.Repeat("0123456789abcdef", 1024)),
	}
	environment.installer.acquire = func(ctx context.Context) (lockHandle, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !environment.held.CompareAndSwap(false, true) {
			return nil, errors.New("test lifecycle lock already held")
		}
		environment.drained.Store(false)
		return &testGuard{held: &environment.held}, nil
	}
	environment.installer.acquireChannel = func(destination string) (lockHandle, error) {
		if destination != environment.destination || !environment.held.Load() || !environment.drained.Load() {
			return nil, errors.New("test fixed-release channel was not acquired after drain under the catalog lock")
		}
		return noopGuard{}, nil
	}
	return environment
}

func (e *testEnvironment) stage(t *testing.T, releaseID string) string {
	t.Helper()
	target, err := e.installer.resolveTarget(e.destination)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(e.parent, target.stagePrefix+releaseID)
}

func (e *testEnvironment) previous(t *testing.T) string {
	t.Helper()
	target, err := e.installer.resolveTarget(e.destination)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(e.parent, target.previousLeaf)
}

func (e *testEnvironment) journal(t *testing.T) string {
	t.Helper()
	target, err := e.installer.resolveTarget(e.destination)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(e.parent, target.journalLeaf)
}

func (e *testEnvironment) drain(ctx context.Context, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if destination != e.destination || !e.held.Load() {
		return errors.New("drain proof was not called under the expected lifecycle lock")
	}
	e.drainCalls.Add(1)
	e.drained.Store(true)
	return nil
}

func (e *testEnvironment) verify(ctx context.Context, root string, candidate bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !e.held.Load() || !e.drained.Load() {
		return "", errors.New("verification did not run after drain under the lifecycle lock")
	}
	e.verifyCalls.Add(1)
	if candidate {
		e.admitCalls.Add(1)
	}
	payload, err := os.ReadFile(filepath.Join(root, "release-id"))
	if err != nil {
		return "", err
	}
	releaseID := strings.TrimSpace(string(payload))
	if candidate {
		e.admittedIDs = append(e.admittedIDs, releaseID)
	} else {
		e.historyIDs = append(e.historyIDs, releaseID)
	}
	return releaseID, nil
}

func writeTestTree(t *testing.T, root, releaseID string) {
	t.Helper()
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-id"), []byte(releaseID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "app"), []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "release-id"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin", "app"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
}

func readReleaseID(t *testing.T, root string) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(root, "release-id"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(payload))
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat identity is unavailable")
	}
	return stat.Ino
}

func TestInitialInstallUpgradeAndRollbackAreAtomicAndCASBound(t *testing.T) {
	environment := newTestEnvironment(t)
	ctx := context.Background()
	stageV1 := environment.stage(t, "v1")
	writeTestTree(t, stageV1, "v1")
	v1Inode := inodeOf(t, stageV1)

	result, err := environment.installer.install(ctx, InstallOptions{
		Destination: environment.destination, StagedRoot: stageV1,
	}, environment.verify, environment.drain)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != actionInitial || result.CurrentRelease != "v1" || result.PreviousRelease != "" || inodeOf(t, environment.destination) != v1Inode {
		t.Fatalf("unexpected initial-install result: %#v", result)
	}
	if _, err := os.Lstat(stageV1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("initial stage still exists: %v", err)
	}
	journalInfo, err := os.Lstat(environment.journal(t))
	if err != nil || journalInfo.Mode().Perm() != 0o600 {
		t.Fatalf("journal is not durable mode 0600: info=%v err=%v", journalInfo, err)
	}

	// Retrying the same initial request is idempotent even though the stage was
	// consumed by the successful atomic rename.
	retried, err := environment.installer.install(ctx, InstallOptions{
		Destination: environment.destination, StagedRoot: stageV1,
	}, environment.verify, environment.drain)
	if err != nil || retried.CurrentRelease != "v1" || inodeOf(t, environment.destination) != v1Inode {
		t.Fatalf("idempotent initial retry failed: result=%#v err=%v", retried, err)
	}

	stageV2 := environment.stage(t, "v2")
	writeTestTree(t, stageV2, "v2")
	v2Inode := inodeOf(t, stageV2)
	upgraded, err := environment.installer.install(ctx, InstallOptions{
		Destination: environment.destination, StagedRoot: stageV2, ExpectedCurrentRelease: "v1",
	}, environment.verify, environment.drain)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Operation != actionUpgrade || upgraded.CurrentRelease != "v2" || upgraded.PreviousRelease != "v1" ||
		inodeOf(t, environment.destination) != v2Inode || inodeOf(t, environment.previous(t)) != v1Inode {
		t.Fatalf("unexpected exchange-upgrade result: %#v", upgraded)
	}

	rolledBack, err := environment.installer.rollback(ctx, RollbackOptions{
		Destination: environment.destination, ExpectedCurrentRelease: "v2", ExpectedPreviousRelease: "v1",
	}, environment.verify, environment.drain)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Operation != actionRollback || rolledBack.CurrentRelease != "v1" || rolledBack.PreviousRelease != "v2" ||
		inodeOf(t, environment.destination) != v1Inode || inodeOf(t, environment.previous(t)) != v2Inode {
		t.Fatalf("unexpected rollback result: %#v", rolledBack)
	}

	// A retry with the old expectations returns the completed transaction and
	// must not exchange the directories for a second time.
	retriedRollback, err := environment.installer.rollback(ctx, RollbackOptions{
		Destination: environment.destination, ExpectedCurrentRelease: "v2", ExpectedPreviousRelease: "v1",
	}, environment.verify, environment.drain)
	if err != nil || retriedRollback.CurrentRelease != "v1" || inodeOf(t, environment.destination) != v1Inode {
		t.Fatalf("idempotent rollback retry failed: result=%#v err=%v", retriedRollback, err)
	}
	if environment.drainCalls.Load() < 5 || environment.verifyCalls.Load() == 0 || environment.admitCalls.Load() == 0 || environment.admitCalls.Load() >= environment.verifyCalls.Load() || environment.held.Load() {
		t.Fatalf("callbacks were not correctly lifecycle locked or candidate-scoped: drain=%d verify=%d admit=%d held=%v", environment.drainCalls.Load(), environment.verifyCalls.Load(), environment.admitCalls.Load(), environment.held.Load())
	}
}

func TestUpgradeArchivesOlderPreviousTreeWithoutDeletingIt(t *testing.T) {
	environment := newTestEnvironment(t)
	ctx := context.Background()
	stageV1 := environment.stage(t, "v1")
	writeTestTree(t, stageV1, "v1")
	if _, err := environment.installer.install(ctx, InstallOptions{Destination: environment.destination, StagedRoot: stageV1}, environment.verify, environment.drain); err != nil {
		t.Fatal(err)
	}
	stageV2 := environment.stage(t, "v2")
	writeTestTree(t, stageV2, "v2")
	if _, err := environment.installer.install(ctx, InstallOptions{Destination: environment.destination, StagedRoot: stageV2, ExpectedCurrentRelease: "v1"}, environment.verify, environment.drain); err != nil {
		t.Fatal(err)
	}
	stageV3 := environment.stage(t, "v3")
	writeTestTree(t, stageV3, "v3")
	result, err := environment.installer.install(ctx, InstallOptions{Destination: environment.destination, StagedRoot: stageV3, ExpectedCurrentRelease: "v2"}, environment.verify, environment.drain)
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentRelease != "v3" || readReleaseID(t, environment.previous(t)) != "v2" || result.ArchivedRelease != "v1" || result.ArchivedPath == "" || readReleaseID(t, result.ArchivedPath) != "v1" {
		t.Fatalf("older rollback tree was not preserved: %#v", result)
	}
	if filepath.Dir(result.ArchivedPath) != environment.parent || !strings.HasPrefix(filepath.Base(result.ArchivedPath), ".control.archive-") {
		t.Fatalf("archive escaped its reserved sibling namespace: %s", result.ArchivedPath)
	}
}

func TestCrashReconciliationAcrossRenamePhases(t *testing.T) {
	t.Run("initial rename", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		crash := errors.New("injected process crash after initial rename")
		environment.installer.afterMutation = func(step string) error {
			if step == stepInitialInstalled {
				return crash
			}
			return nil
		}
		_, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage}, environment.verify, environment.drain)
		if !errors.Is(err, crash) || readReleaseID(t, environment.destination) != "v1" {
			t.Fatalf("initial crash was not injected after rename: %v", err)
		}
		environment.installer.afterMutation = nil
		result, err := environment.installer.reconcile(context.Background(), environment.destination, true, environment.verify, environment.drain)
		if err != nil || !result.Recovered || result.CurrentRelease != "v1" {
			t.Fatalf("initial crash reconciliation failed: result=%#v err=%v", result, err)
		}
	})

	t.Run("upgrade first exchange", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stageV1 := environment.stage(t, "v1")
		writeTestTree(t, stageV1, "v1")
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV1}, environment.verify, environment.drain); err != nil {
			t.Fatal(err)
		}
		stageV2 := environment.stage(t, "v2")
		writeTestTree(t, stageV2, "v2")
		crash := errors.New("injected process crash after exchange")
		environment.installer.afterMutation = func(step string) error {
			if step == stepCurrentExchanged {
				return crash
			}
			return nil
		}
		_, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV2, ExpectedCurrentRelease: "v1"}, environment.verify, environment.drain)
		if !errors.Is(err, crash) || readReleaseID(t, environment.destination) != "v2" || readReleaseID(t, stageV2) != "v1" {
			t.Fatalf("upgrade crash state is wrong: %v", err)
		}
		environment.installer.afterMutation = nil
		if _, err := environment.installer.reconcile(context.Background(), environment.destination, true, environment.verify, environment.drain); err == nil || !strings.Contains(err.Error(), "first-install journal") {
			t.Fatalf("upgrade journal was accepted as initial reconciliation: %v", err)
		}
		if readReleaseID(t, environment.destination) != "v2" || readReleaseID(t, stageV2) != "v1" {
			t.Fatal("rejected initial reconciliation mutated the upgrade paths")
		}
		environment.admitCalls.Store(0)
		environment.verifyCalls.Store(0)
		environment.admittedIDs = nil
		environment.historyIDs = nil
		result, err := environment.installer.reconcile(context.Background(), environment.destination, false, environment.verify, environment.drain)
		if err != nil || !result.Recovered || readReleaseID(t, environment.previous(t)) != "v1" {
			t.Fatalf("upgrade crash reconciliation failed: result=%#v err=%v", result, err)
		}
		if environment.admitCalls.Load() == 0 || environment.admitCalls.Load() >= environment.verifyCalls.Load() {
			t.Fatalf("recovery did not strictly admit only the journaled candidate: verify=%d admit=%d", environment.verifyCalls.Load(), environment.admitCalls.Load())
		}
		for _, releaseID := range environment.admittedIDs {
			if releaseID != "v2" {
				t.Fatalf("historical release %s was subjected to current candidate admission", releaseID)
			}
		}
		if !slices.Contains(environment.historyIDs, "v1") {
			t.Fatalf("historical rollback tree was not signature-verified without admission: %#v", environment.historyIDs)
		}
	})

	t.Run("rotating upgrade second exchange", func(t *testing.T) {
		environment := newTestEnvironment(t)
		for index, releaseID := range []string{"v1", "v2"} {
			stage := environment.stage(t, releaseID)
			writeTestTree(t, stage, releaseID)
			expected := ""
			if index > 0 {
				expected = "v1"
			}
			if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage, ExpectedCurrentRelease: expected}, environment.verify, environment.drain); err != nil {
				t.Fatal(err)
			}
		}
		stageV3 := environment.stage(t, "v3")
		writeTestTree(t, stageV3, "v3")
		crash := errors.New("injected crash after previous exchange")
		environment.installer.afterMutation = func(step string) error {
			if step == stepPreviousExchanged {
				return crash
			}
			return nil
		}
		_, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV3, ExpectedCurrentRelease: "v2"}, environment.verify, environment.drain)
		if !errors.Is(err, crash) || readReleaseID(t, environment.destination) != "v3" || readReleaseID(t, environment.previous(t)) != "v2" || readReleaseID(t, stageV3) != "v1" {
			t.Fatalf("rotating upgrade crash state is wrong: %v", err)
		}
		environment.installer.afterMutation = nil
		result, err := environment.installer.reconcile(context.Background(), environment.destination, false, environment.verify, environment.drain)
		if err != nil || !result.Recovered || result.ArchivedRelease != "v1" || readReleaseID(t, result.ArchivedPath) != "v1" {
			t.Fatalf("rotating upgrade crash reconciliation failed: result=%#v err=%v", result, err)
		}
	})

	t.Run("rollback exchange", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stageV1 := environment.stage(t, "v1")
		writeTestTree(t, stageV1, "v1")
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV1}, environment.verify, environment.drain); err != nil {
			t.Fatal(err)
		}
		stageV2 := environment.stage(t, "v2")
		writeTestTree(t, stageV2, "v2")
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV2, ExpectedCurrentRelease: "v1"}, environment.verify, environment.drain); err != nil {
			t.Fatal(err)
		}
		crash := errors.New("injected crash after rollback exchange")
		environment.installer.afterMutation = func(step string) error {
			if step == stepRollbackExchanged {
				return crash
			}
			return nil
		}
		_, err := environment.installer.rollback(context.Background(), RollbackOptions{Destination: environment.destination, ExpectedCurrentRelease: "v2", ExpectedPreviousRelease: "v1"}, environment.verify, environment.drain)
		if !errors.Is(err, crash) || readReleaseID(t, environment.destination) != "v1" || readReleaseID(t, environment.previous(t)) != "v2" {
			t.Fatalf("rollback crash state is wrong: %v", err)
		}
		environment.installer.afterMutation = nil
		result, err := environment.installer.reconcile(context.Background(), environment.destination, false, environment.verify, environment.drain)
		if err != nil || !result.Recovered || result.CurrentRelease != "v1" || result.PreviousRelease != "v2" {
			t.Fatalf("rollback crash reconciliation failed: result=%#v err=%v", result, err)
		}
	})
}

func TestUnsafePathsTreesJournalAndStaleCASFailClosed(t *testing.T) {
	t.Run("production path helpers", func(t *testing.T) {
		controlStage, err := StagePath(ControlPath, "release_2026-07-27")
		if err != nil || controlStage != "/opt/workagent/.control.stage-release_2026-07-27" {
			t.Fatalf("unexpected control stage path: %q %v", controlStage, err)
		}
		sharedPrevious, err := PreviousPath(SharedPath)
		if err != nil || sharedPrevious != "/opt/workagent/.shared.previous" {
			t.Fatalf("unexpected shared previous path: %q %v", sharedPrevious, err)
		}
		if _, err := StagePath("/opt/workagent/other", "release"); err == nil {
			t.Fatal("production helper accepted a non-allowlisted destination")
		}
	})

	t.Run("destination allowlist", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		_, err := environment.installer.install(context.Background(), InstallOptions{Destination: filepath.Join(environment.parent, "other"), StagedRoot: stage}, environment.verify, environment.drain)
		if err == nil {
			t.Fatal("non-allowlisted fixed-root destination was accepted")
		}
		if environment.drainCalls.Load() != 0 {
			t.Fatal("invalid destination reached the drain callback")
		}
	})

	t.Run("stage alias and symlink", func(t *testing.T) {
		environment := newTestEnvironment(t)
		valid := environment.stage(t, "real")
		writeTestTree(t, valid, "real")
		for _, alias := range []string{environment.destination, filepath.Join(environment.parent, ".control.previous"), filepath.Join(environment.parent, "stage")} {
			if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: alias}, environment.verify, environment.drain); err == nil {
				t.Fatalf("unsafe stage alias was accepted: %s", alias)
			}
		}
		symlink := environment.stage(t, "link")
		if err := os.Symlink(valid, symlink); err != nil {
			t.Fatal(err)
		}
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: symlink}, environment.verify, environment.drain); err == nil {
			t.Fatal("symlinked fixed-root stage was accepted")
		}
		mismatched := environment.stage(t, "declared")
		writeTestTree(t, mismatched, "signed")
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: mismatched}, environment.verify, environment.drain); err == nil {
			t.Fatal("stage name that disagrees with its signed release ID was accepted")
		}
	})

	t.Run("unsafe modes and hardlinks", func(t *testing.T) {
		environment := newTestEnvironment(t)
		unsafeMode := environment.stage(t, "mode")
		writeTestTree(t, unsafeMode, "mode")
		if err := os.Chmod(filepath.Join(unsafeMode, "release-id"), 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: unsafeMode}, environment.verify, environment.drain); err == nil {
			t.Fatal("writable release file was accepted")
		}

		hardlink := environment.stage(t, "hardlink")
		writeTestTree(t, hardlink, "hardlink")
		if err := os.Link(filepath.Join(hardlink, "release-id"), filepath.Join(hardlink, "duplicate")); err != nil {
			t.Fatal(err)
		}
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: hardlink}, environment.verify, environment.drain); err == nil {
			t.Fatal("multiply linked release file was accepted")
		}

		unsafeRoot := environment.stage(t, "rootmode")
		writeTestTree(t, unsafeRoot, "rootmode")
		if err := os.Chmod(unsafeRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: unsafeRoot}, environment.verify, environment.drain); err == nil {
			t.Fatal("noncanonical release-root mode was accepted")
		}

		nestedSymlink := environment.stage(t, "nestedlink")
		writeTestTree(t, nestedSymlink, "nestedlink")
		bin := filepath.Join(nestedSymlink, "bin")
		if err := os.Chmod(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("app", filepath.Join(bin, "alias")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(bin, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: nestedSymlink}, environment.verify, environment.drain); err == nil {
			t.Fatal("nested release symlink was accepted")
		}
	})

	t.Run("stale compare and swap", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stageV1 := environment.stage(t, "v1")
		writeTestTree(t, stageV1, "v1")
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV1}, environment.verify, environment.drain); err != nil {
			t.Fatal(err)
		}
		stageV2 := environment.stage(t, "v2")
		writeTestTree(t, stageV2, "v2")
		v1Inode := inodeOf(t, environment.destination)
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stageV2, ExpectedCurrentRelease: "stale"}, environment.verify, environment.drain); err == nil {
			t.Fatal("stale current release expectation was accepted")
		}
		if inodeOf(t, environment.destination) != v1Inode || readReleaseID(t, environment.destination) != "v1" || readReleaseID(t, stageV2) != "v2" {
			t.Fatal("stale CAS request mutated a fixed-root path")
		}
	})

	t.Run("journal protection", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		crash := errors.New("injected crash")
		environment.installer.afterMutation = func(string) error { return crash }
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage}, environment.verify, environment.drain); !errors.Is(err, crash) {
			t.Fatalf("could not prepare interrupted journal: %v", err)
		}
		if err := os.Chmod(environment.journal(t), 0o644); err != nil {
			t.Fatal(err)
		}
		environment.installer.afterMutation = nil
		if _, err := environment.installer.reconcile(context.Background(), environment.destination, false, environment.verify, environment.drain); err == nil {
			t.Fatal("unprotected journal was accepted")
		}
	})

	t.Run("journal inode CAS", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		crash := errors.New("injected crash")
		environment.installer.afterMutation = func(string) error { return crash }
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage}, environment.verify, environment.drain); !errors.Is(err, crash) {
			t.Fatalf("could not prepare interrupted journal: %v", err)
		}
		moved := filepath.Join(environment.parent, ".untracked-replaced-current")
		if err := os.Rename(environment.destination, moved); err != nil {
			t.Fatal(err)
		}
		writeTestTree(t, environment.destination, "v1")
		environment.installer.afterMutation = nil
		if _, err := environment.installer.reconcile(context.Background(), environment.destination, false, environment.verify, environment.drain); err == nil {
			t.Fatal("same-release replacement inode was accepted during reconciliation")
		}
		if readReleaseID(t, environment.destination) != "v1" || readReleaseID(t, moved) != "v1" {
			t.Fatal("inode-CAS rejection changed either tree")
		}
	})
}

func TestRootDrainAndSignatureRequirementsFailBeforeMutation(t *testing.T) {
	t.Run("effective UID", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		environment.installer.effectiveUID = func() int { return 1000 }
		if _, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage}, environment.verify, environment.drain); err == nil {
			t.Fatal("non-root fixed-root install was accepted")
		}
		if environment.held.Load() || environment.drainCalls.Load() != 0 {
			t.Fatal("non-root request acquired lifecycle resources")
		}
	})

	t.Run("drain proof", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		drainFailure := errors.New("consumers still active")
		_, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage}, environment.verify, func(context.Context, string) error { return drainFailure })
		if !errors.Is(err, drainFailure) {
			t.Fatalf("drain failure was not returned: %v", err)
		}
		if _, statErr := os.Lstat(environment.destination); !errors.Is(statErr, os.ErrNotExist) || readReleaseID(t, stage) != "v1" || environment.held.Load() {
			t.Fatalf("drain failure mutated paths or leaked lock: stat=%v held=%v", statErr, environment.held.Load())
		}
	})

	t.Run("signature revalidation", func(t *testing.T) {
		environment := newTestEnvironment(t)
		stage := environment.stage(t, "v1")
		writeTestTree(t, stage, "v1")
		verifyFailure := errors.New("signature rejected")
		_, err := environment.installer.install(context.Background(), InstallOptions{Destination: environment.destination, StagedRoot: stage}, func(context.Context, string, bool) (string, error) {
			if !environment.held.Load() || !environment.drained.Load() {
				t.Fatal("failed verifier was not lifecycle locked after drain")
			}
			return "", verifyFailure
		}, environment.drain)
		if !errors.Is(err, verifyFailure) {
			t.Fatalf("signature failure was not returned: %v", err)
		}
		if _, statErr := os.Lstat(environment.destination); !errors.Is(statErr, os.ErrNotExist) || readReleaseID(t, stage) != "v1" || environment.held.Load() {
			t.Fatalf("signature failure mutated paths or leaked lock: stat=%v held=%v", statErr, environment.held.Load())
		}
	})
}
