package backup

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestCreateCannotBypassProductionRemoteEnvironmentProof(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(root, "local")
	offHost := filepath.Join(root, "off-host")
	metrics := filepath.Join(root, "metrics", "backup.prom")
	keyPath := filepath.Join(root, "backup.key")
	for _, directory := range []string{local, offHost, filepath.Dir(metrics)} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keyPath, make([]byte, keySize), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := Config{
		SchemaVersion: ConfigSchemaVersion, LocalDirectory: local, OffHostDirectory: offHost,
		RequireRemoteFilesystem: true, EncryptionKey: keyPath, MetricsFile: metrics, RetentionCount: 2,
	}
	snapshot := &Snapshot{
		PortalConfig: "/etc/workagent/portal.json",
		locks:        []io.Closer{io.NopCloser(strings.NewReader("locked"))},
	}
	_, err := Create(snapshot, configuration, make([]byte, keySize), time.Unix(1_800_000_000, 0).UTC())
	if err == nil || !strings.Contains(err.Error(), "verify backup environment at creation boundary") {
		t.Fatalf("Create bypassed production remote-filesystem proof: %v", err)
	}
}

func TestMountForPathSelectsLongestRemoteMount(t *testing.T) {
	fixture := `24 1 8:1 / / rw,relatime - xfs /dev/sda1 rw
25 24 0:42 / /mnt/workagent-backup rw,relatime - nfs4 backup.example:/exports/workagent rw
26 25 0:43 / /mnt/workagent-backup/special rw,relatime - fuse.rclone remote:bucket rw`
	filesystem, source, ok := mountForPath(fixture, "/mnt/workagent-backup/special/off-host")
	if !ok || filesystem != "fuse.rclone" || source != "remote:bucket" {
		t.Fatalf("filesystem=%q source=%q ok=%v", filesystem, source, ok)
	}
}

func TestBackupDirectoryGuardPinsIdentityAndRejectsPathReplacement(t *testing.T) {
	root := t.TempDir()
	guardedPath := filepath.Join(root, "off-host")
	if err := os.Mkdir(guardedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guardedPath, "marker"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := openBackupDirectoryGuard(guardedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.verifyCurrent(); err != nil {
		t.Fatalf("stable directory was rejected: %v", err)
	}

	detachedPath := filepath.Join(root, "detached")
	if err := os.Rename(guardedPath, detachedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(guardedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := guard.verifyCurrent(); err == nil || !strings.Contains(err.Error(), "changed during backup") {
		t.Fatalf("replacement directory was accepted: %v", err)
	}
	pinnedMarker, err := guard.pinnedPath("marker")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(pinnedMarker)
	if err != nil || string(payload) != "original" {
		t.Fatalf("guard did not retain the original directory: %q err=%v", payload, err)
	}
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("pinned-copy"), 0o400); err != nil {
		t.Fatal(err)
	}
	pinnedCopy, err := guard.pinnedPath("copy.wab")
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFileAtomic(source, pinnedCopy, "", 0o400); err != nil {
		t.Fatalf("copy through pinned directory: %v", err)
	}
	if payload, err := os.ReadFile(filepath.Join(detachedPath, "copy.wab")); err != nil || string(payload) != "pinned-copy" {
		t.Fatalf("copy did not stay on pinned directory: %q err=%v", payload, err)
	}
	if _, err := os.Lstat(filepath.Join(guardedPath, "copy.wab")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copy escaped to replacement path: %v", err)
	}
}

func TestRetentionAlwaysPreservesNewBackupAcrossClockRollback(t *testing.T) {
	directory := t.TempDir()
	names := []string{
		"workagent-20300101T000000Z-11111111-1111-4111-8111-111111111111.wab",
		"workagent-20290101T000000Z-22222222-2222-4222-8222-222222222222.wab",
		"workagent-20200101T000000Z-33333333-3333-4333-8333-333333333333.wab",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name+".receipt.json"), []byte("{}"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	newBackup := names[2]
	if err := enforceRetention(directory, 2, newBackup); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{names[0], newBackup} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("retention removed protected set member %s: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(directory, names[1])); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retention kept the wrong unprotected backup: %v", err)
	}
}

func TestRetentionFailsWhenProtectedBackupIsMissing(t *testing.T) {
	directory := t.TempDir()
	missing := "workagent-20200101T000000Z-33333333-3333-4333-8333-333333333333.wab"
	if err := enforceRetention(directory, 2, missing); err == nil || !strings.Contains(err.Error(), "missing before retention") {
		t.Fatalf("retention accepted a missing new backup: %v", err)
	}
}

func TestRetentionFailsClosedOnIncompleteOrUnsafeBackupPairs(t *testing.T) {
	newBackup := "workagent-20200101T000000Z-33333333-3333-4333-8333-333333333333.wab"
	writePair := func(t *testing.T, directory, name string) {
		t.Helper()
		for _, path := range []string{name, name + ".receipt.json"} {
			if err := os.WriteFile(filepath.Join(directory, path), []byte(path), 0o400); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("orphan archive", func(t *testing.T) {
		directory := t.TempDir()
		writePair(t, directory, newBackup)
		orphan := "workagent-20210101T000000Z-44444444-4444-4444-8444-444444444444.wab"
		if err := os.WriteFile(filepath.Join(directory, orphan), []byte("orphan"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := enforceRetention(directory, 2, newBackup); err == nil || !strings.Contains(err.Error(), "incomplete backup pair") {
			t.Fatalf("retention accepted an orphan archive: %v", err)
		}
	})

	t.Run("orphan receipt", func(t *testing.T) {
		directory := t.TempDir()
		writePair(t, directory, newBackup)
		orphan := "workagent-20210101T000000Z-44444444-4444-4444-8444-444444444444.wab.receipt.json"
		if err := os.WriteFile(filepath.Join(directory, orphan), []byte("orphan"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := enforceRetention(directory, 2, newBackup); err == nil || !strings.Contains(err.Error(), "incomplete backup pair") {
			t.Fatalf("retention accepted an orphan receipt: %v", err)
		}
	})

	t.Run("symlink archive", func(t *testing.T) {
		directory := t.TempDir()
		writePair(t, directory, newBackup)
		unsafe := "workagent-20210101T000000Z-44444444-4444-4444-8444-444444444444.wab"
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("target"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, unsafe)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, unsafe+".receipt.json"), []byte("{}"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := enforceRetention(directory, 2, newBackup); err == nil || !strings.Contains(err.Error(), "unsafe backup entry") {
			t.Fatalf("retention accepted a symlink archive: %v", err)
		}
	})

	t.Run("hard-linked receipt", func(t *testing.T) {
		directory := t.TempDir()
		writePair(t, directory, newBackup)
		if err := os.Link(filepath.Join(directory, newBackup+".receipt.json"), filepath.Join(directory, "receipt-alias")); err != nil {
			t.Fatal(err)
		}
		if err := enforceRetention(directory, 2, newBackup); err == nil || !strings.Contains(err.Error(), "unsafe backup entry") {
			t.Fatalf("retention accepted a hard-linked receipt: %v", err)
		}
	})
}

func TestRenameNoReplaceNeverOverwritesConcurrentState(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(source, destination); err == nil {
		t.Fatal("no-replace publication overwrote existing state")
	}
	payload, err := os.ReadFile(destination)
	if err != nil || string(payload) != "existing" {
		t.Fatalf("existing destination changed: %q err=%v", payload, err)
	}
	if payload, err := os.ReadFile(source); err != nil || string(payload) != "new" {
		t.Fatalf("unpublished source changed: %q err=%v", payload, err)
	}
}

func TestCanonicalReleasePointerSourcesDeduplicatesSharedChannel(t *testing.T) {
	shared := "/opt/workagent/runtime/current.json"
	tenants := []config.Tenant{
		{TenantID: "11111111-1111-4111-8111-111111111111", Release: config.TenantRelease{PointerFile: shared}},
		{TenantID: "22222222-2222-4222-8222-222222222222", Release: config.TenantRelease{PointerFile: shared}},
		{TenantID: "33333333-3333-4333-8333-333333333333", Release: config.TenantRelease{PointerFile: "/opt/workagent/other/current.json"}},
	}
	actual := canonicalReleasePointerSources(tenants)
	if len(actual) != 2 || actual[shared] != "release-pointer-11111111-1111-4111-8111-111111111111" {
		t.Fatalf("shared release pointer source was not canonical: %v", actual)
	}
}

func TestReleasePointerSnapshotLockExcludesActivation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production release-lock ownership requires root")
	}
	channel := filepath.Join(t.TempDir(), "channel")
	if err := os.Mkdir(channel, 0o755); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(channel, "current.json")
	lockPath := pointer + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := acquireReleasePointerSnapshotLock(pointer)
	if err != nil {
		t.Fatal(err)
	}
	activationFD, err := unix.Open(lockPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		held.Close()
		t.Fatal(err)
	}
	if err := unix.Flock(activationFD, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		held.Close()
		unix.Close(activationFD)
		t.Fatalf("activation lock was not excluded by snapshot lock: %v", err)
	}
	if err := held.Close(); err != nil {
		unix.Close(activationFD)
		t.Fatal(err)
	}
	if err := unix.Flock(activationFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(activationFD)
		t.Fatalf("activation lock remained blocked after snapshot close: %v", err)
	}
	if err := unix.Close(activationFD); err != nil {
		t.Fatal(err)
	}
}

func TestCopyRecoveredPathIsResumableButNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "state.db"), []byte("verified state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoveredPath(source, destination); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoveredPath(source, destination); err != nil {
		t.Fatalf("matching partial recovery was not resumable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(destination, "state.db"), []byte("foreign state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoveredPath(source, destination); err == nil {
		t.Fatal("recovery overwrote conflicting destination state")
	}
}
