package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
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
		catalogGuard: io.NopCloser(strings.NewReader("catalog-locked")),
		locks:        []io.Closer{io.NopCloser(strings.NewReader("catalog-locked"))},
	}
	_, err := Create(snapshot, configuration, make([]byte, keySize), time.Unix(1_800_000_000, 0).UTC())
	if err == nil || !strings.Contains(err.Error(), "verify backup environment at creation boundary") {
		t.Fatalf("Create bypassed production remote-filesystem proof: %v", err)
	}
}

func TestSnapshotCatalogGuardExcludesWritersAndMixedGenerations(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned catalog lock fixture requires root")
	}
	root := t.TempDir()
	lockPath := filepath.Join(root, "release-config.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(root, "identity")
	configPath := filepath.Join(root, "config")
	for _, path := range []string{identityPath, configPath} {
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	acquireShared := func(ctx context.Context) (io.Closer, error) {
		if ctx == nil {
			return nil, errors.New("missing context")
		}
		fd, err := unix.Open(lockPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		if err := unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		return os.NewFile(uintptr(fd), lockPath), nil
	}
	readGeneration := func() (string, string) {
		t.Helper()
		identity, identityErr := os.ReadFile(identityPath)
		configPayload, configErr := os.ReadFile(configPath)
		if identityErr != nil || configErr != nil {
			t.Fatalf("read generation: identity=%v config=%v", identityErr, configErr)
		}
		return string(identity), string(configPayload)
	}

	snapshot, err := beginCatalogLockedSnapshot(context.Background(), "/etc/workagent/portal.json", acquireShared)
	if err != nil {
		t.Fatal(err)
	}
	writerFD, err := unix.Open(lockPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(writerFD)
	if err := unix.Flock(writerFD, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("tenant writer was not blocked for snapshot lifetime: %v", err)
	}
	if identity, configPayload := readGeneration(); identity != "old\n" || configPayload != "old\n" {
		t.Fatalf("catalog snapshot did not observe one old generation: identity=%q config=%q", identity, configPayload)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}

	if err := unix.Flock(writerFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("tenant writer remained blocked after snapshot close: %v", err)
	}
	if err := os.WriteFile(identityPath, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := beginCatalogLockedSnapshot(context.Background(), "/etc/workagent/portal.json", acquireShared); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("backup admitted a mixed generation while the tenant writer held C_EX: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(writerFD, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	committed, err := beginCatalogLockedSnapshot(context.Background(), "/etc/workagent/portal.json", acquireShared)
	if err != nil {
		t.Fatal(err)
	}
	defer committed.Close()
	if identity, configPayload := readGeneration(); identity != "new\n" || configPayload != "new\n" {
		t.Fatalf("catalog snapshot did not observe one new generation: identity=%q config=%q", identity, configPayload)
	}
}

func TestBeginCatalogLockedSnapshotRejectsNilGuard(t *testing.T) {
	snapshot, err := beginCatalogLockedSnapshot(context.Background(), "/etc/workagent/portal.json", func(context.Context) (io.Closer, error) {
		return nil, nil
	})
	if err == nil || snapshot != nil || !strings.Contains(err.Error(), "no guard") {
		t.Fatalf("nil catalog guard was accepted: snapshot=%v err=%v", snapshot, err)
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
	if os.Geteuid() != 0 {
		t.Skip("production backup directory identity requires root")
	}
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
	if os.Geteuid() != 0 {
		t.Skip("production backup retention ownership requires root")
	}
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

func TestActivationBackupManifestRequiresExactRecoveryContract(t *testing.T) {
	pointer := ReleasePointer{Path: "/opt/workagent/aionui/current.json", Scope: release.ScopeRuntime, Current: "release-one", Activated: "2027-01-15T08:00:00Z"}
	contract := CreateInput{
		PortalConfig: "/etc/workagent/portal.json",
		Sources: []Source{
			{Name: "configuration", Path: "/etc/workagent"},
			{Name: "portal-state", Path: "/var/lib/workagent/portal"},
		},
		ReleasePointers: []ReleasePointer{pointer},
	}
	manifest := Manifest{
		PortalConfig:    contract.PortalConfig,
		Sources:         append([]Source(nil), contract.Sources...),
		ReleasePointers: []ReleasePointer{pointer},
		Entries: []Entry{
			{Path: "rootfs/etc/workagent", Type: "directory"},
			{Path: "rootfs/var/lib/workagent/portal", Type: "directory"},
		},
	}
	if err := ValidateActivationBackupManifest(manifest, contract); err != nil {
		t.Fatalf("complete activation backup contract was rejected: %v", err)
	}
	partial := manifest
	partial.Sources = []Source{{Name: "dummy", Path: "/var/lib/dummy"}}
	partial.Entries = []Entry{{Path: "rootfs/var/lib/dummy", Type: "directory"}}
	if err := ValidateActivationBackupManifest(partial, contract); err == nil {
		t.Fatal("authenticated but partial backup source set was accepted for activation")
	}
	missingRoot := manifest
	missingRoot.Entries = missingRoot.Entries[:1]
	if err := ValidateActivationBackupManifest(missingRoot, contract); err == nil {
		t.Fatal("backup manifest that omitted a required source root was accepted")
	}
	extra := manifest
	extra.Sources = append(extra.Sources, Source{Name: "dummy", Path: "/var/lib/dummy"})
	if err := ValidateActivationBackupManifest(extra, contract); err == nil {
		t.Fatal("backup manifest with an unapproved extra source was accepted")
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
	if os.Geteuid() != 0 {
		t.Skip("recovered production path ownership requires root")
	}
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

func TestCopyRecoveredPathExcludingLeavesTenantCatalogForBatchPublisher(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("recovered production path ownership requires root")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	for _, path := range []string{source, destination, filepath.Join(source, "users"), filepath.Join(destination, "users")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "portal.json"), []byte("authenticated portal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "users", "archived.json"), []byte("must not be copied raw"), 0o600); err != nil {
		t.Fatal(err)
	}
	preserved := filepath.Join(destination, "users", ".workagent-tenant-batch.transaction.json")
	if err := os.WriteFile(preserved, []byte("publisher-owned state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoveredPathExcluding(source, destination, map[string]bool{filepath.Join(destination, "users"): true}); err != nil {
		t.Fatal(err)
	}
	if payload, err := os.ReadFile(preserved); err != nil || string(payload) != "publisher-owned state" {
		t.Fatalf("excluded tenant catalog changed: payload=%q err=%v", payload, err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "users", "archived.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw tenant config was copied: %v", err)
	}
	if payload, err := os.ReadFile(filepath.Join(destination, "portal.json")); err != nil || string(payload) != "authenticated portal" {
		t.Fatalf("ordinary configuration was not copied: payload=%q err=%v", payload, err)
	}
	if err := os.WriteFile(filepath.Join(destination, "foreign"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRecoveredPathExcluding(source, destination, map[string]bool{filepath.Join(destination, "users"): true}); err == nil {
		t.Fatal("exclusion hid an unexpected destination entry")
	}
}
