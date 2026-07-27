//go:build linux

package stagepublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPrepareTenantTemporaryAdoptsOnlyEmptyJournalResidue(t *testing.T) {
	parentPath := t.TempDir()
	if err := os.Chmod(parentPath, 0o711); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	uid, gid := publicationTestIdentity(t)
	item := journalTenant{TenantID: "11111111-1111-4111-8111-111111111111", Temporary: ".tenant.import-test.partial", UID: uid, GID: gid}
	residue := filepath.Join(parentPath, item.Temporary)
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	path, created, err := prepareTenantTemporary(parent, item)
	if err != nil || !created || path != residue {
		t.Fatalf("adopt empty residue: path=%q created=%v err=%v", path, created, err)
	}
	assertIdentity(t, residue, uid, gid, 0o700)

	conflict := item
	conflict.Temporary = ".tenant.import-conflict.partial"
	conflictPath := filepath.Join(parentPath, conflict.Temporary)
	if err := os.Mkdir(conflictPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conflictPath, "foreign"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareTenantTemporary(parent, conflict); err == nil {
		t.Fatal("non-empty root-owned residue was adopted")
	}
}

func TestCopyDirectoryContentsResumesPrivateFilesAndRejectsEscapingLinks(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "source")
	destinationPath := filepath.Join(t.TempDir(), "destination")
	for _, path := range []string{sourcePath, destinationPath, filepath.Join(sourcePath, "nested")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "payload.txt"), []byte("complete-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "nested", "tool"), []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload.txt", filepath.Join(sourcePath, "alias")); err != nil {
		t.Fatal(err)
	}
	uid, gid := publicationTestIdentity(t)
	if err := os.Chown(destinationPath, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destinationPath, "payload.txt"), []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := openDirectoryFD(t, sourcePath)
	defer unix.Close(source)
	destination := openDirectoryFD(t, destinationPath)
	defer unix.Close(destination)
	if err := copyDirectoryContents(context.Background(), source, destination, uid, gid, "", false); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(destinationPath, "payload.txt"))
	if err != nil || string(payload) != "complete-payload" {
		t.Fatalf("resumed payload=%q err=%v", payload, err)
	}
	assertIdentity(t, filepath.Join(destinationPath, "payload.txt"), uid, gid, 0o600)
	assertIdentity(t, filepath.Join(destinationPath, "nested", "tool"), uid, gid, 0o700)
	linkInfo, err := os.Lstat(filepath.Join(destinationPath, "alias"))
	linkStat, ok := fileStat(linkInfo)
	if err != nil || !ok || linkInfo.Mode()&os.ModeSymlink == 0 || linkStat.Uid != uid || linkStat.Gid != gid {
		t.Fatalf("copied link identity invalid: info=%v err=%v", linkInfo, err)
	}

	escapeSourcePath := filepath.Join(t.TempDir(), "escape-source")
	escapeDestinationPath := filepath.Join(t.TempDir(), "escape-destination")
	if err := os.Mkdir(escapeSourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(escapeDestinationPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(escapeDestinationPath, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../outside", filepath.Join(escapeSourcePath, "escape")); err != nil {
		t.Fatal(err)
	}
	escapeSource := openDirectoryFD(t, escapeSourcePath)
	defer unix.Close(escapeSource)
	escapeDestination := openDirectoryFD(t, escapeDestinationPath)
	defer unix.Close(escapeDestination)
	if err := copyDirectoryContents(context.Background(), escapeSource, escapeDestination, uid, gid, "", false); err == nil {
		t.Fatal("escaping symlink was copied")
	}
}

func TestCopyPortalDatabaseResumesAndDetectsSourceSwap(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "stage")
	portalSourceRoot := filepath.Join(stage, "portal")
	if err := os.MkdirAll(portalSourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("verified-portal-database-payload")
	sourcePath := filepath.Join(portalSourceRoot, "portal.db")
	if err := os.WriteFile(sourcePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	expected := hex.EncodeToString(digest[:])
	destinationRoot := t.TempDir()
	destination, err := os.Open(destinationRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	uid, gid := publicationTestIdentity(t)
	partial := ".portal.db.partial"
	if err := os.WriteFile(filepath.Join(destinationRoot, partial), original[:9], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyPortalDatabase(stage, destination, partial, uid, gid, expected); err != nil {
		t.Fatal(err)
	}
	if err := verifyPortalPartial(stage, destination, partial, uid, gid, expected); err != nil {
		t.Fatalf("completed resumable Portal file failed read-only verification: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destinationRoot, partial))
	if err != nil || string(got) != string(original) {
		t.Fatalf("resumed Portal payload=%q err=%v", got, err)
	}
	assertIdentity(t, filepath.Join(destinationRoot, partial), uid, gid, 0o600)

	swapTemporary := ".portal.db.swap.partial"
	replacement := append([]byte(nil), original...)
	replacement[0] ^= 0x20
	err = copyPortalDatabaseWithHook(stage, destination, swapTemporary, uid, gid, expected, func() error {
		replacementPath := filepath.Join(portalSourceRoot, "replacement")
		if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
			return err
		}
		return os.Rename(replacementPath, sourcePath)
	})
	if err == nil {
		t.Fatal("same-size source replacement during Portal copy was accepted")
	}
	if err := os.WriteFile(sourcePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	mtimeTemporary := ".portal.db.mtime.partial"
	err = copyPortalDatabaseWithHook(stage, destination, mtimeTemporary, uid, gid, expected, func() error {
		changed := time.Now().Add(2 * time.Hour)
		return os.Chtimes(sourcePath, changed, changed)
	})
	if err == nil {
		t.Fatal("source mtime change during Portal copy was accepted")
	}
	conflictTemporary := ".portal.db.conflict.partial"
	if err := os.WriteFile(filepath.Join(destinationRoot, conflictTemporary), []byte("not-a-prefix"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyPortalPartial(stage, destination, conflictTemporary, uid, gid, expected); err == nil {
		t.Fatal("conflicting Portal partial passed the read-only resume check")
	}
}

func TestPublishNoReplaceNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "temporary"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "final"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := publishNoReplace(parent, "temporary", "final"); err == nil {
		t.Fatal("publication overwrote an existing target")
	}
	payload, err := os.ReadFile(filepath.Join(root, "final"))
	if err != nil || string(payload) != "old" {
		t.Fatalf("existing target changed: %q %v", payload, err)
	}
}

func publicationTestIdentity(t *testing.T) (uint32, uint32) {
	t.Helper()
	if os.Geteuid() == 0 {
		return 65534, 65534
	}
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

func openDirectoryFD(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func assertIdentity(t *testing.T, path string, uid, gid uint32, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != mode.Perm() {
		t.Fatalf("identity for %s: uid=%d gid=%d mode=%o", path, stat.Uid, stat.Gid, info.Mode().Perm())
	}
}
