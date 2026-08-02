package admin

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProtectedPortalFileRejectsWritableAndSymlinkedInputs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "portal.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := verifyRuntimeReadableFile(path, 1024, stat.Uid, stat.Gid, true); err != nil {
		t.Fatalf("protected private file rejected: %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeReadableFile(path, 1024, stat.Uid, stat.Gid, true); err == nil {
		t.Fatal("group-writable Portal configuration was accepted")
	}
	link := filepath.Join(root, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeReadableFile(link, 1024, stat.Uid, stat.Gid, false); err == nil {
		t.Fatal("symlinked Portal product file was accepted")
	}
}

func TestPortalDirectoryMustBeProtectedAndTraversable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if err := verifyRuntimeTraversableDirectory(root, stat.Uid, stat.Gid); err != nil {
		t.Fatalf("protected directory rejected: %v", err)
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeTraversableDirectory(root, stat.Uid, stat.Gid); err == nil {
		t.Fatal("group-writable Portal directory was accepted")
	}
}
