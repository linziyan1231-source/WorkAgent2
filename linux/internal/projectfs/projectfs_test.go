package projectfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWriteFileAtomicOwnedIsPrivateAndIdempotent(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		uid, gid = 65534, 65534
	}
	for _, payload := range [][]byte{[]byte("first"), []byte("second")} {
		if err := root.WriteFileAtomicOwned("credentials/pending.json", payload, 0o600, uid, gid); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(rootPath, "credentials", "pending.json"))
		if err != nil || string(got) != string(payload) {
			t.Fatalf("activated payload = %q, err = %v", got, err)
		}
	}
	info, err := os.Lstat(filepath.Join(rootPath, "credentials", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != 0o600 {
		t.Fatalf("private file identity = uid %d gid %d mode %o", stat.Uid, stat.Gid, info.Mode().Perm())
	}
}

func TestWriteFileAtomicOwnedRejectsUnsafeConflicts(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFileAtomicOwned("credentials/pending.json", []byte("secret"), 0o600, 0, 1); err == nil {
		t.Fatal("root owner was accepted")
	}
	outside := filepath.Join(rootPath, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootPath, "credentials", "pending.json")); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFileAtomicOwned("credentials/pending.json", []byte("replacement"), 0o600, 65534, 65534); err == nil {
		t.Fatal("symlink destination was accepted")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "outside" {
		t.Fatalf("outside file changed: %q, %v", got, err)
	}
	if err := os.Remove(filepath.Join(rootPath, "credentials", "pending.json")); err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(rootPath, "credentials", "pending.json")
	if err := os.WriteFile(conflict, []byte("preserve"), 0o600); err != nil || os.Chmod(conflict, 0o640) != nil {
		t.Fatal("prepare conflicting private file")
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		uid, gid = 65534, 65534
	}
	if err := root.WriteFileAtomicOwned("credentials/pending.json", []byte("replacement"), 0o600, uid, gid); err == nil {
		t.Fatal("conflicting destination owner/mode was accepted")
	}
	got, err = os.ReadFile(conflict)
	if err != nil || string(got) != "preserve" {
		t.Fatalf("conflicting file changed: %q, %v", got, err)
	}
}

func TestSecureOpenRejectsTraversalAndSymlinks(t *testing.T) {
	base := t.TempDir()
	rootPath := filepath.Join(base, "workspace")
	outsidePath := filepath.Join(base, "outside.txt")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsidePath, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsidePath, filepath.Join(rootPath, "escape")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, candidate := range []string{"../outside.txt", "escape", "./escape", "nested/../escape"} {
		if _, err := root.Open(candidate, unix.O_RDONLY, 0); err == nil {
			t.Fatalf("unsafe path %q was accepted", candidate)
		}
	}
}

func TestProjectDirectoryLifecycle(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.CreateDirectory("route-planning", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.RenameDirectory("route-planning", "dispatch-planning"); err != nil {
		t.Fatal(err)
	}
	entries, err := root.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "dispatch-planning" || !entries[0].IsDir() {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if err := root.CreateDirectory("dispatch-planning", 0o700); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("duplicate directory returned %v", err)
	}
}

func TestOpenRootRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(link); err == nil {
		t.Fatal("symlinked root was accepted")
	}
}

func TestValidName(t *testing.T) {
	for _, value := range []string{"", ".", "..", " leading", "trailing ", "nested/name", "nested\\name", "line\nbreak"} {
		if ValidName(value) {
			t.Fatalf("invalid name %q accepted", value)
		}
	}
	for _, value := range []string{"Route Plan", "项目甲", "dispatch.v2"} {
		if !ValidName(value) {
			t.Fatalf("valid name %q rejected", value)
		}
	}
}

func TestValidProjectNameExcludesHiddenAndRuntimeDirectories(t *testing.T) {
	for _, value := range []string{".hidden", "conversations", "INBOUND", "sessions", "skills", "runtime", "builtin-skills", "aionrs-sessions"} {
		if ValidProjectName(value) {
			t.Fatalf("reserved project name %q was accepted", value)
		}
	}
	for _, value := range []string{"customer-project", "客户项目", "runtime-notes"} {
		if !ValidProjectName(value) {
			t.Fatalf("visible project name %q was rejected", value)
		}
	}
}

func TestEnsureDirectoryAndWriteFileRejectSymlinkTraversal(t *testing.T) {
	rootPath := t.TempDir()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.EnsureDirectory("config/codex", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("config/codex/auth.json", []byte(`{"auth_mode":"apikey"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if payload, err := root.ReadFile("config/codex/auth.json", 1024); err != nil || string(payload) != `{"auth_mode":"apikey"}` {
		t.Fatalf("unexpected private file: %q err=%v", payload, err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(rootPath, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureDirectory("linked/escape", 0o700); err == nil {
		t.Fatal("directory creation followed a symlink")
	}
}

func TestRotateFileUsesBoundedRegularGenerations(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(rootPath, "logs", "backend.log")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 1024*1024); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.RotateFile("logs/backend.log", 1024*1024, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("active oversized log was not rotated: %v", err)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Size() != 1024*1024 {
		t.Fatalf("rotated generation is invalid: info=%v err=%v", info, err)
	}
}
