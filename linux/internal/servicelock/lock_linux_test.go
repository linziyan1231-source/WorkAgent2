package servicelock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAcquireExclusiveCreatesPrivateLockAndReleases(t *testing.T) {
	root := t.TempDir()
	uid, gid := privateTestIdentity(t, root)
	path := filepath.Join(root, ".runtime.lock")
	first, err := AcquireExclusive(path, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireExclusive(path, uid, gid); err == nil {
		t.Fatal("concurrent exclusive acquisition succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireExclusive(path, uid, gid)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	defer second.Close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("lock identity = mode %v uid %d gid %d", info.Mode(), stat.Uid, stat.Gid)
	}
}

func TestAcquireExclusiveRejectsUnsafeExistingInodes(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "mode", "owner"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			uid, gid := privateTestIdentity(t, root)
			path := filepath.Join(root, ".runtime.lock")
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, int(uid), int(gid)); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "owner":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if uid == uint32(os.Geteuid()) && gid == uint32(os.Getegid()) {
					t.Skip("cannot create a foreign-owned fixture without privilege")
				}
				// Under a root-run fixture the file remains root-owned while the
				// directory is owned by the non-root test tenant.
			}
			if _, err := AcquireExclusive(path, uid, gid); err == nil {
				t.Fatalf("unsafe %s lock was accepted", kind)
			}
		})
	}
}

func TestExclusiveBackupLockRequiresQuiescence(t *testing.T) {
	root := t.TempDir()
	stat := mustStat(t, root)
	path := filepath.Join(root, ".runtime.lock")
	shared, err := AcquireShared(path, stat.Uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireExclusiveExisting(path, stat.Uid); err == nil {
		t.Fatal("exclusive backup lock succeeded while the service was active")
	}
	if err := shared.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := AcquireExclusiveExisting(path, stat.Uid)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive.Close()
}

func TestLockRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	stat := mustStat(t, root)
	if err := os.WriteFile(filepath.Join(root, "target"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".runtime.lock")
	if err := os.Symlink("target", path); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireShared(path, stat.Uid); err == nil {
		t.Fatal("symbolic-link lock was accepted")
	}
}

func mustStat(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat metadata unavailable")
	}
	return stat
}

func privateTestIdentity(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		uid, gid = 65534, 65534
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return uid, gid
}
