package admin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEnsureCapacitySlotsCreatesAndVerifiesProtectedLeases(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership verification requires root")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	const groupID = uint32(1)
	if err := ensureCapacitySlotsWithGID(context.Background(), directory, 6, groupID); err != nil {
		t.Fatal(err)
	}
	if err := ensureCapacitySlotsWithGID(context.Background(), directory, 6, groupID); err != nil {
		t.Fatalf("capacity reconciliation is not idempotent: %v", err)
	}
	for index := 1; index <= 6; index++ {
		info, err := os.Lstat(filepath.Join(directory, fmt.Sprintf("slot-%d.lock", index)))
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || stat.Gid != groupID || info.Mode().Perm() != 0o660 {
			t.Fatalf("unsafe capacity slot %d: uid=%d gid=%d mode=%#o", index, stat.Uid, stat.Gid, info.Mode().Perm())
		}
	}
}

func TestEnsureCapacitySlotsRejectsExistingSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership verification requires root")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(directory, "slot-1.lock")); err != nil {
		t.Fatal(err)
	}
	if err := ensureCapacitySlotsWithGID(context.Background(), directory, 1, 1); err == nil {
		t.Fatal("symlinked capacity slot was accepted")
	}
}
