package storageusage

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestMeasureTreeCountsRegularFilesWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "first.bin"), make([]byte, 1536), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "workspace"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "workspace", "second.bin"), make([]byte, 2560), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "not-private.bin"), make([]byte, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "external")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "not-private.bin"), filepath.Join(root, "external.bin")); err != nil {
		t.Fatal(err)
	}

	used, err := MeasureTree(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if used != 4096 {
		t.Fatalf("used=%d, want 4096", used)
	}
}

func TestMeasureTreeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MeasureTree(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

func TestMeasureTreeRejectsSymlinkedRootPath(t *testing.T) {
	parent := t.TempDir()
	realParent := t.TempDir()
	if err := os.Mkdir(filepath.Join(realParent, "root"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, filepath.Join(parent, "linked-parent")); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(parent, "linked-parent", "root")
	if _, err := MeasureTree(context.Background(), linkedRoot); err == nil {
		t.Fatal("storage root beneath a symlinked path was accepted")
	}
}

func TestStorageSizeAdditionRejectsOverflow(t *testing.T) {
	used := uint64(math.MaxUint64 - 4)
	if err := addSize(&used, 5); err == nil || used != math.MaxUint64-4 {
		t.Fatalf("overflow result used=%d err=%v", used, err)
	}
}
