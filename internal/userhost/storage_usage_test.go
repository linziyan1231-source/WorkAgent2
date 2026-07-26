package userhost

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type reparseLikeDirEntry struct {
	infoCalls atomic.Int32
}

func (entry *reparseLikeDirEntry) Name() string      { return "junction" }
func (entry *reparseLikeDirEntry) IsDir() bool       { return true }
func (entry *reparseLikeDirEntry) Type() fs.FileMode { return fs.ModeDir | fs.ModeSymlink }
func (entry *reparseLikeDirEntry) Info() (fs.FileInfo, error) {
	entry.infoCalls.Add(1)
	return nil, fs.ErrPermission
}

func TestMeasureStorageUsageCountsPrivateRegularFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "first.bin"), make([]byte, 1536), 0o600); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(root, "workspace")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "second.bin"), make([]byte, 2560), 0o600); err != nil {
		t.Fatal(err)
	}

	usage, err := measureStorageUsage(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if usage.LimitBytes != userStorageLimitBytes || usage.UsedBytes != 4096 || usage.RemainingBytes != userStorageLimitBytes-4096 {
		t.Fatalf("storage usage=%+v", usage)
	}
	if _, err := time.Parse(time.RFC3339, usage.MeasuredAt); err != nil {
		t.Fatalf("measured_at=%q: %v", usage.MeasuredAt, err)
	}
}

func TestMeasureStorageUsageStopsWhenRequestIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := measureStorageUsage(ctx, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

func TestMeasureStorageUsageSkipsWindowsReparseLikeDirectoryBeforeInfo(t *testing.T) {
	entry := &reparseLikeDirEntry{}
	var used uint64
	err := accumulateStorageEntry(context.Background(), &used)("junction", entry, nil)
	if !errors.Is(err, filepath.SkipDir) || used != 0 || entry.infoCalls.Load() != 0 {
		t.Fatalf("reparse entry result=%v used=%d info_calls=%d", err, used, entry.infoCalls.Load())
	}
}
