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

	"aionuiportal/internal/config"
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
	if personalStorageLimitBytes != 60*1024*1024*1024 || sharedStorageLimitBytes != 20*1024*1024*1024 {
		t.Fatalf("storage limits personal=%d shared=%d", personalStorageLimitBytes, sharedStorageLimitBytes)
	}
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

	usage, err := measureStorageUsage(context.Background(), root, personalStorageLimitBytes)
	if err != nil {
		t.Fatal(err)
	}
	if usage.LimitBytes != personalStorageLimitBytes || usage.UsedBytes != 4096 || usage.RemainingBytes != personalStorageLimitBytes-4096 {
		t.Fatalf("storage usage=%+v", usage)
	}
	if _, err := time.Parse(time.RFC3339, usage.MeasuredAt); err != nil {
		t.Fatalf("measured_at=%q: %v", usage.MeasuredAt, err)
	}
}

func TestMeasureStorageUsageStopsWhenRequestIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := measureStorageUsage(ctx, t.TempDir(), personalStorageLimitBytes)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

func TestCurrentStorageUsageCachesAndRefreshesFullWalk(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "S-1-5-21-100-200-300-1001")
	shared := filepath.Join(base, "shared", "S-1-5-21-100-200-300-1001")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "first.bin"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	host := Host{cfg: config.UserHost{ConfigVersion: 2, WindowsSID: "S-1-5-21-100-200-300-1001", DataRootBase: base, DataRoot: root}}
	first, err := host.currentStorageUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "second.bin"), make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	cached, err := host.currentStorageUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cached.Personal.UsedBytes != first.Personal.UsedBytes || cached.Personal.MeasuredAt != first.Personal.MeasuredAt {
		t.Fatalf("storage cache changed before expiry: first=%+v cached=%+v", first, cached)
	}
	host.storageMu.Lock()
	host.storageUsageAt = time.Now().Add(-storageUsageCacheTTL)
	host.storageMu.Unlock()
	refreshed, err := host.currentStorageUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Personal.UsedBytes != 3072 || refreshed.Shared.LimitBytes != sharedStorageLimitBytes {
		t.Fatalf("expired storage cache was not refreshed: %+v", refreshed)
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
