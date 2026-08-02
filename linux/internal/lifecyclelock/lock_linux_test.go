package lifecyclelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeLifecycleFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFixedConsumerAcquiresCatalogBeforeChannelAndUsesReadOnlyDescriptors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	root := t.TempDir()
	catalogPath := filepath.Join(root, "catalog.lock")
	channelPath := filepath.Join(root, "control.lock")
	writeLifecycleFixture(t, catalogPath)
	writeLifecycleFixture(t, channelPath)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	catalogWriter, err := acquireCatalogAt(ctx, catalogPath, unix.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	completed := make(chan struct{})
	var consumer *FixedConsumerGuards
	var consumerErr error
	go func() {
		close(started)
		consumer, consumerErr = acquireFixedConsumerAt(ctx, catalogPath, channelPath)
		close(completed)
	}()
	<-started
	time.Sleep(50 * time.Millisecond)

	// While C_EX is held, a correctly ordered consumer cannot yet have taken
	// channel SH, so a writer can still take channel EX nonblockingly.
	channelWriterFD, err := unix.Open(channelPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(channelWriterFD)
	deadline := time.Now().Add(time.Second)
	for {
		err = unix.Flock(channelWriterFD, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) || time.Now().After(deadline) {
			t.Fatalf("consumer acquired channel before catalog: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := catalogWriter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
		t.Fatalf("consumer bypassed held channel writer: %v", consumerErr)
	case <-time.After(75 * time.Millisecond):
	}
	if err := unix.Flock(channelWriterFD, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal("ordered fixed consumer did not finish after both writers released")
	}
	if consumerErr != nil {
		t.Fatal(consumerErr)
	}
	for name, guard := range map[string]*Guard{"catalog": consumer.catalog, "channel": consumer.channel} {
		flags, err := unix.FcntlInt(guard.file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatalf("%s consumer descriptor is not read-only: flags=%#x err=%v", name, flags, err)
		}
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogExclusiveFixedConsumerAcquiresWriterBeforeChannelReader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	root := t.TempDir()
	catalogPath := filepath.Join(root, "catalog.lock")
	channelPath := filepath.Join(root, "control.lock")
	writeLifecycleFixture(t, catalogPath)
	writeLifecycleFixture(t, channelPath)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	catalogBlocker, err := acquireCatalogAt(ctx, catalogPath, unix.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan struct{})
	var guards *CatalogExclusiveFixedConsumerGuards
	var acquireErr error
	go func() {
		guards, acquireErr = acquireCatalogExclusiveFixedConsumerAt(ctx, catalogPath, channelPath)
		close(completed)
	}()
	time.Sleep(50 * time.Millisecond)

	// The coupled acquisition cannot reach channel SH while another holder
	// owns C_EX, so channel EX remains available at this point.
	channelWriterFD, err := unix.Open(channelPath, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(channelWriterFD)
	if err := unix.Flock(channelWriterFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("channel reader was acquired before catalog writer: %v", err)
	}
	if err := catalogBlocker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
		t.Fatalf("coupled acquisition bypassed the channel writer: %v", acquireErr)
	case <-time.After(75 * time.Millisecond):
	}
	if err := unix.Flock(channelWriterFD, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal("coupled catalog/channel acquisition did not complete")
	}
	if acquireErr != nil {
		t.Fatal(acquireErr)
	}

	for name, check := range map[string]struct {
		guard *Guard
		mode  int
	}{
		"catalog": {guard: guards.catalog, mode: unix.O_RDWR},
		"channel": {guard: guards.channel, mode: unix.O_RDONLY},
	} {
		flags, err := unix.FcntlInt(check.guard.file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != check.mode {
			t.Fatalf("%s descriptor mode=%#x want %#x: %v", name, flags&unix.O_ACCMODE, check.mode, err)
		}
	}
	if err := guards.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleIdentityRejectsPathReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	root := t.TempDir()
	path := filepath.Join(root, "control.lock")
	writeLifecycleFixture(t, path)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	writeLifecycleFixture(t, path)
	if err := validateFDIdentity(fd, path); err == nil || !strings.Contains(err.Error(), "opened inode") {
		t.Fatalf("replaced lifecycle pathname was accepted: %v", err)
	}
}

func TestFixedConsumerRejectsForeignDestination(t *testing.T) {
	if _, err := AcquireFixedConsumer(context.Background(), "/opt/workagent/other"); err == nil {
		t.Fatal("foreign fixed-root consumer destination was accepted")
	}
}

func TestAdoptedLifecycleReadGuardBlocksPointerWriter(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "current.json.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	readFD, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := adopt(readFD, path, unix.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	writeFD, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(writeFD)
	if err := unix.Flock(writeFD, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("exclusive pointer writer was not blocked by the lifecycle reader: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(writeFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("pointer writer remained blocked after consumer exit: %v", err)
	}
}

func TestLifecycleDescriptorRejectsUnsafeMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	for name, mutate := range map[string]func(string) error{
		"writable mode": func(path string) error { return os.Chmod(path, 0o620) },
		"hard link":     func(path string) error { return os.Link(path, path+".link") },
		"nonempty":      func(path string) error { return os.WriteFile(path, []byte("x"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lifecycle.lock")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := mutate(path); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateFD(fd, path); err == nil {
				_ = unix.Close(fd)
				t.Fatal("unsafe lifecycle descriptor was accepted")
			}
			_ = unix.Close(fd)
		})
	}
}

func TestAdoptedLifecycleGuardRejectsWritableDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "lifecycle.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adopt(fd, path, unix.LOCK_SH); err == nil || !strings.Contains(err.Error(), "access mode") {
		_ = unix.Close(fd)
		t.Fatalf("writable lifecycle descriptor was adopted: %v", err)
	}
}

func TestFixedChannelWriterIsBlockedForConsumerLifetime(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "control.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	consumerFD, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := adopt(consumerFD, path, unix.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireFixedChannelExclusive(path); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("fixed-root writer was not rejected while a consumer was live: %v", err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := acquireFixedChannelExclusive(path)
	if err != nil {
		t.Fatalf("fixed-root writer remained blocked after consumer exit: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedChannelWriterRejectsUnsafeInode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "shared.lock")
	if err := os.WriteFile(path, []byte("not empty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireFixedChannelExclusive(path); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("unsafe fixed-root lock inode was accepted: %v", err)
	}
}

func TestActivationExclusiveSerializesOrchestratorsAndUsesWritableDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned lifecycle inode fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "activation.lock")
	writeLifecycleFixture(t, path)
	first, err := acquireActivationAt(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(first.file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR {
		t.Fatalf("activation descriptor is not writable: flags=%#x err=%v", flags, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if second, err := acquireActivationAt(ctx, path); err == nil {
		_ = second.Close()
		t.Fatal("concurrent activation orchestrator bypassed the exclusive lock")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked activation returned the wrong error: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireActivationAt(context.Background(), path)
	if err != nil {
		t.Fatalf("activation lock remained unavailable after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
