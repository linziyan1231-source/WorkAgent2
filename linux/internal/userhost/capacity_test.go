package userhost

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCapacityLeaseTracksLiveProcesses(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	const slotGID = uint32(1)
	for index := 1; index <= 2; index++ {
		path := filepath.Join(directory, fmt.Sprintf("slot-%d.lock", index))
		if err := os.WriteFile(path, nil, 0o660); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, int(slotGID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
	}
	first, err := acquireCapacityWithGID(directory, 2, slotGID)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquireCapacityWithGID(directory, 2, slotGID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireCapacityWithGID(directory, 2, slotGID); !errors.Is(err, ErrCapacityReached) {
		t.Fatalf("third lease was not rejected: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	reused, err := acquireCapacityWithGID(directory, 2, slotGID)
	if err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	}
	reused.Close()
}

func TestBackendListenerMustBelongToSupervisedProcess(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBackendProcess(listener.Addr().String(), os.Getpid(), executable); err != nil {
		t.Fatalf("owned listener was rejected: %v", err)
	}
	if err := verifyBackendProcess(listener.Addr().String(), os.Getppid(), executable); err == nil {
		t.Fatal("listener was attributed to an unrelated process")
	}
}
