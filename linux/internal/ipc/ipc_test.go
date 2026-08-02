package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNamedSystemdFDSelectsSocketAlongsideLifecycleLocks(t *testing.T) {
	t.Setenv("LISTEN_PID", fmt.Sprint(os.Getpid()))
	t.Setenv("LISTEN_FDS", "3")
	t.Setenv("LISTEN_FDNAMES", "workagent-config-lock:workagent-runtime-release-lock:workagent-userhost-socket")
	fd, err := namedSystemdFD("workagent-userhost-socket")
	if err != nil {
		t.Fatal(err)
	}
	if fd != 5 {
		t.Fatalf("selected descriptor %d, want 5", fd)
	}
}

func TestNamedSystemdFDRejectsMissingOrDuplicateSocketName(t *testing.T) {
	t.Setenv("LISTEN_PID", fmt.Sprint(os.Getpid()))
	t.Setenv("LISTEN_FDS", "3")
	for _, names := range []string{
		"workagent-config-lock:workagent-runtime-release-lock:other",
		"workagent-userhost-socket:workagent-runtime-release-lock:workagent-userhost-socket",
	} {
		t.Setenv("LISTEN_FDNAMES", names)
		if _, err := namedSystemdFD("workagent-userhost-socket"); err == nil {
			t.Fatalf("unsafe descriptor names %q were accepted", names)
		}
	}
}

func TestPeerCredentialsAndAuthenticatedDial(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the test requires a non-root peer UID")
	}
	root := t.TempDir()
	path := filepath.Join(root, "runtime.sock")
	listener, err := Listen(path, 0o600, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			credentials, credentialErr := PeerCredentials(connection)
			if credentialErr == nil && credentials.UID != uint32(os.Getuid()) {
				credentialErr = &net.AddrError{Err: "unexpected peer UID", Addr: path}
			}
			err = credentialErr
			connection.Close()
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := DialContext(ctx, path, DialOptions{ExpectedRuntimeUID: uint32(os.Getuid()), ExpectedSocketUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestDialRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.sock")
	link := filepath.Join(root, "link.sock")
	listener, err := net.Listen("unix", target)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := DialContext(context.Background(), link, DialOptions{ExpectedRuntimeUID: 1000, ExpectedSocketUID: 1000}); err == nil {
		t.Fatal("symlinked socket was accepted")
	}
}

func TestListenerRequiresNonRootPeer(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runtime.sock")
	if _, err := Listen(path, 0o600, 0); err == nil {
		t.Fatal("root peer authorization was accepted")
	}
}
