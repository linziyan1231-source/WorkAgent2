package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
