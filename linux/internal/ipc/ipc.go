package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Credentials struct {
	PID int32
	UID uint32
	GID uint32
}

type DialOptions struct {
	ExpectedRuntimeUID uint32
	ExpectedSocketUID  uint32
	SystemdActivation  bool
}

type AuthorizedListener struct {
	inner       net.Listener
	expectedUID uint32
	rejected    atomic.Uint64
}

func NewAuthorizedListener(inner net.Listener, expectedUID uint32) (*AuthorizedListener, error) {
	if inner == nil {
		return nil, errors.New("nil Unix listener")
	}
	if _, ok := inner.Addr().(*net.UnixAddr); !ok {
		return nil, errors.New("peer authentication requires a Unix listener")
	}
	if expectedUID == 0 {
		return nil, errors.New("expected peer UID must be non-root")
	}
	return &AuthorizedListener{inner: inner, expectedUID: expectedUID}, nil
}

func (l *AuthorizedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		credentials, err := PeerCredentials(connection)
		if err != nil || credentials.UID != l.expectedUID {
			l.rejected.Add(1)
			_ = connection.Close()
			continue
		}
		return connection, nil
	}
}

func (l *AuthorizedListener) Close() error     { return l.inner.Close() }
func (l *AuthorizedListener) Addr() net.Addr   { return l.inner.Addr() }
func (l *AuthorizedListener) Rejected() uint64 { return l.rejected.Load() }

func PeerCredentials(connection net.Conn) (Credentials, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return Credentials{}, errors.New("peer credentials require a Unix connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return Credentials{}, err
	}
	var value *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		value, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Credentials{}, err
	}
	if socketErr != nil {
		return Credentials{}, socketErr
	}
	if value == nil {
		return Credentials{}, errors.New("kernel returned no peer credentials")
	}
	return Credentials{PID: value.Pid, UID: value.Uid, GID: value.Gid}, nil
}

func Listen(path string, mode os.FileMode, expectedPeerUID uint32) (*AuthorizedListener, error) {
	if err := validateSocketPath(path); err != nil {
		return nil, err
	}
	if mode.Perm() != 0o600 {
		return nil, errors.New("Unix socket mode must be 0600")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("refusing to replace a non-socket runtime path")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale Unix socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on Unix socket: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		listener.Close()
		return nil, fmt.Errorf("protect Unix socket: %w", err)
	}
	authorized, err := NewAuthorizedListener(listener, expectedPeerUID)
	if err != nil {
		listener.Close()
		return nil, err
	}
	return authorized, nil
}

func ListenerFromSystemd(expectedPeerUID uint32, expectedPath string) (*AuthorizedListener, error) {
	if err := validateSocketPath(expectedPath); err != nil {
		return nil, err
	}
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil, errors.New("LISTEN_PID does not identify this process")
	}
	fds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || fds != 1 {
		return nil, errors.New("exactly one systemd socket is required")
	}
	file := os.NewFile(uintptr(3), "systemd-userhost-socket")
	if file == nil {
		return nil, errors.New("systemd socket descriptor is unavailable")
	}
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("adopt systemd socket: %w", err)
	}
	address, ok := listener.Addr().(*net.UnixAddr)
	if !ok || address.Net != "unix" || address.Name != expectedPath {
		listener.Close()
		return nil, errors.New("systemd socket address does not match the tenant configuration")
	}
	authorized, err := NewAuthorizedListener(listener, expectedPeerUID)
	if err != nil {
		listener.Close()
		return nil, err
	}
	return authorized, nil
}

func DialContext(ctx context.Context, path string, options DialOptions) (net.Conn, error) {
	if options.ExpectedRuntimeUID == 0 || options.ExpectedSocketUID == 0 {
		return nil, errors.New("expected runtime UID must be non-root")
	}
	if err := validateSocket(path, options.ExpectedSocketUID); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	credentials, err := PeerCredentials(connection)
	peerAccepted := credentials.UID == options.ExpectedRuntimeUID
	if options.SystemdActivation && credentials.UID == 0 && credentials.PID == 1 {
		peerAccepted = true
	}
	if err != nil || !peerAccepted {
		connection.Close()
		if err != nil {
			return nil, fmt.Errorf("authenticate runtime peer: %w", err)
		}
		return nil, fmt.Errorf("runtime peer credentials pid=%d uid=%d were rejected", credentials.PID, credentials.UID)
	}
	return connection, nil
}

func validateSocket(path string, expectedOwnerUID uint32) error {
	if err := validateSocketPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("runtime endpoint is not a real Unix socket")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("runtime Unix socket is accessible outside its owner")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedOwnerUID {
		return errors.New("runtime Unix socket owner does not match the Portal UID")
	}
	return nil
}

func validateSocketPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Ext(path) != ".sock" {
		return errors.New("Unix socket path must be a clean absolute .sock path")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect Unix socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Unix socket directory is unsafe")
	}
	return nil
}

func IsClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EINVAL)
}
