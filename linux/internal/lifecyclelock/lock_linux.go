package lifecyclelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backupquiescence"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/coreactivation"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/edgepublication"
)

var (
	assertBackupQuiescenceClean = backupquiescence.AssertClean
	assertCoreActivationClean   = coreactivation.AssertClean
	assertEdgePublicationClean  = edgepublication.AssertClean
)

const (
	CatalogPath            = "/run/workagent/release-config.lock"
	ActivationPath         = "/run/workagent/activation.lock"
	RuntimeReleasesRoot    = "/opt/workagent/aionui/releases"
	RuntimePointerPath     = "/opt/workagent/aionui/current.json"
	RuntimeChannelLockPath = RuntimePointerPath + ".lock"
	ControlChannelLockPath = "/opt/workagent/control.lock"
	SharedChannelLockPath  = "/opt/workagent/shared.lock"
	CatalogFDName          = "workagent-config-lock"
	ChannelFDName          = "workagent-runtime-release-lock"
	ControlFDName          = "workagent-control-release-lock"
	SharedFDName           = "workagent-shared-release-lock"
	UserHostSocketFDName   = "workagent-userhost-socket"
)

type Guard struct {
	file *os.File
}

type RuntimeGuards struct {
	catalog *Guard
	control *Guard
	channel *Guard
}

// FixedConsumerGuards holds the catalog and fixed-root channel read locks in
// the only permitted order. Keeping the acquisition coupled prevents a
// consumer from taking a channel lock first and deadlocking with a fixed-root
// writer, which always takes the catalog exclusively before the channel.
type FixedConsumerGuards struct {
	catalog *Guard
	channel *Guard
}

// CatalogExclusiveFixedConsumerGuards holds the catalog writer lock followed
// by a fixed-root channel read lock. It is reserved for catalog reconstruction
// that must authenticate and retain the exact control release while C_EX is
// held; acquiring the pair in one function makes C_EX -> channel SH the only
// representable order at that boundary.
type CatalogExclusiveFixedConsumerGuards struct {
	catalog *Guard
	channel *Guard
}

func AdoptSystemdRuntimeGuards() (*RuntimeGuards, error) {
	descriptors, err := systemdDescriptors()
	if err != nil {
		return nil, err
	}
	for name := range descriptors {
		if name != CatalogFDName && name != ControlFDName && name != ChannelFDName && name != UserHostSocketFDName {
			return nil, fmt.Errorf("unexpected systemd descriptor %q", name)
		}
	}
	catalogFD, catalogOK := descriptors[CatalogFDName]
	controlFD, controlOK := descriptors[ControlFDName]
	channelFD, channelOK := descriptors[ChannelFDName]
	if !catalogOK || !controlOK || !channelOK {
		return nil, errors.New("systemd did not provide every release lifecycle lock")
	}
	catalog, err := adopt(catalogFD, CatalogPath, unix.LOCK_SH)
	if err != nil {
		return nil, fmt.Errorf("adopt catalog lifecycle lock: %w", err)
	}
	control, err := adopt(controlFD, ControlChannelLockPath, unix.LOCK_SH)
	if err != nil {
		_ = catalog.Close()
		return nil, fmt.Errorf("adopt control-release lifecycle lock: %w", err)
	}
	channel, err := adopt(channelFD, RuntimeChannelLockPath, unix.LOCK_SH)
	if err != nil {
		_ = control.Close()
		_ = catalog.Close()
		return nil, fmt.Errorf("adopt runtime-channel lifecycle lock: %w", err)
	}
	return &RuntimeGuards{catalog: catalog, control: control, channel: channel}, nil
}

func (g *RuntimeGuards) ValidateChannel(releasesRoot, pointerPath string) error {
	if g == nil || g.channel == nil || releasesRoot != RuntimeReleasesRoot || pointerPath != RuntimePointerPath {
		return errors.New("runtime configuration does not use the lifecycle-locked production channel")
	}
	return nil
}

func (g *RuntimeGuards) ReleaseCatalog() error {
	if g == nil || g.catalog == nil {
		return errors.New("catalog lifecycle guard is unavailable")
	}
	err := g.catalog.Close()
	g.catalog = nil
	return err
}

func (g *RuntimeGuards) Close() error {
	if g == nil {
		return nil
	}
	err := errors.Join(closeGuard(g.channel), closeGuard(g.control), closeGuard(g.catalog))
	g.channel, g.control, g.catalog = nil, nil, nil
	return err
}

func AcquireCatalogShared(ctx context.Context) (*Guard, error) {
	return acquireCatalog(ctx, unix.LOCK_SH)
}

func AcquireCatalogExclusive(ctx context.Context) (*Guard, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("catalog lifecycle writes require root")
	}
	return acquireCatalog(ctx, unix.LOCK_EX)
}

// AcquireActivationExclusive serializes every orchestrator that can change a
// Portal user's enabled bit or the corresponding systemd socket/service
// state.  Callers must acquire this guard before starting the catalog-ready
// target and before taking C_SH/C_EX.  The reconciler and the services started
// by an orchestrator deliberately never take this lock, so waiting for a
// systemd job while the guard is held cannot invert the order.
func AcquireActivationExclusive(ctx context.Context) (*Guard, error) {
	guard, err := acquireActivationExclusiveUnchecked(ctx)
	if err != nil {
		return nil, err
	}
	if err := assertBackupQuiescenceClean(); err != nil {
		return nil, errors.Join(fmt.Errorf("refuse ordinary activation writer while backup quiescence recovery is pending: %w", err), guard.Close())
	}
	if err := assertCoreActivationClean(); err != nil {
		return nil, errors.Join(fmt.Errorf("refuse ordinary activation writer while core activation is pending: %w", err), guard.Close())
	}
	if err := assertEdgePublicationClean(); err != nil {
		return nil, errors.Join(fmt.Errorf("refuse ordinary activation writer while edge publication is pending: %w", err), guard.Close())
	}
	return guard, nil
}

// AcquireActivationExclusiveForEdgeReconciliation is restricted to the
// service-action entrypoint that immediately disables Caddy and reconciles
// authenticated crash evidence. Ordinary writers must use the gated form.
func AcquireActivationExclusiveForEdgeReconciliation(ctx context.Context) (*Guard, error) {
	guard, err := acquireActivationExclusiveUnchecked(ctx)
	if err != nil {
		return nil, err
	}
	if err := assertCoreActivationClean(); err != nil {
		return nil, errors.Join(fmt.Errorf("refuse edge reconciliation while core activation is pending: %w", err), guard.Close())
	}
	return guard, nil
}

// AcquireActivationExclusiveForCoreReconciliation is restricted to the
// activate-core-fleet entrypoint. That reconciler owns the only protocol that
// may inspect and settle a pending core journal and must reconcile any edge
// evidence before it touches core evidence.
func AcquireActivationExclusiveForCoreReconciliation(ctx context.Context) (*Guard, error) {
	return acquireActivationExclusiveUnchecked(ctx)
}

func acquireActivationExclusiveUnchecked(ctx context.Context) (*Guard, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("tenant activation lifecycle writes require root")
	}
	guard, err := acquireActivationAt(ctx, ActivationPath)
	if err != nil {
		return nil, fmt.Errorf("acquire tenant activation lifecycle lock: %w", err)
	}
	return guard, nil
}

func acquireActivationAt(ctx context.Context, path string) (*Guard, error) {
	return acquireCatalogAt(ctx, path, unix.LOCK_EX)
}

// AcquireFixedConsumer acquires C_SH followed by the selected fixed-root
// channel SH lock. Both descriptors are opened read-only and remain held until
// the returned guard is closed.
func AcquireFixedConsumer(ctx context.Context, destination string) (*FixedConsumerGuards, error) {
	path, err := fixedChannelPath(destination)
	if err != nil {
		return nil, err
	}
	return acquireFixedConsumerAt(ctx, CatalogPath, path)
}

// AcquireCatalogExclusiveFixedConsumer acquires C_EX followed by the selected
// fixed-root channel SH lock. The channel remains pinned until the catalog
// reconstruction transaction closes the returned guard.
func AcquireCatalogExclusiveFixedConsumer(ctx context.Context, destination string) (*CatalogExclusiveFixedConsumerGuards, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("catalog lifecycle writes require root")
	}
	path, err := fixedChannelPath(destination)
	if err != nil {
		return nil, err
	}
	return acquireCatalogExclusiveFixedConsumerAt(ctx, CatalogPath, path)
}

func acquireCatalogExclusiveFixedConsumerAt(ctx context.Context, catalogPath, channelPath string) (*CatalogExclusiveFixedConsumerGuards, error) {
	catalog, err := acquireCatalogAt(ctx, catalogPath, unix.LOCK_EX)
	if err != nil {
		return nil, err
	}
	channel, err := acquireFixedChannelShared(ctx, channelPath)
	if err != nil {
		return nil, errors.Join(err, catalog.Close())
	}
	return &CatalogExclusiveFixedConsumerGuards{catalog: catalog, channel: channel}, nil
}

func acquireFixedConsumerAt(ctx context.Context, catalogPath, channelPath string) (*FixedConsumerGuards, error) {
	catalog, err := acquireCatalogAt(ctx, catalogPath, unix.LOCK_SH)
	if err != nil {
		return nil, err
	}
	channel, err := acquireFixedChannelShared(ctx, channelPath)
	if err != nil {
		return nil, errors.Join(err, catalog.Close())
	}
	return &FixedConsumerGuards{catalog: catalog, channel: channel}, nil
}

func AcquireFixedChannelExclusive(destination string) (*Guard, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("fixed-release lifecycle writes require root")
	}
	path, err := fixedChannelPath(destination)
	if err != nil {
		return nil, err
	}
	return acquireFixedChannelExclusive(path)
}

func fixedChannelPath(destination string) (string, error) {
	switch destination {
	case "/opt/workagent/control":
		return ControlChannelLockPath, nil
	case "/opt/workagent/shared":
		return SharedChannelLockPath, nil
	default:
		return "", errors.New("fixed-release destination is invalid")
	}
}

func acquireFixedChannelShared(ctx context.Context, path string) (*Guard, error) {
	if ctx == nil {
		return nil, errors.New("fixed-release lifecycle context is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open fixed-release lifecycle lock: %w", err)
	}
	guard, err := validateFD(fd, path)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := validateAccessMode(fd, true); err != nil {
		_ = guard.Close()
		return nil, err
	}
	for {
		err = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
		if err == nil {
			if err := validateFDIdentity(fd, path); err != nil {
				_ = guard.Close()
				return nil, err
			}
			return guard, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = guard.Close()
			return nil, fmt.Errorf("acquire fixed-release lifecycle lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = guard.Close()
			return nil, fmt.Errorf("acquire fixed-release lifecycle lock: %w", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func acquireFixedChannelExclusive(path string) (*Guard, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open fixed-release lifecycle lock: %w", err)
	}
	guard, err := validateFD(fd, path)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := validateAccessMode(fd, false); err != nil {
		_ = guard.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = guard.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("fixed release is in use by a consumer")
		}
		return nil, fmt.Errorf("lock fixed-release lifecycle channel: %w", err)
	}
	if err := validateFDIdentity(fd, path); err != nil {
		_ = guard.Close()
		return nil, err
	}
	return guard, nil
}

func acquireCatalog(ctx context.Context, operation int) (*Guard, error) {
	return acquireCatalogAt(ctx, CatalogPath, operation)
}

func acquireCatalogAt(ctx context.Context, path string, operation int) (*Guard, error) {
	if ctx == nil {
		return nil, errors.New("catalog lifecycle context is required")
	}
	openMode := unix.O_RDONLY
	if operation == unix.LOCK_EX {
		openMode = unix.O_RDWR
	}
	fd, err := unix.Open(path, openMode|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open catalog lifecycle lock: %w", err)
	}
	guard, err := validateFD(fd, path)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := validateAccessMode(fd, operation == unix.LOCK_SH); err != nil {
		_ = guard.Close()
		return nil, err
	}
	for {
		err = unix.Flock(fd, operation|unix.LOCK_NB)
		if err == nil {
			if err := validateFDIdentity(fd, path); err != nil {
				_ = guard.Close()
				return nil, err
			}
			return guard, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = guard.Close()
			return nil, fmt.Errorf("acquire catalog lifecycle lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = guard.Close()
			return nil, fmt.Errorf("acquire catalog lifecycle lock: %w", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func adopt(fd int, path string, operation int) (*Guard, error) {
	if fd < 3 {
		return nil, errors.New("systemd lifecycle descriptor is invalid")
	}
	unix.CloseOnExec(fd)
	guard, err := validateFD(fd, path)
	if err != nil {
		return nil, err
	}
	if err := validateAccessMode(fd, true); err != nil {
		_ = guard.Close()
		return nil, err
	}
	if err := unix.Flock(fd, operation); err != nil {
		_ = guard.Close()
		return nil, fmt.Errorf("lock adopted lifecycle descriptor: %w", err)
	}
	if err := validateFDIdentity(fd, path); err != nil {
		_ = guard.Close()
		return nil, err
	}
	return guard, nil
}

func validateAccessMode(fd int, readOnly bool) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return errors.New("inspect lifecycle lock descriptor access mode")
	}
	expected := unix.O_RDWR
	if readOnly {
		expected = unix.O_RDONLY
	}
	if flags&unix.O_ACCMODE != expected {
		return errors.New("lifecycle lock descriptor access mode is unsafe")
	}
	return nil
}

func validateFD(fd int, path string) (*Guard, error) {
	if err := validateFDIdentity(fd, path); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return nil, errors.New("adopt lifecycle lock descriptor")
	}
	return &Guard{file: file}, nil
}

func validateFDIdentity(fd int, path string) error {
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return errors.New("inspect lifecycle lock descriptor")
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Mode&0o7777 != 0o600 || opened.Uid != 0 || opened.Gid != 0 || opened.Nlink != 1 || opened.Size != 0 {
		return errors.New("lifecycle lock descriptor metadata is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("lifecycle lock pathname is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != opened.Dev || stat.Ino != opened.Ino || uint32(stat.Mode) != opened.Mode || stat.Uid != opened.Uid || stat.Gid != opened.Gid || stat.Nlink != opened.Nlink || stat.Size != opened.Size {
		return errors.New("lifecycle lock pathname does not identify the opened inode")
	}
	return nil
}

func systemdDescriptors() (map[string]int, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil, errors.New("LISTEN_PID does not identify this process")
	}
	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || count < 3 || count > 8 {
		return nil, errors.New("systemd descriptor count is invalid")
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count {
		return nil, errors.New("systemd descriptor names are incomplete")
	}
	result := make(map[string]int, count)
	for index, name := range names {
		if name == "" || result[name] != 0 {
			return nil, errors.New("systemd descriptor names are invalid or duplicated")
		}
		result[name] = 3 + index
	}
	return result, nil
}

func (g *Guard) Close() error {
	if g == nil || g.file == nil {
		return nil
	}
	err := g.file.Close()
	g.file = nil
	return err
}

func closeGuard(guard *Guard) error {
	if guard == nil {
		return nil
	}
	return guard.Close()
}

func (g *FixedConsumerGuards) Close() error {
	if g == nil {
		return nil
	}
	err := errors.Join(closeGuard(g.channel), closeGuard(g.catalog))
	g.channel, g.catalog = nil, nil
	return err
}

func (g *CatalogExclusiveFixedConsumerGuards) Close() error {
	if g == nil {
		return nil
	}
	err := errors.Join(closeGuard(g.channel), closeGuard(g.catalog))
	g.channel, g.catalog = nil, nil
	return err
}
