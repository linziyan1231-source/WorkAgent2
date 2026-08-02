package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnsureCapacitySlots creates the root-controlled global instance leases used
// by UserHost. It is intentionally a provisioning/recovery operation and must
// never be invoked by a tenant process.
func EnsureCapacitySlots(ctx context.Context, directory string, maximum int) error {
	if os.Geteuid() != 0 {
		return errors.New("capacity slots must be provisioned as root")
	}
	group, err := user.LookupGroup("workagent-slots")
	if err != nil {
		return errors.New("workagent-slots group is unavailable")
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || groupID == 0 {
		return errors.New("workagent-slots group is invalid")
	}
	return ensureCapacitySlotsWithGID(ctx, directory, maximum, uint32(groupID))
}

func ensureCapacitySlotsWithGID(ctx context.Context, directory string, maximum int, groupID uint32) error {
	if maximum < 1 || maximum > 1000 || groupID == 0 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("capacity slot configuration is invalid")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect capacity slot directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o755 {
		return errors.New("capacity slot directory must be a root-owned 0755 real directory")
	}
	for index := 1; index <= maximum; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(directory, fmt.Sprintf("slot-%d.lock", index))
		fd, openErr := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL, 0o600)
		created := openErr == nil
		if errors.Is(openErr, unix.EEXIST) {
			fd, openErr = unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			return fmt.Errorf("open capacity slot %d: %w", index, openErr)
		}
		file := os.NewFile(uintptr(fd), path)
		if created {
			if err := unix.Fchown(fd, 0, int(groupID)); err != nil {
				file.Close()
				return fmt.Errorf("set capacity slot %d ownership: %w", index, err)
			}
			if err := unix.Fchmod(fd, 0o660); err != nil {
				file.Close()
				return fmt.Errorf("set capacity slot %d mode: %w", index, err)
			}
		}
		fileInfo, statErr := file.Stat()
		file.Close()
		fileStat, typed := fileInfoSys(fileInfo)
		if statErr != nil || !typed || fileStat.Uid != 0 || fileStat.Gid != groupID || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o660 {
			return fmt.Errorf("capacity slot %d is unsafe", index)
		}
	}
	return nil
}

func fileInfoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
