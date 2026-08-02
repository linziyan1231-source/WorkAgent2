package userhost

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrCapacityReached = errors.New("runtime capacity reached")

type capacityLease struct {
	file  *os.File
	index int
}

func acquireCapacity(directory string, maximum int) (*capacityLease, error) {
	group, err := user.LookupGroup("workagent-slots")
	if err != nil {
		return nil, errors.New("workagent-slots group is unavailable")
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || groupID == 0 {
		return nil, errors.New("workagent-slots group is invalid")
	}
	return acquireCapacityWithGID(directory, maximum, uint32(groupID))
}

func acquireCapacityWithGID(directory string, maximum int, expectedGID uint32) (*capacityLease, error) {
	if maximum < 1 || maximum > 1000 || expectedGID == 0 {
		return nil, errors.New("capacity lease configuration is invalid")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect capacity slot directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o755 {
		return nil, errors.New("capacity slot directory must be a root-owned 0755 real directory")
	}
	for index := 1; index <= maximum; index++ {
		path := filepath.Join(directory, fmt.Sprintf("slot-%d.lock", index))
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("open capacity slot %d: %w", index, err)
		}
		file := os.NewFile(uintptr(fd), path)
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("capacity slot %d is unsafe", index)
		}
		fileStat, typed := fileInfo.Sys().(*syscall.Stat_t)
		if !typed || fileStat.Uid != 0 || fileStat.Gid != expectedGID || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o660 {
			file.Close()
			return nil, fmt.Errorf("capacity slot %d is unsafe", index)
		}
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return &capacityLease{file: file, index: index}, nil
		} else if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			file.Close()
			continue
		} else {
			file.Close()
			return nil, fmt.Errorf("lock capacity slot %d: %w", index, err)
		}
	}
	return nil, ErrCapacityReached
}

func (l *capacityLease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	return file.Close()
}
