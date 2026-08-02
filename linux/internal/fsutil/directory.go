package fsutil

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// InfoSyscallStat extracts the syscall stat identity behind an os.FileInfo.
func InfoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	return value, ok
}

// SyncDirectory durably syncs a directory after an entry mutation.
func SyncDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Fsync(fd)
	return errors.Join(err, unix.Close(fd))
}
