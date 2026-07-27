package servicelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type Lock struct {
	file *os.File
}

func AcquireShared(path string, expectedUID uint32) (*Lock, error) {
	return acquire(path, expectedUID, true, unix.LOCK_SH)
}

func AcquireExclusiveExisting(path string, expectedUID uint32) (*Lock, error) {
	return acquire(path, expectedUID, false, unix.LOCK_EX|unix.LOCK_NB)
}

// AcquireExclusive creates a missing private lock as the tenant identity or
// opens the existing tenant-owned lock, then takes a non-blocking exclusive
// flock. The validated parent descriptor confines creation to that real
// directory, and no existing inode is ever replaced.
func AcquireExclusive(path string, expectedUID, expectedGID uint32) (*Lock, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedUID == 0 || expectedGID == 0 {
		return nil, errors.New("service lock path or owner is invalid")
	}
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	if base == "." || base == ".." || strings.ContainsAny(base, `/\\`) {
		return nil, errors.New("service lock name is invalid")
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("service lock parent is missing or unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != expectedUID || parentStat.Gid != expectedGID {
		return nil, errors.New("service lock parent ownership does not match")
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open service lock parent: %w", err)
	}
	defer unix.Close(parentFD)
	var openedParent unix.Stat_t
	if err := unix.Fstat(parentFD, &openedParent); err != nil || openedParent.Dev != uint64(parentStat.Dev) || openedParent.Ino != parentStat.Ino {
		return nil, errors.New("service lock parent changed during validation")
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Openat(parentFD, base, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parentFD, base, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open service lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	cleanup := func() { _ = file.Close() }
	if created {
		if err := unix.Fchown(fd, int(expectedUID), int(expectedGID)); err != nil {
			cleanup()
			_ = unix.Unlinkat(parentFD, base, 0)
			return nil, fmt.Errorf("set service lock ownership: %w", err)
		}
		if err := unix.Fchmod(fd, 0o600); err != nil {
			cleanup()
			_ = unix.Unlinkat(parentFD, base, 0)
			return nil, errors.New("protect new service lock")
		}
		if err := unix.Fsync(fd); err != nil || unix.Fsync(parentFD) != nil {
			cleanup()
			_ = unix.Unlinkat(parentFD, base, 0)
			return nil, errors.New("sync new service lock")
		}
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		cleanup()
		return nil, errors.New("service lock is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Gid != expectedGID {
		cleanup()
		return nil, errors.New("service lock ownership does not match")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cleanup()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("service is active; quiesce it before migration")
		}
		return nil, fmt.Errorf("acquire service lock: %w", err)
	}
	return &Lock{file: file}, nil
}

func acquire(path string, expectedUID uint32, create bool, operation int) (*Lock, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("service lock path must be clean and absolute")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("service lock parent is missing or unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != expectedUID {
		return nil, errors.New("service lock parent ownership does not match")
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags = unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_CREAT
	}
	fd, err := unix.Open(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open service lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	cleanup := func() { _ = file.Close() }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		cleanup()
		return nil, errors.New("service lock is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		cleanup()
		return nil, errors.New("service lock ownership does not match")
	}
	if err := unix.Flock(fd, operation); err != nil {
		cleanup()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("service is active; quiesce it before backup or restore")
		}
		return nil, fmt.Errorf("acquire service lock: %w", err)
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	fd := int(l.file.Fd())
	_ = unix.Flock(fd, unix.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}
