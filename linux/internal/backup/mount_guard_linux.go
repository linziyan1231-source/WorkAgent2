package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// backupDirectoryGuard pins one exact directory inode on one exact Linux
// mount for the lifetime of a backup. Holding the descriptor prevents a
// normal unmount. The mount ID additionally detects a lazy unmount followed
// by a replacement mount at the same pathname.
type backupDirectoryGuard struct {
	path      string
	directory *os.File
	identity  backupDirectoryIdentity
}

type backupDirectoryIdentity struct {
	deviceMajor uint32
	deviceMinor uint32
	inode       uint64
	mountID     uint64
	mode        uint16
	uid         uint32
	gid         uint32
}

func openBackupDirectoryGuard(path string) (*backupDirectoryGuard, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("backup directory guard path is invalid")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open protected backup directory: %w", err)
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt protected backup directory descriptor")
	}
	identity, err := backupDirectoryIdentityForFD(fd)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if identity.mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(identity.mode).Perm() != 0o700 || identity.uid != 0 {
		_ = directory.Close()
		return nil, errors.New("protected backup directory identity is unsafe")
	}
	return &backupDirectoryGuard{path: path, directory: directory, identity: identity}, nil
}

func backupDirectoryIdentityForFD(fd int) (backupDirectoryIdentity, error) {
	var stat unix.Statx_t
	const requiredMask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, requiredMask, &stat); err != nil {
		return backupDirectoryIdentity{}, fmt.Errorf("stat protected backup mount: %w", err)
	}
	if stat.Mask&requiredMask != requiredMask || stat.Mnt_id == 0 || stat.Ino == 0 {
		return backupDirectoryIdentity{}, errors.New("kernel did not provide the required backup mount identity")
	}
	return backupDirectoryIdentity{
		deviceMajor: stat.Dev_major,
		deviceMinor: stat.Dev_minor,
		inode:       stat.Ino,
		mountID:     stat.Mnt_id,
		mode:        stat.Mode,
		uid:         stat.Uid,
		gid:         stat.Gid,
	}, nil
}

func (g *backupDirectoryGuard) verifyCurrent() error {
	if g == nil || g.directory == nil {
		return errors.New("backup directory guard is closed")
	}
	current, err := openBackupDirectoryGuard(g.path)
	if err != nil {
		return err
	}
	defer current.Close()
	if current.identity != g.identity {
		return errors.New("off-host backup directory or mount changed during backup")
	}
	return nil
}

func (g *backupDirectoryGuard) pinnedPath(name string) (string, error) {
	if g == nil || g.directory == nil {
		return "", errors.New("backup directory guard is closed")
	}
	root := filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(g.directory.Fd()), 10))
	if name == "" {
		return root, nil
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return "", errors.New("protected backup filename is invalid")
	}
	return filepath.Join(root, name), nil
}

func (g *backupDirectoryGuard) Close() error {
	if g == nil || g.directory == nil {
		return nil
	}
	err := g.directory.Close()
	g.directory = nil
	return err
}
