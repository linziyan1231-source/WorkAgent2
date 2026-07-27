//go:build linux

// Package backupquiescence owns the fail-closed admission check for the
// activation-locked backup service's volatile quiescence journal.  It is kept
// separate from internal/backup so lifecyclelock can enforce the check
// without creating an import cycle.
package backupquiescence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const JournalPath = "/run/workagent-backup/quiesce.json"

type layout struct {
	journalPath string
	uid         uint32
	gid         uint32
}

func productionLayout() layout {
	return layout{journalPath: JournalPath, uid: 0, gid: 0}
}

// AssertClean admits an ordinary activation writer only when two protected
// pathname passes prove that no interrupted backup can later replay an older
// active-unit set.  The caller must already own the global activation lock.
func AssertClean() error {
	return assertCleanAt(productionLayout())
}

func assertCleanAt(value layout) error {
	if !filepath.IsAbs(value.journalPath) || filepath.Clean(value.journalPath) != value.journalPath || filepath.Base(value.journalPath) != filepath.Base(JournalPath) {
		return errors.New("backup quiescence admission layout is invalid")
	}
	firstFD, first, err := openParent(value)
	if err != nil {
		return err
	}
	defer unix.Close(firstFD)
	if err := requireAbsent(firstFD, filepath.Base(value.journalPath)); err != nil {
		return err
	}

	// Reopen the protected pathname rather than trusting one directory
	// descriptor.  A rename/replacement between the two absence checks must not
	// turn an old, now-unlinked directory into an authority for the live path.
	secondFD, second, err := openParent(value)
	if err != nil {
		return err
	}
	defer unix.Close(secondFD)
	if !sameDirectory(first, second) {
		return errors.New("backup quiescence journal parent changed during admission")
	}
	if err := requireAbsent(secondFD, filepath.Base(value.journalPath)); err != nil {
		return err
	}
	var firstAfter, secondAfter unix.Stat_t
	if err := unix.Fstat(firstFD, &firstAfter); err != nil {
		return errors.New("reinspect backup quiescence journal parent")
	}
	if err := unix.Fstat(secondFD, &secondAfter); err != nil {
		return errors.New("reinspect backup quiescence journal parent")
	}
	if !sameDirectory(first, firstAfter) || !sameDirectory(second, secondAfter) || !sameDirectory(firstAfter, secondAfter) {
		return errors.New("backup quiescence journal parent changed during admission")
	}
	return nil
}

func openParent(value layout) (int, unix.Stat_t, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(value.journalPath), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("backup quiescence journal parent is missing or unsafe")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(stat.Mode).Perm() != 0o700 || stat.Uid != value.uid || stat.Gid != value.gid {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("backup quiescence journal parent is missing or unsafe")
	}
	return fd, stat, nil
}

func requireAbsent(parentFD int, base string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect backup quiescence journal: %w", err)
	}
	return errors.New("backup service quiescence recovery is pending")
}

func sameDirectory(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino && first.Mode == second.Mode && first.Uid == second.Uid && first.Gid == second.Gid &&
		first.Nlink == second.Nlink && first.Size == second.Size && first.Mtim == second.Mtim && first.Ctim == second.Ctim
}
