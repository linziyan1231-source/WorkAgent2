//go:build linux

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// assignPortalSQLiteFileSetToStateOwner repairs the owner of a database file
// set that a root-run administrative tool just created inside the Portal
// state directory. Only root-owned files are reassigned to the state
// directory owner; any other foreign owner is left for
// protectPortalSQLiteFileSet to reject.
func assignPortalSQLiteFileSetToStateOwner(databasePath, auditPath string, expectedUID, expectedGID uint32) error {
	if os.Geteuid() != 0 || expectedUID == 0 {
		return nil
	}
	parentFD, err := unix.Open(filepath.Dir(databasePath), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open Portal database directory for ownership repair: %w", err)
	}
	defer unix.Close(parentFD)
	base := filepath.Base(databasePath)
	names := []string{base, base + "-wal", base + "-shm", base + "-journal"}
	if auditDir := filepath.Dir(auditPath); auditDir == filepath.Dir(databasePath) {
		names = append(names, filepath.Base(auditPath))
	}
	for _, name := range names {
		var named unix.Stat_t
		err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect Portal state file %s ownership: %w", name, err)
		}
		if named.Uid != 0 {
			continue
		}
		if err := unix.Fchownat(parentFD, name, int(expectedUID), int(expectedGID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("assign Portal state file %s to the Portal identity: %w", name, err)
		}
	}
	return nil
}

// protectPortalSQLiteFileSet closes the gap between SQLite file creation and
// an inherited administrative umask. The state directory is private, so these
// modes are repaired before Store.Open returns; unexpected owners, links, or
// pathname substitutions are rejected rather than modified.
func protectPortalSQLiteFileSet(databasePath string, expectedUID, expectedGID uint32) error {
	parentFD, err := unix.Open(filepath.Dir(databasePath), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open Portal database directory for protection: %w", err)
	}
	defer unix.Close(parentFD)
	base := filepath.Base(databasePath)
	for index, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		name := base + suffix
		var named unix.Stat_t
		err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) && index != 0 {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect Portal database%s protection: %w", suffix, err)
		}
		if !safePortalSQLiteOwner(named, expectedUID, expectedGID) {
			return fmt.Errorf("Portal database%s owner, type, or link count is unsafe", suffix)
		}
		fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		if err != nil {
			return fmt.Errorf("open Portal database%s for protection: %w", suffix, err)
		}
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil || !samePortalSQLitePathIdentity(named, opened) {
			unix.Close(fd)
			return fmt.Errorf("Portal database%s changed before protection", suffix)
		}
		if err := unix.Fchmod(fd, 0o600); err != nil {
			unix.Close(fd)
			return fmt.Errorf("protect Portal database%s: %w", suffix, err)
		}
		if err := unix.Fsync(fd); err != nil {
			unix.Close(fd)
			return fmt.Errorf("synchronize Portal database%s protection: %w", suffix, err)
		}
		var protected, pathReadback unix.Stat_t
		statErr := unix.Fstat(fd, &protected)
		pathErr := unix.Fstatat(parentFD, name, &pathReadback, unix.AT_SYMLINK_NOFOLLOW)
		closeErr := unix.Close(fd)
		if statErr != nil || pathErr != nil || closeErr != nil || !safePortalSQLiteOwner(protected, expectedUID, expectedGID) ||
			protected.Mode&0o7777 != 0o600 || !samePortalSQLitePathIdentity(protected, pathReadback) {
			return fmt.Errorf("Portal database%s protection readback failed", suffix)
		}
	}
	return nil
}

func safePortalSQLiteOwner(stat unix.Stat_t, expectedUID, expectedGID uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == expectedUID && stat.Gid == expectedGID && stat.Nlink == 1
}

func samePortalSQLitePathIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink
}
