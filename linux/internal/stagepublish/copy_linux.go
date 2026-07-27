//go:build linux

package stagepublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const publicationResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

func openRealDirectory(path string, expectedUID, expectedGID uint32, expectedMode os.FileMode) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := fileStat(info)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != expectedMode.Perm() || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return nil, errors.New("production directory ownership or mode is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != uint64(stat.Dev) || opened.Ino != stat.Ino || opened.Uid != expectedUID || opened.Gid != expectedGID || os.FileMode(opened.Mode).Perm() != expectedMode.Perm() {
		unix.Close(fd)
		return nil, errors.New("production directory changed while it was opened")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func prepareTenantTemporary(parent *os.File, item journalTenant) (string, bool, error) {
	if parent == nil || item.UID == 0 || item.GID == 0 || filepath.Base(item.Temporary) != item.Temporary || strings.ContainsAny(item.Temporary, `/\`) {
		return "", false, errors.New("tenant temporary publication identity is invalid")
	}
	parentFD := int(parent.Fd())
	created := false
	if err := unix.Mkdirat(parentFD, item.Temporary, 0o700); err == nil {
		created = true
		fd, openErr := unix.Openat2(parentFD, item.Temporary, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
		if openErr != nil {
			return "", false, openErr
		}
		if err := unix.Fchown(fd, int(item.UID), int(item.GID)); err != nil {
			unix.Close(fd)
			return "", false, err
		}
		if err := unix.Fchmod(fd, 0o700); err != nil || unix.Fsync(fd) != nil || unix.Fsync(parentFD) != nil {
			unix.Close(fd)
			return "", false, errors.New("durably initialize tenant temporary root")
		}
		unix.Close(fd)
	} else if !errors.Is(err, unix.EEXIST) {
		return "", false, err
	}
	fd, err := unix.Openat2(parentFD, item.Temporary, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return "", false, errors.New("tenant temporary root is unsafe")
	}
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	if statErr == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == 0 && stat.Gid == 0 && os.FileMode(stat.Mode).Perm() == 0o700 {
		// The journal and deterministic name were persisted before Mkdirat. A
		// kill between Mkdirat and Fchown can therefore be recovered only when
		// the root-owned residue is still completely empty.
		empty, emptyErr := directoryFDEmpty(fd)
		if emptyErr != nil || !empty {
			unix.Close(fd)
			return "", false, errors.New("root-owned tenant temporary residue is not an empty adoptable directory")
		}
		if err := unix.Fchown(fd, int(item.UID), int(item.GID)); err != nil || unix.Fchmod(fd, 0o700) != nil || unix.Fsync(fd) != nil || unix.Fsync(parentFD) != nil {
			unix.Close(fd)
			return "", false, errors.New("adopt interrupted tenant temporary root")
		}
		created = true
		statErr = unix.Fstat(fd, &stat)
	}
	unix.Close(fd)
	if statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != item.UID || stat.Gid != item.GID || os.FileMode(stat.Mode).Perm() != 0o700 {
		return "", false, errors.New("tenant temporary root ownership or mode is invalid")
	}
	return filepath.Join(parent.Name(), item.Temporary), created, nil
}

func directoryFDEmpty(fd int) (bool, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return false, err
	}
	directory := os.NewFile(uintptr(duplicate), "adoptable-publication-directory")
	entries, readErr := directory.ReadDir(1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return false, closeErr
	}
	return len(entries) == 0, nil
}

func copyTenantTree(ctx context.Context, stageRoot string, parent *os.File, item journalTenant) error {
	sourceRoot, err := os.OpenFile(stageRoot, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer sourceRoot.Close()
	sourceFD, err := unix.Openat2(int(sourceRoot.Fd()), filepath.ToSlash(filepath.Join("tenants", item.TenantID)), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return errors.New("securely open staged tenant payload")
	}
	defer unix.Close(sourceFD)
	destinationFD, err := unix.Openat2(int(parent.Fd()), item.Temporary, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return errors.New("securely open tenant temporary root")
	}
	defer unix.Close(destinationFD)
	return copyDirectoryContents(ctx, sourceFD, destinationFD, item.UID, item.GID, "", true)
}

func copyDirectoryContents(ctx context.Context, sourceFD, destinationFD int, uid, gid uint32, relative string, root bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	duplicate, err := unix.Dup(sourceFD)
	if err != nil {
		return err
	}
	sourceDirectory := os.NewFile(uintptr(duplicate), "staged-publication-directory")
	entries, readErr := sourceDirectory.ReadDir(-1)
	closeErr := sourceDirectory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	wanted := make(map[string]bool, len(entries)+1)
	if root {
		wanted[".runtime.lock"] = true
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || (root && name == ".runtime.lock") {
			return errors.New("staged tenant payload contains an invalid publication name")
		}
		wanted[name] = true
		var sourceStat unix.Stat_t
		if err := unix.Fstatat(sourceFD, name, &sourceStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch sourceStat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if os.FileMode(sourceStat.Mode).Perm() != 0o700 {
				return errors.New("staged tenant directory mode changed before copy")
			}
			if err := ensureOwnedDirectoryAt(destinationFD, name, uid, gid); err != nil {
				return err
			}
			sourceChild, err := unix.Openat2(sourceFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
			if err != nil {
				return err
			}
			destinationChild, err := unix.Openat2(destinationFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
			if err != nil {
				unix.Close(sourceChild)
				return err
			}
			childRelative := name
			if relative != "" {
				childRelative = path.Join(relative, name)
			}
			err = copyDirectoryContents(ctx, sourceChild, destinationChild, uid, gid, childRelative, false)
			unix.Close(sourceChild)
			unix.Close(destinationChild)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			mode := os.FileMode(sourceStat.Mode).Perm()
			if mode != 0o600 && mode != 0o700 {
				return errors.New("staged tenant file mode changed before copy")
			}
			if err := copyOrVerifyFileAt(sourceFD, destinationFD, name, sourceStat, mode, uid, gid); err != nil {
				return err
			}
		case unix.S_IFLNK:
			if err := copyOrVerifySymlinkAt(sourceFD, destinationFD, relative, name, uid, gid); err != nil {
				return err
			}
		default:
			return errors.New("staged tenant payload contains a special file")
		}
	}
	if err := rejectUnexpectedDestinationEntries(destinationFD, wanted); err != nil {
		return err
	}
	return unix.Fsync(destinationFD)
}

func ensureOwnedDirectoryAt(parentFD int, name string, uid, gid uint32) error {
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return errors.New("tenant destination directory is unsafe")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("tenant destination entry conflicts with a directory")
	}
	if stat.Uid == 0 && stat.Gid == 0 {
		empty, err := directoryFDEmpty(fd)
		if err != nil || !empty {
			return errors.New("root-owned tenant directory residue is not empty and cannot be adopted")
		}
		duplicate, err := unix.Dup(fd)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(duplicate), name)
		err = file.Chown(int(uid), int(gid))
		if err == nil {
			err = file.Chmod(0o700)
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
	}
	if stat.Uid != uid || stat.Gid != gid || os.FileMode(stat.Mode).Perm() != 0o700 {
		return errors.New("tenant destination directory ownership or mode conflicts")
	}
	return nil
}

func copyOrVerifyFileAt(sourceParent, destinationParent int, name string, sourceStat unix.Stat_t, mode os.FileMode, uid, gid uint32) error {
	source, err := unix.Openat2(sourceParent, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return err
	}
	sourceFile := os.NewFile(uintptr(source), name)
	defer sourceFile.Close()
	var openedSource unix.Stat_t
	if err := unix.Fstat(source, &openedSource); err != nil || openedSource.Dev != sourceStat.Dev || openedSource.Ino != sourceStat.Ino || openedSource.Size != sourceStat.Size || openedSource.Mtim != sourceStat.Mtim {
		return errors.New("staged tenant file changed before copy")
	}
	sourceHash, err := hashOpenAt(sourceParent, name, sourceStat)
	if err != nil {
		return err
	}
	destination, err := unix.Openat(destinationParent, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		destination, err = unix.Openat(destinationParent, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
		created = err == nil
	}
	if err != nil {
		return err
	}
	destinationFile := os.NewFile(uintptr(destination), name)
	defer destinationFile.Close()
	var destinationBefore unix.Stat_t
	if err := unix.Fstat(destination, &destinationBefore); err != nil || destinationBefore.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(destinationBefore.Mode).Perm() != mode || destinationBefore.Size < 0 || destinationBefore.Size > sourceStat.Size ||
		!((destinationBefore.Uid == uid && destinationBefore.Gid == gid) || (destinationBefore.Uid == 0 && destinationBefore.Gid == 0)) {
		return errors.New("existing tenant destination file is not an adoptable partial")
	}
	if destinationBefore.Size > 0 {
		matches, err := equalFilePrefix(sourceFile, destinationFile, destinationBefore.Size)
		if err != nil || !matches {
			return errors.New("existing tenant destination file prefix conflicts with the staged payload")
		}
	}
	if err := destinationFile.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if err := destinationFile.Chmod(mode); err != nil {
		return err
	}
	if _, err := sourceFile.Seek(destinationBefore.Size, io.SeekStart); err != nil {
		return err
	}
	if _, err := destinationFile.Seek(destinationBefore.Size, io.SeekStart); err != nil {
		return err
	}
	written, copyErr := io.Copy(destinationFile, sourceFile)
	if copyErr != nil || written != sourceStat.Size-destinationBefore.Size {
		return errors.New("staged tenant file changed during copy")
	}
	if err := destinationFile.Sync(); err != nil {
		return err
	}
	var sourceAfter unix.Stat_t
	if err := unix.Fstat(source, &sourceAfter); err != nil || sourceAfter.Dev != sourceStat.Dev || sourceAfter.Ino != sourceStat.Ino || sourceAfter.Size != sourceStat.Size || sourceAfter.Mtim != sourceStat.Mtim {
		return errors.New("staged tenant file changed during copy")
	}
	sourceHashAfter, err := hashOpenAt(sourceParent, name, sourceStat)
	if err != nil || sourceHashAfter != sourceHash {
		return errors.New("staged tenant file changed during copy")
	}
	var destinationAfter unix.Stat_t
	if err := unix.Fstat(destination, &destinationAfter); err != nil || destinationAfter.Uid != uid || destinationAfter.Gid != gid || os.FileMode(destinationAfter.Mode).Perm() != mode || destinationAfter.Size != sourceStat.Size {
		return errors.New("tenant destination file metadata readback failed")
	}
	destinationHash, err := hashOpenAt(destinationParent, name, destinationAfter)
	if err != nil || destinationHash != sourceHash {
		return errors.New("tenant destination file content readback failed")
	}
	if created || destinationBefore.Size != sourceStat.Size {
		return unix.Fsync(destinationParent)
	}
	return nil
}

func hashOpenAt(parentFD int, name string, before unix.Stat_t) (string, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	digest := sha256.New()
	written, copyErr := io.Copy(digest, file)
	var after unix.Stat_t
	statErr := unix.Fstat(int(file.Fd()), &after)
	closeErr := file.Close()
	if copyErr != nil || statErr != nil || closeErr != nil || written != before.Size || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim {
		return "", errors.New("publication file changed while hashing")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func copyOrVerifySymlinkAt(sourceParent, destinationParent int, relative, name string, uid, gid uint32) error {
	target, err := readlinkAt(sourceParent, name)
	if err != nil {
		return err
	}
	normalized := filepath.ToSlash(target)
	linkPath := name
	if relative != "" {
		linkPath = path.Join(relative, name)
	}
	if path.IsAbs(normalized) || strings.ContainsRune(normalized, '\x00') || strings.Contains(normalized, `\`) || path.Clean(normalized) != normalized {
		return errors.New("staged tenant symbolic link changed to an unsafe target before copy")
	}
	resolved := path.Clean(path.Join(path.Dir(linkPath), normalized))
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
		return errors.New("staged tenant symbolic link changed to an escaping target before copy")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(destinationParent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFLNK || stat.Uid != uid || stat.Gid != gid {
			return errors.New("existing tenant destination link conflicts")
		}
		current, err := readlinkAt(destinationParent, name)
		if err != nil || current != target {
			return errors.New("existing tenant destination link target conflicts")
		}
		return nil
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := unix.Symlinkat(target, destinationParent, name); err != nil {
		return err
	}
	if err := unix.Fchownat(destinationParent, name, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	return unix.Fsync(destinationParent)
}

func readlinkAt(parentFD int, name string) (string, error) {
	buffer := make([]byte, 32*1024)
	length, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil || length == 0 || length == len(buffer) {
		return "", errors.New("read publication symbolic link")
	}
	return string(buffer[:length]), nil
}

func rejectUnexpectedDestinationEntries(directoryFD int, wanted map[string]bool) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "tenant-publication-destination")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] {
			return errors.New("tenant temporary root contains an entry not present in the staged payload")
		}
	}
	return nil
}

func copyPortalDatabase(stageRoot string, portalParent *os.File, temporary string, uid, gid uint32, expectedSHA256 string) error {
	return copyPortalDatabaseWithHook(stageRoot, portalParent, temporary, uid, gid, expectedSHA256, nil)
}

// verifyPortalPartial proves that an interrupted journal-bound Portal copy can
// be resumed without changing either tree. It accepts only an exact prefix of
// the still-verified source and the two ownership states reachable around the
// create/chown crash window.
func verifyPortalPartial(stageRoot string, portalParent *os.File, temporary string, uid, gid uint32, expectedSHA256 string) error {
	if portalParent == nil || filepath.Base(temporary) != temporary || strings.ContainsAny(temporary, `/\`) {
		return errors.New("Portal temporary publication identity is invalid")
	}
	stageFD, err := unix.Open(stageRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("securely open publication stage for Portal resume check")
	}
	defer unix.Close(stageFD)
	sourceFD, err := unix.Openat2(stageFD, "portal/portal.db", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return errors.New("securely open staged Portal database")
	}
	source := os.NewFile(uintptr(sourceFD), "staged-portal.db")
	defer source.Close()
	var sourceBefore unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceBefore); err != nil || sourceBefore.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(sourceBefore.Mode).Perm() != 0o600 || sourceBefore.Size < 1 {
		return errors.New("staged Portal database source metadata is unsafe")
	}
	sourceHash, err := hashOpenAt(stageFD, "portal/portal.db", sourceBefore)
	if err != nil || sourceHash != expectedSHA256 {
		return errors.New("staged Portal database does not match the verified content hash")
	}
	destinationFD, err := unix.Openat(int(portalParent.Fd()), temporary, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("securely open interrupted Portal temporary file")
	}
	destination := os.NewFile(uintptr(destinationFD), temporary)
	defer destination.Close()
	var destinationStat unix.Stat_t
	if err := unix.Fstat(destinationFD, &destinationStat); err != nil || destinationStat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(destinationStat.Mode).Perm() != 0o600 || destinationStat.Size < 0 || destinationStat.Size > sourceBefore.Size ||
		!((destinationStat.Uid == uid && destinationStat.Gid == gid) || (destinationStat.Uid == 0 && destinationStat.Gid == 0)) {
		return errors.New("interrupted Portal temporary file is not safely resumable")
	}
	matches, err := equalFilePrefix(source, destination, destinationStat.Size)
	if err != nil || !matches {
		return errors.New("interrupted Portal temporary file is not an exact verified prefix")
	}
	var sourceAfter unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceAfter); err != nil || sourceAfter.Dev != sourceBefore.Dev || sourceAfter.Ino != sourceBefore.Ino || sourceAfter.Size != sourceBefore.Size || sourceAfter.Mtim != sourceBefore.Mtim {
		return errors.New("staged Portal database changed during resume check")
	}
	sourceHashAfter, err := hashOpenAt(stageFD, "portal/portal.db", sourceBefore)
	if err != nil || sourceHashAfter != expectedSHA256 {
		return errors.New("staged Portal database changed during resume check")
	}
	return nil
}

func copyPortalDatabaseWithHook(stageRoot string, portalParent *os.File, temporary string, uid, gid uint32, expectedSHA256 string, afterSourceHash func() error) error {
	stageFD, err := unix.Open(stageRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("securely open publication stage for Portal copy")
	}
	defer unix.Close(stageFD)
	sourceFD, err := unix.Openat2(stageFD, "portal/portal.db", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: publicationResolve})
	if err != nil {
		return errors.New("securely open staged Portal database")
	}
	source := os.NewFile(uintptr(sourceFD), "staged-portal.db")
	defer source.Close()
	var sourceBefore unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceBefore); err != nil || sourceBefore.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(sourceBefore.Mode).Perm() != 0o600 || sourceBefore.Size < 1 {
		return errors.New("staged Portal database source metadata is unsafe")
	}
	sourceHash, err := hashOpenAt(stageFD, "portal/portal.db", sourceBefore)
	if err != nil || sourceHash != expectedSHA256 {
		return errors.New("staged Portal database does not match the verified content hash")
	}
	if afterSourceHash != nil {
		if err := afterSourceHash(); err != nil {
			return err
		}
	}
	parentFD := int(portalParent.Fd())
	destinationFD, err := unix.Openat(parentFD, temporary, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		destinationFD, err = unix.Openat(parentFD, temporary, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		created = err == nil
	}
	if err != nil {
		return err
	}
	destination := os.NewFile(uintptr(destinationFD), temporary)
	defer destination.Close()
	var destinationBefore unix.Stat_t
	if err := unix.Fstat(destinationFD, &destinationBefore); err != nil || destinationBefore.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(destinationBefore.Mode).Perm() != 0o600 || destinationBefore.Size < 0 || destinationBefore.Size > sourceBefore.Size ||
		!((destinationBefore.Uid == uid && destinationBefore.Gid == gid) || (destinationBefore.Uid == 0 && destinationBefore.Gid == 0)) {
		return errors.New("existing Portal temporary file is not an adoptable journal-bound partial")
	}
	if destinationBefore.Size > 0 {
		matches, err := equalFilePrefix(source, destination, destinationBefore.Size)
		if err != nil || !matches {
			return errors.New("existing Portal temporary prefix conflicts with the verified stage; archive it before retry")
		}
	}
	if err := destination.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if err := destination.Chmod(0o600); err != nil {
		return err
	}
	if _, err := source.Seek(destinationBefore.Size, io.SeekStart); err != nil {
		return err
	}
	if _, err := destination.Seek(destinationBefore.Size, io.SeekStart); err != nil {
		return err
	}
	written, copyErr := io.Copy(destination, source)
	if copyErr != nil || written != sourceBefore.Size-destinationBefore.Size {
		return errors.New("copy staged Portal database")
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	var sourceAfter unix.Stat_t
	if err := unix.Fstat(sourceFD, &sourceAfter); err != nil || sourceAfter.Dev != sourceBefore.Dev || sourceAfter.Ino != sourceBefore.Ino || sourceAfter.Size != sourceBefore.Size || sourceAfter.Mtim != sourceBefore.Mtim {
		return errors.New("staged Portal database changed during copy")
	}
	sourceHashAfter, err := hashOpenAt(stageFD, "portal/portal.db", sourceBefore)
	if err != nil || sourceHashAfter != expectedSHA256 {
		return errors.New("staged Portal database changed during copy")
	}
	var destinationAfter unix.Stat_t
	if err := unix.Fstat(destinationFD, &destinationAfter); err != nil || destinationAfter.Uid != uid || destinationAfter.Gid != gid || os.FileMode(destinationAfter.Mode).Perm() != 0o600 || destinationAfter.Size != sourceBefore.Size {
		return errors.New("Portal temporary file metadata readback failed")
	}
	destinationHash, err := hashOpenAt(parentFD, temporary, destinationAfter)
	if err != nil || destinationHash != expectedSHA256 {
		return errors.New("Portal temporary file content readback failed")
	}
	if created || destinationBefore.Size != sourceBefore.Size {
		return unix.Fsync(parentFD)
	}
	return nil
}

func equalFilePrefix(first, second *os.File, length int64) (bool, error) {
	if length < 0 {
		return false, errors.New("negative publication prefix length")
	}
	if _, err := first.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if _, err := second.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	firstBuffer := make([]byte, 1024*1024)
	secondBuffer := make([]byte, len(firstBuffer))
	remaining := length
	for remaining > 0 {
		chunk := int64(len(firstBuffer))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := io.ReadFull(first, firstBuffer[:chunk]); err != nil {
			return false, err
		}
		if _, err := io.ReadFull(second, secondBuffer[:chunk]); err != nil {
			return false, err
		}
		for index := int64(0); index < chunk; index++ {
			if firstBuffer[index] != secondBuffer[index] {
				return false, nil
			}
		}
		remaining -= chunk
	}
	return true, nil
}

func publishNoReplace(parent *os.File, temporary, final string) error {
	if parent == nil || filepath.Base(temporary) != temporary || filepath.Base(final) != final {
		return errors.New("atomic publication name is invalid")
	}
	if err := unix.Renameat2(int(parent.Fd()), temporary, int(parent.Fd()), final, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("atomically publish without replacement: %w", err)
	}
	return unix.Fsync(int(parent.Fd()))
}

func pathExistsAt(parent *os.File, name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}
