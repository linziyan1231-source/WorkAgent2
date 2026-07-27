//go:build linux

package winmigration

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const sourceResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

func validateSnapshotRootMetadata(snapshotRoot string) error {
	fd, err := openSnapshotRoot(snapshotRoot)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 || os.FileMode(stat.Mode).Perm() != 0o700 {
		return errors.New("snapshot root must be an exact root:root 0700 real directory")
	}
	return nil
}

func openSnapshotRoot(snapshotRoot string) (int, error) {
	resolved, err := filepath.EvalSymlinks(snapshotRoot)
	if err != nil {
		return -1, fmt.Errorf("resolve snapshot root: %w", err)
	}
	if resolved != snapshotRoot {
		return -1, errors.New("snapshot root and all of its ancestors must be real directories")
	}
	fd, err := unix.Open(snapshotRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open snapshot root: %w", err)
	}
	return fd, nil
}

func openAt(rootFD int, relative string, flags int) (int, error) {
	if relative == "" || relative == "." || path.IsAbs(relative) || !fs.ValidPath(relative) {
		return -1, errors.New("invalid snapshot-relative path")
	}
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: sourceResolveFlags,
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func secureDirectoryNames(rootFD int, relative string) ([]string, error) {
	fd, err := openAt(rootFD, relative, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, fmt.Errorf("open tenant snapshot directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), "snapshot-directory")
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("read tenant snapshot directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return nil, errors.New("tenant snapshot contains an invalid directory name")
		}
		childFD, err := unix.Openat2(fd, name, &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: sourceResolveFlags,
		})
		if err != nil {
			return nil, fmt.Errorf("tenant snapshot entry %q is not a safe directory: %w", name, err)
		}
		unix.Close(childFD)
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

type treeInventory struct {
	entries     []treeEntry
	files       int
	directories int
	symlinks    int
	bytes       int64
	skipped     []string
	hash        string
}

func inventoryTree(ctx context.Context, snapshotFD int, relativeRoot string) (treeInventory, error) {
	rootFD, err := openAt(snapshotFD, relativeRoot, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return treeInventory{}, fmt.Errorf("open tenant source tree: %w", err)
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return treeInventory{}, err
	}
	var result treeInventory
	if err := scanDirectory(ctx, rootFD, "", uint64(rootStat.Dev), &result); err != nil {
		return treeInventory{}, err
	}
	sort.Slice(result.entries, func(i, j int) bool { return result.entries[i].Path < result.entries[j].Path })
	result.hash = hashEntries(result.entries)
	return result, nil
}

func scanDirectory(ctx context.Context, directoryFD int, relative string, rootDevice uint64, result *treeInventory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "snapshot-tree")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, directoryEntry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := directoryEntry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return errors.New("tenant tree contains an invalid entry name")
		}
		entryPath := name
		if relative != "" {
			entryPath = path.Join(relative, name)
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("inspect tenant entry %q: %w", entryPath, err)
		}
		kind := stat.Mode & unix.S_IFMT
		switch kind {
		case unix.S_IFDIR:
			childFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
				Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: sourceResolveFlags,
			})
			if err != nil {
				return fmt.Errorf("open tenant directory %q: %w", entryPath, err)
			}
			var opened unix.Stat_t
			if err := unix.Fstat(childFD, &opened); err != nil {
				unix.Close(childFD)
				return err
			}
			if uint64(opened.Dev) != rootDevice {
				unix.Close(childFD)
				return fmt.Errorf("tenant directory %q crosses a filesystem boundary", entryPath)
			}
			result.entries = append(result.entries, treeEntry{Path: entryPath, Kind: 'd', Mode: opened.Mode, ModUnixNano: statUnixNano(opened)})
			result.directories++
			err = scanDirectory(ctx, childFD, entryPath, rootDevice, result)
			unix.Close(childFD)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			fileFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{
				Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: sourceResolveFlags,
			})
			if err != nil {
				return fmt.Errorf("open tenant file %q: %w", entryPath, err)
			}
			var opened unix.Stat_t
			if err := unix.Fstat(fileFD, &opened); err != nil {
				unix.Close(fileFD)
				return err
			}
			if opened.Mode&unix.S_IFMT != unix.S_IFREG || uint64(opened.Dev) != rootDevice || opened.Ino != stat.Ino {
				unix.Close(fileFD)
				return fmt.Errorf("tenant file %q changed during inventory", entryPath)
			}
			digest, err := hashOpenFD(fileFD)
			if err != nil {
				return fmt.Errorf("hash tenant file %q: %w", entryPath, err)
			}
			entryKind := byte('f')
			if isAionTransient(entryPath) {
				entryKind = 'x'
				result.skipped = append(result.skipped, entryPath)
			} else {
				result.files++
				result.bytes += opened.Size
			}
			result.entries = append(result.entries, treeEntry{Path: entryPath, Kind: entryKind, Mode: opened.Mode, Size: opened.Size, ModUnixNano: statUnixNano(opened), SHA256: digest})
		case unix.S_IFLNK:
			buffer := make([]byte, 32*1024)
			length, err := unix.Readlinkat(directoryFD, name, buffer)
			if err != nil {
				return fmt.Errorf("read tenant symlink %q: %w", entryPath, err)
			}
			if length == len(buffer) {
				return fmt.Errorf("tenant symlink %q target is too long", entryPath)
			}
			var after unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || after.Mode&unix.S_IFMT != unix.S_IFLNK || after.Ino != stat.Ino {
				return fmt.Errorf("tenant symlink %q changed during inventory", entryPath)
			}
			result.entries = append(result.entries, treeEntry{Path: entryPath, Kind: 'l', Mode: after.Mode, ModUnixNano: statUnixNano(after), LinkTarget: string(buffer[:length])})
			result.symlinks++
		default:
			return fmt.Errorf("tenant entry %q is not a regular file, directory, or symbolic link", entryPath)
		}
	}
	return nil
}

func statUnixNano(stat unix.Stat_t) int64 {
	return stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec
}

func hashOpenFD(fd int) (string, error) {
	file := os.NewFile(uintptr(fd), "snapshot-file")
	if file == nil {
		unix.Close(fd)
		return "", errors.New("create snapshot file handle")
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func hashSecureFile(snapshotFD int, relative string) (string, int64, error) {
	fd, err := openAt(snapshotFD, relative, unix.O_RDONLY)
	if err != nil {
		return "", 0, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return "", 0, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return "", 0, errors.New("snapshot database is not a regular file")
	}
	digest, err := hashOpenFD(fd)
	return digest, stat.Size, err
}

func readSecureFile(snapshotFD int, relative string, maximum int64) ([]byte, error) {
	return readSecureFileWithMode(snapshotFD, relative, maximum, false)
}

func readSecurePrivateFile(snapshotFD int, relative string, maximum int64) ([]byte, error) {
	return readSecureFileWithMode(snapshotFD, relative, maximum, true)
}

func readSecureFileWithMode(snapshotFD int, relative string, maximum int64, requirePrivate bool) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("invalid secure read limit")
	}
	fd, err := openAt(snapshotFD, relative, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "snapshot-private-file")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("create snapshot file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum || (requirePrivate && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("snapshot file is not a bounded regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		clear(payload)
		return nil, errors.New("snapshot file could not be read safely")
	}
	return payload, nil
}

func hashEntries(entries []treeEntry) string {
	digest := sha256.New()
	for _, entry := range entries {
		writeHashField(digest, entry.Path)
		digest.Write([]byte{entry.Kind})
		var number [8]byte
		binary.BigEndian.PutUint64(number[:], uint64(entry.Mode))
		digest.Write(number[:])
		binary.BigEndian.PutUint64(number[:], uint64(entry.Size))
		digest.Write(number[:])
		binary.BigEndian.PutUint64(number[:], uint64(entry.ModUnixNano))
		digest.Write(number[:])
		writeHashField(digest, entry.SHA256)
		writeHashField(digest, entry.LinkTarget)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeHashField(digest hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	digest.Write(length[:])
	digest.Write([]byte(value))
}

func isAionTransient(relative string) bool {
	switch relative {
	case "data/aionui-backend.db-wal", "data/aionui-backend.db-shm", "data/aionui-backend.db.migrate.lock":
		return true
	default:
		return false
	}
}
