package storageusage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const secureResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

// MeasureTree returns the logical size of regular files beneath root. Every
// directory is opened relative to a pinned root descriptor with symlinks,
// magic links, and mount crossings disabled. This keeps a tenant-controlled
// rename race from redirecting accounting outside the private tree.
func MeasureTree(ctx context.Context, root string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return 0, errors.New("storage root must be a clean absolute path")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return 0, fmt.Errorf("inspect storage root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, errors.New("storage root must be a real directory")
	}
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return 0, fmt.Errorf("open storage root: %w", err)
	}
	defer unix.Close(rootFD)
	return measureDirectory(ctx, rootFD, ".")
}

func measureDirectory(ctx context.Context, rootFD int, relative string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: secureResolve,
	}
	directoryFD, err := unix.Openat2(rootFD, filepath.ToSlash(relative), how)
	if err != nil {
		return 0, err
	}
	directory := os.NewFile(uintptr(directoryFD), relative)
	children := make([]string, 0)
	var used uint64
	for {
		if err := ctx.Err(); err != nil {
			_ = directory.Close()
			return 0, err
		}
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				_ = directory.Close()
				return 0, err
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(directoryFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				_ = directory.Close()
				return 0, fmt.Errorf("inspect private storage entry: %w", err)
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				children = append(children, filepath.Join(relative, entry.Name()))
			case unix.S_IFREG:
				if stat.Size < 0 {
					_ = directory.Close()
					return 0, errors.New("private storage file size is invalid")
				}
				if err := addSize(&used, uint64(stat.Size)); err != nil {
					_ = directory.Close()
					return 0, err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = directory.Close()
			return 0, fmt.Errorf("read private storage directory: %w", readErr)
		}
	}
	if err := directory.Close(); err != nil {
		return 0, fmt.Errorf("close private storage directory: %w", err)
	}
	for _, child := range children {
		childUsed, err := measureDirectory(ctx, rootFD, child)
		if err != nil {
			// A tenant may remove an entry or replace it with a link while it is
			// being measured. Such a path is omitted; it is never followed.
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
				continue
			}
			return 0, fmt.Errorf("measure private storage directory: %w", err)
		}
		if err := addSize(&used, childUsed); err != nil {
			return 0, err
		}
	}
	return used, nil
}

func addSize(total *uint64, size uint64) error {
	if total == nil || math.MaxUint64-*total < size {
		return errors.New("private storage usage overflowed")
	}
	*total += size
	return nil
}
