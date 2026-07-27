//go:build linux

package winmigration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func copyTenantTree(ctx context.Context, snapshotFD int, tenant plannedTenant, destination string) error {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	sourceFD, err := openAt(snapshotFD, tenant.sourceRelative, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer unix.Close(sourceFD)
	for _, entry := range tenant.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		output, err := outputRelative(entry.Path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(output))
		if !pathWithin(destination, target) {
			return errors.New("tenant output path escapes the staging root")
		}
		switch entry.Kind {
		case 'd':
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
		case 'f':
			if err := copyPlannedFile(sourceFD, entry, target); err != nil {
				return err
			}
		case 'x':
			continue
		case 'l':
			current, err := secureReadlink(sourceFD, entry.Path)
			if err != nil || current != entry.LinkTarget {
				return fmt.Errorf("source symlink %q changed during copy", entry.Path)
			}
			rewritten, _, err := rewriteBuiltinLink(output, current, tenant.windowsLeaf)
			if err != nil {
				return err
			}
			if err := os.Symlink(filepath.FromSlash(rewritten), target); err != nil {
				return err
			}
		default:
			return errors.New("planned tenant entry has an invalid type")
		}
	}
	directories := append([]treeEntry(nil), tenant.entries...)
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i].Path, "/") > strings.Count(directories[j].Path, "/")
	})
	for _, entry := range directories {
		if entry.Kind != 'd' {
			continue
		}
		output, _ := outputRelative(entry.Path)
		target := filepath.Join(destination, filepath.FromSlash(output))
		stamp := time.Unix(0, entry.ModUnixNano)
		if err := os.Chtimes(target, stamp, stamp); err != nil {
			return err
		}
		if err := os.Chmod(target, 0o700); err != nil {
			return err
		}
		if err := syncDirectory(target); err != nil {
			return err
		}
	}
	return syncDirectory(destination)
}

func copyExternalWorkspace(ctx context.Context, snapshotFD int, tenantRoot string, workspace plannedExternalWorkspace) error {
	destination := filepath.Join(tenantRoot, filepath.FromSlash(workspace.destinationRelative))
	if !pathWithin(tenantRoot, destination) {
		return errors.New("external workspace output path escapes the tenant staging root")
	}
	if err := ensurePrivateDirectoryPath(tenantRoot, filepath.Dir(destination)); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	sourceFD, err := openAt(snapshotFD, workspace.sourceRelative, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer unix.Close(sourceFD)
	for _, entry := range workspace.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.Path))
		if !pathWithin(destination, target) {
			return errors.New("external workspace entry escapes its staging destination")
		}
		switch entry.Kind {
		case 'd':
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
		case 'f':
			if err := copyPlannedFile(sourceFD, entry, target); err != nil {
				return err
			}
		default:
			return errors.New("external workspace plan contains a non-regular entry")
		}
	}
	directories := append([]treeEntry(nil), workspace.entries...)
	sort.Slice(directories, func(i, j int) bool {
		return strings.Count(directories[i].Path, "/") > strings.Count(directories[j].Path, "/")
	})
	for _, entry := range directories {
		if entry.Kind != 'd' {
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(entry.Path))
		stamp := time.Unix(0, entry.ModUnixNano)
		if err := os.Chtimes(target, stamp, stamp); err != nil {
			return err
		}
		if err := os.Chmod(target, 0o700); err != nil {
			return err
		}
		if err := syncDirectory(target); err != nil {
			return err
		}
	}
	if err := syncDirectory(destination); err != nil {
		return err
	}
	return verifyCopiedExternalWorkspace(destination, workspace)
}

func ensurePrivateDirectoryPath(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("private directory path escapes its root")
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("external workspace destination ancestor is unsafe")
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func verifyCopiedExternalWorkspace(destination string, workspace plannedExternalWorkspace) error {
	expected := make(map[string]treeEntry, len(workspace.entries))
	for _, entry := range workspace.entries {
		expected[entry.Path] = entry
	}
	seen := 0
	err := filepath.WalkDir(destination, func(fullPath string, directoryEntry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fullPath == destination {
			return nil
		}
		relative, err := filepath.Rel(destination, fullPath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		planned, exists := expected[relative]
		if !exists {
			return errors.New("external workspace output contains an unplanned entry")
		}
		info, err := os.Lstat(fullPath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("external workspace output contains an unsafe entry")
		}
		switch planned.Kind {
		case 'd':
			if !info.IsDir() || info.Mode().Perm() != 0o700 {
				return errors.New("external workspace output directory is not private")
			}
		case 'f':
			wantedMode := os.FileMode(0o600)
			if planned.Mode&0o100 != 0 {
				wantedMode = 0o700
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != wantedMode || info.Size() != planned.Size {
				return errors.New("external workspace output file metadata is invalid")
			}
			digest, err := hashLocalRegularFile(fullPath)
			if err != nil || digest != planned.SHA256 {
				return errors.New("external workspace output file content is invalid")
			}
		default:
			return errors.New("external workspace output plan contains an unsafe entry")
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(expected) {
		return errors.New("external workspace output is incomplete")
	}
	return nil
}

func copyPlannedFile(sourceRootFD int, entry treeEntry, target string) error {
	fd, err := openAt(sourceRootFD, entry.Path, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", entry.Path, err)
	}
	source := os.NewFile(uintptr(fd), "tenant-source-file")
	if source == nil {
		unix.Close(fd)
		return errors.New("create source file handle")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
		return fmt.Errorf("source file %q changed before copy", entry.Path)
	}
	mode := os.FileMode(0o600)
	if entry.Mode&0o100 != 0 {
		mode = 0o700
	}
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = destination.Close()
		if remove {
			_ = os.Remove(target)
		}
	}()
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, digest), source)
	if copyErr != nil || written != entry.Size || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("source file %q changed during copy", entry.Path)
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	stamp := time.Unix(0, entry.ModUnixNano)
	if err := os.Chtimes(target, stamp, stamp); err != nil {
		return err
	}
	remove = false
	return nil
}

func secureReadlink(rootFD int, relative string) (string, error) {
	parent, name := filepath.ToSlash(filepath.Dir(relative)), filepath.Base(relative)
	parentFD := rootFD
	owned := false
	if parent != "." {
		var err error
		parentFD, err = openAt(rootFD, parent, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return "", err
		}
		owned = true
	}
	if owned {
		defer unix.Close(parentFD)
	}
	buffer := make([]byte, 32*1024)
	length, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil || length == len(buffer) {
		return "", errors.New("read secure symbolic link")
	}
	return string(buffer[:length]), nil
}

func copySecureSnapshotFile(snapshotFD int, relative, target, expectedHash string) error {
	fd, err := openAt(snapshotFD, relative, unix.O_RDONLY)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), "snapshot-backup-source")
	if source == nil {
		unix.Close(fd)
		return errors.New("create source file handle")
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, digest), source)
	if copyErr != nil || hex.EncodeToString(digest.Sum(nil)) != expectedHash {
		destination.Close()
		_ = os.Remove(target)
		return errors.New("snapshot file changed during archival")
	}
	if err := destination.Sync(); err != nil {
		destination.Close()
		_ = os.Remove(target)
		return err
	}
	return destination.Close()
}

func copyLocalRegularFile(sourcePath, target string) error {
	info, err := os.Lstat(sourcePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("local backup source is not a regular file")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		_ = os.Remove(target)
		return err
	}
	if err := destination.Sync(); err != nil {
		destination.Close()
		_ = os.Remove(target)
		return err
	}
	return destination.Close()
}
