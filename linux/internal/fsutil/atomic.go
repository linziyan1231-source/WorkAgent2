// Package fsutil provides shared filesystem helpers: durable atomic file
// publication and path containment checks.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ErrUnsafeParent classifies an atomic-write parent that is missing, a
// symlink, not a directory, or group/world-writable when SafeParent is set.
var ErrUnsafeParent = errors.New("fsutil: atomic-write parent is missing or unsafe")

// ErrTargetExists classifies a no-replace publication whose target already exists.
var ErrTargetExists = errors.New("fsutil: atomic-write target already exists")

// AtomicOwner is an explicit ownership applied to the temporary file before publication.
type AtomicOwner struct {
	UID int
	GID int
}

// AtomicWriteOptions controls WriteFileAtomic publication semantics.
type AtomicWriteOptions struct {
	Mode      os.FileMode
	NoReplace bool
	Owner     *AtomicOwner
	// TempPattern names the temporary file inside the parent directory.
	TempPattern string
	// CheckParent requires the parent to be an existing, non-symlink directory.
	CheckParent bool
	// SafeParent additionally rejects a group/world-writable parent.
	SafeParent bool
	// CreateError, when non-nil, replaces the temporary-file creation error.
	CreateError error
	// WrapDirSync annotates a post-publication directory sync failure.
	WrapDirSync bool
}

// WriteFileAtomic publishes payload at path only after its complete contents
// have reached stable storage, then syncs the parent directory.
func WriteFileAtomic(path string, payload []byte, options AtomicWriteOptions) error {
	parent := filepath.Dir(path)
	if options.CheckParent || options.SafeParent {
		info, err := os.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || (options.SafeParent && info.Mode().Perm()&0o022 != 0) {
			return ErrUnsafeParent
		}
	}
	pattern := options.TempPattern
	if pattern == "" {
		pattern = ".workagent-*"
	}
	temporary, err := os.CreateTemp(parent, pattern)
	if err != nil {
		if options.CreateError != nil {
			return options.CreateError
		}
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(options.Mode); err != nil {
		temporary.Close()
		return err
	}
	if options.Owner != nil {
		if err := temporary.Chown(options.Owner.UID, options.Owner.GID); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if options.NoReplace {
		err = unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			return ErrTargetExists
		}
	} else {
		err = os.Rename(temporaryPath, path)
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		if options.WrapDirSync {
			return fmt.Errorf("sync atomic-write directory: %w", err)
		}
		return err
	}
	return nil
}
