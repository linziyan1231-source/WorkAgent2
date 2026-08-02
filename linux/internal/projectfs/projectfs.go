package projectfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const MaxNameRunes = 100

var reservedProjectNames = map[string]struct{}{
	"conversations":   {},
	"inbound":         {},
	"sessions":        {},
	"skills":          {},
	"runtime":         {},
	"builtin-skills":  {},
	"aionrs-sessions": {},
}

const secureResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

type Root struct {
	path string
	file *os.File
}

func OpenRoot(path string) (*Root, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("project root must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect project root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("project root must be a real directory")
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open project root: %w", err)
	}
	return &Root{path: path, file: os.NewFile(uintptr(fd), path)}, nil
}

func (r *Root) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	return r.file.Close()
}

func (r *Root) Path() string { return r.path }

func (r *Root) ValidatePrivateOwner(expectedUID uint32) error {
	if r == nil || r.file == nil || expectedUID == 0 {
		return errors.New("private root owner is invalid")
	}
	var info unix.Stat_t
	if err := unix.Fstat(int(r.file.Fd()), &info); err != nil {
		return fmt.Errorf("inspect open private root: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != expectedUID || os.FileMode(info.Mode).Perm() != 0o700 {
		return errors.New("private root must be a 0700 directory owned by the expected UID")
	}
	return nil
}

func (r *Root) Open(relative string, flags int, mode os.FileMode) (*os.File, error) {
	if err := validRelative(relative, true); err != nil {
		return nil, err
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Mode:    uint64(mode.Perm()),
		Resolve: secureResolve,
	}
	fd, err := unix.Openat2(int(r.file.Fd()), filepath.ToSlash(relative), how)
	if err != nil {
		return nil, fmt.Errorf("securely open project path: %w", err)
	}
	return os.NewFile(uintptr(fd), filepath.Join(r.path, relative)), nil
}

func (r *Root) ReadFile(relative string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("maximum read size must be positive")
	}
	file, err := r.Open(relative, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("project file is not a permitted regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("project file exceeds the read limit")
	}
	return data, nil
}

func (r *Root) ReadDir(relative string) ([]os.DirEntry, error) {
	file, err := r.Open(relative, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.ReadDir(-1)
}

func (r *Root) CreateDirectory(name string, mode os.FileMode) error {
	if !ValidName(name) {
		return errors.New("invalid project name")
	}
	if mode.Perm()&0o077 != 0 || mode.Perm() == 0 {
		return errors.New("project directory mode must be private")
	}
	if err := unix.Mkdirat(int(r.file.Fd()), name, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("create project directory: %w", err)
	}
	return nil
}

func (r *Root) EnsureDirectory(relative string, mode os.FileMode) error {
	if err := validRelative(relative, false); err != nil {
		return err
	}
	if mode.Perm() == 0 || mode.Perm()&0o077 != 0 {
		return errors.New("directory mode must be private")
	}
	current, err := unix.Dup(int(r.file.Fd()))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("directory path contains an invalid component")
		}
		if err := unix.Mkdirat(current, part, uint32(mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create private directory: %w", err)
		}
		how := &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: secureResolve}
		next, err := unix.Openat2(current, part, how)
		if err != nil {
			return fmt.Errorf("open private directory: %w", err)
		}
		info := unix.Stat_t{}
		if err := unix.Fstat(next, &info); err != nil || os.FileMode(info.Mode).Perm()&0o077 != 0 {
			_ = unix.Close(next)
			return errors.New("private directory permissions are unsafe")
		}
		_ = unix.Close(current)
		current = next
	}
	return nil
}

func (r *Root) WriteFile(relative string, data []byte, mode os.FileMode) error {
	return r.WriteFileAtomic(relative, data, mode)
}

type fileOwner struct {
	uid uint32
	gid uint32
}

// WriteFileAtomic replaces a private regular file only after its complete
// contents have reached stable storage. The parent directory is resolved from
// the already-open root, so a concurrently inserted symlink cannot redirect
// the write outside the tenant tree.
func (r *Root) WriteFileAtomic(relative string, data []byte, mode os.FileMode) error {
	return r.writeFileAtomic(relative, data, mode, nil)
}

// WriteFileAtomicOwned has the same openat2-confined, durable replacement
// semantics as WriteFileAtomic, but activates the file under an explicit
// non-root tenant identity. If a destination already exists, its ownership and
// mode must already match; this prevents a privileged migration helper from
// silently replacing a foreign or less-protected file.
func (r *Root) WriteFileAtomicOwned(relative string, data []byte, mode os.FileMode, uid, gid uint32) error {
	if uid == 0 || gid == 0 {
		return errors.New("owned private file requires a non-root UID and GID")
	}
	return r.writeFileAtomic(relative, data, mode, &fileOwner{uid: uid, gid: gid})
}

func (r *Root) writeFileAtomic(relative string, data []byte, mode os.FileMode, owner *fileOwner) error {
	if err := validRelative(relative, false); err != nil {
		return err
	}
	if mode.Perm() == 0 || mode.Perm()&0o077 != 0 {
		return errors.New("file mode must be private")
	}
	parent, base, err := r.openParent(relative)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var existing unix.Stat_t
	if err := unix.Fstatat(parent, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("refusing to replace a non-regular file")
		}
		if owner != nil && (existing.Uid != owner.uid || existing.Gid != owner.gid || os.FileMode(existing.Mode).Perm() != mode.Perm()) {
			return errors.New("refusing to replace a private file with conflicting ownership or mode")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect destination file: %w", err)
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("create temporary file name: %w", err)
	}
	temporary := "." + base + ".tmp-" + hex.EncodeToString(random)
	fd, err := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return fmt.Errorf("create temporary private file: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(filepath.Dir(filepath.Join(r.path, relative)), temporary))
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = unix.Unlinkat(parent, temporary, 0)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("protect temporary private file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary private file: %w", err)
	}
	if owner != nil {
		if err := file.Chown(int(owner.uid), int(owner.gid)); err != nil {
			return fmt.Errorf("set temporary private file ownership: %w", err)
		}
		// Linux may clear mode bits during chown. Reassert the exact private mode
		// before the payload is synced and made visible.
		if err := file.Chmod(mode); err != nil {
			return fmt.Errorf("restore temporary private file mode: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary private file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary private file: %w", err)
	}
	if err := unix.Renameat(parent, temporary, parent, base); err != nil {
		return fmt.Errorf("activate private file: %w", err)
	}
	removeTemporary = false
	if err := unix.Fsync(parent); err != nil {
		return fmt.Errorf("sync private file directory: %w", err)
	}
	return nil
}

func (r *Root) RemoveFile(relative string) error {
	if err := validRelative(relative, false); err != nil {
		return err
	}
	parent, base, err := r.openParent(relative)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var info unix.Stat_t
	if err := unix.Fstatat(parent, base, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("refusing to remove a non-regular file")
	}
	if err := unix.Unlinkat(parent, base, 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func (r *Root) RotateFile(relative string, maximumSize int64, generations int) error {
	if err := validRelative(relative, false); err != nil {
		return err
	}
	if maximumSize < 1024*1024 || generations < 1 || generations > 20 {
		return errors.New("file rotation limits are invalid")
	}
	parent, base, err := r.openParent(relative)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var current unix.Stat_t
	if err := unix.Fstatat(parent, base, &current, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if current.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("refusing to rotate a non-regular file")
	}
	if current.Size < maximumSize {
		return nil
	}
	oldest := fmt.Sprintf("%s.%d", base, generations)
	var oldestInfo unix.Stat_t
	if err := unix.Fstatat(parent, oldest, &oldestInfo, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if oldestInfo.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("refusing to replace a non-regular rotated file")
		}
		if err := unix.Unlinkat(parent, oldest, 0); err != nil {
			return err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	for generation := generations - 1; generation >= 1; generation-- {
		source := fmt.Sprintf("%s.%d", base, generation)
		target := fmt.Sprintf("%s.%d", base, generation+1)
		var info unix.Stat_t
		if err := unix.Fstatat(parent, source, &info, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
			continue
		} else if err != nil {
			return err
		}
		if info.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("rotated log generation is not regular")
		}
		if err := unix.Renameat2(parent, source, parent, target, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
	}
	if err := unix.Renameat2(parent, base, parent, base+".1", unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func (r *Root) openParent(relative string) (int, string, error) {
	if err := validRelative(relative, false); err != nil {
		return -1, "", err
	}
	parentPath := filepath.ToSlash(filepath.Dir(relative))
	base := filepath.Base(relative)
	how := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: secureResolve}
	fd, err := unix.Openat2(int(r.file.Fd()), parentPath, how)
	if err != nil {
		return -1, "", fmt.Errorf("securely open parent directory: %w", err)
	}
	return fd, base, nil
}

func (r *Root) RenameDirectory(oldName, newName string) error {
	if !ValidName(oldName) || !ValidName(newName) {
		return errors.New("invalid project name")
	}
	file, err := r.Open(oldName, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file.Close()
	if err := unix.Renameat2(int(r.file.Fd()), oldName, int(r.file.Fd()), newName, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("rename project directory: %w", err)
	}
	return r.syncDirectory()
}

func (r *Root) ValidateDirectory(name string, expectedUID uint32) error {
	if !ValidName(name) {
		return errors.New("invalid private project directory")
	}
	file, err := r.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &info); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != expectedUID || os.FileMode(info.Mode).Perm()&0o077 != 0 {
		return errors.New("project directory is not private or tenant-owned")
	}
	return nil
}

func (r *Root) DirectoryExists(name string) (bool, error) {
	if !ValidName(name) {
		return false, errors.New("invalid private project directory")
	}
	file, err := r.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, file.Close()
}

// RollbackMovedDirectory reverses an interrupted legacy-root move. It is
// restart-safe: entries already restored to the workspace are not revisited,
// and the operation can be retried while the durable journal remains present.
func (r *Root) RollbackMovedDirectory(name string) error {
	if !ValidName(name) {
		return errors.New("invalid legacy project directory")
	}
	target, err := r.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer target.Close()
	entries, err := target.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := unix.Renameat2(int(target.Fd()), entry.Name(), int(r.file.Fd()), entry.Name(), unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("restore legacy project entry %s: %w", entry.Name(), err)
		}
	}
	if err := unix.Fsync(int(target.Fd())); err != nil {
		return err
	}
	if err := r.syncDirectory(); err != nil {
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(r.file.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return r.syncDirectory()
}

// MoveEntriesToDirectory supports the legacy project whose workspace is the
// workspace root itself. It creates a named child and moves every non-preserved
// root entry into it. The returned finalizer must be called with true after the
// caller commits its database transaction, or false to roll the moves back.
func (r *Root) MoveEntriesToDirectory(newName string, preserved map[string]bool) (func(bool) error, error) {
	if !ValidName(newName) {
		return nil, errors.New("invalid project name")
	}
	if err := unix.Mkdirat(int(r.file.Fd()), newName, 0o700); err != nil {
		return nil, fmt.Errorf("create legacy project directory: %w", err)
	}
	target, err := r.Open(newName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Unlinkat(int(r.file.Fd()), newName, unix.AT_REMOVEDIR)
		return nil, err
	}
	entries, err := r.ReadDir(".")
	if err != nil {
		target.Close()
		_ = unix.Unlinkat(int(r.file.Fd()), newName, unix.AT_REMOVEDIR)
		return nil, err
	}
	moved := make([]string, 0, len(entries))
	rollback := func() error {
		var result error
		for index := len(moved) - 1; index >= 0; index-- {
			name := moved[index]
			if err := unix.Renameat2(int(target.Fd()), name, int(r.file.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
				result = errors.Join(result, fmt.Errorf("roll back legacy project entry %s: %w", name, err))
			}
		}
		if err := unix.Fsync(int(target.Fd())); err != nil {
			result = errors.Join(result, err)
		}
		if err := r.syncDirectory(); err != nil {
			result = errors.Join(result, err)
		}
		if err := target.Close(); err != nil {
			result = errors.Join(result, err)
		}
		if err := unix.Unlinkat(int(r.file.Fd()), newName, unix.AT_REMOVEDIR); err != nil {
			result = errors.Join(result, fmt.Errorf("remove rolled-back legacy project directory: %w", err))
		}
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == newName || preserved[name] {
			continue
		}
		if err := unix.Renameat2(int(r.file.Fd()), name, int(target.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
			rollbackErr := rollback()
			return nil, errors.Join(fmt.Errorf("move legacy project entry %s: %w", name, err), rollbackErr)
		}
		moved = append(moved, name)
	}
	if err := unix.Fsync(int(target.Fd())); err != nil {
		return nil, errors.Join(err, rollback())
	}
	if err := r.syncDirectory(); err != nil {
		return nil, errors.Join(err, rollback())
	}
	return func(commit bool) error {
		if commit {
			return target.Close()
		}
		return rollback()
	}, nil
}

func (r *Root) syncDirectory() error {
	file, err := r.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func ValidName(name string) bool {
	if name == "" || name == "." || name == ".." || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > MaxNameRunes {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) || character == '/' || character == '\\' || character == 0 {
			return false
		}
	}
	return true
}

// ValidProjectName narrows a filesystem-safe name to the user-visible project
// namespace shared with AionCore. Dot-prefixed and runtime-reserved directory
// names are implementation storage, never projects.
func ValidProjectName(name string) bool {
	if !ValidName(name) || strings.HasPrefix(name, ".") {
		return false
	}
	_, reserved := reservedProjectNames[strings.ToLower(name)]
	return !reserved
}

func validRelative(value string, allowRoot bool) error {
	if value == "" || strings.ContainsRune(value, 0) || strings.ContainsRune(value, '\\') || filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("path must be a clean relative Linux path")
	}
	if value == "." {
		if allowRoot {
			return nil
		}
		return errors.New("root path is not allowed")
	}
	if value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return errors.New("path escapes project root")
	}
	return nil
}
