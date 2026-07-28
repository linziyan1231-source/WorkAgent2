//go:build linux

package wincapture

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const localResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

func stableFileStat(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Nlink == after.Nlink &&
		before.Uid == after.Uid && before.Gid == after.Gid && before.Size == after.Size && before.Blocks == after.Blocks &&
		before.Mtim.Sec == after.Mtim.Sec && before.Mtim.Nsec == after.Mtim.Nsec &&
		before.Ctim.Sec == after.Ctim.Sec && before.Ctim.Nsec == after.Ctim.Nsec
}

func openPrivateRoot(directory string, expectedUID uint32) (int, unix.Stat_t, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return -1, unix.Stat_t{}, errors.New("capture directory path must be clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return -1, unix.Stat_t{}, errors.New("capture directory path must not contain symbolic links")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return -1, unix.Stat_t{}, errors.New("capture directory must be a real private 0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Gid != expectedUID {
		return -1, unix.Stat_t{}, errors.New("capture directory ownership is invalid")
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("open private capture directory")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Dev != uint64(stat.Dev) || opened.Ino != stat.Ino || opened.Uid != expectedUID || opened.Gid != expectedUID || os.FileMode(opened.Mode).Perm() != 0o700 {
		unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("capture directory changed while it was opened")
	}
	return fd, opened, nil
}

func mkdirAllAt(rootFD int, relative string, expectedUID uint32) error {
	if !safeCapturedRelative(relative) {
		return errors.New("unsafe local capture directory")
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	open := true
	defer func() {
		if open {
			_ = unix.Close(current)
		}
	}()
	for _, component := range splitRelative(relative) {
		if err := unix.Mkdirat(current, component, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return errors.New("create private capture directory")
		}
		child, err := unix.Openat2(current, component, &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags,
		})
		if err != nil {
			return errors.New("open private capture directory component")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(child, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != expectedUID || stat.Gid != expectedUID || os.FileMode(stat.Mode).Perm() != 0o700 {
			unix.Close(child)
			return errors.New("private capture directory component is unsafe")
		}
		_ = unix.Close(current)
		current = child
	}
	open = false
	_ = unix.Close(current)
	return nil
}

func createFileAt(rootFD int, relative string) (*os.File, error) {
	return createFileAtMode(rootFD, relative, 0o600)
}

func createFileAtMode(rootFD int, relative string, mode os.FileMode) (*os.File, error) {
	if !safeCapturedRelative(relative) {
		return nil, errors.New("unsafe local capture file path")
	}
	if mode != 0o600 && mode != 0o700 {
		return nil, errors.New("unsafe local capture file mode")
	}
	parent := path.Dir(relative)
	parentFD := rootFD
	owned := false
	if parent != "." {
		fd, err := unix.Openat2(rootFD, parent, &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags,
		})
		if err != nil {
			return nil, errors.New("open private capture file parent")
		}
		parentFD, owned = fd, true
	}
	if owned {
		defer unix.Close(parentFD)
	}
	fd, err := unix.Openat2(parentFD, path.Base(relative), &unix.OpenHow{
		Flags: uint64(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC), Mode: uint64(mode), Resolve: localResolveFlags,
	})
	if err != nil {
		return nil, errors.New("create private capture file")
	}
	if err := unix.Fchmod(fd, uint32(mode)); err != nil {
		unix.Close(fd)
		return nil, errors.New("secure private capture file mode")
	}
	return os.NewFile(uintptr(fd), "private-capture-file"), nil
}

func createSymlinkAt(rootFD int, relative, target string) error {
	if !safeCapturedRelative(relative) || target == "" || strings.ContainsRune(target, '\x00') {
		return errors.New("unsafe local capture symbolic link")
	}
	parent := path.Dir(relative)
	parentFD := rootFD
	owned := false
	if parent != "." {
		fd, err := unix.Openat2(rootFD, parent, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
		if err != nil {
			return errors.New("open private capture symbolic-link parent")
		}
		parentFD, owned = fd, true
	}
	if owned {
		defer unix.Close(parentFD)
	}
	if err := unix.Symlinkat(target, parentFD, path.Base(relative)); err != nil {
		return errors.New("create private captured symbolic link")
	}
	return nil
}

func setDirectoryMTimeAt(rootFD int, relative string, seconds int64) error {
	if !safeCapturedRelative(relative) {
		return errors.New("unsafe captured directory timestamp path")
	}
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return errors.New("open captured directory for timestamp")
	}
	defer unix.Close(fd)
	if err := unix.Futimes(fd, captureTimevals(seconds)); err != nil {
		return errors.New("set captured directory timestamp")
	}
	return nil
}

func setSymlinkMTimeAt(rootFD int, relative string, seconds int64) error {
	if !safeCapturedRelative(relative) {
		return errors.New("unsafe captured symbolic-link timestamp path")
	}
	parent := path.Dir(relative)
	parentFD := rootFD
	owned := false
	if parent != "." {
		fd, err := unix.Openat2(rootFD, parent, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
		if err != nil {
			return errors.New("open captured symbolic-link timestamp parent")
		}
		parentFD, owned = fd, true
	}
	if owned {
		defer unix.Close(parentFD)
	}
	times := []unix.Timespec{{Sec: seconds}, {Sec: seconds}}
	if err := unix.UtimesNanoAt(parentFD, path.Base(relative), times, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return errors.New("set captured symbolic-link timestamp")
	}
	return nil
}

func captureTimevals(seconds int64) []unix.Timeval {
	return []unix.Timeval{{Sec: seconds}, {Sec: seconds}}
}

func writePrivateJSONAt(rootFD int, relative string, value any) error {
	payload, err := marshalPrivateJSON(value)
	if err != nil {
		return err
	}
	defer clear(payload)
	return writePrivatePayloadAt(rootFD, relative, payload)
}

func writePrivatePayloadAt(rootFD int, relative string, payload []byte) error {
	if len(payload) < 1 || len(payload) > maxRehearsalMetadataBytes {
		return errors.New("private capture metadata payload is invalid")
	}
	file, err := createFileAt(rootFD, relative)
	if err != nil {
		return err
	}
	if written, err := file.Write(payload); err != nil || written != len(payload) {
		file.Close()
		return errors.New("write private capture metadata")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync private capture metadata")
	}
	return file.Close()
}

func copyPrivateLocalInput(rootFD int, input LocalFile, expectedUID uint32) error {
	source, before, err := openPrivateLocalInput(input, expectedUID)
	if err != nil {
		return err
	}
	if parent := path.Dir(input.Destination); parent != "." {
		if err := mkdirAllAt(rootFD, parent, expectedUID); err != nil {
			source.Close()
			return err
		}
	}
	destination, err := createFileAt(rootFD, input.Destination)
	if err != nil {
		source.Close()
		return err
	}
	digest, copyErr := consumePrivateLocalInput(source, before, input.MaxBytes, destination)
	closeSourceErr := source.Close()
	if copyErr != nil || closeSourceErr != nil || digest != input.SHA256 {
		destination.Close()
		return errors.New("private local capture input content is invalid")
	}
	if err := destination.Sync(); err != nil {
		destination.Close()
		return errors.New("sync private local capture input")
	}
	return destination.Close()
}

func verifyPrivateLocalInputs(inputs []LocalFile, expectedUID uint32) error {
	for index, input := range inputs {
		source, before, err := openPrivateLocalInput(input, expectedUID)
		if err != nil {
			return fmt.Errorf("private local input %d is not ready: %w", index+1, err)
		}
		digest, readErr := consumePrivateLocalInput(source, before, input.MaxBytes, nil)
		closeErr := source.Close()
		if readErr != nil || closeErr != nil || digest != input.SHA256 {
			return fmt.Errorf("private local input %d content is invalid", index+1)
		}
	}
	return nil
}

func openPrivateLocalInput(input LocalFile, expectedUID uint32) (*os.File, unix.Stat_t, error) {
	if err := validateAbsoluteFilePath(input.SourcePath, "private local input"); err != nil {
		return nil, unix.Stat_t{}, err
	}
	parent := filepath.Dir(input.SourcePath)
	parentFD, _, err := openPrivateRoot(parent, expectedUID)
	if err != nil {
		return nil, unix.Stat_t{}, errors.New("private local input parent is unsafe")
	}
	defer unix.Close(parentFD)
	leaf := filepath.Base(input.SourcePath)
	if !safePrivateLeaf(leaf) {
		return nil, unix.Stat_t{}, errors.New("private local input filename is unsafe")
	}
	fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return nil, unix.Stat_t{}, errors.New("open private local capture input")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 ||
		stat.Uid != expectedUID || stat.Gid != expectedUID || stat.Nlink != 1 || stat.Size < 0 || stat.Size > input.MaxBytes {
		unix.Close(fd)
		return nil, unix.Stat_t{}, errors.New("private local capture input is unsafe")
	}
	return os.NewFile(uintptr(fd), "private-local-capture-input"), stat, nil
}

func consumePrivateLocalInput(source *os.File, before unix.Stat_t, maximum int64, destination io.Writer) (string, error) {
	hasher := sha256New()
	writers := []io.Writer{hasher}
	if destination != nil {
		writers = append(writers, destination)
	}
	written, err := io.Copy(io.MultiWriter(writers...), io.LimitReader(source, maximum+1))
	var after unix.Stat_t
	if statErr := unix.Fstat(int(source.Fd()), &after); err != nil || statErr != nil || written != before.Size || written > maximum || !stableFileStat(before, after) {
		return "", errors.New("private local capture input changed while it was read")
	}
	return hexDigest(hasher), nil
}

func syncPrivateTree(rootFD int, expectedUID uint32) error {
	return syncDirectoryAt(rootFD, uint64(expectedUID), true)
}

func syncDirectoryAt(directoryFD int, expectedUID uint64, root bool) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "capture-sync-directory")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || !fs.ValidPath(name) {
			return errors.New("capture tree contains an unsafe entry")
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(stat.Uid) != expectedUID || uint64(stat.Gid) != expectedUID {
			return errors.New("capture tree entry ownership is invalid")
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if os.FileMode(stat.Mode).Perm() != 0o700 {
				return errors.New("capture tree directory mode is invalid")
			}
			child, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
			if err != nil {
				return errors.New("open capture tree directory")
			}
			err = syncDirectoryAt(child, expectedUID, false)
			unix.Close(child)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			mode := os.FileMode(stat.Mode).Perm()
			if (mode != 0o600 && mode != 0o700) || stat.Nlink != 1 {
				return errors.New("capture tree file mode or link count is invalid")
			}
			fileFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
			if err != nil {
				return errors.New("open capture tree file")
			}
			err = unix.Fsync(fileFD)
			unix.Close(fileFD)
			if err != nil {
				return errors.New("sync capture tree file")
			}
		case unix.S_IFLNK:
			if stat.Nlink != 1 {
				return errors.New("capture tree symbolic-link count is invalid")
			}
		default:
			return errors.New("capture tree contains a link or special file")
		}
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return errors.New("sync capture tree directory")
	}
	_ = root
	return nil
}

func syncPathDirectory(directory string) error {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func publishNoReplace(partial, destination string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, partial, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fs.ErrExist
		}
		return fmt.Errorf("publish final capture without replacement: %w", err)
	}
	return nil
}

func splitRelative(relative string) []string {
	var result []string
	for relative != "" && relative != "." {
		component := relative
		if slash := strings.IndexByte(relative, '/'); slash >= 0 {
			component, relative = relative[:slash], relative[slash+1:]
		} else {
			relative = ""
		}
		result = append(result, component)
	}
	return result
}

func statFreeBytes(directory string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(directory, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("capture destination block size is invalid")
	}
	blockSize := uint64(stat.Bsize)
	if stat.Bavail > ^uint64(0)/blockSize {
		return 0, errors.New("capture destination free-space value overflows")
	}
	return stat.Bavail * blockSize, nil
}
