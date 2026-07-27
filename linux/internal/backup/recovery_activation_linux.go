//go:build linux

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	recoveryInstallLockPath      = "/run/workagent-backup/recovery-install.lock"
	recoveryActivationPermitPath = "/run/workagent-backup/recovery-activation.permit"
	recoveryActivationLockPath   = "/run/workagent/activation.lock"
	recoveryBootIDPath           = "/proc/sys/kernel/random/boot_id"
	// The activation journal must survive a host reboot. A /run journal would
	// disappear precisely when recovery needs to undo a power-loss-interrupted
	// systemd enable/start sequence.
	recoveryActivationJournalPath = "/var/lib/workagent-backup/recovery-activation.json"
	maxRecoveryActivationJournal  = 256 * 1024
	maxRecoveryActivationPermit   = 512
)

type recoveryActivationJournal struct {
	SchemaVersion int      `json:"schema_version"`
	Units         []string `json:"units"`
}

type recoveryActivationPermit struct {
	SchemaVersion     int    `json:"schema_version"`
	BootID            string `json:"boot_id"`
	JournalDevice     uint64 `json:"journal_device"`
	JournalInode      uint64 `json:"journal_inode"`
	InstallLockDevice uint64 `json:"install_lock_device"`
	InstallLockInode  uint64 `json:"install_lock_inode"`
}

type recoveryInstallLockGuard struct {
	file       *os.File
	path       string
	stat       unix.Stat_t
	openParent func(string) (int, error)
	closed     bool
}

type recoveryActivationPermitGuard struct {
	file       *os.File
	path       string
	stat       unix.Stat_t
	openParent func(string) (int, error)
	closed     bool
}

func validateRecoveryActivationPermit(value recoveryActivationPermit) error {
	parsed, err := uuid.Parse(value.BootID)
	if err != nil || parsed.String() != value.BootID || value.SchemaVersion != 2 || value.JournalDevice == 0 || value.JournalInode == 0 ||
		value.InstallLockDevice == 0 || value.InstallLockInode == 0 {
		return errors.New("blank-host recovery activation permit metadata is invalid")
	}
	return nil
}

func marshalRecoveryActivationPermit(value recoveryActivationPermit) ([]byte, error) {
	if err := validateRecoveryActivationPermit(value); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) > maxRecoveryActivationPermit {
		return nil, errors.New("blank-host recovery activation permit is too large")
	}
	return payload, nil
}

func currentRecoveryBootID() (string, error) {
	payload, err := os.ReadFile(recoveryBootIDPath)
	if err != nil || len(payload) != 37 || payload[len(payload)-1] != '\n' {
		return "", errors.New("read current boot identity")
	}
	bootID := string(payload[:len(payload)-1])
	parsed, err := uuid.Parse(bootID)
	if err != nil || parsed.String() != bootID {
		return "", errors.New("current boot identity is invalid")
	}
	return bootID, nil
}

func acquireRecoveryInstallLock(path string) (*recoveryInstallLockGuard, error) {
	return acquireRecoveryInstallLockWithParent(path, openRecoveryControlParent)
}

func acquireRecoveryInstallLockWithParent(path string, openParent func(string) (int, error)) (*recoveryInstallLockGuard, error) {
	if filepath.Base(path) != filepath.Base(recoveryInstallLockPath) || openParent == nil {
		return nil, errors.New("blank-host recovery lock path is invalid")
	}
	parentFD, err := openParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	base := filepath.Base(path)
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(parentFD, base, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parentFD, base, flags, 0)
	}
	if err != nil {
		return nil, errors.New("open blank-host recovery lock")
	}
	file := os.NewFile(uintptr(fd), path)
	if created {
		if err := unix.Fchown(fd, 0, 0); err != nil || unix.Fchmod(fd, 0o600) != nil || unix.Fsync(fd) != nil || unix.Fsync(parentFD) != nil {
			file.Close()
			_ = unix.Unlinkat(parentFD, base, 0)
			_ = unix.Fsync(parentFD)
			return nil, errors.New("initialize blank-host recovery lock")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size != 0 {
		file.Close()
		return nil, errors.New("blank-host recovery lock is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, base, stat); err != nil {
		file.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another blank-host recovery is already running")
		}
		return nil, errors.New("acquire blank-host recovery lock")
	}
	return &recoveryInstallLockGuard{file: file, path: path, stat: stat, openParent: openParent}, nil
}

func (guard *recoveryInstallLockGuard) identity() (unix.Stat_t, error) {
	if guard == nil || guard.closed || guard.file == nil || guard.openParent == nil || filepath.Base(guard.path) != filepath.Base(recoveryInstallLockPath) {
		return unix.Stat_t{}, errors.New("blank-host recovery install-lock guard is invalid")
	}
	fd := int(guard.file.Fd())
	var current unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil || !sameUnixStat(guard.stat, current) || current.Mode&unix.S_IFMT != unix.S_IFREG ||
		os.FileMode(current.Mode).Perm() != 0o600 || current.Uid != 0 || current.Gid != 0 || current.Nlink != 1 || current.Size != 0 {
		return unix.Stat_t{}, errors.New("blank-host recovery install-lock guard changed")
	}
	parentFD, err := guard.openParent(guard.path)
	if err != nil {
		return unix.Stat_t{}, err
	}
	defer unix.Close(parentFD)
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(guard.path), current); err != nil {
		return unix.Stat_t{}, err
	}
	return current, nil
}

func (guard *recoveryInstallLockGuard) Close() error {
	if guard == nil || guard.closed {
		return nil
	}
	var identityErr error
	if _, err := guard.identity(); err != nil {
		identityErr = err
	}
	guard.closed = true
	if guard.file == nil {
		return errors.Join(identityErr, errors.New("blank-host recovery install-lock guard is invalid"))
	}
	fd := int(guard.file.Fd())
	return errors.Join(identityErr, unix.Flock(fd, unix.LOCK_UN), guard.file.Close())
}

func openRecoveryControlParent(path string) (int, error) {
	if path != recoveryInstallLockPath && path != recoveryActivationPermitPath && path != recoveryActivationJournalPath {
		return -1, errors.New("blank-host recovery control path is invalid")
	}
	return openRootOnlyRecoveryParent(path)
}

func openRootOnlyRecoveryParent(path string) (int, error) {
	if !cleanAbsolute(path) {
		return -1, errors.New("blank-host recovery control path is invalid")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, errors.New("open blank-host recovery control directory")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(stat.Mode).Perm() != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
		unix.Close(fd)
		return -1, errors.New("blank-host recovery control directory is unsafe")
	}
	return fd, nil
}

func openRecoveryActivationLockParent(path string) (int, error) {
	if path != recoveryActivationLockPath || !cleanAbsolute(path) {
		return -1, errors.New("tenant activation lifecycle lock path is invalid")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, errors.New("open tenant activation lifecycle lock directory")
	}
	var stat unix.Stat_t
	mode := os.FileMode(0)
	if err := unix.Fstat(fd, &stat); err == nil {
		mode = os.FileMode(stat.Mode).Perm()
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Gid != 0 || mode&0o022 != 0 {
		unix.Close(fd)
		return -1, errors.New("tenant activation lifecycle lock directory is unsafe")
	}
	return fd, nil
}

func requireRecoveryExclusiveLockHeld(path string, openParent func(string) (int, error)) error {
	if openParent == nil {
		return errors.New("blank-host recovery lock inspection is unavailable")
	}
	parentFD, err := openParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("open blank-host recovery authorization lock")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size != 0 {
		return errors.New("blank-host recovery authorization lock is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), stat); err != nil {
		return err
	}
	err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return errors.New("blank-host recovery authorization lock is not held")
	}
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		return errors.New("inspect blank-host recovery authorization lock ownership")
	}
	return nil
}

func acquireAuthorizedRecoveryActivationPermit(installLock *recoveryInstallLockGuard, journalPath, bootID string) (*recoveryActivationPermitGuard, error) {
	if installLock == nil || installLock.path != recoveryInstallLockPath {
		return nil, errors.New("blank-host recovery install-lock authorization is invalid")
	}
	if _, err := installLock.identity(); err != nil {
		return nil, fmt.Errorf("authenticate held blank-host recovery install lock: %w", err)
	}
	if err := requireRecoveryExclusiveLockHeld(recoveryInstallLockPath, openRecoveryControlParent); err != nil {
		return nil, fmt.Errorf("authenticate blank-host recovery install lock: %w", err)
	}
	if err := requireRecoveryExclusiveLockHeld(recoveryActivationLockPath, openRecoveryActivationLockParent); err != nil {
		return nil, fmt.Errorf("authenticate blank-host recovery activation lock: %w", err)
	}
	return acquireRecoveryActivationPermit(recoveryActivationPermitPath, journalPath, bootID, installLock, openRecoveryControlParent)
}

func recoveryActivationJournalIdentity(path string, openParent func(string) (int, error)) (unix.Stat_t, bool, error) {
	if filepath.Base(path) != filepath.Base(recoveryActivationJournalPath) || openParent == nil {
		return unix.Stat_t{}, false, errors.New("blank-host recovery activation journal path is invalid")
	}
	parentFD, err := openParent(path)
	if err != nil {
		return unix.Stat_t{}, false, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return unix.Stat_t{}, false, nil
	}
	if err != nil {
		return unix.Stat_t{}, false, errors.New("open blank-host recovery activation journal identity")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxRecoveryActivationJournal {
		return unix.Stat_t{}, false, errors.New("blank-host recovery activation journal identity is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), stat); err != nil {
		return unix.Stat_t{}, false, err
	}
	return stat, true, nil
}

func readRecoveryActivationPermit(file *os.File, before unix.Stat_t) (recoveryActivationPermit, error) {
	if file == nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 || before.Uid != 0 || before.Gid != 0 ||
		before.Nlink != 1 || before.Size <= 0 || before.Size > maxRecoveryActivationPermit {
		return recoveryActivationPermit{}, errors.New("blank-host recovery activation permit is unsafe")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return recoveryActivationPermit{}, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxRecoveryActivationPermit+1))
	if err != nil || len(payload) > maxRecoveryActivationPermit || int64(len(payload)) != before.Size {
		return recoveryActivationPermit{}, errors.New("read blank-host recovery activation permit")
	}
	if err := verifyOpenRecoveryFileUnchanged(int(file.Fd()), before); err != nil {
		return recoveryActivationPermit{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var value recoveryActivationPermit
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return recoveryActivationPermit{}, errors.New("blank-host recovery activation permit is invalid")
	}
	canonical, err := marshalRecoveryActivationPermit(value)
	if err != nil || !bytes.Equal(payload, canonical) {
		return recoveryActivationPermit{}, errors.New("blank-host recovery activation permit is not canonical")
	}
	return value, nil
}

func acquireRecoveryActivationPermit(path, journalPath, bootID string, installLock *recoveryInstallLockGuard, openParent func(string) (int, error)) (*recoveryActivationPermitGuard, error) {
	if filepath.Base(path) != filepath.Base(recoveryActivationPermitPath) || openParent == nil {
		return nil, errors.New("blank-host recovery activation permit path is invalid")
	}
	journalStat, found, err := recoveryActivationJournalIdentity(journalPath, openParent)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("blank-host recovery activation permit requires a durable journal")
	}
	installLockStat, err := installLock.identity()
	if err != nil {
		return nil, fmt.Errorf("bind blank-host recovery activation permit to install lock: %w", err)
	}
	value := recoveryActivationPermit{
		SchemaVersion:     2,
		BootID:            bootID,
		JournalDevice:     journalStat.Dev,
		JournalInode:      journalStat.Ino,
		InstallLockDevice: installLockStat.Dev,
		InstallLockInode:  installLockStat.Ino,
	}
	payload, err := marshalRecoveryActivationPermit(value)
	if err != nil {
		return nil, err
	}
	parentFD, err := openParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	base := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return nil, errors.New("blank-host recovery activation permit already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, errors.New("inspect blank-host recovery activation permit")
	}
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create unnamed blank-host recovery activation permit: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	published := false
	cleanup := func() {
		if published {
			var named unix.Stat_t
			if statErr := unix.Fstatat(parentFD, base, &named, unix.AT_SYMLINK_NOFOLLOW); statErr == nil {
				var opened unix.Stat_t
				if unix.Fstat(fd, &opened) == nil && named.Dev == opened.Dev && named.Ino == opened.Ino {
					_ = unix.Unlinkat(parentFD, base, 0)
					_ = unix.Fsync(parentFD)
				}
			}
		}
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}
	if err := unix.Fchown(fd, 0, 0); err != nil || unix.Fchmod(fd, 0o600) != nil {
		cleanup()
		return nil, errors.New("initialize blank-host recovery activation permit")
	}
	written, writeErr := file.Write(payload)
	if writeErr != nil || written != len(payload) || file.Sync() != nil {
		cleanup()
		return nil, errors.New("persist blank-host recovery activation permit")
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != 0 || before.Gid != 0 || before.Nlink != 0 || before.Size != int64(len(payload)) {
		cleanup()
		return nil, errors.New("unnamed blank-host recovery activation permit is unsafe")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cleanup()
		return nil, errors.New("lock blank-host recovery activation permit")
	}
	linkErr := unix.Linkat(fd, "", parentFD, base, unix.AT_EMPTY_PATH)
	if errors.Is(linkErr, unix.EPERM) {
		linkErr = unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), parentFD, base, unix.AT_SYMLINK_FOLLOW)
	}
	if errors.Is(linkErr, unix.EEXIST) {
		cleanup()
		return nil, errors.New("blank-host recovery activation permit appeared concurrently")
	}
	if linkErr != nil {
		cleanup()
		return nil, fmt.Errorf("publish blank-host recovery activation permit: %w", linkErr)
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		cleanup()
		return nil, errors.New("synchronize blank-host recovery activation permit publication")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Mode != before.Mode ||
		after.Uid != before.Uid || after.Gid != before.Gid || after.Nlink != 1 || after.Size != before.Size {
		cleanup()
		return nil, errors.New("published blank-host recovery activation permit is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, base, after); err != nil {
		cleanup()
		return nil, err
	}
	installLockAfter, err := installLock.identity()
	if err != nil || installLockAfter.Dev != value.InstallLockDevice || installLockAfter.Ino != value.InstallLockInode {
		cleanup()
		return nil, errors.New("blank-host recovery install lock changed during permit publication")
	}
	return &recoveryActivationPermitGuard{file: file, path: path, stat: after, openParent: openParent}, nil
}

func (guard *recoveryActivationPermitGuard) Close() (resultErr error) {
	if guard == nil || guard.closed {
		return nil
	}
	guard.closed = true
	if guard.file == nil || guard.openParent == nil {
		return errors.New("blank-host recovery activation permit guard is invalid")
	}
	fd := int(guard.file.Fd())
	defer func() {
		resultErr = errors.Join(resultErr, unix.Flock(fd, unix.LOCK_UN), guard.file.Close())
	}()
	parentFD, err := guard.openParent(guard.path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var current unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil || current.Dev != guard.stat.Dev || current.Ino != guard.stat.Ino ||
		current.Mode != guard.stat.Mode || current.Uid != guard.stat.Uid || current.Gid != guard.stat.Gid || current.Nlink != 1 || current.Size != guard.stat.Size {
		return errors.New("blank-host recovery activation permit changed before release")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(guard.path), current); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, filepath.Base(guard.path), 0); err != nil {
		return fmt.Errorf("unlink blank-host recovery activation permit: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("synchronize blank-host recovery activation permit removal: %w", err)
	}
	return nil
}

func reconcileStaleRecoveryActivationPermit(path, journalPath, bootID string, installLock *recoveryInstallLockGuard, openParent func(string) (int, error)) (resultErr error) {
	if filepath.Base(path) != filepath.Base(recoveryActivationPermitPath) || openParent == nil {
		return errors.New("blank-host recovery activation permit path is invalid")
	}
	installLockStat, err := installLock.identity()
	if err != nil {
		return fmt.Errorf("authenticate stale-permit recovery install lock: %w", err)
	}
	parentFD, err := openParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("open stale blank-host recovery activation permit")
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 || before.Size <= 0 || before.Size > maxRecoveryActivationPermit {
		return errors.New("stale blank-host recovery activation permit is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), before); err != nil {
		return err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return errors.New("another blank-host recovery activation still owns its permit")
		}
		return errors.New("lock stale blank-host recovery activation permit")
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Flock(fd, unix.LOCK_UN)) }()
	value, err := readRecoveryActivationPermit(file, before)
	if err != nil {
		return err
	}
	if value.BootID != bootID {
		return errors.New("stale blank-host recovery activation permit belongs to another boot")
	}
	if value.InstallLockDevice != installLockStat.Dev || value.InstallLockInode != installLockStat.Ino {
		return errors.New("stale blank-host recovery activation permit names another install lock")
	}
	journalStat, found, err := recoveryActivationJournalIdentity(journalPath, openParent)
	if err != nil {
		return err
	}
	if found && (journalStat.Dev != value.JournalDevice || journalStat.Ino != value.JournalInode) {
		return errors.New("stale blank-host recovery activation permit names another journal")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameUnixStat(before, after) || after.Nlink != before.Nlink {
		return errors.New("stale blank-host recovery activation permit changed while inspected")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), after); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, filepath.Base(path), 0); err != nil {
		return fmt.Errorf("unlink stale blank-host recovery activation permit: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("synchronize stale blank-host recovery activation permit removal: %w", err)
	}
	return nil
}

func validateRecoveryActivationJournal(value recoveryActivationJournal) error {
	if value.SchemaVersion != 1 || len(value.Units) < 6 || len(value.Units) > 2006 ||
		value.Units[0] != "workagent-tenant-catalog-ready.target" ||
		value.Units[1] != "cliproxyapi.service" || value.Units[2] != "workagent-notification.service" ||
		value.Units[3] != "workagent-chatforward.service" ||
		value.Units[len(value.Units)-2] != "workagent-chatforward-browser.service" ||
		value.Units[len(value.Units)-1] != "workagent-portal.service" {
		return errors.New("blank-host recovery activation journal metadata is invalid")
	}
	middle := value.Units[4 : len(value.Units)-2]
	if len(middle)%2 != 0 {
		return errors.New("blank-host recovery activation journal tenant-unit set is incomplete")
	}
	tenantCount := len(middle) / 2
	seen := make(map[string]bool, len(value.Units))
	for index, unit := range value.Units {
		valid := (index == 0 && unit == "workagent-tenant-catalog-ready.target") ||
			(index == 1 && unit == "cliproxyapi.service") ||
			(index == 2 && unit == "workagent-notification.service") ||
			(index == 3 && unit == "workagent-chatforward.service") ||
			(index == len(value.Units)-2 && unit == "workagent-chatforward-browser.service") ||
			(index == len(value.Units)-1 && unit == "workagent-portal.service")
		if index >= 4 && index < 4+tenantCount {
			valid = validRecoveryTenantActivationUnit(unit, ".service")
			if index > 4 {
				valid = valid && value.Units[index-1] < unit
			}
		}
		if index >= 4+tenantCount && index < len(value.Units)-2 {
			valid = validRecoveryTenantActivationUnit(unit, ".socket")
			service := value.Units[4+index-(4+tenantCount)]
			valid = valid && strings.TrimSuffix(service, ".service") == strings.TrimSuffix(unit, ".socket")
		}
		if !valid || seen[unit] {
			return errors.New("blank-host recovery activation journal contains an invalid, duplicate, or unsorted unit")
		}
		seen[unit] = true
	}
	return nil
}

func validRecoveryTenantActivationUnit(unit, suffix string) bool {
	if !strings.HasPrefix(unit, "workagent-userhost@") || !strings.HasSuffix(unit, suffix) {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(unit, "workagent-userhost@"), suffix)
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}

func writeRecoveryActivationJournal(path string, value recoveryActivationJournal) error {
	if filepath.Base(path) != filepath.Base(recoveryActivationJournalPath) {
		return errors.New("blank-host recovery activation journal name is invalid")
	}
	if err := validateRecoveryActivationJournal(value); err != nil {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	base := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return errors.New("blank-host recovery activation journal already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return errors.New("inspect blank-host recovery activation journal")
	}
	fd, err := unix.Openat(parentFD, ".", unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create unnamed blank-host recovery activation journal: %w", err)
	}
	file := os.NewFile(uintptr(fd), "recovery-activation-journal")
	defer file.Close()
	if err := unix.Fchown(fd, 0, 0); err != nil || unix.Fchmod(fd, 0o600) != nil {
		return errors.New("initialize blank-host recovery activation journal")
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Linkat(fd, "", parentFD, base, unix.AT_EMPTY_PATH); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("blank-host recovery activation journal appeared concurrently")
		}
		return fmt.Errorf("publish blank-host recovery activation journal: %w", err)
	}
	return unix.Fsync(parentFD)
}

func loadRecoveryActivationJournal(path string) (recoveryActivationJournal, bool, error) {
	if filepath.Base(path) != filepath.Base(recoveryActivationJournalPath) {
		return recoveryActivationJournal{}, false, errors.New("blank-host recovery activation journal name is invalid")
	}
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return recoveryActivationJournal{}, false, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return recoveryActivationJournal{}, false, nil
	}
	if err != nil {
		return recoveryActivationJournal{}, false, errors.New("open blank-host recovery activation journal")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxRecoveryActivationJournal {
		return recoveryActivationJournal{}, false, errors.New("blank-host recovery activation journal is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), stat); err != nil {
		return recoveryActivationJournal{}, false, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxRecoveryActivationJournal+1))
	if err != nil || len(payload) > maxRecoveryActivationJournal {
		return recoveryActivationJournal{}, false, errors.New("read blank-host recovery activation journal")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var value recoveryActivationJournal
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return recoveryActivationJournal{}, false, errors.New("blank-host recovery activation journal is invalid")
	}
	if err := validateRecoveryActivationJournal(value); err != nil {
		return recoveryActivationJournal{}, false, err
	}
	return value, true, nil
}

// AssertNoPendingRecoveryActivation prevents an ordinary admin/backup
// orchestrator from borrowing A_EX while a crash-recovery activation journal
// exists. Only InstallRestoredTree is authorized to consume that journal.
func AssertNoPendingRecoveryActivation() error {
	_, found, err := loadRecoveryActivationJournal(recoveryActivationJournalPath)
	if err != nil {
		return fmt.Errorf("inspect blank-host recovery activation journal: %w", err)
	}
	if found {
		return errors.New("blank-host recovery activation is pending; rerun authenticated recovery before any ordinary activation")
	}
	return nil
}

func removeRecoveryActivationJournal(path string) error {
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Unlinkat(parentFD, filepath.Base(path), 0); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func rollbackRecoveryActivation(controller systemdctl.Controller, path string) error {
	value, found, err := loadRecoveryActivationJournal(path)
	if err != nil || !found {
		return err
	}
	return rollbackKnownRecoveryActivationWithIOAndProof(
		controller, value, path, loadRecoveryActivationJournal, removeRecoveryActivationJournal,
		requireRecoveryRollbackSystemdContract,
	)
}

func rollbackKnownRecoveryActivation(controller systemdctl.Controller, value recoveryActivationJournal, path string) error {
	return rollbackKnownRecoveryActivationWithIOAndProof(
		controller, value, path, loadRecoveryActivationJournal, removeRecoveryActivationJournal,
		requireRecoveryRollbackSystemdContract,
	)
}

func rollbackKnownRecoveryActivationWithIO(
	controller systemdctl.Controller,
	value recoveryActivationJournal,
	path string,
	load func(string) (recoveryActivationJournal, bool, error),
	remove func(string) error,
) error {
	return rollbackKnownRecoveryActivationWithIOAndProof(
		controller, value, path, load, remove,
		func(context.Context, systemdctl.Controller, recoveryActivationJournal) error { return nil },
	)
}

type recoveryRollbackContractProof func(context.Context, systemdctl.Controller, recoveryActivationJournal) error

func rollbackKnownRecoveryActivationWithIOAndProof(
	controller systemdctl.Controller,
	value recoveryActivationJournal,
	path string,
	load func(string) (recoveryActivationJournal, bool, error),
	remove func(string) error,
	prove recoveryRollbackContractProof,
) error {
	if load == nil || remove == nil || prove == nil {
		return errors.New("blank-host recovery activation rollback proof is unavailable")
	}
	// Never discard the durable retry evidence when disable, stop, or the
	// stopped-state or exact signed-manager-contract proof fails. The next
	// recovery invocation must see the journal and repeat the rollback before it
	// is allowed to mutate anything.
	if err := stopRecoveryActivationUnits(controller, value); err != nil {
		return err
	}
	proofContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := prove(proofContext, controller, value); err != nil {
		return err
	}
	current, found, err := load(path)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("blank-host recovery activation journal disappeared during rollback")
	}
	if current.SchemaVersion != value.SchemaVersion || !slices.Equal(current.Units, value.Units) {
		return errors.New("blank-host recovery activation journal changed during rollback")
	}
	return remove(path)
}

func stopRecoveryActivationUnits(controller systemdctl.Controller, value recoveryActivationJournal) error {
	if err := validateRecoveryActivationJournal(value); err != nil {
		return err
	}
	if controller == nil {
		return errors.New("blank-host recovery activation rollback has no systemd controller")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var failures []error
	if err := recoverySystemdActionUnits(ctx, controller, "disable", recoveryActivationEnableUnits(value)); err != nil {
		failures = append(failures, fmt.Errorf("disable partially activated recovery units: %w", err))
	}
	for index := len(value.Units) - 1; index >= 0; index-- {
		if err := controller.Action(ctx, "stop", value.Units[index]); err != nil {
			failures = append(failures, fmt.Errorf("stop partially activated unit %s: %w", value.Units[index], err))
		}
	}
	// Starting the catalog-ready target pulls in this oneshot through Requires=.
	// A killed systemctl client does not guarantee that systemd cancelled or
	// stopped the already-running dependency job, and stopping the target does
	// not propagate a stop to a required unit. Keep the durable recovery journal
	// until that possible writer is explicitly stopped and proved quiescent.
	const reconcileUnit = "workagent-tenant-config-reconcile.service"
	if err := controller.Action(ctx, "stop", reconcileUnit); err != nil {
		failures = append(failures, fmt.Errorf("stop partially activated unit %s: %w", reconcileUnit, err))
	}
	stoppedUnits := append(append([]string(nil), value.Units...), reconcileUnit)
	if err := requireRecoveryUnitsStopped(ctx, controller, stoppedUnits); err != nil {
		failures = append(failures, err)
	}
	if err := requireRecoveryUnitFileState(ctx, controller, recoveryActivationEnableUnits(value), "disabled"); err != nil {
		failures = append(failures, fmt.Errorf("prove partially activated recovery units are disabled: %w", err))
	}
	staticUnits := []string{reconcileUnit}
	for _, unit := range value.Units {
		if unit == "workagent-tenant-catalog-ready.target" ||
			(strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service")) {
			staticUnits = append(staticUnits, unit)
		}
	}
	if len(staticUnits) != 0 {
		if err := requireRecoveryUnitFileState(ctx, controller, staticUnits, "static"); err != nil {
			failures = append(failures, fmt.Errorf("prove recovery tenant services remain static: %w", err))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return nil
}

func recoverySystemdActionUnits(ctx context.Context, controller systemdctl.Controller, action string, units []string) error {
	if controller == nil || (action != "enable" && action != "disable") || len(units) == 0 {
		return errors.New("blank-host recovery bulk systemd action is invalid")
	}
	// systemdctl deliberately caps one invocation at 64 arguments. Keep the
	// action plus at most 63 units per call while the persistent journal makes
	// a partially completed multi-call enable fully rollback-safe.
	for offset := 0; offset < len(units); offset += 63 {
		end := offset + 63
		if end > len(units) {
			end = len(units)
		}
		arguments := append([]string{action}, units[offset:end]...)
		if err := controller.Action(ctx, arguments...); err != nil {
			return err
		}
	}
	return nil
}

func activationJournalForUnits(units []string) (recoveryActivationJournal, error) {
	if len(units) < 6 || units[0] != "workagent-tenant-catalog-ready.target" ||
		units[1] != "cliproxyapi.service" || units[2] != "workagent-notification.service" ||
		units[3] != "workagent-chatforward.service" || units[len(units)-2] != "workagent-chatforward-browser.service" ||
		units[len(units)-1] != "workagent-portal.service" {
		return recoveryActivationJournal{}, errors.New("blank-host recovery activation input is invalid")
	}
	sockets := append([]string(nil), units[4:len(units)-2]...)
	sort.Strings(sockets)
	services := make([]string, len(sockets))
	for index, socket := range sockets {
		if !validRecoveryTenantActivationUnit(socket, ".socket") {
			return recoveryActivationJournal{}, errors.New("blank-host recovery activation input contains an invalid tenant socket")
		}
		services[index] = strings.TrimSuffix(socket, ".socket") + ".service"
	}
	managed := append([]string(nil), units[:4]...)
	managed = append(managed, services...)
	managed = append(managed, sockets...)
	managed = append(managed, units[len(units)-2:]...)
	value := recoveryActivationJournal{SchemaVersion: 1, Units: managed}
	return value, validateRecoveryActivationJournal(value)
}

func recoveryActivationEnableUnits(value recoveryActivationJournal) []string {
	result := make([]string, 0, len(value.Units))
	for _, unit := range value.Units {
		if unit == "workagent-tenant-catalog-ready.target" ||
			(strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service")) {
			continue
		}
		result = append(result, unit)
	}
	return result
}
