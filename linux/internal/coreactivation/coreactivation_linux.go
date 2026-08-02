//go:build linux

// Package coreactivation owns the durable authorization evidence for the
// production core-fleet activation transaction. It intentionally has no
// lifecycle-lock or systemd dependencies: the orchestrator owns those layers,
// while this package authenticates their exact activation-lock inode and makes
// journal/permit publication and settlement crash safe.
package coreactivation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	JournalPath        = "/var/lib/workagent-core/activation.json"
	PermitPath         = "/run/workagent-core/activation.permit"
	ActivationLockPath = "/run/workagent/activation.lock"
	bootIDPath         = "/proc/sys/kernel/random/boot_id"

	journalSchemaVersion = 1
	permitSchemaVersion  = 1
	maxJournalBytes      = 4 * 1024
	maxPermitBytes       = 1024
)

var fixedCoreUnits = []string{
	"workagent-tenant-catalog-ready.target",
	"workagent-tenant-config-reconcile.service",
	"cliproxyapi.service",
	"workagent-notification.service",
	"workagent-chatforward.service",
	"workagent-chatforward-browser.service",
	"workagent-portal.service",
	"caddy.service",
	"workagent-backup.service",
	"workagent-backup.timer",
	"workagent-healthcheck.service",
	"workagent-healthcheck.timer",
}

// CoreUnits returns the immutable, ordered unit contract recorded by every
// core-fleet activation journal. The caller receives a defensive copy.
func CoreUnits() []string {
	return append([]string(nil), fixedCoreUnits...)
}

// Journal is deliberately small and immutable. A schema-v1 journal is valid
// only when Units exactly equals CoreUnits in the same order.
type Journal struct {
	SchemaVersion int      `json:"schema_version"`
	Units         []string `json:"units"`
}

type permit struct {
	SchemaVersion        int    `json:"schema_version"`
	BootID               string `json:"boot_id"`
	JournalDevice        uint64 `json:"journal_device"`
	JournalInode         uint64 `json:"journal_inode"`
	ActivationLockDevice uint64 `json:"activation_lock_device"`
	ActivationLockInode  uint64 `json:"activation_lock_inode"`
}

type layout struct {
	journalPath        string
	permitPath         string
	activationLockPath string
	bootIDPath         string
	expectedUID        uint32
	expectedGID        uint32
	fsync              func(int) error
}

func productionLayout() layout {
	return layout{
		journalPath:        JournalPath,
		permitPath:         PermitPath,
		activationLockPath: ActivationLockPath,
		bootIDPath:         bootIDPath,
		expectedUID:        0,
		expectedGID:        0,
		fsync:              unix.Fsync,
	}
}

func (value layout) normalized() layout {
	if value.fsync == nil {
		value.fsync = unix.Fsync
	}
	return value
}

func (value layout) validate() error {
	value = value.normalized()
	paths := []string{value.journalPath, value.permitPath, value.activationLockPath, value.bootIDPath}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("core activation control layout is invalid")
		}
	}
	if filepath.Base(value.journalPath) != filepath.Base(JournalPath) ||
		filepath.Base(value.permitPath) != filepath.Base(PermitPath) ||
		filepath.Base(value.activationLockPath) != filepath.Base(ActivationLockPath) ||
		filepath.Dir(value.journalPath) == filepath.Dir(value.permitPath) {
		return errors.New("core activation control layout is invalid")
	}
	return nil
}

type directoryIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	gid    uint32
}

type activationHandle struct {
	file   *os.File
	stat   unix.Stat_t
	layout layout
}

type namedFile struct {
	file *os.File
	stat unix.Stat_t
	path string
}

// Pending is authenticated durable retry evidence. Callers should close an
// unused handle. Closing Pending never mutates either evidence pathname.
type Pending struct {
	layout      layout
	journal     Journal
	journalFile *namedFile
	permitFile  *namedFile
	activation  *activationHandle
	closed      bool
}

// Transaction owns a live, exclusively locked permit. Close is the graceful
// abort operation: it removes only the volatile permit and deliberately leaves
// the durable journal for fail-closed rollback/replay.
type Transaction struct {
	pending      *Pending
	permitLocked bool
	closed       bool
	committed    bool
}

func validateJournal(value Journal) error {
	if value.SchemaVersion != journalSchemaVersion || !slices.Equal(value.Units, fixedCoreUnits) {
		return errors.New("core activation journal metadata is invalid")
	}
	return nil
}

func canonicalJournal(value Journal) ([]byte, error) {
	if err := validateJournal(value); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) > maxJournalBytes {
		return nil, errors.New("core activation journal is too large")
	}
	return payload, nil
}

func validatePermit(value permit) error {
	parsed, err := uuid.Parse(value.BootID)
	if err != nil || parsed.String() != value.BootID || value.SchemaVersion != permitSchemaVersion ||
		value.JournalDevice == 0 || value.JournalInode == 0 || value.ActivationLockDevice == 0 || value.ActivationLockInode == 0 {
		return errors.New("core activation permit metadata is invalid")
	}
	return nil
}

func canonicalPermit(value permit) ([]byte, error) {
	if err := validatePermit(value); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) > maxPermitBytes {
		return nil, errors.New("core activation permit is too large")
	}
	return payload, nil
}

func currentBootID(value layout) (string, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, value.bootIDPath, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return "", errors.New("read current core activation boot identity")
	}
	file := os.NewFile(uintptr(fd), value.bootIDPath)
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != value.expectedUID ||
		before.Gid != value.expectedGID || before.Nlink != 1 || os.FileMode(before.Mode).Perm()&0o022 != 0 {
		return "", errors.New("current core activation boot identity source is unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(payload) != 37 || payload[len(payload)-1] != '\n' {
		return "", errors.New("read current core activation boot identity")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameStableStat(before, after) || before.Nlink != after.Nlink {
		return "", errors.New("current core activation boot identity changed while it was read")
	}
	parentFD, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(value.bootIDPath), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return "", errors.New("authenticate current core activation boot identity source")
	}
	defer unix.Close(parentFD)
	if err := verifyNamedStat(parentFD, filepath.Base(value.bootIDPath), after); err != nil {
		return "", errors.New("current core activation boot identity pathname changed")
	}
	bootID := string(payload[:len(payload)-1])
	parsed, err := uuid.Parse(bootID)
	if err != nil || parsed.String() != bootID {
		return "", errors.New("current core activation boot identity is invalid")
	}
	return bootID, nil
}

func openEvidenceParent(value layout, path string) (int, error) {
	if path != value.journalPath && path != value.permitPath {
		return -1, errors.New("core activation evidence path is invalid")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("open core activation evidence directory: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		os.FileMode(stat.Mode).Perm() != 0o700 || stat.Uid != value.expectedUID || stat.Gid != value.expectedGID {
		unix.Close(fd)
		return -1, errors.New("core activation evidence directory is unsafe")
	}
	return fd, nil
}

func evidenceExists(value layout, path string) (directoryIdentity, bool, error) {
	parentFD, err := openEvidenceParent(value, path)
	if err != nil {
		return directoryIdentity{}, false, err
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return directoryIdentity{}, false, errors.New("inspect core activation evidence directory")
	}
	identity := directoryIdentity{device: parentStat.Dev, inode: parentStat.Ino, mode: parentStat.Mode, uid: parentStat.Uid, gid: parentStat.Gid}
	var stat unix.Stat_t
	err = unix.Fstatat(parentFD, filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return identity, false, nil
	}
	if err != nil {
		return directoryIdentity{}, false, errors.New("inspect core activation evidence pathname")
	}
	return identity, true, nil
}

type evidenceSnapshot struct {
	journalParent directoryIdentity
	permitParent  directoryIdentity
	journal       bool
	permit        bool
}

func snapshotEvidence(value layout) (evidenceSnapshot, error) {
	jParent, journal, err := evidenceExists(value, value.journalPath)
	if err != nil {
		return evidenceSnapshot{}, err
	}
	pParent, permit, err := evidenceExists(value, value.permitPath)
	if err != nil {
		return evidenceSnapshot{}, err
	}
	return evidenceSnapshot{journalParent: jParent, permitParent: pParent, journal: journal, permit: permit}, nil
}

func stableEvidenceSnapshot(value layout) (evidenceSnapshot, error) {
	first, err := snapshotEvidence(value)
	if err != nil {
		return evidenceSnapshot{}, err
	}
	second, err := snapshotEvidence(value)
	if err != nil {
		return evidenceSnapshot{}, err
	}
	if first != second {
		return evidenceSnapshot{}, errors.New("core activation evidence changed while it was inspected")
	}
	return second, nil
}

// AssertClean is the ordinary-writer admission gate. It must be called while
// the caller owns the global activation lock. Both protected parents and both
// absences are proved twice, so an orphan permit is rejected as evidence too.
func AssertClean() error {
	return assertCleanAt(productionLayout())
}

func assertCleanAt(value layout) error {
	value = value.normalized()
	if err := value.validate(); err != nil {
		return err
	}
	snapshot, err := stableEvidenceSnapshot(value)
	if err != nil {
		return err
	}
	if snapshot.permit && !snapshot.journal {
		return errors.New("orphan core activation permit exists")
	}
	if snapshot.journal || snapshot.permit {
		return errors.New("core activation transaction is pending")
	}
	return nil
}

func openActivationParent(value layout) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(value.activationLockPath), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, errors.New("open core activation lifecycle directory")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != value.expectedUID ||
		stat.Gid != value.expectedGID || os.FileMode(stat.Mode).Perm()&0o022 != 0 {
		unix.Close(fd)
		return -1, errors.New("core activation lifecycle directory is unsafe")
	}
	return fd, nil
}

func verifyNamedStat(parentFD int, base string, expected unix.Stat_t) error {
	var named unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Mode&unix.S_IFMT != unix.S_IFREG ||
		!sameStableStat(named, expected) || named.Nlink != expected.Nlink {
		return errors.New("core activation pathname changed concurrently")
	}
	return nil
}

func sameStableStat(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino && first.Size == second.Size && first.Mode == second.Mode &&
		first.Uid == second.Uid && first.Gid == second.Gid && first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

func validateActivationStat(stat unix.Stat_t, value layout) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 || stat.Uid != value.expectedUID ||
		stat.Gid != value.expectedGID || stat.Nlink != 1 || stat.Size != 0 {
		return errors.New("core activation lifecycle lock is unsafe")
	}
	return nil
}

// proveExternalExclusiveLock uses a separate open-file description. A shared
// probe can coexist with shared holders, so EWOULDBLOCK specifically proves an
// exclusive flock exists on the exact inode.
func proveExternalExclusiveLock(fd int) error {
	err := unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
	if err == nil {
		unlockErr := unix.Flock(fd, unix.LOCK_UN)
		return errors.Join(errors.New("core activation lifecycle lock is not held exclusively"), unlockErr)
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return nil
	}
	return errors.New("inspect core activation lifecycle lock ownership")
}

func openActivation(value layout) (*activationHandle, error) {
	parentFD, err := openActivationParent(value)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(value.activationLockPath), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("open core activation lifecycle lock")
	}
	file := os.NewFile(uintptr(fd), value.activationLockPath)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || validateActivationStat(stat, value) != nil ||
		verifyNamedStat(parentFD, filepath.Base(value.activationLockPath), stat) != nil || proveExternalExclusiveLock(fd) != nil {
		file.Close()
		return nil, errors.New("authenticate held core activation lifecycle lock")
	}
	return &activationHandle{file: file, stat: stat, layout: value}, nil
}

func (handle *activationHandle) verify() error {
	if handle == nil || handle.file == nil {
		return errors.New("core activation lifecycle handle is invalid")
	}
	fd := int(handle.file.Fd())
	var current unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil || !sameStableStat(current, handle.stat) || current.Nlink != handle.stat.Nlink ||
		validateActivationStat(current, handle.layout) != nil {
		return errors.New("core activation lifecycle lock changed")
	}
	parentFD, err := openActivationParent(handle.layout)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := verifyNamedStat(parentFD, filepath.Base(handle.layout.activationLockPath), current); err != nil {
		return err
	}
	if err := proveExternalExclusiveLock(fd); err != nil {
		return err
	}
	return nil
}

func (handle *activationHandle) close() error {
	if handle == nil || handle.file == nil {
		return nil
	}
	err := handle.file.Close()
	handle.file = nil
	return err
}

func validateNamedFileStat(stat unix.Stat_t, value layout, max int) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 || stat.Uid != value.expectedUID ||
		stat.Gid != value.expectedGID || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > int64(max) {
		return errors.New("core activation evidence file is unsafe")
	}
	return nil
}

func openNamed(value layout, path string, max int) (*namedFile, error) {
	parentFD, err := openEvidenceParent(value, path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open core activation evidence %s: %w", filepath.Base(path), err)
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || validateNamedFileStat(stat, value, max) != nil ||
		verifyNamedStat(parentFD, filepath.Base(path), stat) != nil {
		file.Close()
		return nil, fmt.Errorf("core activation evidence %s is unsafe", filepath.Base(path))
	}
	return &namedFile{file: file, stat: stat, path: path}, nil
}

func (named *namedFile) verifyName(value layout, max int) error {
	if named == nil || named.file == nil || named.path == "" {
		return errors.New("core activation evidence handle is invalid")
	}
	fd := int(named.file.Fd())
	var current unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil || !sameStableStat(current, named.stat) || current.Nlink != named.stat.Nlink ||
		validateNamedFileStat(current, value, max) != nil {
		return errors.New("core activation evidence descriptor changed")
	}
	parentFD, err := openEvidenceParent(value, named.path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	return verifyNamedStat(parentFD, filepath.Base(named.path), current)
}

func (named *namedFile) close() error {
	if named == nil || named.file == nil {
		return nil
	}
	err := named.file.Close()
	named.file = nil
	return err
}

func readPayload(file *os.File, before unix.Stat_t, max int) ([]byte, error) {
	if file == nil || before.Size <= 0 || before.Size > int64(max) {
		return nil, errors.New("core activation evidence is unsafe")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(payload) > max || int64(len(payload)) != before.Size {
		return nil, errors.New("read core activation evidence")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || !sameStableStat(before, after) || after.Nlink != before.Nlink {
		return nil, errors.New("core activation evidence changed while it was read")
	}
	return payload, nil
}

func decodeJournal(named *namedFile, value layout) (Journal, error) {
	if err := named.verifyName(value, maxJournalBytes); err != nil {
		return Journal{}, err
	}
	payload, err := readPayload(named.file, named.stat, maxJournalBytes)
	if err != nil {
		return Journal{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var journal Journal
	if err := decoder.Decode(&journal); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Journal{}, errors.New("core activation journal is invalid")
	}
	canonical, err := canonicalJournal(journal)
	if err != nil || !bytes.Equal(payload, canonical) {
		return Journal{}, errors.New("core activation journal is not canonical")
	}
	return journal, nil
}

func decodePermit(named *namedFile, value layout) (permit, error) {
	if err := named.verifyName(value, maxPermitBytes); err != nil {
		return permit{}, err
	}
	payload, err := readPayload(named.file, named.stat, maxPermitBytes)
	if err != nil {
		return permit{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var result permit
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return permit{}, errors.New("core activation permit is invalid")
	}
	canonical, err := canonicalPermit(result)
	if err != nil || !bytes.Equal(payload, canonical) {
		return permit{}, errors.New("core activation permit is not canonical")
	}
	return result, nil
}

func publishNamed(value layout, path string, payload []byte, max int, lockBeforePublish bool) (*namedFile, error) {
	if len(payload) == 0 || len(payload) > max {
		return nil, errors.New("core activation evidence payload is invalid")
	}
	parentFD, err := openEvidenceParent(value, path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	base := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return nil, errors.New("core activation evidence already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, errors.New("inspect core activation evidence destination")
	}
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create unnamed core activation evidence: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	linked := false
	closeOnError := func() {
		// Once linked, never erase evidence in an error path. In particular, an
		// fsync error makes publication durability ambiguous and must leave the
		// authenticated pathname available for fail-closed reconciliation.
		_ = file.Close()
	}
	if err := unix.Fchown(fd, int(value.expectedUID), int(value.expectedGID)); err != nil || unix.Fchmod(fd, 0o600) != nil {
		closeOnError()
		return nil, errors.New("initialize core activation evidence")
	}
	written, writeErr := file.Write(payload)
	if writeErr != nil || written != len(payload) || value.fsync(fd) != nil {
		closeOnError()
		return nil, errors.New("persist core activation evidence payload")
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != value.expectedUID || before.Gid != value.expectedGID || before.Nlink != 0 || before.Size != int64(len(payload)) {
		closeOnError()
		return nil, errors.New("unnamed core activation evidence is unsafe")
	}
	if lockBeforePublish {
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			closeOnError()
			return nil, errors.New("lock unnamed core activation permit")
		}
	}
	linkErr := unix.Linkat(fd, "", parentFD, base, unix.AT_EMPTY_PATH)
	if errors.Is(linkErr, unix.EPERM) {
		linkErr = unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), parentFD, base, unix.AT_SYMLINK_FOLLOW)
	}
	if linkErr != nil {
		closeOnError()
		if errors.Is(linkErr, unix.EEXIST) {
			return nil, errors.New("core activation evidence appeared concurrently")
		}
		return nil, fmt.Errorf("publish core activation evidence: %w", linkErr)
	}
	linked = true
	if err := value.fsync(parentFD); err != nil {
		closeOnError()
		return nil, errors.New("synchronize core activation evidence publication")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
		after.Mode != before.Mode || after.Uid != before.Uid || after.Gid != before.Gid || after.Nlink != 1 {
		closeOnError()
		return nil, errors.New("published core activation evidence is unsafe")
	}
	if err := verifyNamedStat(parentFD, base, after); err != nil {
		closeOnError()
		return nil, err
	}
	if !linked {
		closeOnError()
		return nil, errors.New("core activation evidence publication was lost")
	}
	return &namedFile{file: file, stat: after, path: path}, nil
}

func writeJournal(value layout) (*namedFile, Journal, error) {
	journal := Journal{SchemaVersion: journalSchemaVersion, Units: CoreUnits()}
	payload, err := canonicalJournal(journal)
	if err != nil {
		return nil, Journal{}, err
	}
	named, err := publishNamed(value, value.journalPath, payload, maxJournalBytes, false)
	if err != nil {
		return nil, Journal{}, err
	}
	return named, journal, nil
}

func publishPermit(value layout, journal *namedFile, activation *activationHandle, bootID string) (*namedFile, error) {
	if journal == nil || activation == nil {
		return nil, errors.New("core activation permit binding is invalid")
	}
	metadata := permit{
		SchemaVersion:        permitSchemaVersion,
		BootID:               bootID,
		JournalDevice:        journal.stat.Dev,
		JournalInode:         journal.stat.Ino,
		ActivationLockDevice: activation.stat.Dev,
		ActivationLockInode:  activation.stat.Ino,
	}
	payload, err := canonicalPermit(metadata)
	if err != nil {
		return nil, err
	}
	named, err := publishNamed(value, value.permitPath, payload, maxPermitBytes, true)
	if err != nil {
		return nil, err
	}
	return named, nil
}

// Begin publishes the durable journal first and only then publishes and locks
// the volatile this-boot permit. The exact global activation lock must already
// be held exclusively by the caller.
func Begin() (*Transaction, error) {
	return beginAt(productionLayout())
}

func beginAt(value layout) (*Transaction, error) {
	value = value.normalized()
	if err := value.validate(); err != nil {
		return nil, err
	}
	bootID, err := currentBootID(value)
	if err != nil {
		return nil, err
	}
	activation, err := openActivation(value)
	if err != nil {
		return nil, err
	}
	closeActivation := true
	defer func() {
		if closeActivation {
			_ = activation.close()
		}
	}()
	if err := assertCleanAt(value); err != nil {
		return nil, err
	}
	journalFile, journal, err := writeJournal(value)
	if err != nil {
		return nil, err
	}
	closeJournal := true
	defer func() {
		if closeJournal {
			_ = journalFile.close()
		}
	}()
	if err := activation.verify(); err != nil {
		return nil, fmt.Errorf("core activation lifecycle lock changed after journal publication: %w", err)
	}
	permitFile, err := publishPermit(value, journalFile, activation, bootID)
	if err != nil {
		return nil, err
	}
	pending := &Pending{layout: value, journal: journal, journalFile: journalFile, permitFile: permitFile, activation: activation}
	transaction := &Transaction{pending: pending, permitLocked: true}
	if err := transaction.Verify(); err != nil {
		// Keep both names. Closing descriptors releases the flock so the next
		// serialized invocation can authenticate and reconcile stale evidence.
		_ = transaction.closeDescriptors()
		return nil, err
	}
	closeActivation = false
	closeJournal = false
	return transaction, nil
}

func verifyPermitBinding(metadata permit, journal *namedFile, activation *activationHandle, bootID string) error {
	if metadata.BootID != bootID || metadata.JournalDevice != journal.stat.Dev || metadata.JournalInode != journal.stat.Ino ||
		metadata.ActivationLockDevice != activation.stat.Dev || metadata.ActivationLockInode != activation.stat.Ino {
		return errors.New("core activation permit binding is invalid")
	}
	return nil
}

func verifyExclusivePermitLock(named *namedFile, value layout) error {
	if named == nil || named.file == nil {
		return errors.New("core activation permit handle is invalid")
	}
	parentFD, err := openEvidenceParent(value, named.path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(named.path), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("reopen core activation permit lock")
	}
	probe := os.NewFile(uintptr(fd), named.path)
	defer probe.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !sameStableStat(before, named.stat) || before.Nlink != named.stat.Nlink ||
		validateNamedFileStat(before, value, maxPermitBytes) != nil || verifyNamedStat(parentFD, filepath.Base(named.path), before) != nil {
		return errors.New("reopened core activation permit names another inode")
	}
	err = unix.Flock(int(probe.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(probe.Fd()), unix.LOCK_UN)
		return errors.New("core activation permit is not held exclusively")
	}
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		return errors.New("inspect core activation permit ownership")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameStableStat(before, after) || before.Nlink != after.Nlink ||
		verifyNamedStat(parentFD, filepath.Base(named.path), after) != nil {
		return errors.New("reopened core activation permit changed during lock inspection")
	}
	return nil
}

func (pending *Pending) verifyJournal() error {
	if pending == nil || pending.closed || pending.journalFile == nil {
		return errors.New("core activation pending handle is invalid")
	}
	journal, err := decodeJournal(pending.journalFile, pending.layout)
	if err != nil {
		return err
	}
	if !slices.Equal(journal.Units, pending.journal.Units) || journal.SchemaVersion != pending.journal.SchemaVersion {
		return errors.New("core activation journal changed")
	}
	// Reopen the name and authenticate the same inode and canonical bytes. This
	// catches descriptor/name displacement independently of verifyName.
	reopened, err := openNamed(pending.layout, pending.layout.journalPath, maxJournalBytes)
	if err != nil {
		return err
	}
	defer reopened.close()
	if reopened.stat.Dev != pending.journalFile.stat.Dev || reopened.stat.Ino != pending.journalFile.stat.Ino {
		return errors.New("core activation journal inode changed")
	}
	other, err := decodeJournal(reopened, pending.layout)
	if err != nil || !slices.Equal(other.Units, journal.Units) || other.SchemaVersion != journal.SchemaVersion {
		return errors.New("core activation journal readback changed")
	}
	return nil
}

// Verify reopens and revalidates both evidence names, canonical JSON, the
// stable descriptors, this boot, both inode bindings, the permit flock, and
// continued exclusive ownership of the exact activation-lock pathname.
func (transaction *Transaction) Verify() error {
	if transaction == nil || transaction.closed || transaction.committed || transaction.pending == nil ||
		!transaction.permitLocked || transaction.pending.permitFile == nil {
		return errors.New("core activation transaction is invalid")
	}
	pending := transaction.pending
	if err := pending.activation.verify(); err != nil {
		return err
	}
	if err := pending.verifyJournal(); err != nil {
		return err
	}
	metadata, err := decodePermit(pending.permitFile, pending.layout)
	if err != nil {
		return err
	}
	bootID, err := currentBootID(pending.layout)
	if err != nil {
		return err
	}
	if err := verifyPermitBinding(metadata, pending.journalFile, pending.activation, bootID); err != nil {
		return err
	}
	if err := verifyExclusivePermitLock(pending.permitFile, pending.layout); err != nil {
		return err
	}
	return nil
}

func removeNamed(value layout, named *namedFile, max int) (bool, error) {
	if err := named.verifyName(value, max); err != nil {
		return false, err
	}
	parentFD, err := openEvidenceParent(value, named.path)
	if err != nil {
		return false, err
	}
	defer unix.Close(parentFD)
	if err := verifyNamedStat(parentFD, filepath.Base(named.path), named.stat); err != nil {
		return false, err
	}
	if err := unix.Unlinkat(parentFD, filepath.Base(named.path), 0); err != nil {
		return false, fmt.Errorf("unlink core activation evidence %s: %w", filepath.Base(named.path), err)
	}
	if err := value.fsync(parentFD); err != nil {
		return true, fmt.Errorf("synchronize core activation evidence removal %s: %w", filepath.Base(named.path), err)
	}
	return true, nil
}

func restoreJournal(value layout, journal Journal) error {
	payload, err := canonicalJournal(journal)
	if err != nil {
		return err
	}
	if _, exists, inspectErr := evidenceExists(value, value.journalPath); inspectErr != nil {
		return inspectErr
	} else if exists {
		return nil
	}
	named, err := publishNamed(value, value.journalPath, payload, maxJournalBytes, false)
	if named != nil {
		_ = named.close()
	}
	return err
}

func (transaction *Transaction) closeDescriptors() error {
	if transaction == nil || transaction.pending == nil {
		return nil
	}
	pending := transaction.pending
	var unlockErr error
	if transaction.permitLocked && pending.permitFile != nil && pending.permitFile.file != nil {
		unlockErr = unix.Flock(int(pending.permitFile.file.Fd()), unix.LOCK_UN)
		transaction.permitLocked = false
	}
	err := errors.Join(unlockErr, pending.permitFile.close(), pending.journalFile.close(), pending.activation.close())
	pending.closed = true
	transaction.closed = true
	return err
}

func (transaction *Transaction) removePermit() error {
	if err := transaction.Verify(); err != nil {
		return err
	}
	removed, err := removeNamed(transaction.pending.layout, transaction.pending.permitFile, maxPermitBytes)
	if removed {
		// The descriptor remains locked until all settlement decisions finish,
		// but the absent name now makes every new service admission fail closed
		// while the journal still exists.
		transaction.pending.permitFile.stat.Nlink = 0
	}
	return err
}

// Commit settles a successfully activated fleet. Permit removal and its
// directory fsync always complete before journal removal begins. Any ambiguous
// permit-removal error leaves the journal. If final journal fsync fails, the
// package attempts to republish canonical retry evidence before returning.
func (transaction *Transaction) Commit() error {
	if err := transaction.Verify(); err != nil {
		closeErr := transaction.closeDescriptors()
		return errors.Join(err, closeErr)
	}
	if err := transaction.removePermit(); err != nil {
		closeErr := transaction.closeDescriptors()
		return errors.Join(err, closeErr)
	}
	removed, removeErr := removeNamed(transaction.pending.layout, transaction.pending.journalFile, maxJournalBytes)
	if removed {
		transaction.pending.journalFile.stat.Nlink = 0
	}
	if removeErr != nil {
		var restoreErr error
		if removed {
			restoreErr = restoreJournal(transaction.pending.layout, transaction.pending.journal)
		}
		closeErr := transaction.closeDescriptors()
		return errors.Join(removeErr, restoreErr, closeErr)
	}
	transaction.committed = true
	return transaction.closeDescriptors()
}

// Close gracefully abandons a live transaction. It removes and fsyncs only
// the permit, then releases all descriptors. The journal always remains.
func (transaction *Transaction) Close() error {
	if transaction == nil || transaction.closed {
		return nil
	}
	if transaction.committed {
		return transaction.closeDescriptors()
	}
	if err := transaction.Verify(); err != nil {
		closeErr := transaction.closeDescriptors()
		return errors.Join(err, closeErr)
	}
	err := transaction.removePermit()
	return errors.Join(err, transaction.closeDescriptors())
}

// LoadPending returns (nil, nil) only when both evidence paths are stably
// absent. Orphan, unsafe, noncanonical, cross-boot, or incorrectly bound
// evidence is rejected. The exact activation lock must be held exclusively.
func LoadPending() (*Pending, error) {
	return loadPendingAt(productionLayout())
}

func loadPendingAt(value layout) (*Pending, error) {
	value = value.normalized()
	if err := value.validate(); err != nil {
		return nil, err
	}
	activation, err := openActivation(value)
	if err != nil {
		return nil, err
	}
	closeActivation := true
	defer func() {
		if closeActivation {
			_ = activation.close()
		}
	}()
	snapshot, err := stableEvidenceSnapshot(value)
	if err != nil {
		return nil, err
	}
	if !snapshot.journal && !snapshot.permit {
		return nil, nil
	}
	if !snapshot.journal && snapshot.permit {
		return nil, errors.New("orphan core activation permit exists")
	}
	journalFile, err := openNamed(value, value.journalPath, maxJournalBytes)
	if err != nil {
		return nil, err
	}
	closeJournal := true
	defer func() {
		if closeJournal {
			_ = journalFile.close()
		}
	}()
	journal, err := decodeJournal(journalFile, value)
	if err != nil {
		return nil, err
	}
	pending := &Pending{layout: value, journal: journal, journalFile: journalFile, activation: activation}
	if snapshot.permit {
		permitFile, err := openNamed(value, value.permitPath, maxPermitBytes)
		if err != nil {
			return nil, err
		}
		closePermit := true
		defer func() {
			if closePermit {
				_ = permitFile.close()
			}
		}()
		metadata, err := decodePermit(permitFile, value)
		if err != nil {
			return nil, err
		}
		bootID, err := currentBootID(value)
		if err != nil {
			return nil, err
		}
		if err := verifyPermitBinding(metadata, journalFile, activation, bootID); err != nil {
			return nil, err
		}
		pending.permitFile = permitFile
		closePermit = false
	}
	if err := pending.verifyJournal(); err != nil {
		return nil, err
	}
	closeActivation = false
	closeJournal = false
	return pending, nil
}

// Journal returns a defensive copy of the authenticated rollback contract.
func (pending *Pending) Journal() Journal {
	if pending == nil {
		return Journal{}
	}
	return Journal{SchemaVersion: pending.journal.SchemaVersion, Units: append([]string(nil), pending.journal.Units...)}
}

// PermitPresent reports whether LoadPending authenticated a permit pathname.
// It does not imply that the permit is stale; ReconcileStalePermit performs the
// atomic lock acquisition that distinguishes a dead owner from a live one.
func (pending *Pending) PermitPresent() bool {
	return pending != nil && !pending.closed && pending.permitFile != nil
}

// ReconcileStalePermit removes an unlocked, exact same-boot permit only while
// the caller still owns the exact activation lock. A live owner (or any shared
// foreign lock) makes LOCK_EX fail and is never stolen.
func (pending *Pending) ReconcileStalePermit() error {
	if pending == nil || pending.closed {
		return errors.New("core activation pending handle is invalid")
	}
	if pending.permitFile == nil {
		return nil
	}
	if err := pending.activation.verify(); err != nil {
		return err
	}
	if err := pending.verifyJournal(); err != nil {
		return err
	}
	metadata, err := decodePermit(pending.permitFile, pending.layout)
	if err != nil {
		return err
	}
	bootID, err := currentBootID(pending.layout)
	if err != nil {
		return err
	}
	if err := verifyPermitBinding(metadata, pending.journalFile, pending.activation, bootID); err != nil {
		return err
	}
	fd := int(pending.permitFile.file.Fd())
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return errors.New("live core activation transaction still owns its permit")
		}
		return errors.New("lock stale core activation permit")
	}
	locked := true
	defer func() {
		if locked {
			_ = unix.Flock(fd, unix.LOCK_UN)
		}
	}()
	// Lock acquisition is a synchronization boundary; revalidate every binding
	// and pathname after it before unlinking anything.
	if err := pending.activation.verify(); err != nil {
		return err
	}
	if err := pending.verifyJournal(); err != nil {
		return err
	}
	metadata, err = decodePermit(pending.permitFile, pending.layout)
	if err != nil || verifyPermitBinding(metadata, pending.journalFile, pending.activation, bootID) != nil {
		return errors.New("stale core activation permit changed while it was locked")
	}
	removed, removeErr := removeNamed(pending.layout, pending.permitFile, maxPermitBytes)
	if removed {
		pending.permitFile.stat.Nlink = 0
	}
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	locked = false
	closeErr := pending.permitFile.close()
	pending.permitFile = nil
	return errors.Join(removeErr, unlockErr, closeErr)
}

func proveEvidenceAbsent(value layout, path string) error {
	firstParent, first, err := evidenceExists(value, path)
	if err != nil {
		return err
	}
	secondParent, second, err := evidenceExists(value, path)
	if err != nil {
		return err
	}
	if first || second || firstParent != secondParent {
		return errors.New("core activation evidence is not stably absent")
	}
	return nil
}

// RemoveJournalAfterRollback settles only a caller-proved fail-closed rollback.
// It refuses while any permit name exists and revalidates the original journal
// descriptor, canonical content, name, and activation lock immediately before
// removal. A final fsync error triggers best-effort canonical republication.
func (pending *Pending) RemoveJournalAfterRollback() error {
	if pending == nil || pending.closed {
		return errors.New("core activation pending handle is invalid")
	}
	if pending.permitFile != nil {
		return errors.New("core activation permit must be reconciled before journal removal")
	}
	if err := pending.activation.verify(); err != nil {
		return err
	}
	if err := proveEvidenceAbsent(pending.layout, pending.layout.permitPath); err != nil {
		return err
	}
	if err := pending.verifyJournal(); err != nil {
		return err
	}
	removed, removeErr := removeNamed(pending.layout, pending.journalFile, maxJournalBytes)
	if removed {
		pending.journalFile.stat.Nlink = 0
	}
	var restoreErr error
	if removeErr != nil && removed {
		restoreErr = restoreJournal(pending.layout, pending.journal)
	}
	closeErr := pending.Close()
	return errors.Join(removeErr, restoreErr, closeErr)
}

// Close releases a loaded Pending handle without changing durable or volatile
// evidence. It is safe to call more than once.
func (pending *Pending) Close() error {
	if pending == nil || pending.closed {
		return nil
	}
	pending.closed = true
	return errors.Join(pending.permitFile.close(), pending.journalFile.close(), pending.activation.close())
}
