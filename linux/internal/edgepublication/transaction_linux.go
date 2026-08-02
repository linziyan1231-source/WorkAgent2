//go:build linux

package edgepublication

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
)

type journal struct {
	SchemaVersion int    `json:"schema_version"`
	BootID        string `json:"boot_id"`
	PermitDevice  uint64 `json:"permit_device"`
	PermitInode   uint64 `json:"permit_inode"`
}

type permit struct {
	SchemaVersion int    `json:"schema_version"`
	BootID        string `json:"boot_id"`
	JournalDevice uint64 `json:"journal_device"`
	JournalInode  uint64 `json:"journal_inode"`
}

// Transaction is an in-progress edge publication. The volatile permit stays
// locked from Begin until Commit or Close so the blocking systemd watcher
// cannot admit Caddy before the caller proves fail-closed disablement.
type Transaction struct {
	permitFD       int
	permitStat     unix.Stat_t
	journalStat    unix.Stat_t
	permitPayload  []byte
	journalPayload []byte
}

func Begin() (_ *Transaction, resultErr error) {
	if err := validateDirectories(); err != nil {
		return nil, err
	}
	for _, path := range []string{JournalPath, PermitPath} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(errors.New("edge-publication crash evidence already exists"), err)
		}
	}
	bootID, err := currentBootID()
	if err != nil {
		return nil, err
	}
	transaction := &Transaction{permitFD: -1}
	journalFD := -1
	permitLinked := false
	journalLinked := false
	defer func() {
		if resultErr == nil {
			return
		}
		var cleanupErrors []error
		// Caddy is still disabled. Removing a published permit before its
		// journal ensures a cleanup crash leaves only a canonical lone journal.
		if permitLinked {
			if err := unlinkArtifactIdentity(PermitPath, transaction.permitStat); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				cleanupErrors = append(cleanupErrors, fsutil.SyncDirectory(filepath.Dir(PermitPath)))
			}
		}
		if journalLinked {
			if err := unlinkArtifactIdentity(JournalPath, transaction.journalStat); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				cleanupErrors = append(cleanupErrors, fsutil.SyncDirectory(filepath.Dir(JournalPath)))
			}
		}
		if journalFD >= 0 {
			cleanupErrors = append(cleanupErrors, unix.Close(journalFD))
			journalFD = -1
		}
		if transaction.permitFD >= 0 {
			cleanupErrors = append(cleanupErrors, unix.Close(transaction.permitFD))
			transaction.permitFD = -1
		}
		resultErr = errors.Join(resultErr, errors.Join(cleanupErrors...))
	}()

	permitFD, err := unix.Open(filepath.Dir(PermitPath), unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create anonymous edge-publication permit: %w", err)
	}
	transaction.permitFD = permitFD
	if err := unix.Fchmod(permitFD, 0o600); err != nil {
		return nil, err
	}
	if err := unix.Flock(permitFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock anonymous edge-publication permit: %w", err)
	}
	if err := unix.Fstat(permitFD, &transaction.permitStat); err != nil || !safeAnonymousArtifactStat(transaction.permitStat, true) {
		return nil, errors.Join(errors.New("anonymous edge-publication permit inode is unsafe"), err)
	}

	journalFD, err = unix.Open(filepath.Dir(JournalPath), unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create anonymous edge-publication journal: %w", err)
	}
	if err := unix.Fchmod(journalFD, 0o600); err != nil {
		return nil, err
	}
	if err := unix.Fstat(journalFD, &transaction.journalStat); err != nil || !safeAnonymousArtifactStat(transaction.journalStat, true) {
		return nil, errors.Join(errors.New("anonymous edge-publication journal inode is unsafe"), err)
	}

	journal := journal{SchemaVersion: 1, BootID: bootID, PermitDevice: transaction.permitStat.Dev, PermitInode: transaction.permitStat.Ino}
	transaction.journalPayload, err = canonicalJSON(journal)
	if err != nil {
		return nil, err
	}
	permit := permit{SchemaVersion: 1, BootID: bootID, JournalDevice: transaction.journalStat.Dev, JournalInode: transaction.journalStat.Ino}
	transaction.permitPayload, err = canonicalJSON(permit)
	if err != nil {
		return nil, err
	}
	if err := writeFD(journalFD, transaction.journalPayload); err != nil {
		return nil, err
	}
	if err := writeFD(permitFD, transaction.permitPayload); err != nil {
		return nil, err
	}
	if err := unix.Fsync(journalFD); err != nil {
		return nil, err
	}
	if err := unix.Fsync(permitFD); err != nil {
		return nil, err
	}
	if err := unix.Fstat(journalFD, &transaction.journalStat); err != nil || !safeAnonymousArtifactStat(transaction.journalStat, false) {
		return nil, errors.Join(errors.New("anonymous edge-publication journal payload is unsafe"), err)
	}
	if err := unix.Fstat(permitFD, &transaction.permitStat); err != nil || !safeAnonymousArtifactStat(transaction.permitStat, false) {
		return nil, errors.Join(errors.New("anonymous edge-publication permit payload is unsafe"), err)
	}

	if err := unix.Linkat(journalFD, "", unix.AT_FDCWD, JournalPath, unix.AT_EMPTY_PATH); err != nil {
		return nil, fmt.Errorf("publish canonical edge-publication journal: %w", err)
	}
	journalLinked = true
	if err := unix.Fstat(journalFD, &transaction.journalStat); err != nil || !safeArtifactStat(transaction.journalStat, false) {
		return nil, errors.Join(errors.New("published edge-publication journal inode is unsafe"), err)
	}
	if err := fsutil.SyncDirectory(filepath.Dir(JournalPath)); err != nil {
		return nil, err
	}
	if err := unix.Linkat(permitFD, "", unix.AT_FDCWD, PermitPath, unix.AT_EMPTY_PATH); err != nil {
		return nil, fmt.Errorf("publish canonical edge-publication permit: %w", err)
	}
	permitLinked = true
	if err := unix.Fstat(permitFD, &transaction.permitStat); err != nil || !safeArtifactStat(transaction.permitStat, false) {
		return nil, errors.Join(errors.New("published edge-publication permit inode is unsafe"), err)
	}
	if err := fsutil.SyncDirectory(filepath.Dir(PermitPath)); err != nil {
		return nil, err
	}
	closeErr := unix.Close(journalFD)
	journalFD = -1
	if closeErr != nil {
		return nil, closeErr
	}
	return transaction, nil
}

func (transaction *Transaction) Commit() error {
	if transaction == nil || transaction.permitFD < 0 {
		return errors.New("edge-publication transaction is unavailable")
	}
	if err := transaction.Verify(); err != nil {
		return err
	}
	// The durable journal is removed and synced first. The volatile permit
	// pathname is the final commit signal observed by the blocking systemd
	// watcher; no fallible durability operation may follow that signal. On any
	// earlier error this method deliberately retains the permit lock so the
	// watcher cannot admit Caddy before the caller proves fail-closed disablement.
	if err := unix.Unlink(JournalPath); err != nil {
		return err
	}
	if err := fsutil.SyncDirectory(filepath.Dir(JournalPath)); err != nil {
		return err
	}
	if err := unix.Unlink(PermitPath); err != nil {
		return err
	}
	closeErr := unix.Close(transaction.permitFD)
	transaction.permitFD = -1
	return closeErr
}

func (transaction *Transaction) Verify() error {
	if transaction == nil || transaction.permitFD < 0 {
		return errors.New("edge-publication transaction is unavailable")
	}
	if err := validateDirectories(); err != nil {
		return err
	}
	if err := verifyOpenArtifact(transaction.permitFD, PermitPath, transaction.permitStat, transaction.permitPayload); err != nil {
		return err
	}
	journalFD, err := unix.Open(JournalPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	journalErr := verifyOpenArtifact(journalFD, JournalPath, transaction.journalStat, transaction.journalPayload)
	return errors.Join(journalErr, unix.Close(journalFD))
}

func (transaction *Transaction) Close() error {
	if transaction == nil || transaction.permitFD < 0 {
		return nil
	}
	err := unix.Close(transaction.permitFD)
	transaction.permitFD = -1
	return err
}

func artifactEntryPresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, fmt.Errorf("inspect edge-publication evidence path %s: %w", path, err)
}

func unlinkArtifactIdentity(path string, expected unix.Stat_t) error {
	present, current, err := artifactState(path, false)
	if err != nil || !present || current.Dev != expected.Dev || current.Ino != expected.Ino {
		return errors.Join(fmt.Errorf("refuse to unlink replaced edge-publication artifact %s", path), err)
	}
	return unix.Unlink(path)
}

func validateRecoverableEvidence(journalPresent bool, journalFD int, journalStat unix.Stat_t, permitPresent bool, permitFD int, permitStat unix.Stat_t) error {
	if !journalPresent && !permitPresent {
		return errors.New("edge-publication evidence is absent")
	}
	var journal journal
	if journalPresent {
		payload, err := readOpenArtifact(journalFD, JournalPath, journalStat, false)
		if err != nil {
			return fmt.Errorf("read edge-publication journal: %w", err)
		}
		journal, err = decodeCanonicalJournal(payload)
		if err != nil {
			return err
		}
	}
	if permitPresent {
		payload, err := readOpenArtifact(permitFD, PermitPath, permitStat, true)
		if err != nil {
			return fmt.Errorf("read edge-publication permit: %w", err)
		}
		if len(payload) == 0 {
			return errors.New("visible edge-publication permit is empty")
		}
		permit, err := decodeCanonicalPermit(payload)
		if err != nil {
			return err
		}
		currentBootID, err := currentBootID()
		if err != nil {
			return err
		}
		if !journalPresent {
			// The success path durably removes the journal before the volatile
			// permit. A canonical lone permit is therefore a recoverable final
			// commit transition once Caddy has already been disabled.
			if permit.BootID != currentBootID {
				return errors.New("lone edge-publication permit belongs to another boot")
			}
			return nil
		}
		if journal.BootID != permit.BootID || journal.PermitDevice != permitStat.Dev || journal.PermitInode != permitStat.Ino ||
			permit.JournalDevice != journalStat.Dev || permit.JournalInode != journalStat.Ino {
			return errors.New("edge-publication journal and permit are not mutually bound")
		}
		if permit.BootID != currentBootID {
			return errors.New("paired edge-publication evidence belongs to another boot")
		}
		return nil
	}
	// Begin publishes the durable journal before the volatile permit. A lone
	// journal can therefore be a current-boot begin tail or a previous-boot
	// crash after /run was cleared, and remains safely recoverable.
	return nil
}

func decodeCanonicalJournal(payload []byte) (journal, error) {
	var value journal
	if err := decodeCanonicalJSON(payload, &value); err != nil {
		return journal{}, fmt.Errorf("edge-publication journal is not canonical: %w", err)
	}
	if value.SchemaVersion != 1 || value.PermitDevice == 0 || value.PermitInode == 0 || !canonicalBootID(value.BootID) {
		return journal{}, errors.New("edge-publication journal fields are invalid")
	}
	return value, nil
}

func decodeCanonicalPermit(payload []byte) (permit, error) {
	var value permit
	if err := decodeCanonicalJSON(payload, &value); err != nil {
		return permit{}, fmt.Errorf("edge-publication permit is not canonical: %w", err)
	}
	if value.SchemaVersion != 1 || value.JournalDevice == 0 || value.JournalInode == 0 || !canonicalBootID(value.BootID) {
		return permit{}, errors.New("edge-publication permit fields are invalid")
	}
	return value, nil
}

func decodeCanonicalJSON(payload []byte, destination any) error {
	if len(payload) == 0 || len(payload) > 1024 || payload[len(payload)-1] != '\n' {
		return errors.New("edge-publication JSON size or termination is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.Join(errors.New("edge-publication JSON shape is invalid"), err)
	}
	canonical, err := canonicalJSON(destination)
	if err != nil || !bytes.Equal(canonical, payload) {
		return errors.Join(errors.New("edge-publication JSON encoding is not canonical"), err)
	}
	return nil
}

func canonicalBootID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && len(value) == 36
}

func readOpenArtifact(fd int, path string, expected unix.Stat_t, allowEmpty bool) ([]byte, error) {
	if fd < 0 || expected.Size < 0 || expected.Size > 1024 || !safeArtifactStat(expected, allowEmpty) {
		return nil, errors.New("edge-publication artifact descriptor contract is invalid")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameArtifactStat(opened, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact descriptor changed"), err)
	}
	present, pathStat, err := artifactState(path, allowEmpty)
	if err != nil || !present || !sameArtifactStat(pathStat, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact path changed"), err)
	}
	buffer := make([]byte, int(expected.Size)+1)
	count, err := unix.Pread(fd, buffer, 0)
	if err != nil || count != int(expected.Size) {
		return nil, errors.Join(errors.New("edge-publication artifact content length changed"), err)
	}
	if err := unix.Fstat(fd, &opened); err != nil || !sameArtifactStat(opened, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact changed while reading"), err)
	}
	present, pathStat, err = artifactState(path, allowEmpty)
	if err != nil || !present || !sameArtifactStat(pathStat, expected) {
		return nil, errors.Join(errors.New("edge-publication artifact path changed while reading"), err)
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func validateDirectories() error {
	for _, path := range []string{filepath.Dir(JournalPath), filepath.Dir(PermitPath)} {
		info, err := os.Lstat(path)
		stat, ok := fsutil.InfoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("edge-publication directory %s is unsafe", path), err)
		}
	}
	return nil
}

func artifactState(path string, allowEmpty bool) (bool, unix.Stat_t, error) {
	var stat unix.Stat_t
	err := unix.Lstat(path, &stat)
	if errors.Is(err, unix.ENOENT) {
		return false, unix.Stat_t{}, nil
	}
	if err != nil {
		return false, unix.Stat_t{}, errors.Join(errors.New("inspect edge-publication artifact"), err)
	}
	if !safeArtifactStat(stat, allowEmpty) {
		return false, unix.Stat_t{}, errors.New("edge-publication artifact metadata is unsafe")
	}
	return true, stat, nil
}

func safeArtifactStat(stat unix.Stat_t, allowEmpty bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 1 && stat.Size >= 0 && stat.Size <= 1024 && (allowEmpty || stat.Size > 0)
}

func safeAnonymousArtifactStat(stat unix.Stat_t, allowEmpty bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 && stat.Uid == 0 && stat.Gid == 0 && stat.Nlink == 0 && stat.Size >= 0 && stat.Size <= 1024 && (allowEmpty || stat.Size > 0)
}

func sameArtifactStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink && left.Size == right.Size
}

func canonicalJSON(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > 1023 {
		return nil, errors.Join(errors.New("edge-publication evidence is invalid"), err)
	}
	return append(payload, '\n'), nil
}

func currentBootID() (string, error) {
	payload, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(payload) != 37 || payload[36] != '\n' {
		return "", errors.Join(errors.New("current boot identity is invalid"), err)
	}
	value := string(payload[:36])
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return "", errors.New("current boot identity is not canonical")
	}
	return value, nil
}

func writeFD(fd int, payload []byte) error {
	for len(payload) > 0 {
		written, err := unix.Write(fd, payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func verifyOpenArtifact(fd int, path string, expected unix.Stat_t, payload []byte) error {
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameArtifactStat(opened, expected) {
		return errors.Join(errors.New("edge-publication artifact descriptor changed"), err)
	}
	present, pathStat, err := artifactState(path, false)
	if err != nil || !present || !sameArtifactStat(pathStat, expected) {
		return errors.Join(errors.New("edge-publication artifact path changed"), err)
	}
	buffer := make([]byte, len(payload)+1)
	count, err := unix.Pread(fd, buffer, 0)
	if err != nil || count != len(payload) || !bytes.Equal(buffer[:count], payload) {
		return errors.Join(errors.New("edge-publication artifact content changed"), err)
	}
	return nil
}
