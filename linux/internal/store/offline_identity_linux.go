//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	offlinePortalWorkPrefix = "workagent-portal-offline-"
	offlinePortalMainLimit  = int64(4 * 1024 * 1024 * 1024)
	offlinePortalWALLimit   = int64(4 * 1024 * 1024 * 1024)
	offlinePortalSHMLimit   = int64(1 * 1024 * 1024 * 1024)
	offlinePortalJournalMax = int64(4 * 1024 * 1024 * 1024)
)

const offlinePortalResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

// PortalUserIdentity is the part of a Portal user row that must agree with the
// production tenant catalog before either Portal or a UserHost is activated.
type PortalUserIdentity struct {
	TenantID    string
	RuntimeUser string
	DataRoot    string
	Enabled     bool
}

// InspectPortalIdentitiesOffline returns the complete Portal user identity
// catalog from a stopped Portal database. The caller must hold the Portal
// runtime lock exclusively for the whole call. This function deliberately
// does not acquire that lock itself so callers can preserve the global lock
// order while comparing the returned rows with other protected state.
//
// The live database and every present SQLite sidecar are opened without
// following links and pinned to their exact pathname identity. A private copy
// of the main database, WAL, and rollback journal is then inspected. The SHM
// file is validated but never copied: SQLite reconstructs private WAL-index
// state for the copy instead of trusting shared-memory bytes from the live
// tree.
func InspectPortalIdentitiesOffline(ctx context.Context, databasePath string, expectedUID, expectedGID uint32) ([]PortalUserIdentity, error) {
	if ctx == nil {
		return nil, errors.New("Portal database inspection context is missing")
	}
	sources, err := openOfflinePortalSources(databasePath, expectedUID, expectedGID)
	if err != nil {
		return nil, err
	}
	defer sources.close()

	workRoot, workFD, err := makeOfflinePortalWorkRoot()
	if err != nil {
		return nil, err
	}
	defer cleanupOfflinePortalWorkRoot(workRoot, workFD)

	copyPath := filepath.Join(workRoot, "portal.db")
	for _, source := range sources.files {
		if !source.present || source.suffix == "-shm" {
			continue
		}
		if err := copyOfflinePortalSource(ctx, workFD, "portal.db"+source.suffix, source); err != nil {
			return nil, fmt.Errorf("copy stopped Portal database%s: %w", source.suffix, err)
		}
	}
	if err := unix.Fsync(workFD); err != nil {
		return nil, fmt.Errorf("synchronize private Portal database copy: %w", err)
	}
	if err := sources.revalidate(); err != nil {
		return nil, err
	}

	identities, inspectErr := inspectOfflinePortalCopy(ctx, copyPath)
	revalidateErr := sources.revalidate()
	if inspectErr != nil || revalidateErr != nil {
		return nil, errors.Join(inspectErr, revalidateErr)
	}
	return identities, nil
}

type offlinePortalSource struct {
	suffix  string
	limit   int64
	present bool
	fd      int
	stat    unix.Stat_t
}

type offlinePortalSources struct {
	rootFD     int
	parentFD   int
	parentPath string
	parentStat unix.Stat_t
	base       string
	uid        uint32
	gid        uint32
	files      []*offlinePortalSource
}

func openOfflinePortalSources(databasePath string, expectedUID, expectedGID uint32) (*offlinePortalSources, error) {
	if !filepath.IsAbs(databasePath) || filepath.Clean(databasePath) != databasePath || filepath.Base(databasePath) == "." || filepath.Base(databasePath) == string(filepath.Separator) {
		return nil, errors.New("Portal database path must be clean and absolute")
	}
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for Portal database inspection: %w", err)
	}
	parentPath := filepath.Dir(databasePath)
	parentRelative := strings.TrimPrefix(parentPath, string(filepath.Separator))
	if parentRelative == "" {
		parentRelative = "."
	}
	parentFD, err := unix.Openat2(rootFD, filepath.ToSlash(parentRelative), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: offlinePortalResolve,
	})
	if err != nil {
		unix.Close(rootFD)
		return nil, errors.New("Portal database parent path is unsafe")
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(parentFD)
		unix.Close(rootFD)
		return nil, errors.New("Portal database parent identity is unavailable")
	}
	result := &offlinePortalSources{
		rootFD: rootFD, parentFD: parentFD, parentPath: parentRelative, parentStat: parentStat,
		base: filepath.Base(databasePath), uid: expectedUID, gid: expectedGID,
		files: []*offlinePortalSource{
			{suffix: "", limit: offlinePortalMainLimit, fd: -1},
			{suffix: "-wal", limit: offlinePortalWALLimit, fd: -1},
			{suffix: "-shm", limit: offlinePortalSHMLimit, fd: -1},
			{suffix: "-journal", limit: offlinePortalJournalMax, fd: -1},
		},
	}
	clean := false
	defer func() {
		if !clean {
			result.close()
		}
	}()
	for index, source := range result.files {
		mandatory := index == 0
		if err := result.openSource(source, mandatory); err != nil {
			return nil, err
		}
	}
	if err := result.revalidate(); err != nil {
		return nil, err
	}
	clean = true
	return result, nil
}

func (s *offlinePortalSources) openSource(source *offlinePortalSource, mandatory bool) error {
	name := s.base + source.suffix
	var named unix.Stat_t
	err := unix.Fstatat(s.parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) && !mandatory {
		return nil
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return errors.New("Portal database is missing")
		}
		return fmt.Errorf("inspect Portal database%s: %w", source.suffix, err)
	}
	if err := validateOfflinePortalMetadata(named, source.limit, s.uid, s.gid, mandatory); err != nil {
		return fmt.Errorf("Portal database%s is unsafe: %w", source.suffix, err)
	}
	fd, err := unix.Openat2(s.parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: offlinePortalResolve,
	})
	if err != nil {
		return fmt.Errorf("open Portal database%s without following links: %w", source.suffix, err)
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !stableOfflinePortalStat(named, opened) {
		unix.Close(fd)
		return fmt.Errorf("Portal database%s changed while it was opened", source.suffix)
	}
	source.present = true
	source.fd = fd
	source.stat = opened
	return nil
}

func validateOfflinePortalMetadata(stat unix.Stat_t, maximum int64, expectedUID, expectedGID uint32, requireContent bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != expectedUID || stat.Gid != expectedGID || stat.Nlink != 1 {
		return errors.New("ownership, mode, link count, or object type is invalid")
	}
	if stat.Size < 0 || stat.Size > maximum || (requireContent && stat.Size == 0) {
		return errors.New("size is outside the inspection boundary")
	}
	return nil
}

func (s *offlinePortalSources) revalidate() error {
	currentParentFD, err := unix.Openat2(s.rootFD, filepath.ToSlash(s.parentPath), &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: offlinePortalResolve,
	})
	if err != nil {
		return errors.New("Portal database parent path identity changed during inspection")
	}
	var currentParent unix.Stat_t
	currentErr := unix.Fstat(currentParentFD, &currentParent)
	_ = unix.Close(currentParentFD)
	if currentErr != nil || !sameOfflinePortalObject(s.parentStat, currentParent) {
		return errors.New("Portal database parent path identity changed during inspection")
	}
	var openedParent unix.Stat_t
	if err := unix.Fstat(s.parentFD, &openedParent); err != nil || !stableOfflinePortalStat(s.parentStat, openedParent) {
		return errors.New("opened Portal database parent changed during inspection")
	}
	for index, source := range s.files {
		name := s.base + source.suffix
		var named unix.Stat_t
		err := unix.Fstatat(s.parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW)
		if !source.present {
			if !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("Portal database%s appeared during inspection", source.suffix)
			}
			continue
		}
		if err != nil || !stableOfflinePortalStat(source.stat, named) {
			return fmt.Errorf("Portal database%s path identity changed during inspection", source.suffix)
		}
		var opened unix.Stat_t
		if err := unix.Fstat(source.fd, &opened); err != nil || !stableOfflinePortalStat(source.stat, opened) {
			return fmt.Errorf("opened Portal database%s changed during inspection", source.suffix)
		}
		if err := validateOfflinePortalMetadata(opened, source.limit, s.uid, s.gid, index == 0); err != nil {
			return fmt.Errorf("Portal database%s became unsafe: %w", source.suffix, err)
		}
	}
	return nil
}

func (s *offlinePortalSources) close() {
	if s == nil {
		return
	}
	for _, source := range s.files {
		if source.fd >= 0 {
			_ = unix.Close(source.fd)
			source.fd = -1
		}
	}
	if s.parentFD >= 0 {
		_ = unix.Close(s.parentFD)
		s.parentFD = -1
	}
	if s.rootFD >= 0 {
		_ = unix.Close(s.rootFD)
		s.rootFD = -1
	}
}

func stableOfflinePortalStat(before, after unix.Stat_t) bool {
	return sameOfflinePortalObject(before, after) && before.Size == after.Size && before.Blocks == after.Blocks &&
		before.Mtim.Sec == after.Mtim.Sec && before.Mtim.Nsec == after.Mtim.Nsec &&
		before.Ctim.Sec == after.Ctim.Sec && before.Ctim.Nsec == after.Ctim.Nsec
}

func sameOfflinePortalObject(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Nlink == after.Nlink && before.Uid == after.Uid && before.Gid == after.Gid
}

func makeOfflinePortalWorkRoot() (string, int, error) {
	const temporaryBase = "/tmp"
	info, err := os.Lstat(temporaryBase)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", -1, errors.New("private Portal inspection temporary parent is unsafe")
	}
	var stat unix.Stat_t
	statOK := unix.Lstat(temporaryBase, &stat) == nil
	privateOwner := statOK && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o022 == 0
	rootSticky := statOK && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
	if !privateOwner && !rootSticky {
		return "", -1, errors.New("private Portal inspection temporary parent is not protected")
	}
	workRoot, err := os.MkdirTemp(temporaryBase, offlinePortalWorkPrefix)
	if err != nil {
		return "", -1, fmt.Errorf("create private Portal inspection directory: %w", err)
	}
	clean := false
	defer func() {
		if !clean {
			_ = os.Remove(workRoot)
		}
	}()
	if err := os.Chmod(workRoot, 0o700); err != nil {
		return "", -1, fmt.Errorf("protect private Portal inspection directory: %w", err)
	}
	workFD, err := unix.Open(workRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", -1, errors.New("open private Portal inspection directory")
	}
	var opened unix.Stat_t
	var pathStat unix.Stat_t
	pathErr := unix.Lstat(workRoot, &pathStat)
	if fstatErr := unix.Fstat(workFD, &opened); pathErr != nil || fstatErr != nil ||
		pathStat.Mode&unix.S_IFMT != unix.S_IFDIR || pathStat.Mode&0o7777 != 0o700 ||
		opened.Uid != uint32(os.Geteuid()) || opened.Gid != uint32(os.Getegid()) || !stableOfflinePortalStat(pathStat, opened) {
		unix.Close(workFD)
		return "", -1, errors.New("private Portal inspection directory identity is unsafe")
	}
	clean = true
	return workRoot, workFD, nil
}

func copyOfflinePortalSource(ctx context.Context, workFD int, name string, source *offlinePortalSource) error {
	fd, err := unix.Openat(workFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	destination := os.NewFile(uintptr(fd), name)
	if destination == nil {
		unix.Close(fd)
		return errors.New("create destination file handle")
	}
	closeDestination := true
	defer func() {
		if closeDestination {
			_ = destination.Close()
		}
	}()
	if _, err := unix.Seek(source.fd, 0, io.SeekStart); err != nil {
		return err
	}
	buffer := make([]byte, 1024*1024)
	remaining := source.stat.Size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		request := int64(len(buffer))
		if remaining < request {
			request = remaining
		}
		read, readErr := unix.Read(source.fd, buffer[:request])
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
			remaining -= int64(read)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && remaining == 0 {
				break
			}
			return readErr
		}
		if read == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	var extra [1]byte
	if read, err := unix.Read(source.fd, extra[:]); read != 0 || err != nil {
		return errors.New("Portal database source size changed while it was copied")
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	closeDestination = false
	var copied unix.Stat_t
	if err := unix.Fstatat(workFD, name, &copied, unix.AT_SYMLINK_NOFOLLOW); err != nil || copied.Mode&unix.S_IFMT != unix.S_IFREG || copied.Mode&0o7777 != 0o600 || copied.Uid != uint32(os.Geteuid()) || copied.Gid != uint32(os.Getegid()) || copied.Nlink != 1 || copied.Size != source.stat.Size {
		return errors.New("private Portal database copy has unsafe metadata")
	}
	return nil
}

func inspectOfflinePortalCopy(ctx context.Context, databasePath string) ([]PortalUserIdentity, error) {
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(databasePath)}
	query := uri.Query()
	query.Set("mode", "rw")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "query_only(1)")
	uri.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, fmt.Errorf("open private Portal database copy: %w", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()

	transaction, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin private Portal database inspection: %w", err)
	}
	defer transaction.Rollback()
	var queryOnly int
	if err := transaction.QueryRowContext(ctx, `PRAGMA query_only`).Scan(&queryOnly); err != nil || queryOnly != 1 {
		return nil, errors.New("private Portal database inspection is not query-only")
	}
	var version int
	if err := transaction.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return nil, fmt.Errorf("read Portal database schema version: %w", err)
	}
	if version != schemaVersion {
		return nil, fmt.Errorf("Portal database schema version is %d; expected %d", version, schemaVersion)
	}
	if err := quickCheckOfflinePortal(ctx, transaction); err != nil {
		return nil, err
	}
	// Keep the activation inspector's integrity contract explicit even though
	// validatePortalSchema also checks this invariant during normal Store
	// initialization. No violation row may be ignored or partially scanned.
	if err := foreignKeyCheckOfflinePortal(ctx, transaction); err != nil {
		return nil, err
	}
	if err := validatePortalSchema(ctx, transaction); err != nil {
		return nil, fmt.Errorf("validate Portal database v%d schema: %w", schemaVersion, err)
	}
	identities, err := queryOfflinePortalIdentities(ctx, transaction)
	if err != nil {
		return nil, err
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("complete private Portal database inspection: %w", err)
	}
	return identities, nil
}

func foreignKeyCheckOfflinePortal(ctx context.Context, transaction *sql.Tx) error {
	rows, err := transaction.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("run Portal database foreign_key_check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("Portal database contains a foreign-key violation")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read Portal database foreign_key_check: %w", err)
	}
	return nil
}

func quickCheckOfflinePortal(ctx context.Context, transaction *sql.Tx) error {
	rows, err := transaction.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return fmt.Errorf("run Portal database quick_check: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("read Portal database quick_check: %w", err)
		}
		count++
		if result != "ok" {
			return errors.New("Portal database quick_check did not return ok")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read Portal database quick_check: %w", err)
	}
	if count != 1 {
		return errors.New("Portal database quick_check result is invalid")
	}
	return nil
}

func queryOfflinePortalIdentities(ctx context.Context, transaction *sql.Tx) ([]PortalUserIdentity, error) {
	rows, err := transaction.QueryContext(ctx, `SELECT tenant_id,typeof(tenant_id),runtime_user,typeof(runtime_user),data_root,typeof(data_root),enabled,typeof(enabled) FROM portal_users ORDER BY tenant_id,runtime_user,data_root,id`)
	if err != nil {
		return nil, fmt.Errorf("read Portal user identities: %w", err)
	}
	defer rows.Close()
	var identities []PortalUserIdentity
	for rows.Next() {
		var tenantID, tenantType, runtimeUser, runtimeType, dataRoot, dataRootType string
		var enabled any
		var enabledType string
		if err := rows.Scan(&tenantID, &tenantType, &runtimeUser, &runtimeType, &dataRoot, &dataRootType, &enabled, &enabledType); err != nil {
			return nil, fmt.Errorf("decode Portal user identity: %w", err)
		}
		if tenantType != "text" || runtimeType != "text" || dataRootType != "text" || tenantID == "" || runtimeUser == "" || dataRoot == "" ||
			!utf8.ValidString(tenantID) || !utf8.ValidString(runtimeUser) || !utf8.ValidString(dataRoot) ||
			strings.ContainsRune(tenantID, '\x00') || strings.ContainsRune(runtimeUser, '\x00') || strings.ContainsRune(dataRoot, '\x00') {
			return nil, errors.New("Portal user identity contains an invalid text value")
		}
		enabledInteger, ok := enabled.(int64)
		if !ok || enabledType != "integer" || (enabledInteger != 0 && enabledInteger != 1) {
			return nil, errors.New("Portal user enabled value is not exactly integer 0 or 1")
		}
		identities = append(identities, PortalUserIdentity{
			TenantID: tenantID, RuntimeUser: runtimeUser, DataRoot: dataRoot, Enabled: enabledInteger == 1,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read Portal user identities: %w", err)
	}
	return identities, nil
}

func cleanupOfflinePortalWorkRoot(workRoot string, workFD int) {
	if workFD >= 0 {
		_ = unix.Close(workFD)
	}
	if workRoot == "" || !filepath.IsAbs(workRoot) || filepath.Clean(workRoot) != workRoot ||
		!strings.HasPrefix(filepath.Base(workRoot), offlinePortalWorkPrefix) || filepath.Base(workRoot) == offlinePortalWorkPrefix {
		return
	}
	info, err := os.Lstat(workRoot)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return
	}
	var stat unix.Stat_t
	if unix.Lstat(workRoot, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return
	}
	entries, err := os.ReadDir(workRoot)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return
		}
	}
	for _, entry := range entries {
		_ = os.Remove(filepath.Join(workRoot, entry.Name()))
	}
	_ = os.Remove(workRoot)
}
