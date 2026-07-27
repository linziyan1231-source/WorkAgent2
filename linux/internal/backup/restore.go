package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/google/uuid"
)

func VerifyArchive(source io.Reader, key []byte) (Manifest, error) {
	return readArchive(source, key, "")
}

func RestoreArchive(source io.Reader, key []byte, target string) (Manifest, error) {
	if !cleanAbsolute(target) {
		return Manifest{}, errors.New("restore target must be a clean absolute path")
	}
	if _, err := os.Lstat(target); err == nil {
		return Manifest{}, errors.New("restore target already exists; a blank target is required")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	parent := filepath.Dir(target)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return Manifest{}, errors.New("restore target parent is missing or unsafe")
	}
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(target)+".partial-*")
	if err != nil {
		return Manifest{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	manifest, err := readArchive(source, key, temporary)
	if err != nil {
		return Manifest{}, err
	}
	if err := syncRestoredDirectories(temporary); err != nil {
		return Manifest{}, err
	}
	if err := renameNoReplace(temporary, target); err != nil {
		return Manifest{}, err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return Manifest{}, err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return Manifest{}, syncErr
	}
	if closeErr != nil {
		return Manifest{}, closeErr
	}
	committed = true
	return manifest, nil
}

// Files are synced as they are restored, but their directory entries and
// symlink inodes are durable only after every containing directory is synced.
// Walk bottom-up before publishing the restore root with RENAME_NOREPLACE.
func syncRestoredDirectories(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return fmt.Errorf("sync restored directory %s: %w", directory, err)
		}
	}
	return nil
}

// VerifyRestoredFiles binds an existing, resumable restore target back to the
// authenticated manifest. It checks every byte, type, mode and archived
// identity and rejects all extra entries; only restore-created ancestor
// directories that are implicit in the manifest are permitted.
func VerifyRestoredFiles(target string, manifest Manifest, requireRootOwner bool) error {
	if !cleanAbsolute(target) || manifest.SchemaVersion != ManifestSchemaVersion || manifest.BackupID == "" || len(manifest.Entries) == 0 {
		return errors.New("existing restore verification input is invalid")
	}
	rootInfo, err := os.Lstat(target)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		return errors.New("existing restore root is missing or unsafe")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || (requireRootOwner && (rootStat.Uid != 0 || rootStat.Gid != 0)) {
		return errors.New("existing restore root ownership is unsafe")
	}
	expected := make(map[string]Entry, len(manifest.Entries))
	allowedAncestors := map[string]bool{".": true}
	for _, entry := range manifest.Entries {
		if !strings.HasPrefix(entry.Path, "rootfs/") {
			return errors.New("authenticated restore manifest path is outside rootfs")
		}
		relative := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(entry.Path, "rootfs/")))
		if relative == "." || filepath.IsAbs(relative) || expected[relative].Path != "" {
			return errors.New("authenticated restore manifest contains an invalid or duplicate path")
		}
		expected[relative] = entry
		for parent := filepath.Dir(relative); parent != "."; parent = filepath.Dir(parent) {
			allowedAncestors[parent] = true
		}
	}
	seen := make(map[string]bool, len(expected))
	err = filepath.WalkDir(target, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(target, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("existing restore entry escapes its root")
		}
		if relative == "." {
			return nil
		}
		entry, covered := expected[relative]
		if !covered {
			if !allowedAncestors[relative] {
				return fmt.Errorf("existing restore contains unexpected entry %s", relative)
			}
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
				return errors.New("existing restore implicit directory is unsafe")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || (requireRootOwner && (stat.Uid != 0 || stat.Gid != 0)) {
				return errors.New("existing restore implicit directory ownership is unsafe")
			}
			return nil
		}
		if err := verifyRestoredManifestEntry(path, entry); err != nil {
			return fmt.Errorf("verify existing restored entry %s: %w", relative, err)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("existing restore omits authenticated manifest entries")
	}
	return nil
}

func verifyRestoredManifestEntry(path string, expected Entry) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != os.FileMode(expected.Mode) {
		return errors.New("restored entry mode does not match")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expected.UID || stat.Gid != expected.GID {
		return errors.New("restored entry ownership does not match")
	}
	switch expected.Type {
	case "directory":
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("restored directory type does not match")
		}
		after, err := os.Lstat(path)
		afterStat, afterOK := fileSyscallStat(after)
		if err != nil || !afterOK || !sameArchivedStat(stat, afterStat) {
			return errors.New("restored directory changed during verification")
		}
	case "symlink":
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("restored symbolic-link type does not match")
		}
		target, err := os.Readlink(path)
		if err != nil || target != expected.LinkTarget {
			return errors.New("restored symbolic-link target does not match")
		}
		after, err := os.Lstat(path)
		afterStat, afterOK := fileSyscallStat(after)
		if err != nil || !afterOK || !sameArchivedStat(stat, afterStat) {
			return errors.New("restored symbolic link changed during verification")
		}
	case "file":
		if !info.Mode().IsRegular() || info.Size() != expected.Size {
			return errors.New("restored file metadata does not match")
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		before, err := file.Stat()
		beforeStat, beforeOK := fileSyscallStat(before)
		if err != nil || !beforeOK || !sameArchivedStat(stat, beforeStat) || !os.SameFile(info, before) || before.Size() != expected.Size {
			file.Close()
			return errors.New("restored file changed while it was opened")
		}
		hash := sha256.New()
		written, copyErr := io.CopyN(hash, file, expected.Size)
		var extra [1]byte
		extraCount, extraErr := file.Read(extra[:])
		after, statErr := file.Stat()
		afterStat, afterOK := fileSyscallStat(after)
		closeErr := file.Close()
		named, namedErr := os.Lstat(path)
		namedStat, namedOK := fileSyscallStat(named)
		if copyErr != nil || written != expected.Size || extraCount != 0 || !errors.Is(extraErr, io.EOF) || statErr != nil || closeErr != nil ||
			!afterOK || namedErr != nil || !namedOK || !sameArchivedStat(beforeStat, afterStat) || !sameArchivedStat(beforeStat, namedStat) || !os.SameFile(before, after) {
			return errors.New("restored file changed while it was hashed")
		}
		if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return errors.New("restored file hash does not match")
		}
	default:
		return errors.New("restored manifest entry type is invalid")
	}
	return nil
}

type restoredDirectory struct {
	path string
	mode os.FileMode
	uid  int
	gid  int
}

func readArchive(source io.Reader, key []byte, restoreRoot string) (Manifest, error) {
	encrypted, err := newDecryptReader(source, key)
	if err != nil {
		return Manifest{}, err
	}
	compressed, err := gzip.NewReader(encrypted)
	if err != nil {
		return Manifest{}, errors.New("backup compression stream is invalid")
	}
	archive := tar.NewReader(compressed)
	entries := make([]Entry, 0)
	seen := make(map[string]bool)
	symlinkPaths := make(map[string]bool)
	directories := make([]restoredDirectory, 0)
	var manifest Manifest
	manifestSeen := false
	for count := 0; ; count++ {
		if count > maximumArchiveEntries+1 {
			return Manifest{}, errors.New("backup contains too many archive entries")
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, errors.New("backup archive is truncated or invalid")
		}
		if manifestSeen {
			return Manifest{}, errors.New("backup manifest is not the final archive entry")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == manifestArchivePath {
			if header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 64*1024*1024 || header.Mode != 0o400 {
				return Manifest{}, errors.New("backup manifest entry is invalid")
			}
			payload, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
			if err != nil || int64(len(payload)) != header.Size {
				return Manifest{}, errors.New("backup manifest entry is truncated")
			}
			if err := decodeManifest(payload, &manifest); err != nil {
				return Manifest{}, err
			}
			manifestSeen = true
			continue
		}
		entry, err := validateArchiveHeader(header, name)
		if err != nil {
			return Manifest{}, err
		}
		if seen[entry.Path] {
			return Manifest{}, errors.New("backup contains a duplicate filesystem entry")
		}
		seen[entry.Path] = true
		if hasSymlinkAncestor(entry.Path, symlinkPaths) {
			return Manifest{}, errors.New("backup entry traverses an archived symbolic link")
		}
		if entry.Type == "symlink" {
			symlinkPaths[entry.Path] = true
		}
		var destination io.Writer = io.Discard
		var output *os.File
		var outputPath string
		if restoreRoot != "" {
			outputPath, err = restorePath(restoreRoot, entry.Path)
			if err != nil {
				return Manifest{}, err
			}
			if err := ensureRestoreParents(restoreRoot, filepath.Dir(outputPath)); err != nil {
				return Manifest{}, err
			}
			switch entry.Type {
			case "directory":
				if err := ensureRestoreDirectory(outputPath); err != nil {
					return Manifest{}, err
				}
				if err := os.Chown(outputPath, int(entry.UID), int(entry.GID)); err != nil {
					return Manifest{}, err
				}
				directories = append(directories, restoredDirectory{path: outputPath, mode: os.FileMode(entry.Mode), uid: int(entry.UID), gid: int(entry.GID)})
			case "file":
				output, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return Manifest{}, err
				}
				destination = output
			case "symlink":
				if err := os.Symlink(entry.LinkTarget, outputPath); err != nil {
					return Manifest{}, err
				}
				if err := os.Lchown(outputPath, int(entry.UID), int(entry.GID)); err != nil {
					return Manifest{}, err
				}
			}
		}
		if entry.Type == "file" {
			hash := sha256.New()
			written, copyErr := io.CopyN(io.MultiWriter(destination, hash), archive, entry.Size)
			if output != nil {
				if copyErr == nil {
					copyErr = output.Chown(int(entry.UID), int(entry.GID))
				}
				if copyErr == nil {
					copyErr = output.Chmod(os.FileMode(entry.Mode))
				}
				if copyErr == nil {
					// Flush contents and the final ownership/mode through the same
					// no-follow descriptor before the containing directories are
					// synced and the complete tree is published.
					copyErr = output.Sync()
				}
				if closeErr := output.Close(); copyErr == nil {
					copyErr = closeErr
				}
			}
			if copyErr != nil || written != entry.Size {
				return Manifest{}, errors.New("backup file entry is truncated")
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
		}
		entries = append(entries, entry)
	}
	if err := compressed.Close(); err != nil {
		return Manifest{}, errors.New("backup compression trailer is invalid")
	}
	if err := encrypted.Complete(); err != nil {
		return Manifest{}, err
	}
	if !manifestSeen {
		return Manifest{}, errors.New("backup manifest is missing")
	}
	if !reflect.DeepEqual(entries, manifest.Entries) {
		return Manifest{}, errors.New("backup contents do not match the authenticated manifest")
	}
	if restoreRoot != "" {
		sort.Slice(directories, func(i, j int) bool { return len(directories[i].path) > len(directories[j].path) })
		for _, directory := range directories {
			if err := os.Chown(directory.path, directory.uid, directory.gid); err != nil {
				return Manifest{}, err
			}
			if err := os.Chmod(directory.path, directory.mode); err != nil {
				return Manifest{}, err
			}
		}
	}
	return manifest, nil
}

func decodeManifest(payload []byte, value *Manifest) error {
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("backup manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("backup manifest contains trailing data")
	}
	if value.SchemaVersion != ManifestSchemaVersion || uuid.Validate(value.BackupID) != nil || value.CreatedAt.IsZero() || !cleanAbsolute(value.PortalConfig) || len(value.Sources) == 0 || len(value.Entries) == 0 || len(value.Entries) > maximumArchiveEntries {
		return errors.New("backup manifest metadata is invalid")
	}
	if err := validateSources(value.Sources); err != nil {
		return err
	}
	if err := validateReleasePointers(value.ReleasePointers); err != nil {
		return err
	}
	if !sort.SliceIsSorted(value.ReleasePointers, func(i, j int) bool { return value.ReleasePointers[i].Path < value.ReleasePointers[j].Path }) {
		return errors.New("backup release-pointer evidence is not canonical")
	}
	return nil
}

func validateArchiveHeader(header *tar.Header, name string) (Entry, error) {
	if name == "" || strings.Contains(name, `\`) || filepath.IsAbs(name) || filepath.Clean(filepath.FromSlash(name)) != filepath.FromSlash(name) || !strings.HasPrefix(name, "rootfs/") || name == "rootfs" || header.Mode < 0 || header.Mode > 0o777 || header.Uid < 0 || header.Gid < 0 || header.Size < 0 {
		return Entry{}, errors.New("backup contains an unsafe archive header")
	}
	entry := Entry{Path: name, Mode: uint32(header.Mode), UID: uint32(header.Uid), GID: uint32(header.Gid)}
	switch header.Typeflag {
	case tar.TypeDir:
		if header.Size != 0 || header.Linkname != "" {
			return Entry{}, errors.New("backup directory header is invalid")
		}
		entry.Type = "directory"
	case tar.TypeReg, tar.TypeRegA:
		if header.Linkname != "" {
			return Entry{}, errors.New("backup file header is invalid")
		}
		entry.Type, entry.Size = "file", header.Size
	case tar.TypeSymlink:
		if header.Size != 0 || header.Linkname == "" || strings.ContainsRune(header.Linkname, 0) || len(header.Linkname) > 4096 {
			return Entry{}, errors.New("backup symbolic-link header is invalid")
		}
		entry.Type, entry.LinkTarget = "symlink", header.Linkname
	default:
		return Entry{}, errors.New("backup contains an unsupported archive entry")
	}
	return entry, nil
}

func hasSymlinkAncestor(path string, symlinks map[string]bool) bool {
	current := filepath.ToSlash(filepath.Dir(filepath.FromSlash(path)))
	for current != "." && current != "/" {
		if symlinks[current] {
			return true
		}
		current = filepath.ToSlash(filepath.Dir(filepath.FromSlash(current)))
	}
	return false
}

func restorePath(root, archivePath string) (string, error) {
	relative := strings.TrimPrefix(archivePath, "rootfs/")
	result := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, result)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("backup restore path escapes its target")
	}
	return result, nil
}

func ensureRestoreParents(root, parent string) error {
	relative, err := filepath.Rel(root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("backup restore parent escapes its target")
	}
	current := root
	if relative == "." {
		return nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("backup restore parent is unsafe")
		}
	}
	return nil
}

func ensureRestoreDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(path, 0o700)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("backup restore directory collides with another entry")
	}
	return nil
}

func ArchiveName(manifest Manifest) string {
	return fmt.Sprintf("workagent-%s-%s.wab", manifest.CreatedAt.UTC().Format("20060102T150405Z"), manifest.BackupID)
}
