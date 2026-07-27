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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	ManifestSchemaVersion = 1
	manifestArchivePath   = "_workagent/manifest.json"
	maximumArchiveEntries = 2_000_000
)

type Source struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type ReleasePointer struct {
	Path      string `json:"path"`
	Scope     string `json:"scope"`
	Current   string `json:"current"`
	Previous  string `json:"previous,omitempty"`
	Activated string `json:"activated_at"`
}

type Manifest struct {
	SchemaVersion   int              `json:"schema_version"`
	BackupID        string           `json:"backup_id"`
	CreatedAt       time.Time        `json:"created_at"`
	PortalConfig    string           `json:"portal_config"`
	Sources         []Source         `json:"sources"`
	ReleasePointers []ReleasePointer `json:"release_pointers"`
	Entries         []Entry          `json:"entries"`
}

type Entry struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Size       int64  `json:"size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
}

type CreateInput struct {
	PortalConfig    string
	Sources         []Source
	ReleasePointers []ReleasePointer
	Now             time.Time
}

type archivedDirectorySnapshot struct {
	path    string
	stat    syscall.Stat_t
	entries []string
}

func CreateArchive(destination io.Writer, key []byte, input CreateInput) (Manifest, error) {
	if destination == nil || !cleanAbsolute(input.PortalConfig) || len(input.Sources) == 0 || len(input.Sources) > 10000 {
		return Manifest{}, errors.New("backup archive input is invalid")
	}
	if input.Now.IsZero() {
		input.Now = time.Now().UTC()
	}
	input.Now = input.Now.UTC()
	if err := validateSources(input.Sources); err != nil {
		return Manifest{}, err
	}
	if err := validateReleasePointers(input.ReleasePointers); err != nil {
		return Manifest{}, err
	}
	sort.Slice(input.ReleasePointers, func(i, j int) bool { return input.ReleasePointers[i].Path < input.ReleasePointers[j].Path })
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, BackupID: uuid.NewString(), CreatedAt: input.Now, PortalConfig: input.PortalConfig, Sources: append([]Source(nil), input.Sources...), ReleasePointers: append([]ReleasePointer(nil), input.ReleasePointers...)}
	sort.Slice(manifest.Sources, func(i, j int) bool { return manifest.Sources[i].Path < manifest.Sources[j].Path })

	encrypted, err := newEncryptWriter(destination, key)
	if err != nil {
		return Manifest{}, err
	}
	compressed, err := gzip.NewWriterLevel(encrypted, gzip.BestCompression)
	if err != nil {
		return Manifest{}, err
	}
	compressed.Name = ""
	compressed.Comment = ""
	compressed.ModTime = time.Unix(0, 0).UTC()
	archive := tar.NewWriter(compressed)
	closeWithError := func(operationErr error) error {
		archiveErr := archive.Close()
		gzipErr := compressed.Close()
		encryptionErr := encrypted.Close()
		if operationErr != nil {
			return operationErr
		}
		if archiveErr != nil {
			return archiveErr
		}
		if gzipErr != nil {
			return gzipErr
		}
		return encryptionErr
	}

	seen := make(map[string]struct{})
	for _, source := range manifest.Sources {
		if err := appendSource(archive, source.Path, &manifest, seen); err != nil {
			return Manifest{}, closeWithError(err)
		}
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, closeWithError(err)
	}
	payload = append(payload, '\n')
	header := &tar.Header{Name: manifestArchivePath, Typeflag: tar.TypeReg, Mode: 0o400, Size: int64(len(payload)), Uid: 0, Gid: 0, ModTime: input.Now, Format: tar.FormatPAX}
	if err := archive.WriteHeader(header); err != nil {
		return Manifest{}, closeWithError(err)
	}
	if _, err := archive.Write(payload); err != nil {
		return Manifest{}, closeWithError(err)
	}
	if err := closeWithError(nil); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func appendSource(archive *tar.Writer, sourcePath string, manifest *Manifest, seen map[string]struct{}) error {
	rootInfo, err := os.Lstat(sourcePath)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || (!rootInfo.IsDir() && !rootInfo.Mode().IsRegular()) {
		return fmt.Errorf("backup source is missing or unsafe: %s", sourcePath)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("backup source metadata is unavailable: %s", sourcePath)
	}
	var directories []archivedDirectorySnapshot
	err = filepath.WalkDir(sourcePath, func(path string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if len(manifest.Entries) >= maximumArchiveEntries {
			return errors.New("backup contains too many filesystem entries")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Dev != rootStat.Dev {
			return fmt.Errorf("backup source crosses a filesystem boundary: %s", path)
		}
		archivePath := "rootfs" + filepath.ToSlash(path)
		if _, duplicate := seen[archivePath]; duplicate {
			return fmt.Errorf("backup sources overlap at %s", path)
		}
		seen[archivePath] = struct{}{}
		entry := Entry{Path: archivePath, Mode: uint32(info.Mode().Perm()), UID: stat.Uid, GID: stat.Gid}
		header := &tar.Header{Name: archivePath, Mode: int64(info.Mode().Perm()), Uid: int(stat.Uid), Gid: int(stat.Gid), ModTime: info.ModTime().UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{}, Format: tar.FormatPAX}
		switch {
		case info.IsDir():
			entry.Type = "directory"
			header.Typeflag = tar.TypeDir
			header.Name += "/"
			names, err := archiveDirectoryNames(path)
			if err != nil {
				return fmt.Errorf("read backup directory %s: %w", path, err)
			}
			directories = append(directories, archivedDirectorySnapshot{path: path, stat: *stat, entries: names})
		case info.Mode().IsRegular():
			entry.Type = "file"
			entry.Size = info.Size()
			header.Typeflag = tar.TypeReg
			header.Size = info.Size()
		case info.Mode()&os.ModeSymlink != 0:
			entry.Type = "symlink"
			target, err := os.Readlink(path)
			if err != nil || strings.ContainsRune(target, 0) || len(target) > 4096 {
				return fmt.Errorf("read backup symbolic link: %s", path)
			}
			after, err := os.Lstat(path)
			afterStat, afterOK := fileSyscallStat(after)
			if err != nil || !afterOK || !sameArchivedStat(stat, afterStat) {
				return fmt.Errorf("backup symbolic link changed while it was read: %s", path)
			}
			entry.LinkTarget = target
			header.Typeflag = tar.TypeSymlink
			header.Linkname = target
		default:
			return fmt.Errorf("backup source contains an unsupported filesystem entry: %s", path)
		}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		if entry.Type == "file" {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return fmt.Errorf("open backup file %s: %w", path, err)
			}
			file := os.NewFile(uintptr(fd), path)
			before, err := file.Stat()
			beforeStat, beforeOK := fileSyscallStat(before)
			if err != nil || !beforeOK || !sameArchivedStat(stat, beforeStat) || !os.SameFile(info, before) || before.Size() != entry.Size {
				file.Close()
				return fmt.Errorf("backup file changed while it was opened: %s", path)
			}
			hash := sha256.New()
			written, copyErr := io.CopyN(io.MultiWriter(archive, hash), file, entry.Size)
			after, statErr := file.Stat()
			afterStat, afterOK := fileSyscallStat(after)
			closeErr := file.Close()
			named, namedErr := os.Lstat(path)
			namedStat, namedOK := fileSyscallStat(named)
			if copyErr != nil || written != entry.Size || statErr != nil || !afterOK || closeErr != nil || namedErr != nil || !namedOK ||
				!sameArchivedStat(beforeStat, afterStat) || !sameArchivedStat(beforeStat, namedStat) || !os.SameFile(before, after) {
				return fmt.Errorf("backup file changed while it was copied: %s", path)
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
		}
		manifest.Entries = append(manifest.Entries, entry)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i].path) > len(directories[j].path) })
	for _, directory := range directories {
		info, err := os.Lstat(directory.path)
		stat, ok := fileSyscallStat(info)
		if err != nil || !ok || !sameArchivedStat(&directory.stat, stat) {
			return fmt.Errorf("backup directory changed while it was archived: %s", directory.path)
		}
		names, err := archiveDirectoryNames(directory.path)
		if err != nil || !equalArchiveNames(names, directory.entries) {
			return fmt.Errorf("backup directory entries changed while it was archived: %s", directory.path)
		}
	}
	return nil
}

func fileSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func sameArchivedStat(first, second *syscall.Stat_t) bool {
	return first != nil && second != nil && first.Dev == second.Dev && first.Ino == second.Ino && first.Nlink == second.Nlink &&
		first.Mode == second.Mode && first.Uid == second.Uid && first.Gid == second.Gid && first.Size == second.Size &&
		first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

func archiveDirectoryNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}

func equalArchiveNames(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func validateSources(sources []Source) error {
	names := make(map[string]bool)
	paths := make(map[string]bool)
	for _, source := range sources {
		if !validName(source.Name) || !cleanAbsolute(source.Path) || names[source.Name] || paths[source.Path] {
			return errors.New("backup source names and paths must be unique and valid")
		}
		names[source.Name], paths[source.Path] = true, true
	}
	for first := range paths {
		for second := range paths {
			if first != second && pathWithin(first, second) {
				return errors.New("backup source paths must not overlap")
			}
		}
	}
	return nil
}

func validName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validateReleasePointers(pointers []ReleasePointer) error {
	if len(pointers) > 10000 {
		return errors.New("backup contains too many release pointers")
	}
	seen := make(map[string]bool, len(pointers))
	for _, pointer := range pointers {
		activated, err := time.Parse(time.RFC3339Nano, pointer.Activated)
		if !cleanAbsolute(pointer.Path) || seen[pointer.Path] ||
			(pointer.Scope != "portal" && pointer.Scope != "runtime" && pointer.Scope != "shared" && pointer.Scope != "combined") ||
			!validReleaseIdentifier(pointer.Current) || (pointer.Previous != "" && !validReleaseIdentifier(pointer.Previous)) ||
			err != nil || activated.IsZero() || activated.Location() != time.UTC || activated.UTC().Format(time.RFC3339Nano) != pointer.Activated {
			return errors.New("backup release-pointer evidence is invalid or duplicate")
		}
		seen[pointer.Path] = true
	}
	return nil
}

func validReleaseIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
