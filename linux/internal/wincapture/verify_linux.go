//go:build linux

package wincapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type captureJournal struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	CaptureID     string `json:"capture_id"`
	SpecSHA256    string `json:"spec_sha256"`
}

func verifyStoredCapture(rootFD int, spec Spec, manifest finalManifest, expectedUID uint32) error {
	if len(manifest.Before) != len(spec.Sources) || len(manifest.Captured) != len(spec.Sources) || len(manifest.After) != len(spec.Sources) || manifest.OAuthBefore != manifest.OAuthAfter {
		return errors.New("existing capture manifest cardinality or OAuth evidence is invalid")
	}
	if manifest.OAuthBefore.Files < 0 || manifest.OAuthBefore.Files > spec.OAuthEvidence.MaxFiles || manifest.OAuthBefore.Bytes < 0 ||
		manifest.OAuthBefore.Bytes > spec.OAuthEvidence.MaxBytes || !sha256Pattern.MatchString(manifest.OAuthBefore.SHA256) {
		return errors.New("existing capture manifest OAuth evidence is outside its bound")
	}
	var journal captureJournal
	if err := readStoredStrictJSONAt(rootFD, "journal-start.json", 1024*1024, expectedUID, &journal); err != nil ||
		journal.SchemaVersion != 1 || journal.Status != "in-progress" || journal.CaptureID != manifest.CaptureID || journal.SpecSHA256 != manifest.SpecSHA256 {
		return errors.New("existing capture start journal is invalid")
	}
	var beforeEvidence, afterEvidence evidenceFile
	if err := readStoredStrictJSONAt(rootFD, "evidence-before.json", 8*1024*1024, expectedUID, &beforeEvidence); err != nil ||
		beforeEvidence.SchemaVersion != 1 || beforeEvidence.Phase != "before" || beforeEvidence.OAuth != manifest.OAuthBefore || !equalSourceEvidence(beforeEvidence.Sources, manifest.Before) {
		return errors.New("existing capture before evidence is invalid")
	}
	if err := readStoredStrictJSONAt(rootFD, "evidence-after.json", 8*1024*1024, expectedUID, &afterEvidence); err != nil ||
		afterEvidence.SchemaVersion != 1 || afterEvidence.Phase != "after" || afterEvidence.OAuth != manifest.OAuthAfter || !equalSourceEvidence(afterEvidence.Sources, manifest.After) {
		return errors.New("existing capture after evidence is invalid")
	}
	stored := make([]inventory, len(spec.Sources))
	allowedRoots := []string{"journal-start.json", "evidence-before.json", "evidence-after.json", "capture-manifest.json"}
	for index, source := range spec.Sources {
		if manifest.Before[index].Summary != manifest.Captured[index].Summary || manifest.After[index].Summary != manifest.Captured[index].Summary ||
			manifest.Before[index].ArchiveSHA256 != manifest.Captured[index].ArchiveSHA256 || manifest.After[index].ArchiveSHA256 != manifest.Captured[index].ArchiveSHA256 ||
			manifest.Before[index].EvidenceSHA256 != manifest.After[index].EvidenceSHA256 ||
			manifest.Before[index].ExclusionSHA != manifest.After[index].ExclusionSHA ||
			!sha256Pattern.MatchString(manifest.Captured[index].ArchiveSHA256) || !sha256Pattern.MatchString(manifest.Before[index].EvidenceSHA256) ||
			!sha256Pattern.MatchString(manifest.Before[index].ExclusionSHA) {
			return errors.New("existing capture manifest does not prove three-way convergence")
		}
		item, err := inventoryStoredSource(rootFD, source, expectedUID)
		if err != nil || item.summary != manifest.Captured[index].Summary {
			return errors.New("existing captured source content is missing, damaged, or altered")
		}
		stored[index] = item
		allowedRoots = append(allowedRoots, source.Destination)
	}
	for _, input := range spec.LocalFiles {
		if err := verifyStoredLocalInput(rootFD, input, expectedUID); err != nil {
			return err
		}
		allowedRoots = append(allowedRoots, input.Destination)
	}
	aggregate, err := aggregateSummaries(stored)
	if err != nil || aggregate != manifest.Aggregate {
		return errors.New("existing capture aggregate content evidence is invalid")
	}
	if err := verifyNoUnexpectedStoredEntries(rootFD, allowedRoots, expectedUID); err != nil {
		return err
	}
	return nil
}

func equalSourceEvidence(first, second []sourceEvidence) bool {
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

func readStoredStrictJSONAt(rootFD int, relative string, maximum int64, expectedUID uint32, destination any) error {
	_, err := readStoredStrictJSONAtDigest(rootFD, relative, maximum, expectedUID, destination)
	return err
}

func readStoredStrictJSONAtDigest(rootFD int, relative string, maximum int64, expectedUID uint32, destination any) (string, error) {
	if !safeCapturedRelative(relative) || maximum < 1 {
		return "", errors.New("stored capture metadata path or bound is invalid")
	}
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return "", errors.New("open stored capture metadata")
	}
	file := os.NewFile(uintptr(fd), "stored-capture-metadata")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != expectedUID || before.Gid != expectedUID || before.Nlink != 1 || before.Size < 1 || before.Size > maximum {
		return "", errors.New("stored capture metadata is unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) != before.Size {
		clear(payload)
		return "", errors.New("stored capture metadata is unreadable")
	}
	defer clear(payload)
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !stableFileStat(before, after) {
		return "", errors.New("stored capture metadata changed while it was read")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", errors.New("stored capture metadata is not strict JSON")
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func inventoryStoredSource(rootFD int, source Source, expectedUID uint32) (inventory, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if source.Kind == SourceDirectory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(rootFD, source.Destination, &unix.OpenHow{Flags: uint64(flags), Resolve: localResolveFlags})
	if err != nil {
		return inventory{}, errors.New("open stored capture source")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != expectedUID || stat.Gid != expectedUID {
		return inventory{}, errors.New("stored capture source ownership is invalid")
	}
	entries := make([]inventoryEntry, 0)
	var files, directories, symlinks, bytesTotal int64
	if source.Kind == SourceFile {
		mode := os.FileMode(stat.Mode).Perm()
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || (mode != 0o600 && mode != 0o700) || stat.Nlink != 1 {
			return inventory{}, errors.New("stored capture file is unsafe")
		}
		digest, err := hashStoredFD(fd)
		if err != nil {
			return inventory{}, err
		}
		var after unix.Stat_t
		if err := unix.Fstat(fd, &after); err != nil || !stableFileStat(stat, after) {
			return inventory{}, errors.New("stored capture file changed during verification")
		}
		entries = append(entries, inventoryEntry{Path: ".", Kind: 'f', Mode: uint32(mode), Size: stat.Size, MTime: stat.Mtim.Sec, SHA256: digest})
		files, bytesTotal = 1, stat.Size
	} else {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(stat.Mode).Perm() != 0o700 {
			return inventory{}, errors.New("stored capture directory is unsafe")
		}
		entries = append(entries, inventoryEntry{Path: ".", Kind: 'd', MTime: stat.Mtim.Sec})
		directories = 1
		if err := scanStoredDirectory(fd, "", uint64(stat.Dev), expectedUID, source, &entries, &files, &directories, &symlinks, &bytesTotal); err != nil {
			return inventory{}, err
		}
	}
	if int64(len(entries)) > source.MaxFiles || bytesTotal > source.MaxBytes {
		return inventory{}, errors.New("stored capture source exceeds its bound")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return inventory{entries: entries, summary: Summary{Files: files, Directories: directories, Symlinks: symlinks, Bytes: bytesTotal, SHA256: hashInventory(entries, false)}}, nil
}

func scanStoredDirectory(directoryFD int, relative string, rootDevice uint64, expectedUID uint32, source Source, entries *[]inventoryEntry, files, directories, symlinks, bytesTotal *int64) error {
	var directoryBefore unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryBefore); err != nil || directoryBefore.Mode&unix.S_IFMT != unix.S_IFDIR ||
		directoryBefore.Dev != rootDevice || directoryBefore.Uid != expectedUID || directoryBefore.Gid != expectedUID || os.FileMode(directoryBefore.Mode).Perm() != 0o700 {
		return errors.New("stored capture directory is unsafe")
	}
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "stored-capture-directory")
	children, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	for _, child := range children {
		name := child.Name()
		if name == "" || name == "." || name == ".." || !safeCapturedRelative(name) {
			return errors.New("stored capture contains an unsafe name")
		}
		entryPath := name
		if relative != "" {
			entryPath = path.Join(relative, name)
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Dev != rootDevice || stat.Uid != expectedUID || stat.Gid != expectedUID {
			return errors.New("stored capture entry changed or crossed a filesystem boundary")
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if os.FileMode(stat.Mode).Perm() != 0o700 {
				return errors.New("stored capture directory mode is invalid")
			}
			childFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
			if err != nil {
				return errors.New("open stored capture directory")
			}
			*entries = append(*entries, inventoryEntry{Path: entryPath, Kind: 'd', MTime: stat.Mtim.Sec})
			*directories++
			err = scanStoredDirectory(childFD, entryPath, rootDevice, expectedUID, source, entries, files, directories, symlinks, bytesTotal)
			unix.Close(childFD)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			mode := os.FileMode(stat.Mode).Perm()
			if (mode != 0o600 && mode != 0o700) || stat.Nlink != 1 || stat.Size < 0 || stat.Size > source.MaxBytes-*bytesTotal {
				return errors.New("stored capture file mode, link count, or size is invalid")
			}
			fileFD, err := unix.Openat2(directoryFD, name, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
			if err != nil {
				return errors.New("open stored capture file")
			}
			var opened unix.Stat_t
			if err := unix.Fstat(fileFD, &opened); err != nil || !stableFileStat(stat, opened) {
				unix.Close(fileFD)
				return errors.New("stored capture file changed while it was opened")
			}
			digest, err := hashStoredFD(fileFD)
			var after unix.Stat_t
			statErr := unix.Fstat(fileFD, &after)
			unix.Close(fileFD)
			if err != nil {
				return err
			}
			if statErr != nil || !stableFileStat(opened, after) {
				return errors.New("stored capture file changed while it was hashed")
			}
			*entries = append(*entries, inventoryEntry{Path: entryPath, Kind: 'f', Mode: uint32(mode), Size: stat.Size, MTime: stat.Mtim.Sec, SHA256: digest})
			*files++
			*bytesTotal += stat.Size
		case unix.S_IFLNK:
			if stat.Nlink != 1 || stat.Size < 1 || stat.Size > 32*1024 {
				return errors.New("stored capture symbolic link is unsafe")
			}
			buffer := make([]byte, 32*1024+1)
			length, err := unix.Readlinkat(directoryFD, name, buffer)
			if err != nil || length < 1 || length > 32*1024 {
				return errors.New("read stored capture symbolic link")
			}
			target := string(buffer[:length])
			var after unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !stableFileStat(stat, after) {
				return errors.New("stored capture symbolic link changed while it was read")
			}
			if err := validateCapturedSymlink(source, entryPath, target); err != nil {
				return errors.New("stored capture symbolic link is outside its approved contract")
			}
			*entries = append(*entries, inventoryEntry{Path: entryPath, Kind: 'l', Size: int64(len(target)), MTime: stat.Mtim.Sec, LinkTarget: target})
			*symlinks++
		default:
			return errors.New("stored capture contains a link or special file")
		}
		if int64(len(*entries)) > source.MaxFiles {
			return errors.New("stored capture source exceeds its entry bound")
		}
	}
	var directoryAfter unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryAfter); err != nil || !stableFileStat(directoryBefore, directoryAfter) {
		return errors.New("stored capture directory changed while it was scanned")
	}
	return nil
}

func hashStoredFD(fd int) (string, error) {
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 {
		return "", errors.New("inspect stored capture file before hashing")
	}
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		return "", errors.New("seek stored capture file")
	}
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(duplicate), "stored-capture-file")
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.New("hash stored capture file")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || written != before.Size || !stableFileStat(before, after) {
		return "", errors.New("stored capture file changed while it was hashed")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func verifyStoredLocalInput(rootFD int, input LocalFile, expectedUID uint32) error {
	fd, err := unix.Openat2(rootFD, input.Destination, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return errors.New("stored private local input is missing")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 || stat.Uid != expectedUID || stat.Gid != expectedUID || stat.Nlink != 1 || stat.Size > input.MaxBytes {
		return errors.New("stored private local input is unsafe")
	}
	digest, err := hashStoredFD(fd)
	if err != nil || digest != input.SHA256 {
		return errors.New("stored private local input digest is invalid")
	}
	return nil
}

func verifyNoUnexpectedStoredEntries(rootFD int, allowedRoots []string, expectedUID uint32) error {
	return walkStoredRoot(rootFD, "", allowedRoots, expectedUID)
}

func walkStoredRoot(directoryFD int, relative string, allowedRoots []string, expectedUID uint32) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "stored-capture-layout")
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		entryPath := entry.Name()
		if relative != "" {
			entryPath = path.Join(relative, entry.Name())
		}
		allowed := false
		for _, root := range allowedRoots {
			if entryPath == root || strings.HasPrefix(entryPath, root+"/") || strings.HasPrefix(root, entryPath+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("existing capture contains an unexpected entry")
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Uid != expectedUID || stat.Gid != expectedUID {
			return errors.New("existing capture layout changed during verification")
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := unix.Openat2(directoryFD, entry.Name(), &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
			if err != nil {
				return errors.New("open existing capture layout directory")
			}
			err = walkStoredRoot(child, entryPath, allowedRoots, expectedUID)
			unix.Close(child)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
