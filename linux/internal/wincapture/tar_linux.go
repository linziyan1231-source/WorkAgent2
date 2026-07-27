//go:build linux

package wincapture

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

func captureSource(ctx context.Context, transport remoteTransport, rootFD int, source Source, before inventory, expectedUID uint32) (inventory, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	remoteResult := make(chan error, 1)
	go func() {
		_, err := transport.run(ctx, "tar", tarArguments(source), writer, source.MaxTarBytes)
		_ = writer.CloseWithError(err)
		remoteResult <- err
	}()
	captured, extractErr := extractTar(rootFD, reader, source, expectedUID)
	if extractErr != nil {
		cancel()
		_ = reader.CloseWithError(extractErr)
	} else {
		_ = reader.Close()
	}
	remoteErr := <-remoteResult
	if extractErr != nil {
		return inventory{}, extractErr
	}
	if remoteErr != nil {
		return inventory{}, remoteErr
	}
	if before.summary != captured.summary || before.archiveSHA256 != captured.archiveSHA256 {
		return inventory{}, errors.New("captured tar content does not match the before inventory")
	}
	return captured, nil
}

func extractTar(rootFD int, stream io.Reader, source Source, expectedUID uint32) (inventory, error) {
	archive := tar.NewReader(stream)
	base := path.Base(source.SourcePath)
	seenArchive := make(map[string]bool)
	entries := make([]inventoryEntry, 0)
	symlinkTargets := make(map[string]string)
	directoryTimes := make(map[string]int64)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return inventory{}, errors.New("read bounded remote tar stream")
		}
		if err := validateTarHeader(header); err != nil {
			return inventory{}, err
		}
		name := strings.TrimSuffix(header.Name, "/")
		var relative string
		if name == base {
			relative = "."
		} else if strings.HasPrefix(name, base+"/") {
			relative = strings.TrimPrefix(name, base+"/")
			if !safeCapturedRelative(relative) {
				return inventory{}, errors.New("remote tar contains an unsafe relative path")
			}
		} else {
			return inventory{}, errors.New("remote tar escapes its bound source root")
		}
		if seenArchive[relative] {
			return inventory{}, errors.New("remote tar contains a duplicate path")
		}
		seenArchive[relative] = true
		entry := inventoryEntry{Path: relative, Mode: uint32(header.Mode) & 0o777, Size: header.Size, MTime: header.ModTime.Unix(), NLink: 1}
		destination := source.Destination
		if relative != "." {
			destination = path.Join(destination, relative)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return inventory{}, errors.New("remote tar directory has a payload")
			}
			entry.Kind = 'd'
			if err := mkdirAllAt(rootFD, destination, expectedUID); err != nil {
				return inventory{}, err
			}
			directoryTimes[destination] = entry.MTime
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > source.MaxBytes {
				return inventory{}, errors.New("remote tar file size is invalid")
			}
			entry.Kind = 'f'
			parent := path.Dir(destination)
			if parent != "." {
				if err := mkdirAllAt(rootFD, parent, expectedUID); err != nil {
					return inventory{}, err
				}
			}
			capturedMode := os.FileMode(0o600)
			if header.Mode&0o100 != 0 {
				capturedMode = 0o700
			}
			file, err := createFileAtMode(rootFD, destination, capturedMode)
			if err != nil {
				return inventory{}, err
			}
			hasher := sha256.New()
			written, copyErr := io.CopyN(io.MultiWriter(file, hasher), archive, header.Size)
			if copyErr != nil || written != header.Size {
				file.Close()
				return inventory{}, errors.New("remote tar file payload is truncated")
			}
			if err := unix.Futimes(int(file.Fd()), captureTimevals(entry.MTime)); err != nil {
				file.Close()
				return inventory{}, errors.New("set captured file timestamp")
			}
			if err := file.Sync(); err != nil {
				file.Close()
				return inventory{}, errors.New("sync captured file")
			}
			if err := file.Close(); err != nil {
				return inventory{}, errors.New("close captured file")
			}
			entry.SHA256 = hex.EncodeToString(hasher.Sum(nil))
		case tar.TypeSymlink:
			if err := validateCapturedSymlink(source, relative, header.Linkname); err != nil {
				return inventory{}, errors.New("remote tar contains an unapproved symbolic link")
			}
			parent := path.Dir(destination)
			if parent != "." {
				if err := mkdirAllAt(rootFD, parent, expectedUID); err != nil {
					return inventory{}, err
				}
			}
			if err := createSymlinkAt(rootFD, destination, header.Linkname); err != nil {
				return inventory{}, err
			}
			if err := setSymlinkMTimeAt(rootFD, destination, entry.MTime); err != nil {
				return inventory{}, err
			}
			entry.Kind = 'l'
			entry.Size = int64(len(header.Linkname))
			entry.LinkTarget = header.Linkname
			targetRelative, err := capturedSymlinkTargetRelative(source, header.Linkname)
			if err != nil {
				return inventory{}, err
			}
			symlinkTargets[relative] = targetRelative
		default:
			return inventory{}, errors.New("remote tar contains a link, hardlink, device, sparse file, or other special entry")
		}
		entries = append(entries, entry)
		if int64(len(entries)) > source.MaxFiles {
			return inventory{}, errors.New("remote tar exceeds its entry limit")
		}
	}
	if len(entries) == 0 || !seenArchive["."] {
		return inventory{}, errors.New("remote tar is empty or missing its bound root")
	}
	rootEntry := entries[indexOfInventory(entries, ".")]
	if (source.Kind == SourceFile && (len(entries) != 1 || rootEntry.Kind != 'f')) || (source.Kind == SourceDirectory && rootEntry.Kind != 'd') {
		return inventory{}, errors.New("remote tar root kind does not match its bound source")
	}
	for _, target := range symlinkTargets {
		if !seenArchive[target] {
			return inventory{}, errors.New("remote tar symbolic link points to a missing captured target")
		}
	}
	directoriesByDepth := make([]string, 0, len(directoryTimes))
	for directory := range directoryTimes {
		directoriesByDepth = append(directoriesByDepth, directory)
	}
	sort.Slice(directoriesByDepth, func(i, j int) bool {
		return strings.Count(directoriesByDepth[i], "/") > strings.Count(directoriesByDepth[j], "/")
	})
	for _, directory := range directoriesByDepth {
		if err := setDirectoryMTimeAt(rootFD, directory, directoryTimes[directory]); err != nil {
			return inventory{}, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	var files, directories, symlinks, bytesTotal int64
	for _, entry := range entries {
		if entry.Kind == 'f' {
			files++
			if entry.Size > source.MaxBytes-bytesTotal {
				return inventory{}, errors.New("remote tar exceeds its byte limit")
			}
			bytesTotal += entry.Size
		} else if entry.Kind == 'd' {
			directories++
		} else {
			symlinks++
		}
	}
	result := inventory{entries: entries, summary: Summary{Files: files, Directories: directories, Symlinks: symlinks, Bytes: bytesTotal, SHA256: hashInventory(entries, false)}, archiveSHA256: hashInventoryArchive(entries)}
	return result, nil
}

func validateTarHeader(header *tar.Header) error {
	if header == nil || header.Name == "" || strings.HasPrefix(header.Name, "/") || strings.ContainsAny(header.Name, "\x00\\") ||
		header.Uid < 0 || header.Gid < 0 || header.Size < 0 || header.Mode < 0 || header.Mode&^0o777 != 0 {
		return errors.New("remote tar header is unsafe")
	}
	if (header.Typeflag == tar.TypeSymlink && (header.Linkname == "" || header.Size != 0)) || (header.Typeflag != tar.TypeSymlink && header.Linkname != "") {
		return errors.New("remote tar link metadata is unsafe")
	}
	clean := path.Clean(header.Name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(header.Name, "/") {
		return errors.New("remote tar path is non-canonical or traverses outside its root")
	}
	for key := range header.PAXRecords {
		switch key {
		case "path", "mtime", "atime", "ctime":
		default:
			return fmt.Errorf("remote tar contains unsupported extended metadata")
		}
	}
	return nil
}

func ensureTarDestinationAbsent(rootFD int, relative string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(rootFD, relative, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return errors.New("capture destination already exists")
	}
	if !errors.Is(err, unix.ENOENT) {
		return errors.New("inspect capture destination")
	}
	return nil
}
