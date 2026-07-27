//go:build linux

package wincapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type inventoryEntry struct {
	Path         string
	Kind         byte
	Mode         uint32
	Size         int64
	MTime        int64
	SHA256       string
	Device       uint64
	Inode        uint64
	NLink        uint64
	PhysicalSize int64
	LinkTarget   string
}

type inventory struct {
	entries        []inventoryEntry
	summary        Summary
	archiveSHA256  string
	evidenceSHA256 string
}

func readInventory(payload []byte, source Source) (inventory, error) {
	fields, err := splitNUL(payload, 13*int(source.MaxFiles)+2)
	if err != nil || len(fields) < 1 || fields[0] != "WAI1" || (len(fields)-1)%12 != 0 {
		return inventory{}, errors.New("remote inventory protocol is invalid")
	}
	entries := make([]inventoryEntry, 0, (len(fields)-1)/12)
	seen := make(map[string]bool, cap(entries))
	var files, directories, symlinks, totalBytes int64
	for offset := 1; offset < len(fields); offset += 12 {
		if fields[offset] != "E" {
			return inventory{}, errors.New("remote inventory record type is invalid")
		}
		relative, kind := fields[offset+1], fields[offset+2]
		if relative != "." && !safeCapturedRelative(relative) {
			return inventory{}, errors.New("remote inventory contains an unsafe path")
		}
		if seen[relative] {
			return inventory{}, errors.New("remote inventory contains a duplicate path")
		}
		seen[relative] = true
		mode, err := parseUint(fields[offset+3], 8, 32)
		if err != nil || mode > 0o777 {
			return inventory{}, errors.New("remote inventory mode is invalid")
		}
		size, err := parseInt(fields[offset+4], 10, 64)
		if err != nil || size < 0 {
			return inventory{}, errors.New("remote inventory size is invalid")
		}
		mtime, err := parseInt(fields[offset+5], 10, 64)
		if err != nil {
			return inventory{}, errors.New("remote inventory timestamp is invalid")
		}
		digest := fields[offset+6]
		device, deviceErr := parseUint(fields[offset+7], 10, 64)
		inode, inodeErr := parseUint(fields[offset+8], 10, 64)
		nlink, linkErr := parseUint(fields[offset+9], 10, 64)
		physicalSize, physicalErr := parseInt(fields[offset+10], 10, 64)
		linkTarget := fields[offset+11]
		if deviceErr != nil || inodeErr != nil || linkErr != nil || physicalErr != nil || physicalSize < 0 || device == 0 || inode == 0 || nlink == 0 {
			return inventory{}, errors.New("remote inventory identity is invalid")
		}
		entry := inventoryEntry{Path: relative, Mode: uint32(mode), Size: size, MTime: mtime, SHA256: digest, Device: device, Inode: inode, NLink: nlink, PhysicalSize: physicalSize, LinkTarget: linkTarget}
		switch kind {
		case "f":
			if !sha256Pattern.MatchString(digest) || linkTarget != "" || nlink != 1 || (size > 0 && physicalSize < size) {
				return inventory{}, errors.New("remote regular-file inventory is invalid")
			}
			entry.Kind = 'f'
			files++
			if size > source.MaxBytes-totalBytes {
				return inventory{}, errors.New("remote source exceeds its byte limit")
			}
			totalBytes += size
		case "d":
			if digest != "" || linkTarget != "" || size != 0 {
				return inventory{}, errors.New("remote directory inventory is invalid")
			}
			entry.Kind = 'd'
			directories++
		case "l":
			if digest != "" || nlink != 1 || size != int64(len(linkTarget)) || validateCapturedSymlink(source, relative, linkTarget) != nil {
				return inventory{}, errors.New("remote symbolic-link inventory is invalid")
			}
			entry.Kind = 'l'
			symlinks++
		default:
			return inventory{}, errors.New("remote source contains a link or special file")
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 || int64(len(entries)) > source.MaxFiles || !seen["."] {
		return inventory{}, errors.New("remote source entry count is invalid")
	}
	root := entries[indexOfInventory(entries, ".")]
	if (source.Kind == SourceFile && (len(entries) != 1 || root.Kind != 'f')) || (source.Kind == SourceDirectory && root.Kind != 'd') {
		return inventory{}, errors.New("remote source root kind is invalid")
	}
	for _, entry := range entries {
		if entry.Device != root.Device {
			return inventory{}, errors.New("remote source crosses a filesystem boundary")
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	canonical := hashInventory(entries, false)
	archiveDigest := hashInventoryArchive(entries)
	evidence := hashInventory(entries, true)
	return inventory{entries: entries, summary: Summary{Files: files, Directories: directories, Symlinks: symlinks, Bytes: totalBytes, SHA256: canonical}, archiveSHA256: archiveDigest, evidenceSHA256: evidence}, nil
}

func indexOfInventory(entries []inventoryEntry, relative string) int {
	for index := range entries {
		if entries[index].Path == relative {
			return index
		}
	}
	return -1
}

func hashInventory(entries []inventoryEntry, evidence bool) string {
	hasher := sha256.New()
	for _, entry := range entries {
		writeHashField(hasher, entry.Path)
		writeHashField(hasher, string(entry.Kind))
		writeHashField(hasher, strconv.FormatInt(entry.Size, 10))
		writeHashField(hasher, entry.SHA256)
		writeHashField(hasher, entry.LinkTarget)
		writeHashField(hasher, strconv.FormatInt(entry.MTime, 10))
		if entry.Kind == 'f' {
			mode := uint32(0o600)
			if entry.Mode&0o100 != 0 {
				mode = 0o700
			}
			writeHashField(hasher, strconv.FormatUint(uint64(mode), 8))
		} else {
			writeHashField(hasher, "")
		}
		if evidence {
			writeHashField(hasher, strconv.FormatUint(uint64(entry.Mode), 8))
			writeHashField(hasher, strconv.FormatInt(entry.MTime, 10))
			writeHashField(hasher, strconv.FormatUint(entry.Device, 10))
			writeHashField(hasher, strconv.FormatUint(entry.Inode, 10))
			writeHashField(hasher, strconv.FormatUint(entry.NLink, 10))
			writeHashField(hasher, strconv.FormatInt(entry.PhysicalSize, 10))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func hashInventoryArchive(entries []inventoryEntry) string {
	hasher := sha256.New()
	for _, entry := range entries {
		writeHashField(hasher, entry.Path)
		writeHashField(hasher, string(entry.Kind))
		writeHashField(hasher, strconv.FormatUint(uint64(entry.Mode), 8))
		writeHashField(hasher, strconv.FormatInt(entry.Size, 10))
		writeHashField(hasher, strconv.FormatInt(entry.MTime, 10))
		writeHashField(hasher, entry.SHA256)
		writeHashField(hasher, entry.LinkTarget)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeHashField(writer io.Writer, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}

type exclusionEvidence struct {
	SHA256 string
}

func readExclusionEvidence(payload []byte, source Source) (exclusionEvidence, error) {
	fields, err := splitNUL(payload, 7*len(source.Exclusions)+2)
	if err != nil || len(fields) < 1 || fields[0] != "WAX1" || (len(fields)-1)%7 != 0 || (len(fields)-1)/7 != len(source.Exclusions) {
		return exclusionEvidence{}, errors.New("remote exclusion evidence protocol is invalid")
	}
	hasher := sha256.New()
	for offset := 1; offset < len(fields); offset += 7 {
		if fields[offset] != "X" {
			return exclusionEvidence{}, errors.New("remote exclusion evidence record is invalid")
		}
		index, err := strconv.Atoi(fields[offset+1])
		mode, modeErr := parseUint(fields[offset+3], 16, 32)
		_, mtimeErr := parseInt(fields[offset+4], 10, 64)
		inode, inodeErr := parseUint(fields[offset+5], 10, 64)
		if err != nil || index != (offset-1)/7 || fields[offset+2] != source.Exclusions[index].Type ||
			modeErr != nil || mode&0xf000 != 0x4000 || mtimeErr != nil || inodeErr != nil || inode == 0 ||
			(fields[offset+6] != "-" && !sha256Pattern.MatchString(fields[offset+6])) {
			return exclusionEvidence{}, errors.New("remote exclusion evidence value is invalid")
		}
		for field := offset + 1; field <= offset+6; field++ {
			writeHashField(hasher, fields[field])
		}
	}
	return exclusionEvidence{SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func readOAuthEvidence(payload []byte, limits OAuthEvidence) (OAuthSummary, error) {
	fields, err := splitNUL(payload, int(limits.MaxFiles)*5+2)
	if err != nil || len(fields) < 1 || fields[0] != "WAO1" || (len(fields)-1)%5 != 0 {
		return OAuthSummary{}, errors.New("remote OAuth evidence protocol is invalid")
	}
	type anonymous struct{ path, size, mtime, content string }
	records := make([]anonymous, 0, (len(fields)-1)/5)
	seen := make(map[string]bool)
	var bytesTotal int64
	for offset := 1; offset < len(fields); offset += 5 {
		if fields[offset] != "A" || !sha256Pattern.MatchString(fields[offset+1]) || !sha256Pattern.MatchString(fields[offset+4]) || seen[fields[offset+1]] {
			return OAuthSummary{}, errors.New("remote OAuth evidence record is invalid")
		}
		seen[fields[offset+1]] = true
		size, err := parseInt(fields[offset+2], 10, 64)
		if err != nil || size < 0 || size > limits.MaxBytes-bytesTotal {
			return OAuthSummary{}, errors.New("remote OAuth evidence exceeds its byte limit")
		}
		if _, err := parseInt(fields[offset+3], 10, 64); err != nil {
			return OAuthSummary{}, errors.New("remote OAuth evidence timestamp is invalid")
		}
		bytesTotal += size
		records = append(records, anonymous{fields[offset+1], fields[offset+2], fields[offset+3], fields[offset+4]})
	}
	if int64(len(records)) > limits.MaxFiles {
		return OAuthSummary{}, errors.New("remote OAuth evidence exceeds its file limit")
	}
	sort.Slice(records, func(i, j int) bool { return records[i].path < records[j].path })
	hasher := sha256.New()
	for _, record := range records {
		writeHashField(hasher, record.path)
		writeHashField(hasher, record.size)
		writeHashField(hasher, record.mtime)
		writeHashField(hasher, record.content)
	}
	return OAuthSummary{Files: int64(len(records)), Bytes: bytesTotal, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func splitNUL(payload []byte, maxFields int) ([]string, error) {
	if len(payload) == 0 || payload[len(payload)-1] != 0 || maxFields < 1 {
		return nil, errors.New("NUL protocol is truncated")
	}
	parts := bytes.Split(payload[:len(payload)-1], []byte{0})
	if len(parts) > maxFields {
		return nil, errors.New("NUL protocol exceeds its field limit")
	}
	result := make([]string, len(parts))
	for index, part := range parts {
		if bytes.IndexByte(part, 0) >= 0 || !utf8Valid(part) {
			return nil, errors.New("NUL protocol contains invalid text")
		}
		result[index] = string(part)
	}
	return result, nil
}

func utf8Valid(value []byte) bool {
	return utf8.Valid(value)
}

func parseUint(value string, base, bits int) (uint64, error) {
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return 0, errors.New("invalid unsigned integer")
	}
	return strconv.ParseUint(value, base, bits)
}

func parseInt(value string, base, bits int) (int64, error) {
	if value == "" || strings.HasPrefix(value, "+") {
		return 0, errors.New("invalid integer")
	}
	return strconv.ParseInt(value, base, bits)
}

func compareInventories(before, after inventory) error {
	if before.summary != after.summary || before.archiveSHA256 != after.archiveSHA256 || before.evidenceSHA256 != after.evidenceSHA256 {
		return errors.New("Windows source drifted during the read-only capture window")
	}
	return nil
}

func aggregateSummaries(inventories []inventory) (Summary, error) {
	var result Summary
	hasher := sha256.New()
	for index, item := range inventories {
		if item.summary.Files > (1<<62)-result.Files || item.summary.Directories > (1<<62)-result.Directories || item.summary.Symlinks > (1<<62)-result.Symlinks || item.summary.Bytes > (1<<62)-result.Bytes {
			return Summary{}, fmt.Errorf("aggregate source %d overflows", index+1)
		}
		result.Files += item.summary.Files
		result.Directories += item.summary.Directories
		result.Symlinks += item.summary.Symlinks
		result.Bytes += item.summary.Bytes
		writeHashField(hasher, item.summary.SHA256)
	}
	result.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	return result, nil
}
