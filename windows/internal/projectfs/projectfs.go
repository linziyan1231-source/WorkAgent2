package projectfs

import (
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxNameRunes = 100

var reservedWindowsNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {}, "COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {}, "LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

func ValidName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > MaxNameRunes || strings.HasSuffix(name, ".") {
		return false
	}
	// Windows 8.3 aliases (for example LONGNA~1) can resolve to a different
	// long-name directory while still passing lexical direct-child checks.
	// Project APIs use names as stable tenant-scoped identifiers, so reject the
	// alias shape instead of allowing two spellings for the same directory.
	if looksLikeWindowsShortName(name) {
		return false
	}
	for _, character := range name {
		if unicode.IsControl(character) || strings.ContainsRune(`<>:"/\|?*`, character) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	_, reserved := reservedWindowsNames[base]
	return !reserved
}

func looksLikeWindowsShortName(name string) bool {
	parts := strings.SplitN(name, ".", 2)
	base := parts[0]
	if len(parts) == 2 && len(parts[1]) > 3 {
		return false
	}
	tilde := strings.LastIndexByte(base, '~')
	if tilde < 1 || tilde > 6 || tilde == len(base)-1 {
		return false
	}
	for _, character := range base[tilde+1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func ResolveChild(root, name string) (string, bool) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || !ValidName(name) {
		return "", false
	}
	target := filepath.Join(root, name)
	return target, true
}

func NameFromPath(root, path string) (string, bool) {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) || !strings.EqualFold(filepath.Dir(path), root) {
		return "", false
	}
	name := filepath.Base(path)
	if !ValidName(name) {
		return "", false
	}
	return name, true
}
