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
	for _, character := range name {
		if unicode.IsControl(character) || strings.ContainsRune(`<>:"/\|?*`, character) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	_, reserved := reservedWindowsNames[base]
	return !reserved
}

func ResolveChild(root, name string) (string, bool) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || !ValidName(name) {
		return "", false
	}
	target := filepath.Join(root, name)
	if !strings.EqualFold(filepath.Dir(target), root) {
		return "", false
	}
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
