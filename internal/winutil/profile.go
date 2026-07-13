package winutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

// ProfileDirectoryForSID returns the fixed Windows profile registered for a
// SID. It never derives the path from a mutable account name.
func ProfileDirectoryForSID(sidText string) (string, error) {
	sid, err := windows.StringToSid(sidText)
	if err != nil || sid == nil || !sid.IsValid() || !strings.EqualFold(sid.String(), sidText) {
		return "", fmt.Errorf("invalid Windows SID %q", sidText)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey+sid.String(), registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open Windows profile registration for %s: %w", sidText, err)
	}
	defer key.Close()
	value, valueType, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", fmt.Errorf("read Windows profile path for %s: %w", sidText, err)
	}
	if valueType == registry.EXPAND_SZ {
		value, err = registry.ExpandString(value)
		if err != nil {
			return "", fmt.Errorf("expand Windows profile path for %s: %w", sidText, err)
		}
	} else if valueType != registry.SZ {
		return "", fmt.Errorf("Windows profile path for %s has registry type %d", sidText, valueType)
	}
	profile := filepath.Clean(value)
	if !filepath.IsAbs(profile) || strings.ContainsRune(profile, '\x00') {
		return "", fmt.Errorf("Windows profile path for %s is not an absolute safe path", sidText)
	}
	info, err := os.Lstat(profile)
	if err != nil {
		return "", fmt.Errorf("inspect Windows profile path %s: %w", profile, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return "", fmt.Errorf("Windows profile path is not a normal directory: %s", profile)
	}
	if attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(profile)); err != nil {
		return "", fmt.Errorf("read Windows profile attributes for %s: %w", profile, err)
	} else if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", fmt.Errorf("Windows profile path is a reparse point: %s", profile)
	}
	return profile, nil
}
