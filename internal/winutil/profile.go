package winutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

var procLogonUser = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
var procLoadUserProfile = windows.NewLazySystemDLL("userenv.dll").NewProc("LoadUserProfileW")
var procUnloadUserProfile = windows.NewLazySystemDLL("userenv.dll").NewProc("UnloadUserProfile")

type profileInfo struct {
	Size        uint32
	Flags       uint32
	Username    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

func EnsureProfileForAccount(sidText, username string, password []byte) (string, error) {
	if _, err := ProfileDirectoryForSID(sidText); err == nil {
		return ProfileDirectoryForSID(sidText)
	}
	if err := ValidateLocalUsername(username); err != nil {
		return "", err
	}
	expectedSID, err := windows.StringToSid(sidText)
	if err != nil || expectedSID == nil || !expectedSID.IsValid() {
		return "", fmt.Errorf("invalid Windows SID %q", sidText)
	}
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return "", err
	}
	domain, err := windows.UTF16PtrFromString(".")
	if err != nil {
		return "", err
	}
	secret, err := passwordUTF16(password)
	if err != nil {
		return "", err
	}
	defer zeroUTF16(secret)
	var token windows.Token
	ok, _, logonErr := procLogonUser.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(&secret[0])), 4, 0, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return "", fmt.Errorf("log on Windows account %s for profile creation: %w", username, logonErr)
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil || tokenUser == nil || tokenUser.User.Sid == nil || !strings.EqualFold(tokenUser.User.Sid.String(), expectedSID.String()) {
		return "", errors.New("profile logon resolved to an unexpected Windows identity")
	}
	profile := profileInfo{Size: uint32(unsafe.Sizeof(profileInfo{})), Flags: 1, Username: name}
	ok, _, loadErr := procLoadUserProfile.Call(uintptr(token), uintptr(unsafe.Pointer(&profile)))
	if ok == 0 {
		return "", fmt.Errorf("load Windows profile for %s: %w", username, loadErr)
	}
	if unloaded, _, unloadErr := procUnloadUserProfile.Call(uintptr(token), uintptr(profile.Profile)); unloaded == 0 {
		return "", fmt.Errorf("unload Windows profile for %s: %w", username, unloadErr)
	}
	registered, err := ProfileDirectoryForSID(sidText)
	if err != nil {
		return "", err
	}
	return registered, nil
}

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
