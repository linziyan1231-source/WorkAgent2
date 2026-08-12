package winutil

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	userAccountDisabled = 0x0002
	userPrivUser        = 1
	userFlagScript      = 0x0001
	userFlagNormal      = 0x0200
	userFlagNeverExpire = 0x10000
	localGroupsIndirect = 0x0001
	maxPreferredLength  = 0xffffffff
	nerrUserNotFound    = 2221

	ProvisioningAccountComment = "AionUi Portal provisioning"
	ManagedAccountComment      = "AionUi Portal standard user"
)

var procNetUserGetLocalGroups = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserGetLocalGroups")
var procNetUserAdd = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd")
var procNetUserSetInfo = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserSetInfo")

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Privilege   uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type localGroupUsersInfo0 struct {
	Name *uint16
}

type userInfo1003 struct {
	Password *uint16
}

type userInfo1007 struct {
	Comment *uint16
}

func ValidateLocalUsername(username string) error {
	if len(username) < 1 || len(username) > 20 {
		return errors.New("Windows username must be between 1 and 20 ASCII characters")
	}
	for index, character := range username {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return errors.New("Windows username must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen")
	}
	return nil
}

func CreateLocalStandardAccount(username string, password []byte) (sid, canonical string, err error) {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return "", "", err
	}
	secret, err := passwordUTF16(password)
	if err != nil {
		return "", "", err
	}
	defer zeroUTF16(secret)
	comment, err := windows.UTF16PtrFromString(ProvisioningAccountComment)
	if err != nil {
		return "", "", err
	}
	info := userInfo1{Name: name, Password: &secret[0], Privilege: userPrivUser, Comment: comment, Flags: userFlagScript | userFlagNormal | userFlagNeverExpire}
	var parameterError uint32
	status, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameterError)))
	if status != 0 {
		return "", "", fmt.Errorf("create Windows standard account %s: Windows error %d (parameter %d)", username, status, parameterError)
	}
	computer, err := windows.ComputerName()
	if err != nil {
		return "", "", err
	}
	return ValidateStandardAccount(computer + `\` + username)
}

func InspectLocalStandardAccount(username string) (sid, canonical, comment string, exists bool, err error) {
	pointer, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return "", "", "", false, err
	}
	var buffer *byte
	if err := windows.NetUserGetInfo(nil, pointer, 1, &buffer); err != nil {
		if errors.Is(err, syscall.Errno(nerrUserNotFound)) {
			return "", "", "", false, nil
		}
		return "", "", "", false, fmt.Errorf("read Windows account %s: %w", username, err)
	}
	defer windows.NetApiBufferFree(buffer)
	info := (*userInfo1)(unsafe.Pointer(buffer))
	if info.Comment != nil {
		comment = windows.UTF16PtrToString(info.Comment)
	}
	computer, err := windows.ComputerName()
	if err != nil {
		return "", "", "", false, err
	}
	sid, canonical, err = ValidateStandardAccount(computer + `\` + username)
	if err != nil {
		return "", "", "", false, err
	}
	return sid, canonical, comment, true, nil
}

func SetLocalAccountPassword(username string, password []byte) error {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	secret, err := passwordUTF16(password)
	if err != nil {
		return err
	}
	defer zeroUTF16(secret)
	info := userInfo1003{Password: &secret[0]}
	return setLocalAccountInfo(name, 1003, unsafe.Pointer(&info), "password")
}

func SetLocalAccountComment(username, comment string) error {
	name, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	value, err := windows.UTF16PtrFromString(comment)
	if err != nil {
		return err
	}
	info := userInfo1007{Comment: value}
	return setLocalAccountInfo(name, 1007, unsafe.Pointer(&info), "description")
}

func setLocalAccountInfo(name *uint16, level uint32, info unsafe.Pointer, field string) error {
	var parameterError uint32
	status, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), uintptr(level), uintptr(info), uintptr(unsafe.Pointer(&parameterError)))
	if status != 0 {
		return fmt.Errorf("set Windows account %s: Windows error %d (parameter %d)", field, status, parameterError)
	}
	return nil
}

func passwordUTF16(password []byte) ([]uint16, error) {
	if len(password) == 0 || !utf8.Valid(password) {
		return nil, errors.New("Windows password must be non-empty valid UTF-8")
	}
	result := make([]uint16, 0, len(password)+1)
	for offset := 0; offset < len(password); {
		r, size := utf8.DecodeRune(password[offset:])
		if r == 0 {
			zeroUTF16(result)
			return nil, errors.New("Windows password contains NUL")
		}
		if r <= 0xffff {
			result = append(result, uint16(r))
		} else {
			first, second := utf16.EncodeRune(r)
			result = append(result, uint16(first), uint16(second))
		}
		offset += size
	}
	return append(result, 0), nil
}

func zeroUTF16(value []uint16) {
	for index := range value {
		value[index] = 0
	}
}

func ValidateStandardAccount(account string) (sid, canonical string, err error) {
	sid, canonical, err = LookupAccount(account)
	if err != nil {
		return "", "", err
	}
	name := canonical
	if index := strings.LastIndexAny(name, `\`); index >= 0 {
		name = name[index+1:]
	}
	if name == "" {
		return "", "", errors.New("resolved Windows account has no username")
	}
	disabled, err := accountDisabled(name)
	if err != nil {
		return "", "", err
	}
	if disabled {
		return "", "", errors.New("Windows account is disabled")
	}
	admin, err := accountInAdministrators(name)
	if err != nil {
		return "", "", err
	}
	if admin {
		return "", "", errors.New("Windows UserHost account belongs to Administrators")
	}
	return sid, canonical, nil
}

func accountDisabled(username string) (bool, error) {
	pointer, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return false, err
	}
	var buffer *byte
	if err := windows.NetUserGetInfo(nil, pointer, 1, &buffer); err != nil {
		return false, fmt.Errorf("read Windows account state for %s: %w", username, err)
	}
	defer windows.NetApiBufferFree(buffer)
	info := (*userInfo1)(unsafe.Pointer(buffer))
	return info.Flags&userAccountDisabled != 0, nil
}

func accountInAdministrators(username string) (bool, error) {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	adminName, _, _, err := adminSID.LookupAccount("")
	if err != nil {
		return false, err
	}
	userPointer, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return false, err
	}
	var buffer uintptr
	var entriesRead, totalEntries uint32
	result, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(userPointer)), 0, localGroupsIndirect,
		uintptr(unsafe.Pointer(&buffer)), maxPreferredLength, uintptr(unsafe.Pointer(&entriesRead)), uintptr(unsafe.Pointer(&totalEntries)))
	if result != 0 {
		return false, fmt.Errorf("read local group membership for %s: Windows error %d", username, result)
	}
	if buffer != 0 {
		defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(buffer)))
	}
	if entriesRead == 0 || buffer == 0 {
		return false, nil
	}
	groups := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buffer)), int(entriesRead))
	for _, group := range groups {
		if group.Name != nil && strings.EqualFold(windows.UTF16PtrToString(group.Name), adminName) {
			return true, nil
		}
	}
	return false, nil
}
