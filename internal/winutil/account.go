package winutil

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	userAccountDisabled = 0x0002
	localGroupsIndirect = 0x0001
	maxPreferredLength  = 0xffffffff
)

var procNetUserGetLocalGroups = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserGetLocalGroups")

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
	if buffer == nil {
		return false, errors.New("Windows account lookup returned no data")
	}
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
