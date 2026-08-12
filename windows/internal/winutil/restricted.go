package winutil

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	disableMaxPrivilege       = 0x1
	codexSandboxUsersAlias    = "CodexSandboxUsers"
	changeNotifyPrivilegeName = "SeChangeNotifyPrivilege"
)

var createRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// RestrictedToken preserves the current Windows identity and its ordinary
// groups, but removes powerful privileges and converts selected machine-local
// groups to deny-only. This keeps normal per-user ACL behavior while preventing
// an unrelated sandbox group from granting cross-profile access.
type RestrictedToken struct {
	token        windows.Token
	disabledSIDs []string
}

func NewCurrentUserRestrictedToken(expectedSID string) (*RestrictedToken, error) {
	forbidden, found, err := lookupLocalAlias(codexSandboxUsersAlias)
	if err != nil {
		return nil, err
	}
	var disabled []*windows.SID
	if found {
		disabled = append(disabled, forbidden)
	}
	return newCurrentUserRestrictedToken(expectedSID, disabled)
}

func newCurrentUserRestrictedToken(expectedSID string, disabled []*windows.SID) (*RestrictedToken, error) {
	var source windows.Token
	access := uint32(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &source); err != nil {
		return nil, fmt.Errorf("open current process token for restriction: %w", err)
	}
	defer source.Close()

	user, err := source.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read source token user: %w", err)
	}
	if !strings.EqualFold(user.User.Sid.String(), expectedSID) {
		return nil, fmt.Errorf("source token SID %s does not match configured SID %s", user.User.Sid.String(), expectedSID)
	}
	entries := make([]windows.SIDAndAttributes, 0, len(disabled))
	disabledStrings := make([]string, 0, len(disabled))
	for _, sid := range disabled {
		entries = append(entries, windows.SIDAndAttributes{Sid: sid})
		disabledStrings = append(disabledStrings, sid.String())
	}
	var entriesPointer uintptr
	if len(entries) != 0 {
		entriesPointer = uintptr(unsafe.Pointer(&entries[0]))
	}

	var restricted windows.Token
	result, _, callErr := createRestrictedToken.Call(
		uintptr(source),
		disableMaxPrivilege,
		uintptr(len(entries)),
		entriesPointer,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if result == 0 {
		return nil, fmt.Errorf("create restricted token: %w", callErr)
	}
	created := &RestrictedToken{token: restricted, disabledSIDs: disabledStrings}
	if err := created.Verify(expectedSID); err != nil {
		created.Close()
		return nil, err
	}
	return created, nil
}

func RequireCurrentTokenOutsideCodexSandboxGroup() error {
	sid, found, err := lookupLocalAlias(codexSandboxUsersAlias)
	if err != nil || !found {
		return err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("open current token for %s membership check: %w", codexSandboxUsersAlias, err)
	}
	defer token.Close()
	member, err := tokenHasEnabledSID(token, sid)
	if err != nil {
		return fmt.Errorf("check %s membership: %w", codexSandboxUsersAlias, err)
	}
	if member {
		return fmt.Errorf("UserHost refuses to run while its Windows account is a member of %s", codexSandboxUsersAlias)
	}
	return nil
}

func lookupLocalAlias(name string) (*windows.SID, bool, error) {
	computer, err := windows.ComputerName()
	if err != nil {
		return nil, false, fmt.Errorf("resolve local computer name: %w", err)
	}
	sid, _, accountType, err := windows.LookupSID("", computer+`\`+name)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) || errors.Is(err, windows.ERROR_NO_SUCH_ALIAS) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("resolve local alias %s: %w", name, err)
	}
	if accountType != windows.SidTypeAlias && accountType != windows.SidTypeGroup && accountType != windows.SidTypeWellKnownGroup {
		return nil, false, fmt.Errorf("local account %s is not a group", name)
	}
	return sid, true, nil
}

func tokenHasEnabledSID(token windows.Token, sid *windows.SID) (bool, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(sid) && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true, nil
		}
	}
	return false, nil
}

func (t *RestrictedToken) Close() error {
	if t == nil || t.token == 0 {
		return nil
	}
	err := t.token.Close()
	t.token = 0
	return err
}

func (t *RestrictedToken) Apply(command *exec.Cmd) error {
	if t == nil || t.token == 0 {
		return errors.New("restricted token is closed")
	}
	if command == nil {
		return errors.New("command is nil")
	}
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	if command.SysProcAttr.Token != 0 {
		return errors.New("command already has a process token")
	}
	command.SysProcAttr.Token = syscall.Token(t.token)
	return nil
}

func (t *RestrictedToken) Verify(expectedSID string) error {
	if t == nil || t.token == 0 {
		return errors.New("restricted token is closed")
	}
	return verifyPrivilegeReducedToken(t.token, expectedSID, t.disabledSIDs)
}

func (t *RestrictedToken) VerifyProcess(pid uint32, expectedSID string) error {
	if t == nil || t.token == 0 {
		return errors.New("restricted token is closed")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("open process %d token: %w", pid, err)
	}
	defer token.Close()
	if err := verifyPrivilegeReducedToken(token, expectedSID, t.disabledSIDs); err != nil {
		return fmt.Errorf("process %d token verification: %w", pid, err)
	}
	return nil
}

func verifyPrivilegeReducedToken(token windows.Token, expectedSID string, disabledSIDs []string) error {
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read restricted token user: %w", err)
	}
	if !strings.EqualFold(user.User.Sid.String(), expectedSID) {
		return fmt.Errorf("restricted token SID %s does not match configured SID %s", user.User.Sid.String(), expectedSID)
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return fmt.Errorf("read restricted token groups: %w", err)
	}
	for _, disabledSID := range disabledSIDs {
		for _, group := range groups.AllGroups() {
			if strings.EqualFold(group.Sid.String(), disabledSID) {
				if group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 || group.Attributes&windows.SE_GROUP_ENABLED != 0 {
					return fmt.Errorf("disabled SID %s is not deny-only", disabledSID)
				}
				break
			}
		}
	}
	return verifyMinimalPrivileges(token)
}

func verifyMinimalPrivileges(token windows.Token) error {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return fmt.Errorf("query restricted token privileges size: %w", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], size, &size); err != nil {
		return fmt.Errorf("read restricted token privileges: %w", err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0])).AllPrivileges()
	name, _ := windows.UTF16PtrFromString(changeNotifyPrivilegeName)
	var changeNotify windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &changeNotify); err != nil {
		return fmt.Errorf("resolve %s: %w", changeNotifyPrivilegeName, err)
	}
	for _, privilege := range privileges {
		if privilege.Luid != changeNotify {
			return fmt.Errorf("restricted token retained unexpected privilege LUID %+v", privilege.Luid)
		}
	}
	return nil
}
