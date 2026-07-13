package winutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SystemSID         = "S-1-5-18"
	AdministratorsSID = "S-1-5-32-544"
	UsersSID          = "S-1-5-32-545"
	EveryoneSID       = "S-1-1-0"

	fileAllAccess windows.ACCESS_MASK = 0x001F01FF
	fileWriteBits windows.ACCESS_MASK = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
)

type ACLPermission int

const (
	ACLFullControl ACLPermission = iota + 1
	ACLReadExecute
)

type ACLPolicy struct {
	OwnerSID              string
	AllowedOwnerSIDs      []string
	DescendantsMayInherit bool
	Principals            map[string]ACLPermission
}

func PrivateTreePolicy(userSID string) ACLPolicy {
	return ACLPolicy{OwnerSID: AdministratorsSID, AllowedOwnerSIDs: []string{userSID, SystemSID}, DescendantsMayInherit: true, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, userSID: ACLFullControl,
	}}
}

func SharedReadOnlyPolicy() ACLPolicy {
	return ACLPolicy{OwnerSID: AdministratorsSID, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, UsersSID: ACLReadExecute,
	}}
}

func ServicePrivatePolicy(serviceSID string) ACLPolicy {
	return ACLPolicy{OwnerSID: AdministratorsSID, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, serviceSID: ACLFullControl,
	}}
}

func UserConfigPolicy(serviceSID, userSID string) ACLPolicy {
	return ACLPolicy{OwnerSID: AdministratorsSID, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, serviceSID: ACLFullControl, userSID: ACLReadExecute,
	}}
}

func ApplyACL(path string, policy ACLPolicy) error {
	if !filepath.IsAbs(path) {
		return errors.New("ACL path must be absolute")
	}
	if err := validateACLPolicy(policy); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if reparse, err := isReparsePoint(path); err != nil {
		return err
	} else if reparse {
		return fmt.Errorf("refuse to apply ACL to reparse point: %s", path)
	}
	return applyPathACL(path, info.IsDir(), policy)
}

func VerifyACL(path string, policy ACLPolicy) error {
	if !filepath.IsAbs(path) {
		return errors.New("ACL path must be absolute")
	}
	if err := validateACLPolicy(policy); err != nil {
		return err
	}
	if reparse, err := isReparsePoint(path); err != nil {
		return err
	} else if reparse {
		return fmt.Errorf("ACL path is a reparse point: %s", path)
	}
	return verifyPathACL(path, policy, true)
}

func ApplyTreeACL(root string, policy ACLPolicy) error {
	if !filepath.IsAbs(root) {
		return errors.New("ACL root must be absolute")
	}
	if err := validateACLPolicy(policy); err != nil {
		return err
	}
	cleanRoot := filepath.Clean(root)
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if reparse, err := isReparsePoint(path); err != nil {
			return err
		} else if reparse {
			if !policy.DescendantsMayInherit || strings.EqualFold(filepath.Clean(path), cleanRoot) {
				return fmt.Errorf("refuse to apply ACL through reparse point: %s", path)
			}
			if err := validateContainedReparsePoint(cleanRoot, path); err != nil {
				return err
			}
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return applyPathACL(path, entry.IsDir(), policy)
	})
}

func VerifyTreeACL(root string, policy ACLPolicy) error {
	if !filepath.IsAbs(root) {
		return errors.New("ACL root must be absolute")
	}
	if err := validateACLPolicy(policy); err != nil {
		return err
	}
	cleanRoot := filepath.Clean(root)
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if reparse, err := isReparsePoint(path); err != nil {
			return err
		} else if reparse {
			if !policy.DescendantsMayInherit || strings.EqualFold(filepath.Clean(path), cleanRoot) {
				return fmt.Errorf("ACL tree contains reparse point: %s", path)
			}
			if err := validateContainedReparsePoint(cleanRoot, path); err != nil {
				return err
			}
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		requireProtected := !policy.DescendantsMayInherit || strings.EqualFold(filepath.Clean(path), cleanRoot)
		if err := verifyPathACL(path, policy, requireProtected); err != nil {
			return fmt.Errorf("ACL verification failed for %s: %w", path, err)
		}
		return nil
	})
}

func validateContainedReparsePoint(root, path string) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve private ACL root: %w", err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve private-tree reparse point %s: %w", path, err)
	}
	rootPrefix := filepath.Clean(resolvedRoot) + string(filepath.Separator)
	target := filepath.Clean(resolvedTarget)
	if !strings.EqualFold(target, filepath.Clean(resolvedRoot)) && !strings.HasPrefix(strings.ToLower(target), strings.ToLower(rootPrefix)) {
		return fmt.Errorf("private-tree reparse point escapes its protected root: %s -> %s", path, resolvedTarget)
	}
	return nil
}

func applyPathACL(path string, directory bool, policy ACLPolicy) error {
	sddl := "O:" + policy.OwnerSID + "G:" + SystemSID + "D:P"
	for _, sid := range sortedPolicySIDs(policy) {
		rights := "FA"
		if policy.Principals[sid] == ACLReadExecute {
			rights = "GRGX"
		}
		flags := ""
		if directory {
			flags = "OICI"
		}
		sddl += "(A;" + flags + ";" + rights + ";;;" + sid + ")"
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build protected security descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	information := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("set protected NTFS ACL: %w", err)
	}
	return nil
}

func verifyPathACL(path string, policy ACLPolicy, requireProtected bool) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("DACL inheritance is not protected")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !allowedOwner(policy, owner.String()) {
		return fmt.Errorf("owner is %v, want one of %v", owner, append([]string{policy.OwnerSID}, policy.AllowedOwnerSIDs...))
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("protected DACL is missing")
	}
	granted := make(map[string]windows.ACCESS_MASK)
	header := (*aclHeader)(unsafe.Pointer(dacl))
	for index := uint32(0); index < uint32(header.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unexpected non-allow ACE at index %d", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("invalid ACE SID at index %d", index)
		}
		sidText := sid.String()
		permission, allowed := permissionForSID(policy, sidText)
		if !allowed {
			return fmt.Errorf("unexpected allowed principal %s", sidText)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			granted[canonicalSID(policy, sidText)] |= ace.Mask
		}
		if permission == ACLReadExecute && ace.Mask&fileWriteBits != 0 {
			return fmt.Errorf("read-only principal %s has write or ACL-management rights 0x%08x", sidText, uint32(ace.Mask))
		}
	}
	for sid, permission := range policy.Principals {
		mask := granted[sid]
		switch permission {
		case ACLFullControl:
			if mask&windows.GENERIC_ALL == 0 && mask&fileAllAccess != fileAllAccess {
				return fmt.Errorf("principal %s lacks full control (mask 0x%08x)", sid, uint32(mask))
			}
		case ACLReadExecute:
			hasGeneric := mask&windows.GENERIC_READ != 0 && mask&windows.GENERIC_EXECUTE != 0
			hasSpecific := mask&windows.FILE_GENERIC_READ == windows.FILE_GENERIC_READ && mask&windows.FILE_GENERIC_EXECUTE == windows.FILE_GENERIC_EXECUTE
			if !hasGeneric && !hasSpecific {
				return fmt.Errorf("principal %s lacks read/execute rights (mask 0x%08x)", sid, uint32(mask))
			}
		}
	}
	return nil
}

func validateACLPolicy(policy ACLPolicy) error {
	if !validSIDText(policy.OwnerSID) || len(policy.Principals) == 0 {
		return errors.New("ACL policy has an invalid owner or no principals")
	}
	if _, ok := policy.Principals[policy.OwnerSID]; !ok {
		return errors.New("ACL owner must also be an allowed principal")
	}
	for sid, permission := range policy.Principals {
		if !validSIDText(sid) || (permission != ACLFullControl && permission != ACLReadExecute) {
			return errors.New("ACL policy contains an invalid principal or permission")
		}
	}
	for _, sid := range policy.AllowedOwnerSIDs {
		if !validSIDText(sid) {
			return errors.New("ACL policy contains an invalid allowed owner")
		}
		if _, ok := policy.Principals[sid]; !ok {
			return errors.New("ACL allowed owner must also be an allowed principal")
		}
	}
	return nil
}

func allowedOwner(policy ACLPolicy, actual string) bool {
	if strings.EqualFold(actual, policy.OwnerSID) {
		return true
	}
	for _, sid := range policy.AllowedOwnerSIDs {
		if strings.EqualFold(actual, sid) {
			return true
		}
	}
	return false
}

func validSIDText(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.IsValid() && strings.EqualFold(sid.String(), value)
}

func permissionForSID(policy ACLPolicy, sid string) (ACLPermission, bool) {
	for expected, permission := range policy.Principals {
		if strings.EqualFold(expected, sid) {
			return permission, true
		}
	}
	return 0, false
}

func canonicalSID(policy ACLPolicy, sid string) string {
	for expected := range policy.Principals {
		if strings.EqualFold(expected, sid) {
			return expected
		}
	}
	return sid
}

func sortedPolicySIDs(policy ACLPolicy) []string {
	order := []string{SystemSID, AdministratorsSID, policy.OwnerSID, UsersSID}
	seen := make(map[string]bool)
	result := make([]string, 0, len(policy.Principals))
	for _, sid := range order {
		if _, ok := policy.Principals[sid]; ok && !seen[sid] {
			result = append(result, sid)
			seen[sid] = true
		}
	}
	for sid := range policy.Principals {
		if !seen[sid] {
			result = append(result, sid)
		}
	}
	return result
}

func isReparsePoint(path string) (bool, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return false, err
	}
	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

type aclHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}
