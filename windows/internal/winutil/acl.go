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
	SystemSID           = "S-1-5-18"
	AdministratorsSID   = "S-1-5-32-544"
	UsersSID            = "S-1-5-32-545"
	EveryoneSID         = "S-1-1-0"
	OwnerRightsSID      = "S-1-3-4"
	capabilitySIDPrefix = "S-1-15-3-1024-"

	fileAllAccess windows.ACCESS_MASK = 0x001F01FF
	// Directory metadata lookup on Windows opens a handle that also requests
	// SYNCHRONIZE. FILE_TRAVERSE | FILE_READ_ATTRIBUTES alone still makes
	// Node.js realpathSync fail with EPERM, while this exact mask does not grant
	// FILE_LIST_DIRECTORY or any read-data, write, delete, or ACL-management bit.
	directoryTraverseAttributesAccess windows.ACCESS_MASK = windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	directoryReadExecuteAccess        windows.ACCESS_MASK = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
	fileWriteBits                     windows.ACCESS_MASK = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	cacheCapabilityAccess windows.ACCESS_MASK = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE |
		windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE
)

type ACLPermission int

const (
	ACLFullControl ACLPermission = iota + 1
	ACLModify
	ACLReadExecute
	ACLTraverse
)

type ACLPolicy struct {
	OwnerSID                             string
	AllowedOwnerSIDs                     []string
	DescendantsMayInherit                bool
	allowContainedReparsePoints          bool
	Principals                           map[string]ACLPermission
	allowOwnerRightsForDescendants       bool
	allowHeadlessChromeCacheCapabilities bool
}

func SharedOwnerRootPolicy(ownerSID string, memberSIDs []string) ACLPolicy {
	principals := map[string]ACLPermission{SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, ownerSID: ACLFullControl}
	for _, sid := range memberSIDs {
		if !strings.EqualFold(sid, ownerSID) {
			principals[sid] = ACLTraverse
		}
	}
	return ACLPolicy{OwnerSID: ownerSID, AllowedOwnerSIDs: []string{SystemSID, AdministratorsSID}, Principals: principals}
}

func SharedProjectPolicy(ownerSID string, memberSIDs []string) ACLPolicy {
	// OWNER RIGHTS replaces Windows' implicit owner WRITE_DAC grant. Files
	// created by a member may be owned by that member, but ownership must not
	// let the member rewrite the protected collaboration ACL.
	principals := map[string]ACLPermission{SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, ownerSID: ACLFullControl, OwnerRightsSID: ACLModify}
	allowedOwners := []string{SystemSID, AdministratorsSID}
	for _, sid := range memberSIDs {
		principals[sid] = ACLModify
		if !strings.EqualFold(sid, ownerSID) {
			allowedOwners = append(allowedOwners, sid)
		}
	}
	return ACLPolicy{OwnerSID: ownerSID, AllowedOwnerSIDs: allowedOwners, DescendantsMayInherit: true, Principals: principals}
}

func PrivateTreePolicy(userSID string) ACLPolicy {
	return ACLPolicy{OwnerSID: AdministratorsSID, AllowedOwnerSIDs: []string{userSID, SystemSID}, DescendantsMayInherit: true, allowContainedReparsePoints: true, allowOwnerRightsForDescendants: true, allowHeadlessChromeCacheCapabilities: true, Principals: map[string]ACLPermission{
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

func ServiceCredentialPolicy(serviceSID string) ACLPolicy {
	return ACLPolicy{OwnerSID: AdministratorsSID, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, serviceSID: ACLReadExecute,
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
	return verifyPathACL(path, policy, true, "")
}

func VerifyDescendantACL(path string, policy ACLPolicy) error {
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
	return verifyPathACL(path, policy, false, "")
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
			if !policy.allowContainedReparsePoints || strings.EqualFold(filepath.Clean(path), cleanRoot) {
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
			if !policy.allowContainedReparsePoints || strings.EqualFold(filepath.Clean(path), cleanRoot) {
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
		if err := verifyPathACL(path, policy, requireProtected, cleanRoot); err != nil {
			return fmt.Errorf("ACL verification failed for %s: %w", path, err)
		}
		return nil
	})
}

func validateContainedReparsePoint(root, path string) error {
	resolvedRoot, err := finalPathByHandle(root)
	if err != nil {
		return fmt.Errorf("resolve private ACL root: %w", err)
	}
	resolvedTarget, err := finalReparseTargetForContainment(path)
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

func finalReparseTargetForContainment(path string) (string, error) {
	resolved, err := finalPathByHandle(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return "", err
	}
	target, readErr := os.Readlink(path)
	if readErr != nil {
		return "", err
	}
	target = normalizeWindowsFinalPath(target)
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return canonicalizePossiblyMissingPath(target)
}

func canonicalizePossiblyMissingPath(path string) (string, error) {
	current := filepath.Clean(path)
	missing := []string{}
	for {
		resolved, err := finalPathByHandle(current)
		if err == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return "", err
		}
		parent := filepath.Dir(current)
		if strings.EqualFold(parent, current) {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

// finalPathByHandle asks Windows for the normalized path of the object opened
// through any reparse points. Unlike filepath.EvalSymlinks on Windows, it does
// not enumerate each parent directory to recover case-preserved component
// names, so callers need only metadata-traverse access to external ancestors.
func finalPathByHandle(path string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(pointer,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	size := uint32(windows.MAX_PATH)
	for {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if length < size {
			return filepath.Clean(normalizeWindowsFinalPath(windows.UTF16ToString(buffer[:length]))), nil
		}
		size = length + 1
	}
}

func normalizeWindowsFinalPath(path string) string {
	upper := strings.ToUpper(path)
	if strings.HasPrefix(upper, `\\?\UNC\`) {
		return `\\` + path[len(`\\?\UNC\`):]
	}
	if strings.HasPrefix(upper, `\??\UNC\`) {
		return `\\` + path[len(`\??\UNC\`):]
	}
	for _, prefix := range []string{`\\?\`, `\??\`} {
		if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
			return path[len(prefix):]
		}
	}
	return path
}

func applyPathACL(path string, directory bool, policy ACLPolicy) error {
	sddl := "O:" + policy.OwnerSID + "G:" + SystemSID + "D:P"
	for _, sid := range sortedPolicySIDs(policy) {
		rights := "FA"
		if policy.Principals[sid] == ACLModify {
			rights = "GRGWGXSD"
		} else if policy.Principals[sid] == ACLReadExecute {
			rights = "GRGX"
		} else if policy.Principals[sid] == ACLTraverse {
			rights = "0x001000a0"
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

func verifyPathACL(path string, policy ACLPolicy, requireProtected bool, treeRoot string) error {
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
	ownerSID := owner.String()
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
		principalSID := sidText
		permission, allowed := permissionForSID(policy, sidText)
		if !allowed && !requireProtected && policy.allowOwnerRightsForDescendants && strings.EqualFold(sidText, OwnerRightsSID) {
			principalSID = ownerSID
			permission, allowed = permissionForSID(policy, principalSID)
		}
		if !allowed && policy.allowHeadlessChromeCacheCapabilities && allowedHeadlessChromeCacheCapability(path, treeRoot, sidText, ace.Mask) {
			continue
		}
		if !allowed {
			return fmt.Errorf("unexpected allowed principal %s", sidText)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			granted[canonicalSID(policy, principalSID)] |= ace.Mask
		}
		if permission == ACLReadExecute && ace.Mask&fileWriteBits != 0 {
			return fmt.Errorf("read-only principal %s has write or ACL-management rights 0x%08x", principalSID, uint32(ace.Mask))
		}
		if permission == ACLTraverse && ace.Mask&^directoryTraverseAttributesAccess != 0 {
			return fmt.Errorf("metadata-traverse principal %s has excessive rights (mask 0x%08x)", principalSID, uint32(ace.Mask))
		}
	}
	for sid, permission := range policy.Principals {
		mask := granted[sid]
		switch permission {
		case ACLFullControl:
			if mask&windows.GENERIC_ALL == 0 && mask&fileAllAccess != fileAllAccess {
				return fmt.Errorf("principal %s lacks full control (mask 0x%08x)", sid, uint32(mask))
			}
		case ACLModify:
			if mask&(windows.GENERIC_ALL|windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
				return fmt.Errorf("principal %s has ACL ownership rights (mask 0x%08x)", sid, uint32(mask))
			}
			hasGeneric := mask&windows.GENERIC_READ != 0 && mask&windows.GENERIC_WRITE != 0 && mask&windows.GENERIC_EXECUTE != 0
			hasSpecific := mask&windows.FILE_GENERIC_READ == windows.FILE_GENERIC_READ && mask&windows.FILE_GENERIC_WRITE == windows.FILE_GENERIC_WRITE && mask&windows.FILE_GENERIC_EXECUTE == windows.FILE_GENERIC_EXECUTE
			if (!hasGeneric && !hasSpecific) || mask&windows.DELETE == 0 {
				return fmt.Errorf("principal %s lacks modify rights (mask 0x%08x)", sid, uint32(mask))
			}
		case ACLReadExecute:
			hasGeneric := mask&windows.GENERIC_READ != 0 && mask&windows.GENERIC_EXECUTE != 0
			hasSpecific := mask&windows.FILE_GENERIC_READ == windows.FILE_GENERIC_READ && mask&windows.FILE_GENERIC_EXECUTE == windows.FILE_GENERIC_EXECUTE
			if !hasGeneric && !hasSpecific {
				return fmt.Errorf("principal %s lacks read/execute rights (mask 0x%08x)", sid, uint32(mask))
			}
		case ACLTraverse:
			if mask != directoryTraverseAttributesAccess {
				return fmt.Errorf("principal %s requires exact metadata-traverse rights 0x%08x, got 0x%08x", sid, uint32(directoryTraverseAttributesAccess), uint32(mask))
			}
		}
	}
	return nil
}

// ApplyDirectoryMetadataTraverseACL replaces only the named SID's ACE and
// preserves the directory's owner, protection state, and every unrelated ACE.
func ApplyDirectoryMetadataTraverseACL(path, sidText string) error {
	return applyExactDirectoryACL(path, sidText, directoryTraverseAttributesAccess, "metadata-traverse")
}

func ApplyDirectoryReadExecuteACL(path, sidText string) error {
	return applyExactDirectoryACL(path, sidText, directoryReadExecuteAccess, "read-execute")
}

func applyExactDirectoryACL(path, sidText string, access windows.ACCESS_MASK, label string) error {
	if err := validateNormalACLDirectory(path, sidText); err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("directory DACL is missing")
	}
	sid, err := windows.StringToSid(sidText)
	if err != nil {
		return fmt.Errorf("parse directory %s SID: %w", label, err)
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	updated, err := windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return fmt.Errorf("replace directory %s ACE: %w", label, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, updated, nil); err != nil {
		return fmt.Errorf("set directory %s ACE: %w", label, err)
	}
	return verifyExactDirectoryACL(path, sidText, access, label)
}

func VerifyDirectoryMetadataTraverseACL(path, sidText string) error {
	return verifyExactDirectoryACL(path, sidText, directoryTraverseAttributesAccess, "metadata-traverse")
}

func VerifyDirectoryReadExecuteACL(path, sidText string) error {
	return verifyExactDirectoryACL(path, sidText, directoryReadExecuteAccess, "read-execute")
}

func verifyExactDirectoryACL(path, sidText string, access windows.ACCESS_MASK, label string) error {
	if err := validateNormalACLDirectory(path, sidText); err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("directory DACL is missing")
	}
	header := (*aclHeader)(unsafe.Pointer(dacl))
	matching := 0
	for index := uint32(0); index < uint32(header.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace == nil {
			return fmt.Errorf("invalid ACE at index %d", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() || !strings.EqualFold(sid.String(), sidText) {
			continue
		}
		matching++
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("directory %s SID %s has a non-allow ACE", label, sidText)
		}
		if ace.Header.AceFlags != 0 {
			return fmt.Errorf("directory %s SID %s has inherited or propagating flags 0x%02x", label, sidText, ace.Header.AceFlags)
		}
		if ace.Mask != access {
			return fmt.Errorf("directory %s SID %s requires exact mask 0x%08x, got 0x%08x", label, sidText, uint32(access), uint32(ace.Mask))
		}
	}
	if matching != 1 {
		return fmt.Errorf("directory %s SID %s requires exactly one explicit ACE, found %d", label, sidText, matching)
	}
	return nil
}

func validateNormalACLDirectory(path, sidText string) error {
	if !filepath.IsAbs(path) {
		return errors.New("directory metadata-traverse path must be absolute")
	}
	if !validSIDText(sidText) {
		return errors.New("directory metadata-traverse SID is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("directory metadata-traverse path is not a directory")
	}
	if reparse, err := isReparsePoint(path); err != nil {
		return err
	} else if reparse {
		return fmt.Errorf("directory metadata-traverse path is a reparse point: %s", path)
	}
	return nil
}

func allowedHeadlessChromeCacheCapability(path, treeRoot, sidText string, mask windows.ACCESS_MASK) bool {
	if treeRoot == "" || !strings.HasPrefix(sidText, capabilitySIDPrefix) || mask&^cacheCapabilityAccess != 0 {
		return false
	}
	relative, err := filepath.Rel(treeRoot, path)
	if err != nil {
		return false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) < 4 || !strings.EqualFold(parts[0], "temp") || !strings.EqualFold(parts[2], "Default") || !strings.EqualFold(parts[3], "Cache") {
		return false
	}
	const prefix = "HeadlessChrome"
	if len(parts[1]) <= len(prefix) || !strings.EqualFold(parts[1][:len(prefix)], prefix) {
		return false
	}
	for _, character := range parts[1][len(prefix):] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateACLPolicy(policy ACLPolicy) error {
	if !validSIDText(policy.OwnerSID) || len(policy.Principals) == 0 {
		return errors.New("ACL policy has an invalid owner or no principals")
	}
	if _, ok := policy.Principals[policy.OwnerSID]; !ok {
		return errors.New("ACL owner must also be an allowed principal")
	}
	for sid, permission := range policy.Principals {
		if !validSIDText(sid) || (permission != ACLFullControl && permission != ACLModify && permission != ACLReadExecute && permission != ACLTraverse) {
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
