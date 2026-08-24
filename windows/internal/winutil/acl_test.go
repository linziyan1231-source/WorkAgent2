package winutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSharedProjectPolicyAllowsAcceptedMemberOwnersButNeverReparsePoints(t *testing.T) {
	owner := "S-1-5-21-1-1001"
	member := "S-1-5-21-1-1002"
	policy := SharedProjectPolicy(owner, []string{member})
	if policy.allowContainedReparsePoints {
		t.Fatal("shared projects must reject all contained reparse points")
	}
	if !allowedOwner(policy, member) {
		t.Fatal("accepted members must be permitted as NTFS owners of files they create")
	}
	if policy.Principals[member] != ACLModify {
		t.Fatal("accepted members must modify files without WRITE_DAC or WRITE_OWNER")
	}
	if policy.Principals[OwnerRightsSID] != ACLModify {
		t.Fatal("member-owned files must restrict implicit owner rights to modify without WRITE_DAC")
	}
	removed := SharedProjectPolicy(owner, nil)
	if allowedOwner(removed, member) {
		t.Fatal("removed members must no longer be accepted as file owners after ACL rewrite")
	}
}

func TestApplyAndVerifySharedProjectACLRestrictsOwnerRights(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "shared-project")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "member-editable.txt"), []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := SharedProjectPolicy(identity.SID, []string{"S-1-5-21-1-1002"})
	if err := ApplyTreeACL(root, policy); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAndVerifyProtectedPrivateTreeACL(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(filepath.Join(root, "data", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "nested", "record.json"), []byte(`{"owner":"one"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := PrivateTreePolicy(identity.SID)
	if err := ApplyTreeACL(root, policy); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err != nil {
		t.Fatal(err)
	}
	createdAfterProtection := filepath.Join(root, "data", "created-by-user.json")
	if err := os.WriteFile(createdAfterProtection, []byte(`{"owner":"runtime-user"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err != nil {
		t.Fatalf("safe inherited ACL or user-owned runtime file was rejected: %v", err)
	}
	permissive := policy
	permissive.Principals = map[string]ACLPermission{}
	for sid, permission := range policy.Principals {
		permissive.Principals[sid] = permission
	}
	permissive.Principals[EveryoneSID] = ACLReadExecute
	file := filepath.Join(root, "data", "nested", "record.json")
	if err := applyPathACL(file, false, permissive); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err == nil {
		t.Fatal("private ACL verifier accepted an Everyone allow ACE")
	}
}

func TestPrivateTreeAcceptsOwnerRightsForUserOwnedDescendant(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := PrivateTreePolicy(identity.SID)
	if err := ApplyTreeACL(root, policy); err != nil {
		t.Fatal(err)
	}

	var pipTemp string
	for _, name := range []string{"pip-unpack-python313", "pip-install-python313"} {
		pipTemp = filepath.Join(root, "temp", name)
		if err := os.MkdirAll(pipTemp, 0o700); err != nil {
			t.Fatal(err)
		}
		applyOwnerRightsPrivateACLForTest(t, pipTemp, identity.SID, true)
		artifact := filepath.Join(pipTemp, "artifact.whl")
		if err := os.WriteFile(artifact, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
		applyOwnerRightsPrivateACLForTest(t, artifact, identity.SID, false)
	}

	if err := VerifyTreeACL(root, policy); err != nil {
		t.Fatalf("Python 3.13-style OWNER RIGHTS descendant was rejected: %v", err)
	}
	if err := VerifyACL(pipTemp, policy); err == nil {
		t.Fatal("exact/root ACL verification accepted OWNER RIGHTS")
	}
	if err := VerifyDescendantACL(pipTemp, PrivateTreePolicy("S-1-5-19")); err == nil {
		t.Fatal("OWNER RIGHTS was accepted for an owner outside the private-tree policy")
	}
}

func TestPrivateTreeAllowsOnlyNarrowHeadlessChromeCacheCapabilities(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const capabilitySID = "S-1-15-3-1024-1653277547-598600573-1504598449-2187120098-1115546814-1860042162-2924348907-3700367812"
	tests := []struct {
		name           string
		relative       string
		capabilityACEs string
		wantAccept     bool
	}{
		{name: "cache modify", relative: filepath.Join("temp", "HeadlessChrome124801119435078", "Default", "Cache"), capabilityACEs: "(A;;0x001301bf;;;%[1]s)(A;OICIIO;0xe0010000;;;%[1]s)", wantAccept: true},
		{name: "outside cache", relative: filepath.Join("data", "HeadlessChrome124801119435078", "Default", "Cache"), capabilityACEs: "(A;;0x001301bf;;;%s)"},
		{name: "cache full control", relative: filepath.Join("temp", "HeadlessChrome124801119435078", "Default", "Cache"), capabilityACEs: "(A;;FA;;;%s)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "private")
			target := filepath.Join(root, test.relative)
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			policy := PrivateTreePolicy(identity.SID)
			if err := ApplyTreeACL(root, policy); err != nil {
				t.Fatal(err)
			}
			applySecurityDescriptorForTest(t, target, "O:"+identity.SID+"G:"+SystemSID+"D:P"+
				"(A;;FA;;;"+SystemSID+")"+
				"(A;;FA;;;"+AdministratorsSID+")"+
				"(A;;FA;;;"+identity.SID+")"+
				fmt.Sprintf(test.capabilityACEs, capabilitySID))
			err := VerifyTreeACL(root, policy)
			if test.wantAccept && err != nil {
				t.Fatalf("safe cache capability was rejected: %v", err)
			}
			if !test.wantAccept && err == nil {
				t.Fatal("unsafe capability exception was accepted")
			}
		})
	}
}

func TestOwnerRightsPrivateTreeExceptionRemainsNarrow(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	privatePolicy := PrivateTreePolicy(identity.SID)
	newDirectory := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "acl-target")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("shared policy", func(t *testing.T) {
		path := newDirectory(t)
		applySecurityDescriptorForTest(t, path, "O:"+AdministratorsSID+"G:"+SystemSID+"D:P"+
			"(A;;FA;;;"+OwnerRightsSID+")"+
			"(A;;FA;;;"+SystemSID+")"+
			"(A;;FA;;;"+AdministratorsSID+")"+
			"(A;;GRGX;;;"+UsersSID+")")
		if err := VerifyDescendantACL(path, SharedReadOnlyPolicy()); err == nil {
			t.Fatal("shared policy accepted OWNER RIGHTS")
		}
	})

	t.Run("Everyone allow ACE", func(t *testing.T) {
		path := newDirectory(t)
		applySecurityDescriptorForTest(t, path, "O:"+identity.SID+"G:"+SystemSID+"D:P"+
			"(A;;FA;;;"+OwnerRightsSID+")"+
			"(A;;FA;;;"+SystemSID+")"+
			"(A;;FA;;;"+AdministratorsSID+")"+
			"(A;;GRGX;;;"+EveryoneSID+")")
		if err := VerifyDescendantACL(path, privatePolicy); err == nil {
			t.Fatal("private descendant accepted Everyone alongside OWNER RIGHTS")
		}
	})

	t.Run("cross-user SID ACE", func(t *testing.T) {
		path := newDirectory(t)
		foreignUserSID := "S-1-5-21-111-222-333-1001"
		applySecurityDescriptorForTest(t, path, "O:"+identity.SID+"G:"+SystemSID+"D:P"+
			"(A;;FA;;;"+OwnerRightsSID+")"+
			"(A;;FA;;;"+SystemSID+")"+
			"(A;;FA;;;"+AdministratorsSID+")"+
			"(A;;FA;;;"+foreignUserSID+")")
		if err := VerifyDescendantACL(path, privatePolicy); err == nil {
			t.Fatal("private descendant accepted a cross-user SID alongside OWNER RIGHTS")
		}
	})

	t.Run("deny ACE", func(t *testing.T) {
		path := newDirectory(t)
		applySecurityDescriptorForTest(t, path, "O:"+identity.SID+"G:"+SystemSID+"D:P"+
			"(D;;FA;;;"+EveryoneSID+")"+
			"(A;;FA;;;"+OwnerRightsSID+")"+
			"(A;;FA;;;"+SystemSID+")"+
			"(A;;FA;;;"+AdministratorsSID+")")
		if err := VerifyDescendantACL(path, privatePolicy); err == nil {
			t.Fatal("private descendant accepted a non-Allow ACE alongside OWNER RIGHTS")
		}
	})
}

func TestSharedReadOnlyPolicyRejectsUsersWrite(t *testing.T) {
	policy := SharedReadOnlyPolicy()
	if policy.Principals[UsersSID] != ACLReadExecute {
		t.Fatal("shared release Users permission is not read/execute")
	}
	bad := policy
	bad.Principals = map[string]ACLPermission{SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, UsersSID: ACLFullControl}
	root := filepath.Join(t.TempDir(), "release")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ApplyTreeACL(root, bad); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err == nil {
		t.Fatal("read-only verifier accepted Users full control")
	}
}

func TestDirectoryMetadataTraverseACLRequiresExactMinimalMask(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newTarget := func(t *testing.T, rights, flags string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "ancestor")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		applySecurityDescriptorForTest(t, path, "O:"+AdministratorsSID+"G:"+SystemSID+"D:P"+
			"(A;OICI;FA;;;"+SystemSID+")"+
			"(A;OICI;FA;;;"+AdministratorsSID+")"+
			"(A;"+flags+";"+rights+";;;"+identity.SID+")")
		return path
	}

	t.Run("exact", func(t *testing.T) {
		path := newTarget(t, "0x001000a0", "")
		if err := VerifyDirectoryMetadataTraverseACL(path, identity.SID); err != nil {
			t.Fatal(err)
		}
	})
	for _, test := range []struct {
		name   string
		rights string
		flags  string
	}{
		{name: "missing synchronize", rights: "0x000000a0"},
		{name: "list directory", rights: "0x001000a1"},
		{name: "generic read", rights: "GRGX"},
		{name: "write attributes", rights: "0x001001a0"},
		{name: "inheriting", rights: "0x001000a0", flags: "OICI"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := newTarget(t, test.rights, test.flags)
			if err := VerifyDirectoryMetadataTraverseACL(path, identity.SID); err == nil {
				t.Fatal("unsafe or incomplete metadata-traverse ACE was accepted")
			}
		})
	}
}

func TestApplyDirectoryMetadataTraverseACLIsIdempotentAndPreservesOtherPrincipals(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	applySecurityDescriptorForTest(t, path, "O:"+AdministratorsSID+"G:"+SystemSID+"D:P"+
		"(A;OICI;FA;;;"+SystemSID+")"+
		"(A;OICI;FA;;;"+AdministratorsSID+")"+
		"(A;;GRGX;;;"+identity.SID+")")
	for attempt := 0; attempt < 2; attempt++ {
		if err := ApplyDirectoryMetadataTraverseACL(path, identity.SID); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyDirectoryMetadataTraverseACL(path, identity.SID); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	header := (*aclHeader)(unsafe.Pointer(dacl))
	seen := map[string]bool{}
	for index := uint32(0); index < uint32(header.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		seen[sid.String()] = true
	}
	if !seen[SystemSID] || !seen[AdministratorsSID] {
		t.Fatal("metadata-traverse repair removed an unrelated administrative ACE")
	}
}

func TestDirectoryReadExecuteACLRequiresExactMaskAndIsIdempotent(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	applySecurityDescriptorForTest(t, path, "O:"+AdministratorsSID+"G:"+SystemSID+"D:P"+
		"(A;OICI;FA;;;"+SystemSID+")"+
		"(A;OICI;FA;;;"+AdministratorsSID+")"+
		"(A;;0x001000a0;;;"+identity.SID+")")
	if err := VerifyDirectoryReadExecuteACL(path, identity.SID); err == nil {
		t.Fatal("read-execute verifier accepted metadata-traverse-only access")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := ApplyDirectoryReadExecuteACL(path, identity.SID); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyDirectoryReadExecuteACL(path, identity.SID); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDirectoryMetadataTraverseACL(path, identity.SID); err == nil {
		t.Fatal("metadata-traverse verifier accepted enumerable read-execute access")
	}
}

func TestServiceCredentialPolicyGrantsServiceReadOnly(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	policy := ServiceCredentialPolicy(identity.SID)
	if policy.Principals[identity.SID] != ACLReadExecute {
		t.Fatal("credential policy did not constrain the service identity to read/execute")
	}
	if policy.Principals[SystemSID] != ACLFullControl || policy.Principals[AdministratorsSID] != ACLFullControl {
		t.Fatal("credential policy removed an administrative principal")
	}
	if _, exists := policy.Principals[UsersSID]; exists {
		t.Fatal("credential policy exposed credentials to Users")
	}
}

func TestPrivateTreeAllowsOnlyContainedDescendantReparsePoints(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "private")
	target := filepath.Join(root, "data", "builtin-skills", "cron")
	linkDirectory := filepath.Join(root, "data", "conversations", "session", ".codex", "skills")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	contained := filepath.Join(linkDirectory, "cron")
	if err := os.Symlink(target, contained); err != nil {
		t.Skipf("directory symlink creation is unavailable: %v", err)
	}
	policy := PrivateTreePolicy(identity.SID)
	if err := ApplyTreeACL(root, policy); err != nil {
		t.Fatalf("contained private-tree skill link was rejected: %v", err)
	}
	if err := VerifyTreeACL(root, policy); err != nil {
		t.Fatalf("contained private-tree skill link failed ACL verification: %v", err)
	}
	danglingContained := filepath.Join(linkDirectory, "dangling-contained")
	if err := os.Symlink(filepath.Join(root, "data", "builtin-skills", "not-installed"), danglingContained); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err != nil {
		t.Fatalf("contained dangling private-tree skill link failed ACL verification: %v", err)
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	escaping := filepath.Join(linkDirectory, "escaping")
	if err := os.Symlink(outside, escaping); err != nil {
		t.Fatal(err)
	}
	if err := ApplyTreeACL(root, policy); err == nil {
		t.Fatal("private-tree link escaping its protected root was accepted")
	}
	if err := VerifyTreeACL(root, policy); err == nil {
		t.Fatal("escaping private-tree link passed ACL verification")
	}
	if err := VerifyTreeACL(root, SharedReadOnlyPolicy()); err == nil {
		t.Fatal("shared immutable policy accepted a reparse point")
	}
	if err := ApplyTreeACL(root, SharedProjectPolicy(identity.SID, nil)); err == nil {
		t.Fatal("shared project policy accepted a contained reparse point")
	}
	if err := VerifyTreeACL(root, SharedProjectPolicy(identity.SID, nil)); err == nil {
		t.Fatal("shared project policy verified a contained reparse point")
	}
	if err := os.Remove(escaping); err != nil {
		t.Fatal(err)
	}
	danglingEscaping := filepath.Join(linkDirectory, "dangling-escaping")
	if err := os.Symlink(filepath.Join(outside, "not-installed"), danglingEscaping); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeACL(root, policy); err == nil {
		t.Fatal("dangling private-tree link escaping its protected root was accepted")
	}
}

func applyOwnerRightsPrivateACLForTest(t *testing.T, path, ownerSID string, directory bool) {
	t.Helper()
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "O:" + ownerSID + "G:" + SystemSID + "D:P" +
		"(A;" + flags + ";FA;;;" + OwnerRightsSID + ")" +
		"(A;" + flags + ";FA;;;" + SystemSID + ")" +
		"(A;" + flags + ";FA;;;" + AdministratorsSID + ")"
	applySecurityDescriptorForTest(t, path, sddl)
}

func applySecurityDescriptorForTest(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	information := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
