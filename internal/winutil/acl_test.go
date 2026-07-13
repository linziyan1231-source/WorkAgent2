package winutil

import (
	"os"
	"path/filepath"
	"testing"
)

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
