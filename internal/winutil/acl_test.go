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
}
