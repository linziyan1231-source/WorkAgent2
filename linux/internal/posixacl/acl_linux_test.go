package posixacl

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestUserPermissionsAppliesACLMask(t *testing.T) {
	payload := testACLPayload([]aclTestEntry{
		{aclUserObjTag, 6, aclUndefinedID},
		{aclUserTag, 6, 1234},
		{aclGroupObjTag, 4, aclUndefinedID},
		{aclMaskTag, 4, aclUndefinedID},
		{aclOtherTag, 0, aclUndefinedID},
	})
	permission, err := userPermissions(payload, 1234)
	if err != nil || permission.Perm() != 0o4 {
		t.Fatalf("permissions=%#o err=%v", permission.Perm(), err)
	}
	if _, err := userPermissions(payload, 4321); err == nil {
		t.Fatal("missing named user was accepted")
	}
}

func TestExclusiveUserPermissionsRejectsAdditionalPrincipals(t *testing.T) {
	baseline := []aclTestEntry{
		{aclUserObjTag, 6, aclUndefinedID},
		{aclUserTag, 4, 1234},
		{aclGroupObjTag, 4, aclUndefinedID},
		{aclMaskTag, 4, aclUndefinedID},
		{aclOtherTag, 0, aclUndefinedID},
	}
	if err := verifyExclusiveUserPermissions(testACLPayload(baseline), 1234, os.FileMode(0o4)); err != nil {
		t.Fatalf("exclusive tenant ACL rejected: %v", err)
	}
	for name, extra := range map[string]aclTestEntry{
		"user":  {aclUserTag, 4, 4321},
		"group": {aclGroupTag, 4, 999},
	} {
		t.Run(name, func(t *testing.T) {
			entries := append(append([]aclTestEntry(nil), baseline...), extra)
			if err := verifyExclusiveUserPermissions(testACLPayload(entries), 1234, os.FileMode(0o4)); err == nil {
				t.Fatal("additional named ACL principal was accepted")
			}
		})
	}
}

type aclTestEntry struct {
	tag        uint16
	permission uint16
	id         uint32
}

func testACLPayload(entries []aclTestEntry) []byte {
	payload := make([]byte, 4+len(entries)*8)
	binary.LittleEndian.PutUint32(payload[:4], aclXattrVersion)
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(payload[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(payload[offset+2:offset+4], entry.permission)
		binary.LittleEndian.PutUint32(payload[offset+4:offset+8], entry.id)
	}
	return payload
}
