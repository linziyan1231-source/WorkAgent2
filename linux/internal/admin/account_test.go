package admin

import (
	"os/user"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestVerifyRuntimeAccountEvidence(t *testing.T) {
	tenant := config.Tenant{RuntimeUser: "workagent_test", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111"}
	account := &user.User{Username: tenant.RuntimeUser, Uid: "2001", Gid: "2001", HomeDir: tenant.DataRoot}
	passwd := []byte("workagent_test:x:2001:2001::" + tenant.DataRoot + ":/usr/sbin/nologin\n")
	shadow := []byte("workagent_test:!locked:20000:0:99999:7:::\n")
	options := RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true}
	verified, err := verifyRuntimeAccountEvidence(tenant, account, "workagent_test", "1999", []string{"2001", "1999"}, passwd, shadow, options)
	if err != nil {
		t.Fatal(err)
	}
	if verified.UID != 2001 || verified.GID != 2001 {
		t.Fatalf("unexpected identity: %+v", verified)
	}
}

func TestVerifyRuntimeAccountEvidenceRejectsUnsafeShape(t *testing.T) {
	tenant := config.Tenant{RuntimeUser: "workagent_test", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111"}
	account := &user.User{Username: tenant.RuntimeUser, Uid: "2001", Gid: "2001", HomeDir: tenant.DataRoot}
	passwd := []byte("workagent_test:x:2001:2001::" + tenant.DataRoot + ":/bin/bash\n")
	shadow := []byte("workagent_test:hash:20000:0:99999:7:::\n")
	options := RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true}
	cases := []struct {
		name         string
		primaryGroup string
		groups       []string
		passwd       []byte
		shadow       []byte
	}{
		{name: "interactive shell", primaryGroup: "workagent_test", groups: []string{"2001", "1999"}, passwd: passwd, shadow: []byte("workagent_test:!locked:::::::\n")},
		{name: "foreign primary group", primaryGroup: "shared", groups: []string{"2001", "1999"}, passwd: []byte("workagent_test:x:2001:2001::" + tenant.DataRoot + ":/sbin/nologin\n"), shadow: []byte("workagent_test:!locked:::::::\n")},
		{name: "unexpected supplementary group", primaryGroup: "workagent_test", groups: []string{"2001", "1999", "27"}, passwd: []byte("workagent_test:x:2001:2001::" + tenant.DataRoot + ":/sbin/nologin\n"), shadow: []byte("workagent_test:!locked:::::::\n")},
		{name: "unlocked password", primaryGroup: "workagent_test", groups: []string{"2001", "1999"}, passwd: []byte("workagent_test:x:2001:2001::" + tenant.DataRoot + ":/sbin/nologin\n"), shadow: shadow},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := verifyRuntimeAccountEvidence(tenant, account, test.primaryGroup, "1999", test.groups, test.passwd, test.shadow, options); err == nil {
				t.Fatal("unsafe account evidence was accepted")
			}
		})
	}
}
