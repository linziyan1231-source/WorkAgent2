package admin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/posixacl"
)

func TestExclusiveTenantFileACLRemovesUnexpectedPrincipals(t *testing.T) {
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl is unavailable")
	}
	path := filepath.Join(t.TempDir(), "tenant.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := setACL(context.Background(), path, "u:2:r--"); err != nil {
		t.Fatal(err)
	}
	if err := setExclusiveFileACL(context.Background(), path, "u:1:r--"); err != nil {
		t.Fatal(err)
	}
	if err := posixacl.VerifyExclusiveUserPermissions(path, 1, 0o4); err != nil {
		t.Fatalf("exclusive tenant ACL was not installed: %v", err)
	}
	if _, err := posixacl.UserPermissions(path, 2); err == nil {
		t.Fatal("unexpected inherited ACL principal remains")
	}
}
