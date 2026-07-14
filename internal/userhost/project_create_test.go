package userhost

import (
	"os"
	"path/filepath"
	"testing"

	"aionuiportal/internal/winutil"
)

func TestCreateProjectCreatesProtectedDirectory(t *testing.T) {
	workspace := projectCreateWorkspace(t)
	result, code, err := createProjectState(workspace, projectRenameTestSID, "网站项目")
	if err != nil || code != "" {
		t.Fatalf("create failed: code=%s err=%v", code, err)
	}
	target := filepath.Join(workspace, "网站项目")
	if result.Path != target {
		t.Fatalf("unexpected creation result: %+v", result)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("created directory is unavailable: info=%v err=%v", info, err)
	}
	if err := winutil.VerifyDescendantACL(target, winutil.PrivateTreePolicy(projectRenameTestSID)); err != nil {
		t.Fatalf("created directory ACL is invalid: %v", err)
	}
}

func TestCreateProjectConflictLeavesExistingDirectory(t *testing.T) {
	workspace := projectCreateWorkspace(t)
	target := filepath.Join(workspace, "existing")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	_, code, err := createProjectState(workspace, projectRenameTestSID, "existing")
	if err == nil || code != "PROJECT_EXISTS" {
		t.Fatalf("conflict result: code=%s err=%v", code, err)
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 1 || entries[0].Name() != "existing" {
		t.Fatalf("conflict changed workspace: entries=%v err=%v", entries, err)
	}
}

func projectCreateWorkspace(t *testing.T) string {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := winutil.ApplyACL(workspace, winutil.PrivateTreePolicy(projectRenameTestSID)); err != nil {
		t.Fatal(err)
	}
	return workspace
}
