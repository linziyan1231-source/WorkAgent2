package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aionuiportal/internal/winutil"
	"golang.org/x/sys/windows"
	_ "modernc.org/sqlite"
)

const projectRenameTestSID = "S-1-5-21-1958036862-1490797588-1401426644-2813"

func TestRenameProjectUpdatesDirectoryAndMatchingConversationPaths(t *testing.T) {
	workspace, dbPath, source := projectRenameFixture(t)
	result, code, err := renameProjectState(context.Background(), workspace, dbPath, projectRenameTestSID, "old-project", "new-project")
	if err != nil || code != "" {
		t.Fatalf("rename failed: code=%s err=%v", code, err)
	}
	target := filepath.Join(workspace, "new-project")
	if result.OldPath != source || result.NewPath != target || result.UpdatedConversations != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("old directory remains: %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("renamed directory is unavailable: info=%v err=%v", info, err)
	}
	if err := winutil.VerifyDescendantACL(target, winutil.PrivateTreePolicy(projectRenameTestSID)); err != nil {
		t.Fatalf("renamed directory ACL is invalid: %v", err)
	}
	workspaces := readConversationWorkspaces(t, dbPath)
	if workspaces["one"] != target || workspaces["two"] != target || workspaces["other"] == target {
		t.Fatalf("conversation paths were not updated exactly: %+v", workspaces)
	}
}

func TestRenameProjectConflictLeavesDirectoryAndDatabaseUnchanged(t *testing.T) {
	workspace, dbPath, source := projectRenameFixture(t)
	target := filepath.Join(workspace, "existing-project")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	_, code, err := renameProjectState(context.Background(), workspace, dbPath, projectRenameTestSID, "old-project", "existing-project")
	if err == nil || code != "PROJECT_EXISTS" {
		t.Fatalf("conflict result: code=%s err=%v", code, err)
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("source changed after conflict: info=%v err=%v", info, err)
	}
	if got := readConversationWorkspaces(t, dbPath)["one"]; got != source {
		t.Fatalf("conversation changed after conflict: %s", got)
	}
}

func TestRenameProjectReportsWindowsDirectoryOccupationWithoutPartialUpdates(t *testing.T) {
	workspace, dbPath, source := projectRenameFixture(t)
	pointer, err := windows.UTF16PtrFromString(source)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)

	_, code, err := renameProjectState(context.Background(), workspace, dbPath, projectRenameTestSID, "old-project", "blocked-project")
	if err == nil || code != "PROJECT_IN_USE" {
		t.Fatalf("occupied result: code=%s err=%v", code, err)
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("source changed while occupied: info=%v err=%v", info, err)
	}
	if got := readConversationWorkspaces(t, dbPath)["one"]; got != source {
		t.Fatalf("conversation changed while occupied: %s", got)
	}
}

func projectRenameFixture(t *testing.T) (workspace, dbPath, source string) {
	t.Helper()
	root := t.TempDir()
	workspace = filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := winutil.PrivateTreePolicy(projectRenameTestSID)
	if err := winutil.ApplyACL(workspace, policy); err != nil {
		t.Fatal(err)
	}
	source = filepath.Join(workspace, "old-project")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath = filepath.Join(root, "aionui-backend.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE conversations(id TEXT PRIMARY KEY,extra TEXT NOT NULL,updated_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		id    string
		extra map[string]any
	}{
		{id: "one", extra: map[string]any{"workspace": source, "custom_workspace": true, "backend": "codex"}},
		{id: "two", extra: map[string]any{"workspace": source, "custom_workspace": true, "nested": map[string]any{"keep": true}}},
		{id: "other", extra: map[string]any{"workspace": filepath.Join(workspace, "other"), "custom_workspace": true}},
		{id: "temporary", extra: map[string]any{"workspace": source, "custom_workspace": false}},
	}
	for _, row := range rows {
		encoded, err := json.Marshal(row.extra)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO conversations(id,extra,updated_at) VALUES(?,?,1)`, row.id, string(encoded)); err != nil {
			t.Fatal(err)
		}
	}
	return workspace, dbPath, source
}

func readConversationWorkspaces(t *testing.T, dbPath string) map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id,extra FROM conversations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			t.Fatal(err)
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			t.Fatal(err)
		}
		if workspace, ok := extra["workspace"].(string); ok {
			result[id] = workspace
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
