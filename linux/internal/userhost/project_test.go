package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	_ "modernc.org/sqlite"
)

func TestCreateProjectHandlerMatchesWindowsConflictContract(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := projectfs.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	host := &Host{workspace: workspace, uid: uint32(os.Getuid()), cfg: config.Tenant{TenantID: "11111111-1111-4111-8111-111111111111"}, logger: log.New(io.Discard, "", 0)}

	create := func(name string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://userhost/internal/projects", strings.NewReader(`{"name":"`+name+`"}`))
		recorder := httptest.NewRecorder()
		host.createProject(recorder, request)
		return recorder
	}
	if response := create("project-one"); response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"path"`) || strings.Contains(response.Body.String(), `"name"`) {
		t.Fatalf("unexpected project creation response: %d %s", response.Code, response.Body.String())
	}
	if response := create("project-one"); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"PROJECT_EXISTS"`) {
		t.Fatalf("project conflict contract changed: %d %s", response.Code, response.Body.String())
	}
	if response := create("../escape"); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"INVALID_PROJECT_NAME"`) {
		t.Fatalf("invalid project contract changed: %d %s", response.Code, response.Body.String())
	}
	for _, name := range []string{".hidden", "sessions", "BUILTIN-SKILLS"} {
		if response := create(name); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"INVALID_PROJECT_NAME"`) {
			t.Fatalf("reserved project %q was accepted: %d %s", name, response.Code, response.Body.String())
		}
	}
}

func TestRenameProjectUpdatesDirectoryAndMatchingConversationPaths(t *testing.T) {
	dataRoot, workspace, dbRelative, source := projectRenameFixture(t)
	defer dataRoot.Close()
	defer workspace.Close()
	result, code, err := renameProjectState(context.Background(), workspace, dataRoot, dbRelative, uint32(os.Getuid()), "old-project", "new-project", false)
	if err != nil || code != "" {
		t.Fatalf("rename failed: code=%s err=%v", code, err)
	}
	target := filepath.Join(workspace.Path(), "new-project")
	if result.OldPath != source || result.NewPath != target || result.UpdatedConversations != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("old directory remains: %v", err)
	}
	workspaces := readConversationWorkspaces(t, filepath.Join(dataRoot.Path(), dbRelative))
	if workspaces["one"] != target || workspaces["two"] != target || workspaces["other"] == target {
		t.Fatalf("conversation paths were not updated exactly: %+v", workspaces)
	}
}

func TestRenameProjectConflictLeavesFilesystemAndDatabaseUnchanged(t *testing.T) {
	dataRoot, workspace, dbRelative, source := projectRenameFixture(t)
	defer dataRoot.Close()
	defer workspace.Close()
	if err := workspace.CreateDirectory("existing-project", 0o700); err != nil {
		t.Fatal(err)
	}
	_, code, err := renameProjectState(context.Background(), workspace, dataRoot, dbRelative, uint32(os.Getuid()), "old-project", "existing-project", false)
	if err == nil || code != "PROJECT_EXISTS" {
		t.Fatalf("conflict result: code=%s err=%v", code, err)
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("source changed after conflict: info=%v err=%v", info, err)
	}
	if got := readConversationWorkspaces(t, filepath.Join(dataRoot.Path(), dbRelative))["one"]; got != source {
		t.Fatalf("conversation changed after conflict: %s", got)
	}
}

func TestRenameLegacyWorkspacePreservesManagedChild(t *testing.T) {
	dataRoot, workspace, dbRelative, child := projectRenameFixture(t)
	defer dataRoot.Close()
	defer workspace.Close()
	rootFile := filepath.Join(workspace.Path(), "index.html")
	if err := os.WriteFile(rootFile, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataRoot.Path(), dbRelative))
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := json.Marshal(map[string]any{"workspace": workspace.Path(), "custom_workspace": true})
	if _, err := db.Exec(`INSERT INTO conversations(id,extra) VALUES('legacy-root',?)`, string(extra)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	result, code, err := renameProjectState(context.Background(), workspace, dataRoot, dbRelative, uint32(os.Getuid()), "", "renamed-root", true)
	if err != nil || code != "" || result.UpdatedConversations != 1 {
		t.Fatalf("legacy rename result=%+v code=%s err=%v", result, code, err)
	}
	if content, err := os.ReadFile(filepath.Join(workspace.Path(), "renamed-root", "index.html")); err != nil || string(content) != "legacy" {
		t.Fatalf("legacy file was not moved: content=%q err=%v", content, err)
	}
	if info, err := os.Stat(child); err != nil || !info.IsDir() {
		t.Fatalf("managed child moved with legacy root: info=%v err=%v", info, err)
	}
}

func TestProjectActivityCancelsOnlyActiveConversations(t *testing.T) {
	var mu sync.Mutex
	active := true
	var cancelled string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		id := request.URL.Path[len("/api/conversations/"):]
		if request.Method == http.MethodPost {
			mu.Lock()
			active = false
			cancelled = id[:len(id)-len("/cancel")]
			mu.Unlock()
			_ = json.NewEncoder(writer).Encode(map[string]any{"success": true})
			return
		}
		mu.Lock()
		isActive := active && id == "active"
		mu.Unlock()
		state, turnID := "idle", ""
		if isActive {
			state, turnID = "running", "turn-1"
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "data": map[string]any{"id": id, "runtime": map[string]any{"state": state, "is_processing": isActive, "pending_confirmations": 0, "turn_id": turnID}}})
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	host := Host{backendURL: base, transport: server.Client().Transport.(*http.Transport)}
	items, err := host.activeProjectConversations(context.Background(), []string{"idle", "active"})
	if err != nil || len(items) != 1 || items[0].id != "active" {
		t.Fatalf("project activity mismatch: items=%+v err=%v", items, err)
	}
	if err := host.stopProjectConversations(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if cancelled != "active" {
		t.Fatalf("wrong conversation cancelled: %q", cancelled)
	}
}

func TestProjectRenameJournalRollsBackFilesystemWhenDatabaseDidNotCommit(t *testing.T) {
	dataRoot, workspace, dbRelative, source := projectRenameFixture(t)
	defer dataRoot.Close()
	defer workspace.Close()
	target := filepath.Join(workspace.Path(), "recovered-project")
	updates := readProjectUpdates(t, filepath.Join(dataRoot.Path(), dbRelative), source, target)
	journal, err := newProjectRenameJournal(dbRelative, "old-project", "recovered-project", source, target, false, updates)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeProjectRenameJournal(dataRoot, journal, workspace); err != nil {
		t.Fatal(err)
	}
	if err := workspace.RenameDirectory("old-project", "recovered-project"); err != nil {
		t.Fatal(err)
	}
	if err := recoverProjectRenameState(context.Background(), workspace, dataRoot, dbRelative, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source was not restored: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("uncommitted target remains: %v", err)
	}
	if _, err := dataRoot.ReadFile(projectRenameJournalPath, projectRenameJournalMax); !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
		t.Fatalf("recovery journal remains: %v", err)
	}
}

func TestProjectRenameJournalCompletesCommittedRename(t *testing.T) {
	dataRoot, workspace, dbRelative, source := projectRenameFixture(t)
	defer dataRoot.Close()
	defer workspace.Close()
	target := filepath.Join(workspace.Path(), "committed-project")
	updates := readProjectUpdates(t, filepath.Join(dataRoot.Path(), dbRelative), source, target)
	journal, err := newProjectRenameJournal(dbRelative, "old-project", "committed-project", source, target, false, updates)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeProjectRenameJournal(dataRoot, journal, workspace); err != nil {
		t.Fatal(err)
	}
	if err := workspace.RenameDirectory("old-project", "committed-project"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataRoot.Path(), dbRelative))
	if err != nil {
		t.Fatal(err)
	}
	for _, update := range updates {
		if _, err := db.Exec(`UPDATE conversations SET extra=? WHERE id=?`, update.NewJSON, update.ID); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recoverProjectRenameState(context.Background(), workspace, dataRoot, dbRelative, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("committed target missing: %v", err)
	}
	if got := readConversationWorkspaces(t, filepath.Join(dataRoot.Path(), dbRelative))["one"]; got != target {
		t.Fatalf("committed conversation path changed during recovery: %s", got)
	}
}

func readProjectUpdates(t *testing.T, databasePath, source, target string) []projectConversationUpdate {
	t.Helper()
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	updates, err := projectConversationUpdates(context.Background(), tx, source, target)
	if err != nil {
		t.Fatal(err)
	}
	return updates
}

func projectRenameFixture(t *testing.T) (*projectfs.Root, *projectfs.Root, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	workspacePath := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspacePath, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(workspacePath, "old-project")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	dbRelative := "aionui-backend.db"
	dbPath := filepath.Join(root, dbRelative)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE conversations(id TEXT PRIMARY KEY,extra TEXT NOT NULL)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	rows := []struct {
		id    string
		extra map[string]any
	}{
		{"one", map[string]any{"workspace": source, "custom_workspace": true, "backend": "codex"}},
		{"two", map[string]any{"workspace": source, "custom_workspace": true, "nested": map[string]any{"keep": true}}},
		{"other", map[string]any{"workspace": filepath.Join(workspacePath, "other"), "custom_workspace": true}},
		{"temporary", map[string]any{"workspace": source, "custom_workspace": false}},
	}
	for _, row := range rows {
		encoded, _ := json.Marshal(row.extra)
		if _, err := db.Exec(`INSERT INTO conversations(id,extra) VALUES(?,?)`, row.id, string(encoded)); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		t.Fatal(err)
	}
	dataRoot, err := projectfs.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := projectfs.OpenRoot(workspacePath)
	if err != nil {
		dataRoot.Close()
		t.Fatal(err)
	}
	return dataRoot, workspace, dbRelative, source
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
	return result
}
