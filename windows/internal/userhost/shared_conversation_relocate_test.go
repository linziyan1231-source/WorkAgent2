package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSharedConversationRelocationMovesOnlyPrivateRowsAndRollsBack(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "aionui-backend.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE conversations (id TEXT PRIMARY KEY, extra TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	oldPath := `C:\AionData\shared\S-1-5-21-1\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
	newPath := `C:\AionData\shared\S-1-5-21-2\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
	insert := func(id string, internal bool) {
		extra, marshalErr := json.Marshal(map[string]any{
			"workspace": oldPath, "custom_workspace": true, "is_project_workspace": true,
			"internal_shared_runtime": internal,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, execErr := db.Exec(`INSERT INTO conversations(id,extra) VALUES(?,?)`, id, string(extra)); execErr != nil {
			t.Fatal(execErr)
		}
	}
	privateID := "11111111-1111-4111-8111-111111111111"
	internalID := "22222222-2222-4222-8222-222222222222"
	insert(privateID, false)
	insert(internalID, true)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	ids, err := privateSharedConversationIDs(context.Background(), dbPath, oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != privateID {
		t.Fatalf("private relocation IDs = %#v", ids)
	}
	if err := setConversationWorkspaces(context.Background(), dbPath, ids, oldPath, newPath, newPath); err != nil {
		t.Fatal(err)
	}
	assertWorkspace := func(id, expected string) {
		db, openErr := sql.Open("sqlite", dbPath)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer db.Close()
		var raw string
		if scanErr := db.QueryRow(`SELECT extra FROM conversations WHERE id=?`, id).Scan(&raw); scanErr != nil {
			t.Fatal(scanErr)
		}
		var extra map[string]any
		if unmarshalErr := json.Unmarshal([]byte(raw), &extra); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		if actual, _ := extra["workspace"].(string); !samePath(actual, expected) {
			t.Fatalf("conversation %s workspace = %q, want %q", id, actual, expected)
		}
	}
	assertWorkspace(privateID, newPath)
	assertWorkspace(internalID, oldPath)
	if err := setConversationWorkspaces(context.Background(), dbPath, ids, oldPath, newPath, oldPath); err != nil {
		t.Fatal(err)
	}
	assertWorkspace(privateID, oldPath)
}

func TestSameConversationIDsRequiresAnExactPreparedSnapshot(t *testing.T) {
	prepared := []string{"a", "b"}
	if !sameConversationIDs(prepared, []string{"a", "b"}) {
		t.Fatal("identical relocation snapshot was rejected")
	}
	if sameConversationIDs(prepared, []string{"a", "b", "c"}) {
		t.Fatal("new conversation after prepare was not detected")
	}
	if sameConversationIDs(prepared, []string{"a", "c"}) {
		t.Fatal("changed conversation set was not detected")
	}
}
