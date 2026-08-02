package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestApplyCodexAssistantDefaultsSetsManagedNewConversationDefaultsOnce(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE agent_metadata (id TEXT PRIMARY KEY,backend TEXT,agent_source TEXT);
CREATE TABLE assistant_definitions (
 id TEXT PRIMARY KEY,source TEXT,source_ref TEXT,agent_id TEXT,default_model_mode TEXT,default_model_value TEXT,
 default_permission_mode TEXT,default_permission_value TEXT,updated_at INTEGER,deleted_at INTEGER);
INSERT INTO agent_metadata VALUES ('codex','codex','builtin'),('custom','codex','custom');
INSERT INTO assistant_definitions VALUES ('bare:codex','generated','codex','codex','auto',NULL,'auto',NULL,1,NULL);
INSERT INTO assistant_definitions VALUES ('user:codex','user',NULL,'custom','auto',NULL,'auto',NULL,1,NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	markerPath := filepath.Join(root, codexAssistantDefaultsMarkerName)
	applied, err := applyCodexAssistantDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1785000000000))
	if err != nil || !applied {
		t.Fatalf("apply defaults: applied=%t err=%v", applied, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var modelMode, modelValue, permissionMode, permissionValue string
	if err := db.QueryRow(`SELECT default_model_mode,default_model_value,default_permission_mode,default_permission_value
FROM assistant_definitions WHERE id='bare:codex'`).Scan(&modelMode, &modelValue, &permissionMode, &permissionValue); err != nil {
		t.Fatal(err)
	}
	if modelMode != "fixed" || modelValue != "example-balanced" || permissionMode != "fixed" || permissionValue != "agent-full-access" {
		t.Fatalf("unexpected defaults: %s %s %s %s", modelMode, modelValue, permissionMode, permissionValue)
	}
	if applied, err := applyCodexAssistantDefaults(context.Background(), dbPath, markerPath, time.Now()); err != nil || applied {
		t.Fatalf("repeat defaults: applied=%t err=%v", applied, err)
	}
}

func TestApplyCodexAssistantDefaultsFailsClosedForAmbiguousManagedTargets(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE agent_metadata (id TEXT PRIMARY KEY,backend TEXT,agent_source TEXT);
CREATE TABLE assistant_definitions (
 id TEXT PRIMARY KEY,source TEXT,source_ref TEXT,agent_id TEXT,default_model_mode TEXT,default_model_value TEXT,
 default_permission_mode TEXT,default_permission_value TEXT,updated_at INTEGER,deleted_at INTEGER);
INSERT INTO agent_metadata VALUES ('codex-a','codex','builtin'),('codex-b','codex','builtin');
INSERT INTO assistant_definitions VALUES ('a','generated','codex-a','codex-a','auto',NULL,'auto',NULL,1,NULL);
INSERT INTO assistant_definitions VALUES ('b','generated','codex-b','codex-b','auto',NULL,'auto',NULL,1,NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	markerPath := filepath.Join(root, codexAssistantDefaultsMarkerName)
	if applied, err := applyCodexAssistantDefaults(context.Background(), dbPath, markerPath, time.Now()); err == nil || applied {
		t.Fatalf("ambiguous defaults: applied=%t err=%v", applied, err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker exists after failed migration: %v", err)
	}
}
