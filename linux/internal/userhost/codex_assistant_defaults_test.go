package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"

	_ "modernc.org/sqlite"
)

func TestApplyCodexAssistantDefaultsSetsOnlyManagedNewConversationDefaultsOnce(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "aionui-backend.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE agent_metadata (id TEXT PRIMARY KEY,backend TEXT,agent_source TEXT);
CREATE TABLE assistant_definitions (
 id TEXT PRIMARY KEY,source TEXT,source_ref TEXT,agent_id TEXT,default_model_mode TEXT,default_model_value TEXT,
 default_permission_mode TEXT,default_permission_value TEXT,updated_at INTEGER,deleted_at INTEGER);
INSERT INTO agent_metadata VALUES ('codex','codex','builtin'),('custom','codex','custom'),('kimi','kimi','builtin');
INSERT INTO assistant_definitions VALUES ('bare:codex','generated','codex','codex','auto',NULL,'auto',NULL,1,NULL);
INSERT INTO assistant_definitions VALUES ('user:codex','user',NULL,'custom','auto',NULL,'auto',NULL,1,NULL);
INSERT INTO assistant_definitions VALUES ('bare:kimi','generated','kimi','kimi','auto',NULL,'auto',NULL,1,NULL);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(root, codexAssistantDefaultsMarkerName)
	applied, err := applyCodexAssistantDefaults(context.Background(), databasePath, markerPath, uint32(os.Getuid()), time.UnixMilli(1_785_000_000_000))
	if err != nil || !applied {
		t.Fatalf("apply defaults: applied=%t err=%v", applied, err)
	}
	database, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var modelMode, modelValue, permissionMode, permissionValue string
	if err := database.QueryRow(`SELECT default_model_mode,default_model_value,default_permission_mode,default_permission_value
FROM assistant_definitions WHERE id='bare:codex'`).Scan(&modelMode, &modelValue, &permissionMode, &permissionValue); err != nil {
		t.Fatal(err)
	}
	if modelMode != "fixed" || modelValue != modelbootstrap.DefaultCodexModel || permissionMode != "fixed" || permissionValue != "agent-full-access" {
		t.Fatalf("unexpected managed defaults: %s %s %s %s", modelMode, modelValue, permissionMode, permissionValue)
	}
	for _, id := range []string{"user:codex", "bare:kimi"} {
		if err := database.QueryRow(`SELECT default_model_mode,default_permission_mode FROM assistant_definitions WHERE id=?`, id).Scan(&modelMode, &permissionMode); err != nil {
			t.Fatal(err)
		}
		if modelMode != "auto" || permissionMode != "auto" {
			t.Fatalf("unmanaged assistant %s changed: model=%s permission=%s", id, modelMode, permissionMode)
		}
	}
	if applied, err := applyCodexAssistantDefaults(context.Background(), databasePath, markerPath, uint32(os.Getuid()), time.Now()); err != nil || applied {
		t.Fatalf("repeat defaults: applied=%t err=%v", applied, err)
	}
}

func TestApplyCodexAssistantDefaultsFailsClosedForAmbiguousManagedTargets(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "aionui-backend.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE agent_metadata (id TEXT PRIMARY KEY,backend TEXT,agent_source TEXT);
CREATE TABLE assistant_definitions (
 id TEXT PRIMARY KEY,source TEXT,source_ref TEXT,agent_id TEXT,default_model_mode TEXT,default_model_value TEXT,
 default_permission_mode TEXT,default_permission_value TEXT,updated_at INTEGER,deleted_at INTEGER);
INSERT INTO agent_metadata VALUES ('codex-a','codex','builtin'),('codex-b','codex','builtin');
INSERT INTO assistant_definitions VALUES ('a','generated','codex-a','codex-a','auto',NULL,'auto',NULL,1,NULL);
INSERT INTO assistant_definitions VALUES ('b','generated','codex-b','codex-b','auto',NULL,'auto',NULL,1,NULL);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(root, codexAssistantDefaultsMarkerName)
	if applied, err := applyCodexAssistantDefaults(context.Background(), databasePath, markerPath, uint32(os.Getuid()), time.Now()); err == nil || applied {
		t.Fatalf("ambiguous defaults: applied=%t err=%v", applied, err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker exists after failed migration: %v", err)
	}
}
