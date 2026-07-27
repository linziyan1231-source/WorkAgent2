package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestApplyInitialAgentDefaultsIsOneTimeAndPreservesCustomAgents(t *testing.T) {
	root := t.TempDir()
	databasePath := filepath.Join(root, "aionui-backend.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE agent_metadata(id TEXT PRIMARY KEY,backend TEXT,agent_type TEXT NOT NULL,agent_source TEXT NOT NULL,enabled INTEGER NOT NULL,updated_at INTEGER NOT NULL)`,
		`CREATE TABLE assistant_definitions(id TEXT PRIMARY KEY,source TEXT NOT NULL,source_ref TEXT,agent_id TEXT NOT NULL,default_permission_mode TEXT NOT NULL,default_permission_value TEXT,updated_at INTEGER NOT NULL,deleted_at INTEGER)`,
		`INSERT INTO agent_metadata VALUES('aion',NULL,'aionrs','internal',0,1),('codex','codex','acp','builtin',0,1),('kimi','kimi','acp','builtin',0,1),('qwen','qwen','acp','builtin',1,1),('custom','private','acp','custom',1,1)`,
		`INSERT INTO assistant_definitions VALUES('bare:aion','generated','aion','aion','auto',NULL,1,NULL)`,
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, agentDefaultsMarkerName)
	applied, err := applyInitialAgentDefaults(context.Background(), databasePath, marker, uint32(os.Getuid()), time.Unix(1_800_000_000, 0))
	if err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	database, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT id FROM agent_metadata WHERE enabled<>0 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var enabled []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		enabled = append(enabled, id)
	}
	rows.Close()
	if !reflect.DeepEqual(enabled, []string{"aion", "codex", "custom", "kimi"}) {
		t.Fatalf("enabled=%v", enabled)
	}
	if _, err := database.Exec(`UPDATE agent_metadata SET enabled=1 WHERE id='qwen'`); err != nil {
		t.Fatal(err)
	}
	applied, err = applyInitialAgentDefaults(context.Background(), databasePath, marker, uint32(os.Getuid()), time.Now())
	if err != nil || applied {
		t.Fatalf("repeat applied=%v err=%v", applied, err)
	}
}
