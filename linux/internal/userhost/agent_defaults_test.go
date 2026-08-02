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
		`CREATE TABLE assistant_definitions(id TEXT PRIMARY KEY,assistant_id TEXT NOT NULL UNIQUE,source TEXT NOT NULL,source_ref TEXT,agent_id TEXT NOT NULL,default_permission_mode TEXT NOT NULL,default_permission_value TEXT,updated_at INTEGER NOT NULL,deleted_at INTEGER)`,
		`CREATE TABLE assistant_overlays(assistant_definition_id TEXT PRIMARY KEY,enabled INTEGER NOT NULL,updated_at INTEGER NOT NULL)`,
		`CREATE TABLE assistant_overrides(assistant_id TEXT PRIMARY KEY,enabled INTEGER NOT NULL,updated_at INTEGER NOT NULL)`,
		`INSERT INTO agent_metadata VALUES('aion',NULL,'aionrs','internal',0,1),('codex','codex','acp','builtin',0,1),('kimi','kimi','acp','builtin',0,1),('qwen','qwen','acp','builtin',1,1),('custom','private','acp','custom',1,1)`,
		`INSERT INTO assistant_definitions VALUES
('bare:aion','bare:aion','generated','aion','aion','auto',NULL,1,NULL),
('bare:codex','bare:codex','generated','codex','codex','auto',NULL,1,NULL),
('bare:kimi','bare:kimi','generated','kimi','kimi','auto',NULL,1,NULL),
('bare:qwen','bare:qwen','generated','qwen','qwen','auto',NULL,1,NULL),
('custom','custom','user','custom','custom','auto',NULL,1,NULL),
('builtin:workagent','aionui-assistant','builtin','aionui-assistant','aion','auto',NULL,1,NULL),
('builtin:game','game-3d','builtin','game-3d','aion','auto',NULL,1,NULL)`,
		`INSERT INTO assistant_overlays VALUES
('bare:aion',1,1),('bare:codex',0,1),('bare:kimi',0,1),('bare:qwen',1,1),('custom',1,1),
('builtin:workagent',0,1),('builtin:game',1,1)`,
		`INSERT INTO assistant_overrides VALUES('aionui-assistant',0,1),('game-3d',1,1)`,
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
	assertInitialAssistantVisibility(t, database, []string{"codex", "kimi"}, []string{"aionui-assistant"})
	if _, err := database.Exec(`UPDATE agent_metadata SET enabled=1 WHERE id='qwen'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE assistant_overlays SET enabled=1 WHERE assistant_definition_id IN ('bare:qwen','builtin:game')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE assistant_overrides SET enabled=1 WHERE assistant_id='game-3d'`); err != nil {
		t.Fatal(err)
	}
	applied, err = applyInitialAgentDefaults(context.Background(), databasePath, marker, uint32(os.Getuid()), time.Now())
	if err != nil || applied {
		t.Fatalf("repeat applied=%v err=%v", applied, err)
	}
	assertInitialAssistantVisibility(t, database, []string{"codex", "kimi", "qwen"}, []string{"aionui-assistant", "game-3d"})
}

func assertInitialAssistantVisibility(t *testing.T, database *sql.DB, generated, builtin []string) {
	t.Helper()
	queries := []struct {
		sql  string
		want []string
	}{
		{`SELECT ad.agent_id FROM assistant_overlays ao JOIN assistant_definitions ad ON ad.id=ao.assistant_definition_id WHERE ad.source='generated' AND ao.enabled<>0 ORDER BY ad.agent_id`, generated},
		{`SELECT ad.assistant_id FROM assistant_overlays ao JOIN assistant_definitions ad ON ad.id=ao.assistant_definition_id WHERE ad.source='builtin' AND ao.enabled<>0 ORDER BY ad.assistant_id`, builtin},
		{`SELECT assistant_id FROM assistant_overrides WHERE enabled<>0 ORDER BY assistant_id`, builtin},
	}
	for _, query := range queries {
		rows, err := database.Query(query.sql)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			got = append(got, value)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, query.want) {
			t.Fatalf("visibility=%v want=%v", got, query.want)
		}
	}
}
