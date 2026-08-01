package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestApplyInitialAgentDefaultsEnablesOnlyAionCodexAndKimiOnce(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	markerPath := filepath.Join(root, agentDefaultsMarkerName)
	db := seedAgentMetadata(t, dbPath, []agentFixture{
		{"aion", "Aion CLI", "", "internal", 1},
		{"claude", "Claude Code", "claude", "builtin", 1},
		{"codex", "Codex CLI", "codex", "builtin", 0},
		{"copilot", "Copilot", "copilot", "builtin", 1},
		{"custom", "Private Agent", "private", "custom", 1},
		{"gemini", "Gemini CLI", "gemini", "builtin", 1},
		{"kimi", "Kimi", "kimi", "builtin", 0},
		{"nanobot", "Nanobot", "", "builtin", 1},
		{"openclaw-acp", "OpenClaw", "openclaw", "builtin", 1},
		{"openclaw-gateway", "OpenClaw", "", "builtin", 1},
		{"qwen", "Qwen", "qwen", "builtin", 1},
	})
	db.Close()
	applied, err := applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1783969000000))
	if err != nil || !applied {
		t.Fatalf("apply defaults: applied=%v err=%v", applied, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"aion", "codex", "custom", "kimi"}) {
		t.Fatalf("unexpected enabled agents: %v", got)
	}
	assertYoloAssistantDefaults(t, db)
	assertAssistantVisibility(t, db, []string{"codex", "kimi"}, []string{"aionui-assistant"}, []string{"aionui-assistant"})
	if _, err := db.Exec(`UPDATE agent_metadata SET enabled=1 WHERE id='qwen'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assistant_overlays SET enabled=1 WHERE assistant_definition_id IN ('bare:qwen','builtin:game')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assistant_overrides SET enabled=1 WHERE assistant_id='game-3d'`); err != nil {
		t.Fatal(err)
	}
	applied, err = applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1783969100000))
	if err != nil || applied {
		t.Fatalf("repeat defaults: applied=%v err=%v", applied, err)
	}
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"aion", "codex", "custom", "kimi", "qwen"}) {
		t.Fatalf("repeat call overwrote user selection: %v", got)
	}
	assertAssistantVisibility(t, db, []string{"codex", "kimi", "qwen"}, []string{"aionui-assistant", "game-3d"}, []string{"aionui-assistant", "game-3d"})
}

func TestApplyInitialAgentDefaultsFailsWithoutBothTargets(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	db := seedAgentMetadata(t, dbPath, []agentFixture{
		{"codex", "Codex CLI", "codex", "builtin", 0},
		{"qwen", "Qwen", "qwen", "builtin", 1},
	})
	db.Close()
	markerPath := filepath.Join(root, agentDefaultsMarkerName)
	applied, err := applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.Now())
	if err == nil || applied || !strings.Contains(err.Error(), "Aion, Codex, and Kimi") {
		t.Fatalf("expected missing-target failure, applied=%v err=%v", applied, err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker exists after failed initialization: %v", err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"qwen"}) {
		t.Fatalf("failed initialization changed agent state: %v", got)
	}
}

func TestApplyInitialAgentDefaultsRollsBackWhenGeneratedOverlayIsMissing(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	markerPath := filepath.Join(root, agentDefaultsMarkerName)
	db := seedAgentMetadata(t, dbPath, []agentFixture{
		{"aion", "Aion CLI", "", "internal", 1},
		{"codex", "Codex CLI", "codex", "builtin", 0},
		{"kimi", "Kimi", "kimi", "builtin", 0},
		{"qwen", "Qwen", "qwen", "builtin", 1},
	})
	if _, err := db.Exec(`DELETE FROM assistant_overlays WHERE assistant_definition_id='bare:qwen'`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	applied, err := applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1783969150000))
	if err == nil || applied || !strings.Contains(err.Error(), "missing 1") {
		t.Fatalf("expected missing-overlay failure, applied=%v err=%v", applied, err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker exists after rolled-back initialization: %v", err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"aion", "qwen"}) {
		t.Fatalf("failed visibility initialization changed agent state: %v", got)
	}
	assertAssistantVisibility(t, db, []string{"aion"}, []string{"game-3d"}, []string{"game-3d"})
}

func TestApplyInitialAgentDefaultsV2EnablesAionWithoutOverwritingSelections(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	markerPath := filepath.Join(root, agentDefaultsMarkerName)
	db := seedAgentMetadata(t, dbPath, []agentFixture{
		{"aion", "Aion CLI", "", "internal", 0},
		{"claude", "Claude Code", "claude", "builtin", 1},
		{"codex", "Codex CLI", "codex", "builtin", 1},
		{"kimi", "Kimi", "kimi", "builtin", 1},
		{"qwen", "Qwen", "qwen", "builtin", 1},
	})
	db.Close()
	if err := os.WriteFile(filepath.Join(root, legacyAgentDefaultsMarkerName), []byte(legacyAgentDefaultsMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	applied, err := applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1783969200000))
	if err != nil || !applied {
		t.Fatalf("apply v2 defaults: applied=%v err=%v", applied, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"aion", "claude", "codex", "kimi", "qwen"}) {
		t.Fatalf("v2 migration overwrote prior selections: %v", got)
	}
	assertAssistantVisibility(t, db, []string{"claude", "codex", "kimi", "qwen"}, []string{"game-3d"}, []string{"game-3d"})
}

func TestApplyInitialAgentDefaultsV3PreservesAgentSelectionsAndSetsYolo(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "aionui-backend.db")
	markerPath := filepath.Join(root, agentDefaultsMarkerName)
	db := seedAgentMetadata(t, dbPath, []agentFixture{
		{"aion", "Aion CLI", "", "internal", 0},
		{"codex", "Codex CLI", "codex", "builtin", 1},
		{"kimi", "Kimi", "kimi", "builtin", 0},
	})
	db.Close()
	if err := os.WriteFile(filepath.Join(root, previousAgentDefaultsMarkerName), []byte(previousAgentDefaultsMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	applied, err := applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1783969300000))
	if err != nil || !applied {
		t.Fatalf("apply v3 defaults: applied=%v err=%v", applied, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"codex"}) {
		t.Fatalf("v3 migration overwrote agent selections: %v", got)
	}
	assertYoloAssistantDefaults(t, db)
	assertAssistantVisibility(t, db, []string{"codex"}, []string{"game-3d"}, []string{"game-3d"})
}

type agentFixture struct {
	id, name, backend, source string
	enabled                   int
}

func seedAgentMetadata(t *testing.T, path string, agents []agentFixture) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE agent_metadata (
id TEXT PRIMARY KEY NOT NULL,icon TEXT,name TEXT NOT NULL,name_i18n TEXT,description TEXT,description_i18n TEXT,
backend TEXT,agent_type TEXT NOT NULL,agent_source TEXT NOT NULL,agent_source_info TEXT,enabled INTEGER NOT NULL DEFAULT 1,
command TEXT,args TEXT,env TEXT,native_skills_dirs TEXT,behavior_policy TEXT,yolo_id TEXT,agent_capabilities TEXT,
auth_methods TEXT,config_options TEXT,available_modes TEXT,available_models TEXT,available_commands TEXT,
sort_order INTEGER NOT NULL DEFAULT 1000,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
last_check_status TEXT,last_check_kind TEXT,last_check_error_code TEXT,last_check_error_message TEXT,last_check_guidance TEXT,
last_check_latency_ms INTEGER,last_check_at INTEGER,last_success_at INTEGER,last_failure_at INTEGER,command_override TEXT,env_override TEXT)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE assistant_definitions (
id TEXT PRIMARY KEY NOT NULL,assistant_id TEXT NOT NULL UNIQUE,source TEXT NOT NULL,source_ref TEXT,agent_id TEXT NOT NULL,
default_permission_mode TEXT NOT NULL,default_permission_value TEXT,updated_at INTEGER NOT NULL,deleted_at INTEGER)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE assistant_overlays (
assistant_definition_id TEXT PRIMARY KEY NOT NULL,enabled INTEGER NOT NULL,sort_order INTEGER NOT NULL DEFAULT 0,
agent_id_override TEXT,last_used_at INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE assistant_overrides (
assistant_id TEXT PRIMARY KEY NOT NULL,enabled INTEGER NOT NULL,sort_order INTEGER NOT NULL DEFAULT 0,
agent_backend TEXT,last_used_at INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	for _, agent := range agents {
		var backend any
		if agent.backend != "" {
			backend = agent.backend
		}
		agentType := "acp"
		if agent.id == "aion" {
			agentType = "aionrs"
		}
		if _, err := db.Exec(`INSERT INTO agent_metadata(id,name,backend,agent_type,agent_source,enabled,created_at,updated_at)
VALUES(?,?,?,?,?,?,1783950847713,1783950847713)`, agent.id, agent.name, backend, agentType, agent.source, agent.enabled); err != nil {
			db.Close()
			t.Fatal(err)
		}
		definitionSource := "generated"
		if agent.source == "custom" {
			definitionSource = "user"
		}
		definitionID := "bare:" + agent.id
		if _, err := db.Exec(`INSERT INTO assistant_definitions(id,assistant_id,source,source_ref,agent_id,default_permission_mode,updated_at)
VALUES(?,?,?,?,?,?,1783950847713)`, definitionID, definitionID, definitionSource, agent.id, agent.id, "auto"); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO assistant_overlays(assistant_definition_id,enabled,created_at,updated_at)
VALUES(?,?,1783950847713,1783950847713)`, definitionID, agent.enabled); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	for _, builtin := range []struct {
		definitionID, assistantID string
		enabled                   int
	}{{"builtin:workagent", "aionui-assistant", 0}, {"builtin:game", "game-3d", 1}} {
		if _, err := db.Exec(`INSERT INTO assistant_definitions(id,assistant_id,source,source_ref,agent_id,default_permission_mode,updated_at)
VALUES(?,?, 'builtin',?,?, 'auto',1783950847713)`, builtin.definitionID, builtin.assistantID, builtin.assistantID, "aion"); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO assistant_overlays(assistant_definition_id,enabled,created_at,updated_at)
VALUES(?,?,1783950847713,1783950847713)`, builtin.definitionID, builtin.enabled); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO assistant_overrides(assistant_id,enabled,created_at,updated_at)
VALUES(?,?,1783950847713,1783950847713)`, builtin.assistantID, builtin.enabled); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return db
}

func assertYoloAssistantDefaults(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`SELECT agent_id,default_permission_mode,default_permission_value
FROM assistant_definitions WHERE source='generated' AND agent_id IN ('aion','kimi') ORDER BY agent_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var agentID, mode string
		var value sql.NullString
		if err := rows.Scan(&agentID, &mode, &value); err != nil {
			t.Fatal(err)
		}
		got = append(got, agentID+":"+mode+":"+value.String)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"aion:fixed:yolo", "kimi:auto:"}) {
		t.Fatalf("unexpected assistant permission defaults: %v", got)
	}
}

func assertAssistantVisibility(t *testing.T, db *sql.DB, generated, builtin, legacy []string) {
	t.Helper()
	queries := []struct {
		name string
		sql  string
		want []string
	}{
		{"generated", `SELECT ad.agent_id
FROM assistant_overlays ao JOIN assistant_definitions ad ON ad.id=ao.assistant_definition_id
WHERE ad.source='generated' AND ao.enabled<>0 ORDER BY ad.agent_id`, generated},
		{"builtin", `SELECT ad.source_ref
FROM assistant_overlays ao JOIN assistant_definitions ad ON ad.id=ao.assistant_definition_id
WHERE ad.source='builtin' AND ao.enabled<>0 ORDER BY ad.source_ref`, builtin},
		{"legacy", `SELECT assistant_id FROM assistant_overrides WHERE enabled<>0 ORDER BY assistant_id`, legacy},
	}
	for _, query := range queries {
		rows, err := db.Query(query.sql)
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
			t.Fatalf("unexpected enabled %s assistants: got %v want %v", query.name, got, query.want)
		}
	}
}

func enabledAgentIDs(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id FROM agent_metadata WHERE enabled<>0 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}
