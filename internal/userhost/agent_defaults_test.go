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

func TestApplyInitialAgentDefaultsEnablesOnlyCodexAndKimiOnce(t *testing.T) {
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
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"codex", "custom", "kimi"}) {
		t.Fatalf("unexpected enabled agents: %v", got)
	}
	if _, err := db.Exec(`UPDATE agent_metadata SET enabled=1 WHERE id='qwen'`); err != nil {
		t.Fatal(err)
	}
	applied, err = applyInitialAgentDefaults(context.Background(), dbPath, markerPath, time.UnixMilli(1783969100000))
	if err != nil || applied {
		t.Fatalf("repeat defaults: applied=%v err=%v", applied, err)
	}
	if got := enabledAgentIDs(t, db); !reflect.DeepEqual(got, []string{"codex", "custom", "kimi", "qwen"}) {
		t.Fatalf("repeat call overwrote user selection: %v", got)
	}
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
	if err == nil || applied || !strings.Contains(err.Error(), "Codex and Kimi") {
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
	for _, agent := range agents {
		var backend any
		if agent.backend != "" {
			backend = agent.backend
		}
		if _, err := db.Exec(`INSERT INTO agent_metadata(id,name,backend,agent_type,agent_source,enabled,created_at,updated_at)
VALUES(?,?,?,'acp',?,?,1783950847713,1783950847713)`, agent.id, agent.name, backend, agent.source, agent.enabled); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return db
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
