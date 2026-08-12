package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestApplyWorkAgentBrandingConvergesBuiltinAssistantPromptAndSkills(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedWorkAgentSkillFiles(t, dataDir)
	dbPath := filepath.Join(dataDir, "aionui-backend.db")
	db := seedWorkAgentBrandingDB(t, dbPath)
	db.Close()
	markerPath := filepath.Join(configDir, workagentBrandingMarkerName)
	applied, err := applyWorkAgentBranding(context.Background(), dbPath, dataDir, markerPath, time.UnixMilli(1784095000000))
	if err != nil || !applied {
		t.Fatalf("apply branding: applied=%v err=%v", applied, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name, nameI18n, description, resourceType, skillsMode, skillIDs string
	var resourceRef sql.NullString
	var prompt string
	if err := db.QueryRow(`SELECT name,name_i18n,description,rule_resource_type,rule_resource_ref,rule_inline_content,
default_skills_mode,default_skill_ids
FROM assistant_definitions WHERE assistant_id='aionui-assistant'`).Scan(&name, &nameI18n, &description, &resourceType, &resourceRef, &prompt, &skillsMode, &skillIDs); err != nil {
		t.Fatal(err)
	}
	if name != "WorkAgent Butler" || !strings.Contains(nameI18n, `"zh-CN":"WorkAgent 管家"`) || !strings.Contains(description, "WorkAgent") {
		t.Fatalf("unexpected assistant branding: name=%q i18n=%q description=%q", name, nameI18n, description)
	}
	if resourceType != "inline" || resourceRef.Valid || prompt != workagentAssistantPrompt || strings.Contains(prompt, "AionUi") || strings.Contains(prompt, "AionUI") {
		t.Fatalf("unexpected branded prompt state: type=%q ref=%v prompt=%q", resourceType, resourceRef, prompt[:min(len(prompt), 160)])
	}
	if !strings.Contains(prompt, "`workagent-help`") || strings.Contains(prompt, "三个技能") {
		t.Fatal("latest WorkAgent prompt does not route product help through workagent-help")
	}
	if skillsMode != "fixed" || skillIDs != `["workagent-help","aionui-config","aionui-troubleshooting","aionui-webui-public"]` {
		t.Fatalf("unexpected assistant skill defaults: mode=%q skills=%s", skillsMode, skillIDs)
	}
	var snapshot, snapshotSkills string
	if err := db.QueryRow(`SELECT rules_content,resolved_skill_ids FROM conversation_assistant_snapshots WHERE conversation_id='conversation'`).Scan(&snapshot, &snapshotSkills); err != nil {
		t.Fatal(err)
	}
	if snapshot != workagentAssistantPrompt || snapshotSkills != `["workagent-help","aionui-config","aionui-troubleshooting","aionui-webui-public"]` {
		t.Fatalf("existing assistant snapshot was not updated: skills=%s", snapshotSkills)
	}
	if err := db.QueryRow(`SELECT resolved_skill_ids FROM conversation_assistant_snapshots WHERE conversation_id='conversation-with-custom-skill'`).Scan(&snapshotSkills); err != nil {
		t.Fatal(err)
	}
	if snapshotSkills != `["custom-docs","workagent-help","aionui-config","workagent-help"]` {
		t.Fatalf("custom snapshot skills were modified while updating the prompt: %s", snapshotSkills)
	}
	var customName, customPrompt string
	if err := db.QueryRow(`SELECT name,rule_inline_content FROM assistant_definitions WHERE assistant_id='custom-assistant'`).Scan(&customName, &customPrompt); err != nil {
		t.Fatal(err)
	}
	if customName != "My AionUi helper" || customPrompt != "Keep my AionUi wording" {
		t.Fatalf("custom assistant was modified: %q %q", customName, customPrompt)
	}
	for _, relative := range workagentSkillFiles {
		content, err := os.ReadFile(filepath.Join(dataDir, "builtin-skills", relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if strings.Contains(text, "AionUI") {
			t.Fatalf("legacy AionUI branding remains in %s", relative)
		}
		if !strings.Contains(text, "WorkAgent") {
			t.Fatalf("WorkAgent branding missing from %s", relative)
		}
	}
	reference, err := os.ReadFile(filepath.Join(dataDir, "builtin-skills", "aionui-webui-setup", "references", "aionui-webui.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range []string{"https://github.com/iOfficeAI/AionUi", "/Applications/AionUi.app/Contents/MacOS/AionUi", "%APPDATA%/AionUi", "ps aux | grep AionUi"} {
		if !strings.Contains(string(reference), preserved) {
			t.Fatalf("technical identifier was changed: %s", preserved)
		}
	}
	if content, err := os.ReadFile(markerPath); err != nil || string(content) != workagentBrandingMarkerContent {
		t.Fatalf("unexpected marker: content=%q err=%v", content, err)
	}
	applied, err = applyWorkAgentBranding(context.Background(), dbPath, dataDir, markerPath, time.UnixMilli(1784096000000))
	if err != nil || applied {
		t.Fatalf("repeat branding: applied=%v err=%v", applied, err)
	}
}

func TestApplyWorkAgentBrandingFailsWhenManagedSkillFileIsMissing(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedWorkAgentSkillFiles(t, dataDir)
	missing := filepath.Join(dataDir, "builtin-skills", workagentSkillFiles[0])
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "aionui-backend.db")
	db := seedWorkAgentBrandingDB(t, dbPath)
	db.Close()
	applied, err := applyWorkAgentBranding(context.Background(), dbPath, dataDir, filepath.Join(configDir, workagentBrandingMarkerName), time.Now())
	if err == nil || applied || !strings.Contains(err.Error(), "inspect built-in skill file") {
		t.Fatalf("expected missing skill failure: applied=%v err=%v", applied, err)
	}
}

func TestApplyWorkAgentBrandingFailsWhenWorkAgentHelpFileIsMissing(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedWorkAgentSkillFiles(t, dataDir)
	missing := filepath.Join(dataDir, "builtin-skills", workagentHelpFiles[0])
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "aionui-backend.db")
	db := seedWorkAgentBrandingDB(t, dbPath)
	db.Close()
	applied, err := applyWorkAgentBranding(context.Background(), dbPath, dataDir, filepath.Join(configDir, workagentBrandingMarkerName), time.Now())
	if err == nil || applied || !strings.Contains(err.Error(), "inspect built-in workagent-help file") {
		t.Fatalf("expected missing workagent-help failure: applied=%v err=%v", applied, err)
	}
}

func TestApplyWorkAgentBrandingRollsBackWhenWorkAgentHelpIsNotRegistered(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedWorkAgentSkillFiles(t, dataDir)
	dbPath := filepath.Join(dataDir, "aionui-backend.db")
	db := seedWorkAgentBrandingDB(t, dbPath)
	if _, err := db.Exec(`DELETE FROM skills WHERE name='workagent-help'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	markerPath := filepath.Join(configDir, workagentBrandingMarkerName)
	applied, err := applyWorkAgentBranding(context.Background(), dbPath, dataDir, markerPath, time.Now())
	if err == nil || applied || !strings.Contains(err.Error(), "enabled built-in workagent-help skill") {
		t.Fatalf("expected unregistered workagent-help failure: applied=%v err=%v", applied, err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var skillIDs string
	var prompt sql.NullString
	if err := db.QueryRow(`SELECT default_skill_ids,rule_inline_content FROM assistant_definitions WHERE assistant_id='aionui-assistant'`).Scan(&skillIDs, &prompt); err != nil {
		t.Fatal(err)
	}
	if skillIDs != `["aionui-config","aionui-troubleshooting","aionui-webui-public"]` || prompt.Valid {
		t.Fatalf("failed migration did not roll back: skills=%s prompt=%v", skillIDs, prompt)
	}
	skillFile, err := os.ReadFile(filepath.Join(dataDir, "builtin-skills", workagentSkillFiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(skillFile), "AionUi") {
		t.Fatal("failed preflight modified managed skill files")
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("failed migration published a marker: %v", err)
	}
}

func TestApplyWorkAgentBrandingRejectsWorkAgentHelpOutsidePrivateBuiltinRoot(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedWorkAgentSkillFiles(t, dataDir)
	dbPath := filepath.Join(dataDir, "aionui-backend.db")
	db := seedWorkAgentBrandingDB(t, dbPath)
	if _, err := db.Exec(`UPDATE skills SET path=? WHERE name='workagent-help'`, filepath.Join(root, "other", "workagent-help")); err != nil {
		t.Fatal(err)
	}
	db.Close()
	applied, err := applyWorkAgentBranding(context.Background(), dbPath, dataDir, filepath.Join(configDir, workagentBrandingMarkerName), time.Now())
	if err == nil || applied || !strings.Contains(err.Error(), "does not match expected private path") {
		t.Fatalf("expected wrong workagent-help path failure: applied=%v err=%v", applied, err)
	}
}

func seedWorkAgentSkillFiles(t *testing.T, dataDir string) {
	t.Helper()
	for _, relative := range workagentSkillFiles {
		path := filepath.Join(dataDir, "builtin-skills", relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		content := "# AionUi\nConfigure AionUI and the AionUi Butler.\n"
		if strings.HasSuffix(relative, filepath.Join("references", "aionui-webui.md")) {
			content += "https://github.com/iOfficeAI/AionUi\n/Applications/AionUi.app/Contents/MacOS/AionUi\n%APPDATA%/AionUi\nps aux | grep AionUi\n"
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, relative := range workagentHelpFiles {
		path := filepath.Join(dataDir, "builtin-skills", relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("# WorkAgent help\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func seedWorkAgentBrandingDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE assistant_definitions (
id TEXT PRIMARY KEY,assistant_id TEXT NOT NULL,source TEXT NOT NULL,owner_type TEXT NOT NULL,source_ref TEXT,source_version TEXT,source_hash TEXT,
name TEXT NOT NULL,name_i18n TEXT NOT NULL DEFAULT '{}',description TEXT,description_i18n TEXT NOT NULL DEFAULT '{}',avatar_type TEXT NOT NULL,avatar_value TEXT,
agent_id TEXT NOT NULL,rule_resource_type TEXT NOT NULL,rule_resource_ref TEXT,rule_inline_content TEXT,recommended_prompts TEXT NOT NULL DEFAULT '[]',
recommended_prompts_i18n TEXT NOT NULL DEFAULT '{}',default_model_mode TEXT NOT NULL,default_model_value TEXT,default_permission_mode TEXT NOT NULL,
default_permission_value TEXT,default_skills_mode TEXT NOT NULL,default_skill_ids TEXT NOT NULL DEFAULT '[]',custom_skill_names TEXT NOT NULL DEFAULT '[]',
default_disabled_builtin_skill_ids TEXT NOT NULL DEFAULT '[]',default_mcps_mode TEXT NOT NULL,default_mcp_ids TEXT NOT NULL DEFAULT '[]',created_at INTEGER NOT NULL,
updated_at INTEGER NOT NULL,deleted_at INTEGER)`,
		`CREATE TABLE conversation_assistant_snapshots (conversation_id TEXT PRIMARY KEY,assistant_definition_id TEXT NOT NULL,assistant_id TEXT NOT NULL,
assistant_source TEXT NOT NULL,agent_id TEXT NOT NULL,rules_content TEXT NOT NULL DEFAULT '',default_model_mode TEXT NOT NULL,resolved_model_id TEXT,
default_permission_mode TEXT NOT NULL,resolved_permission_value TEXT,default_skills_mode TEXT NOT NULL,resolved_skill_ids TEXT NOT NULL DEFAULT '[]',
resolved_disabled_builtin_skill_ids TEXT NOT NULL DEFAULT '[]',default_mcps_mode TEXT NOT NULL,resolved_mcp_ids TEXT NOT NULL DEFAULT '[]',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)`,
		`CREATE TABLE skills (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,description TEXT,path TEXT NOT NULL,source TEXT NOT NULL,enabled INTEGER NOT NULL,
deleted_at INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)`,
		`CREATE TABLE mcp_servers (id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT,enabled INTEGER NOT NULL DEFAULT 0,transport_type TEXT NOT NULL,
transport_config TEXT NOT NULL,tools TEXT,last_test_status TEXT NOT NULL DEFAULT 'disconnected',last_connected INTEGER,original_json TEXT,builtin INTEGER NOT NULL DEFAULT 0,
created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,deleted_at INTEGER)`,
		`CREATE TABLE assistant_preferences (assistant_definition_id TEXT PRIMARY KEY,last_model_id TEXT,last_permission_value TEXT,last_skill_ids TEXT NOT NULL DEFAULT '[]',
last_disabled_builtin_skill_ids TEXT NOT NULL DEFAULT '[]',last_mcp_ids TEXT NOT NULL DEFAULT '[]',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)`,
		`INSERT INTO assistant_definitions VALUES ('builtin','aionui-assistant','builtin','system','aionui-assistant',NULL,NULL,'AionUi Butler',
'{"en-US":"AionUi Butler","zh-CN":"AionUi管家"}','Your all-in-one AionUi butler','{"zh-CN":"你的 AionUI 管家"}','builtin_asset','avatars/aionui-assistant.jpg',
'agent','builtin_asset','aionui-assistant',NULL,'["Open AionUi"]','{"zh-CN":["打开 AionUi"]}','auto',NULL,'auto',NULL,'fixed','["aionui-config","aionui-troubleshooting","aionui-webui-public"]','[]','[]','auto','[]',1,1,NULL)`,
		`INSERT INTO assistant_definitions VALUES ('custom','custom-assistant','user','user',NULL,NULL,NULL,'My AionUi helper','{}','Custom','{}','none',NULL,
'agent','inline',NULL,'Keep my AionUi wording','[]','{}','auto',NULL,'auto',NULL,'auto','[]','[]','[]','auto','[]',1,1,NULL)`,
		`INSERT INTO conversation_assistant_snapshots VALUES ('conversation','builtin','aionui-assistant','builtin','agent','# AionUi管家','auto',NULL,'auto',NULL,'fixed','["aionui-config","aionui-troubleshooting","aionui-webui-public"]','[]','auto','[]',1,1)`,
		`INSERT INTO conversation_assistant_snapshots VALUES ('conversation-with-custom-skill','builtin','aionui-assistant','builtin','agent','# AionUi管家','auto',NULL,'auto',NULL,'fixed','["custom-docs","workagent-help","aionui-config","workagent-help"]','[]','auto','[]',1,1)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	for index, name := range []string{"aionui-config", "aionui-troubleshooting", "aionui-webui-public", "aionui-webui-setup"} {
		if _, err := db.Exec(`INSERT INTO skills VALUES (?,?,?,?, 'builtin',1,NULL,1,1)`, "skill"+string(rune('0'+index)), name, "Configure AionUi and AionUI", filepath.Join(path, name)); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO skills VALUES (?,?,?,?, 'builtin',1,NULL,1,1)`, "skill-help", "workagent-help", "Read WorkAgent help", filepath.Join(filepath.Dir(path), "builtin-skills", "workagent-help")); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}
