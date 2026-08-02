package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

func TestLoadWorkAgentAssistantPromptBrandsLegacySignedContent(t *testing.T) {
	releaseRoot := t.TempDir()
	promptPath := filepath.Join(releaseRoot, filepath.FromSlash(workagentAssistantPromptPath))
	if err := os.MkdirAll(filepath.Dir(promptPath), 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPrompt := "# " + legacyDisplayBrand + " 管家\n\n帮助用户管理 " + legacyDisplayBrand + "。\n"
	if err := os.WriteFile(promptPath, []byte(legacyPrompt), 0o600); err != nil {
		t.Fatal(err)
	}
	prompt, err := loadWorkAgentAssistantPrompt(releaseRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prompt)
	if !strings.Contains(string(prompt), "WorkAgent2") || strings.Contains(string(prompt), legacyDisplayBrand) {
		t.Fatalf("signed prompt was not branded: %q", prompt)
	}
}

func TestApplyWorkAgentBrandingConvergesBuiltinStateAndPreservesCustomState(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootPath, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootPath, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Existing tenants carry the previous brand marker. Migrate it in place
	// instead of treating a valid tenant as foreign state.
	if err := os.WriteFile(filepath.Join(rootPath, workagentBrandingMarkerPath), []byte(legacyBrandingMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	seedWorkAgentSkillFiles(t, rootPath)
	databasePath := filepath.Join(rootPath, "data", "aionui-backend.db")
	database := seedWorkAgentBrandingDatabase(t, databasePath)
	database.Close()
	if err := os.Chmod(databasePath, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	prompt := []byte("# WorkAgent2 管家\n\n帮助用户管理 WorkAgent2。\n")
	changed, err := applyWorkAgentBranding(context.Background(), root, "data/aionui-backend.db", prompt, uint32(os.Getuid()), time.Unix(100, 0))
	if err != nil || !changed {
		t.Fatalf("first branding convergence changed=%v err=%v", changed, err)
	}
	marker, err := os.ReadFile(filepath.Join(rootPath, workagentBrandingMarkerPath))
	if err != nil || string(marker) != workagentBrandingMarkerContent {
		t.Fatalf("legacy branding marker was not migrated: marker=%q err=%v", marker, err)
	}
	database, err = sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var name, inline, snapshot string
	if err := database.QueryRow(`SELECT name,rule_inline_content FROM assistant_definitions WHERE assistant_id='aionui-assistant'`).Scan(&name, &inline); err != nil {
		t.Fatal(err)
	}
	if name != "WorkAgent2 Butler" || inline != string(prompt) {
		t.Fatalf("built-in assistant was not converged: name=%q prompt=%q", name, inline)
	}
	if err := database.QueryRow(`SELECT rules_content FROM conversation_assistant_snapshots WHERE assistant_id='aionui-assistant'`).Scan(&snapshot); err != nil || snapshot != string(prompt) {
		t.Fatalf("assistant snapshot was not converged: %q err=%v", snapshot, err)
	}
	var customName, customPrompt string
	if err := database.QueryRow(`SELECT name,rule_inline_content FROM assistant_definitions WHERE assistant_id='custom-assistant'`).Scan(&customName, &customPrompt); err != nil {
		t.Fatal(err)
	}
	if customName != "My AionUi helper" || customPrompt != "Keep my AionUi wording" {
		t.Fatal("custom assistant state was overwritten")
	}
	content, err := os.ReadFile(filepath.Join(rootPath, workagentManagedSkillFiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "WorkAgent2") || strings.Contains(string(content), legacyDisplayBrand) || !strings.Contains(string(content), "https://github.com/iOfficeAI/AionUi") {
		t.Fatalf("skill branding or protected technical literal is wrong: %q", content)
	}
	changed, err = applyWorkAgentBranding(context.Background(), root, "data/aionui-backend.db", prompt, uint32(os.Getuid()), time.Unix(200, 0))
	if err != nil || changed {
		t.Fatalf("second branding convergence changed=%v err=%v", changed, err)
	}
}

func seedWorkAgentSkillFiles(t *testing.T, root string) {
	t.Helper()
	for _, relative := range workagentManagedSkillFiles {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		content := "# AionUi\nConfigure AionUI and the AionUi Butler.\n"
		if relative == workagentManagedSkillFiles[0] {
			content += "https://github.com/iOfficeAI/AionUi\n"
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func seedWorkAgentBrandingDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
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
		`INSERT INTO assistant_definitions VALUES ('builtin','aionui-assistant','builtin','system','aionui-assistant',NULL,NULL,'AionUi Butler',
'{"en-US":"AionUi Butler","zh-CN":"AionUi管家"}','Your all-in-one AionUi butler','{"zh-CN":"你的 AionUI 管家"}','builtin_asset','avatars/aionui-assistant.jpg',
'agent','builtin_asset','aionui-assistant',NULL,'["Open AionUi"]','{"zh-CN":["打开 AionUi"]}','auto',NULL,'auto',NULL,'fixed','["aionui-config"]','[]','[]','auto','[]',1,1,NULL)`,
		`INSERT INTO assistant_definitions VALUES ('custom','custom-assistant','user','user',NULL,NULL,NULL,'My AionUi helper','{}','Custom','{}','none',NULL,
'agent','inline',NULL,'Keep my AionUi wording','[]','{}','auto',NULL,'auto',NULL,'auto','[]','[]','[]','auto','[]',1,1,NULL)`,
		`INSERT INTO conversation_assistant_snapshots VALUES ('conversation','builtin','aionui-assistant','builtin','agent','# AionUi管家','auto',NULL,'auto',NULL,'fixed','[]','[]','auto','[]',1,1)`,
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	for index, name := range []string{"aionui-config", "aionui-troubleshooting", "aionui-webui-public", "aionui-webui-setup"} {
		if _, err := database.Exec(`INSERT INTO skills VALUES (?,?,?,?, 'builtin',1,NULL,1,1)`, "skill"+string(rune('0'+index)), name, "Configure AionUi and AionUI", filepath.Join(path, name)); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	return database
}
