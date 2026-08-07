package userhost

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/config"
)

func TestApplyKimiDatasourceAccessBindsAndRevokesManagedMCPAndSkill(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	dbPath := filepath.Join(dataDir, "aionui-backend.db")
	db := seedWorkAgentBrandingDB(t, dbPath)
	if _, err := db.Exec(`INSERT INTO assistant_preferences
(assistant_definition_id,last_model_id,last_permission_value,last_skill_ids,last_disabled_builtin_skill_ids,last_mcp_ids,created_at,updated_at)
VALUES('builtin',NULL,NULL,'[]','[]','["stale-plugin"]',1,1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	access := &config.KimiDatasourceAccess{Endpoint: "http://127.0.0.1:3211/mcp", Token: strings.Repeat("t", 40)}
	if _, err := applyKimiDatasourceAccess(context.Background(), dbPath, dataDir, access, time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var enabled int
	var name, transport string
	if err := db.QueryRow(`SELECT name,enabled,transport_config FROM mcp_servers WHERE id=?`, kimiDatasourceManagedID).Scan(&name, &enabled, &transport); err != nil {
		t.Fatal(err)
	}
	if name != kimiDatasourceMCPName || enabled != 1 || !strings.Contains(transport, "Bearer "+access.Token) {
		t.Fatalf("managed MCP was not configured: name=%s enabled=%d transport=%s", name, enabled, transport)
	}
	var skillIDs, mcpIDs string
	if err := db.QueryRow(`SELECT default_skill_ids,default_mcp_ids FROM assistant_definitions WHERE assistant_id='aionui-assistant'`).Scan(&skillIDs, &mcpIDs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(skillIDs, kimiDatasourceSkillName) || strings.Contains(mcpIDs, kimiDatasourceManagedID) {
		t.Fatalf("assistant bindings missing: skills=%s mcps=%s", skillIDs, mcpIDs)
	}
	var rememberedMCPs string
	if err := db.QueryRow(`SELECT last_mcp_ids FROM assistant_preferences WHERE assistant_definition_id='builtin'`).Scan(&rememberedMCPs); err != nil {
		t.Fatal(err)
	}
	if rememberedMCPs != "[]" {
		t.Fatalf("remembered MCP selection was not cleared: %s", rememberedMCPs)
	}
	if _, err := applyKimiDatasourceAccess(context.Background(), dbPath, dataDir, nil, time.Unix(1_800_000_100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT enabled FROM mcp_servers WHERE id=?`, kimiDatasourceManagedID).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("managed MCP was not revoked: enabled=%d err=%v", enabled, err)
	}
	if err := db.QueryRow(`SELECT default_skill_ids,default_mcp_ids FROM assistant_definitions WHERE assistant_id='aionui-assistant'`).Scan(&skillIDs, &mcpIDs); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(skillIDs, kimiDatasourceManagedID) || strings.Contains(mcpIDs, kimiDatasourceManagedID) {
		t.Fatalf("revoked assistant bindings remained: skills=%s mcps=%s", skillIDs, mcpIDs)
	}
}
