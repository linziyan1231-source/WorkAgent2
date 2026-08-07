package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aionuiportal/internal/config"
	_ "modernc.org/sqlite"
)

const (
	kimiDatasourceManagedID   = "workagent2-kimi-datasource"
	kimiDatasourceMCPName     = "WorkAgent2_Professional_Database"
	kimiDatasourceSkillName   = "专业数据库"
	kimiDatasourceLegacySkill = "kimi-professional-datasource"
	kimiDatasourceSkillReadme = `---
name: 专业数据库
description: Query the professional databases authorized for this employee.
---

# 专业数据库

Use this skill when the user asks for financial, company, economic, academic, paper, or legal-regulation data that may be available from the managed professional databases.

1. Inspect the MCP tool schema. Only datasource IDs shown in its enum are authorized for this employee.
2. Call get_data_source_desc for the chosen datasource before making a data query.
3. Use only the API names and parameter shapes returned by that description.
4. Call call_data_source_tool and cite the datasource and relevant identifiers or dates in the answer.
5. Never attempt to bypass a source denial or quota error. Explain the policy error concisely and ask an administrator to change access if needed.
`
)

func applyKimiDatasourceAccess(ctx context.Context, dbPath, dataDir string, access *config.KimiDatasourceAccess, now time.Time) (bool, error) {
	info, err := os.Lstat(dbPath)
	if err != nil {
		return false, fmt.Errorf("inspect AionCore database for Kimi datasource access: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("AionCore database must be a regular non-symlink file")
	}
	skillDir := filepath.Join(dataDir, "skills", kimiDatasourceSkillName)
	skillPath := filepath.Join(skillDir, "SKILL.md")
	fileChanged := false
	legacyDir := filepath.Join(dataDir, "skills", kimiDatasourceLegacySkill)
	legacyPath := filepath.Join(legacyDir, "SKILL.md")
	if legacyContent, readErr := os.ReadFile(legacyPath); readErr == nil {
		if !strings.Contains(string(legacyContent), "name: "+kimiDatasourceLegacySkill) {
			return false, fmt.Errorf("refuse to replace unmanaged legacy skill at %s", legacyPath)
		}
		if err := os.Remove(legacyPath); err != nil {
			return false, fmt.Errorf("remove legacy managed skill file: %w", err)
		}
		if err := os.Remove(legacyDir); err != nil {
			return false, fmt.Errorf("remove legacy managed skill directory: %w", err)
		}
		fileChanged = true
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return false, fmt.Errorf("inspect legacy managed skill: %w", readErr)
	}
	if access != nil {
		if err := access.Validate(); err != nil {
			return false, err
		}
		if err := os.MkdirAll(skillDir, 0o700); err != nil {
			return false, fmt.Errorf("create Kimi datasource skill directory: %w", err)
		}
		current, readErr := os.ReadFile(skillPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return false, readErr
		}
		if string(current) != kimiDatasourceSkillReadme {
			if err := replaceFile(skillPath, []byte(kimiDatasourceSkillReadme), 0o600); err != nil {
				return false, fmt.Errorf("write Kimi datasource skill: %w", err)
			}
			fileChanged = true
		}
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return false, err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := validateKimiDatasourceSchema(ctx, tx); err != nil {
		return false, err
	}
	stamp := now.UnixMilli()
	changed := fileChanged
	if access != nil {
		transport, _ := json.Marshal(map[string]any{"url": access.Endpoint, "headers": map[string]string{"Authorization": "Bearer " + access.Token}})
		result, err := tx.ExecContext(ctx, `INSERT INTO mcp_servers
(id,name,description,enabled,transport_type,transport_config,tools,last_test_status,last_connected,original_json,builtin,created_at,updated_at,deleted_at)
VALUES(?,?,?,1,'http',?,NULL,'disconnected',NULL,NULL,0,?,?,NULL)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,enabled=1,transport_type='http',transport_config=excluded.transport_config,
tools=NULL,last_test_status='disconnected',last_connected=NULL,original_json=NULL,builtin=0,updated_at=excluded.updated_at,deleted_at=NULL`,
			kimiDatasourceManagedID, kimiDatasourceMCPName, "Managed professional databases with per-employee source and quota policy", string(transport), stamp, stamp)
		if err != nil {
			return false, fmt.Errorf("register managed Kimi datasource MCP: %w", err)
		}
		if count, _ := result.RowsAffected(); count > 0 {
			changed = true
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO skills(id,name,description,path,source,enabled,deleted_at,created_at,updated_at)
VALUES(?,?,?,?, 'user',1,NULL,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,path=excluded.path,source='user',enabled=1,deleted_at=NULL,updated_at=excluded.updated_at`,
			kimiDatasourceManagedID, kimiDatasourceSkillName, "Use the employee-authorized professional databases", skillDir, stamp, stamp); err != nil {
			return false, fmt.Errorf("register managed Kimi datasource skill: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_servers SET enabled=0,deleted_at=?,updated_at=? WHERE id=? AND deleted_at IS NULL`, stamp, stamp, kimiDatasourceManagedID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE skills SET enabled=0,deleted_at=?,updated_at=? WHERE id=? AND deleted_at IS NULL`, stamp, stamp, kimiDatasourceManagedID); err != nil {
			return false, err
		}
	}
	for _, target := range []struct {
		table   string
		id      string
		column  string
		binding string
		enabled bool
	}{
		{"assistant_definitions", "assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL", "default_skill_ids", kimiDatasourceSkillName, access != nil},
		// New conversations start with no remembered/default MCP selection.
		// The Web client adds this managed MCP when the paired skill is selected.
		{"assistant_definitions", "assistant_id='aionui-assistant' AND source='builtin' AND owner_type='system' AND deleted_at IS NULL", "default_mcp_ids", kimiDatasourceManagedID, false},
		{"conversation_assistant_snapshots", "assistant_id='aionui-assistant' AND assistant_source='builtin'", "resolved_skill_ids", kimiDatasourceSkillName, access != nil},
		{"conversation_assistant_snapshots", "assistant_id='aionui-assistant' AND assistant_source='builtin'", "resolved_mcp_ids", kimiDatasourceManagedID, access != nil},
	} {
		if err := updateJSONIDBinding(ctx, tx, target.table, target.column, target.id, target.binding, target.enabled, stamp); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assistant_preferences SET last_mcp_ids='[]',updated_at=? WHERE last_mcp_ids<>'[]'`, stamp); err != nil {
		return false, fmt.Errorf("clear remembered assistant MCP selections: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed, nil
}

func validateKimiDatasourceSchema(ctx context.Context, tx *sql.Tx) error {
	required := map[string][]string{
		"mcp_servers":                      {"id", "name", "enabled", "transport_type", "transport_config", "builtin", "created_at", "updated_at", "deleted_at"},
		"skills":                           {"id", "name", "path", "source", "enabled", "created_at", "updated_at", "deleted_at"},
		"assistant_definitions":            {"default_skill_ids", "default_mcp_ids", "updated_at"},
		"conversation_assistant_snapshots": {"resolved_skill_ids", "resolved_mcp_ids", "updated_at"},
		"assistant_preferences":            {"last_mcp_ids", "updated_at"},
	}
	for table, columns := range required {
		actual, err := tableColumns(ctx, tx, table)
		if err != nil {
			return err
		}
		for _, column := range columns {
			if !containsColumn(actual, column) {
				return fmt.Errorf("unsupported AionCore %s schema: missing %s", table, column)
			}
		}
	}
	return nil
}

func updateJSONIDBinding(ctx context.Context, tx *sql.Tx, table, column, where, binding string, enabled bool, stamp int64) error {
	query := fmt.Sprintf("SELECT rowid,%s FROM %s WHERE %s", column, table, where)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	type update struct {
		rowID int64
		value string
	}
	var updates []update
	for rows.Next() {
		var rowID int64
		var raw string
		if err := rows.Scan(&rowID, &raw); err != nil {
			rows.Close()
			return err
		}
		var ids []string
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			rows.Close()
			return fmt.Errorf("decode %s.%s JSON: %w", table, column, err)
		}
		filtered := make([]string, 0, len(ids)+1)
		for _, id := range ids {
			if id != kimiDatasourceManagedID && id != kimiDatasourceSkillName && id != kimiDatasourceLegacySkill {
				filtered = append(filtered, id)
			}
		}
		if enabled {
			filtered = append(filtered, binding)
		}
		encoded, _ := json.Marshal(filtered)
		if string(encoded) != raw {
			updates = append(updates, update{rowID: rowID, value: string(encoded)})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range updates {
		statement := fmt.Sprintf("UPDATE %s SET %s=?,updated_at=? WHERE rowid=?", table, column)
		if _, err := tx.ExecContext(ctx, statement, item.value, stamp, item.rowID); err != nil {
			return err
		}
	}
	return rows.Err()
}
