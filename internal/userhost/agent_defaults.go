package userhost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

const (
	agentDefaultsMarkerName            = "agent-defaults-v3.applied"
	agentDefaultsMarkerContent         = "builtin-enabled=aion,codex,kimi;default-yolo=aion\n"
	previousAgentDefaultsMarkerName    = "agent-defaults-v2.applied"
	previousAgentDefaultsMarkerContent = "builtin-enabled=aion,codex,kimi\n"
	legacyAgentDefaultsMarkerName      = "agent-defaults-v1.applied"
	legacyAgentDefaultsMarkerContent   = "builtin-enabled=codex,kimi\n"
)

func applyInitialAgentDefaults(ctx context.Context, dbPath, markerPath string, now time.Time) (bool, error) {
	applied, err := agentDefaultsAlreadyApplied(markerPath)
	if err != nil {
		return false, err
	}
	if applied {
		return false, nil
	}
	legacyApplied, err := markerHasContent(filepath.Join(filepath.Dir(markerPath), legacyAgentDefaultsMarkerName), legacyAgentDefaultsMarkerContent)
	if err != nil {
		return false, err
	}
	previousApplied, err := markerHasContent(filepath.Join(filepath.Dir(markerPath), previousAgentDefaultsMarkerName), previousAgentDefaultsMarkerContent)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return false, fmt.Errorf("inspect AionCore database for agent defaults: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("AionCore database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(0)&_pragma=foreign_keys(1)&_pragma=locking_mode(EXCLUSIVE)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return false, fmt.Errorf("open AionCore database for agent defaults: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin agent defaults transaction: %w", err)
	}
	defer tx.Rollback()
	columns, err := tableColumns(ctx, tx, "agent_metadata")
	if err != nil {
		return false, err
	}
	for _, required := range []string{"id", "backend", "agent_source", "enabled", "updated_at"} {
		if !containsColumn(columns, required) {
			return false, fmt.Errorf("unsupported AionCore agent_metadata schema: missing %s", required)
		}
	}
	var managedCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_metadata WHERE agent_source IN ('builtin','internal')`).Scan(&managedCount); err != nil {
		return false, fmt.Errorf("count managed AionUi agents: %w", err)
	}
	if managedCount < 2 {
		return false, fmt.Errorf("expected managed AionUi agents, found %d", managedCount)
	}
	targets, err := managedAgentTargets(ctx, tx, `backend IN ('codex','kimi') OR agent_type='aionrs'`)
	if err != nil {
		return false, err
	}
	if len(targets) != 3 || targets[0] != "aion" || targets[1] != "codex" || targets[2] != "kimi" {
		return false, fmt.Errorf("expected exactly one managed Aion, Codex, and Kimi agent, found %v", targets)
	}
	query := `UPDATE agent_metadata
SET enabled=CASE WHEN backend IN ('codex','kimi') OR agent_type='aionrs' THEN 1 ELSE 0 END,updated_at=?
WHERE agent_source IN ('builtin','internal')
  AND enabled<>CASE WHEN backend IN ('codex','kimi') OR agent_type='aionrs' THEN 1 ELSE 0 END`
	if previousApplied {
		query = `UPDATE agent_metadata SET updated_at=updated_at WHERE 0`
	} else if legacyApplied {
		query = `UPDATE agent_metadata SET enabled=1,updated_at=?
WHERE agent_source='internal' AND agent_type='aionrs' AND enabled=0`
	}
	if _, err := tx.ExecContext(ctx, query, now.UnixMilli()); err != nil {
		return false, fmt.Errorf("set initial AionUi agent defaults: %w", err)
	}
	if !previousApplied {
		enabled, err := managedAgentTargets(ctx, tx, `enabled<>0 AND (backend IN ('codex','kimi') OR agent_type='aionrs')`)
		if err != nil {
			return false, err
		}
		if len(enabled) != 3 || enabled[0] != "aion" || enabled[1] != "codex" || enabled[2] != "kimi" {
			return false, fmt.Errorf("verify initial AionUi agent defaults: enabled=%v", enabled)
		}
	}
	assistantColumns, err := tableColumns(ctx, tx, "assistant_definitions")
	if err != nil {
		return false, err
	}
	for _, required := range []string{"id", "assistant_id", "source", "source_ref", "agent_id", "default_permission_mode", "default_permission_value", "updated_at", "deleted_at"} {
		if !containsColumn(assistantColumns, required) {
			return false, fmt.Errorf("unsupported AionCore assistant_definitions schema: missing %s", required)
		}
	}
	if !legacyApplied && !previousApplied {
		if err := applyInitialAssistantVisibilityDefaults(ctx, tx, now); err != nil {
			return false, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE assistant_definitions
SET default_permission_mode='fixed',default_permission_value='yolo',updated_at=?
WHERE source='generated' AND deleted_at IS NULL
  AND source_ref=agent_id
  AND agent_id IN (
    SELECT id FROM agent_metadata
    WHERE agent_source='internal' AND agent_type='aionrs'
  )
  AND (default_permission_mode<>'fixed' OR default_permission_value<>'yolo')`, now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("set Aion CLI YOLO default: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed < 0 || changed > 1 {
		return false, fmt.Errorf("unexpected Aion CLI YOLO update count: %d (%v)", changed, err)
	}
	var yoloCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions
WHERE source='generated' AND deleted_at IS NULL AND source_ref=agent_id
  AND agent_id IN (
    SELECT id FROM agent_metadata
    WHERE agent_source='internal' AND agent_type='aionrs'
  )
	  AND default_permission_mode='fixed' AND default_permission_value='yolo'`).Scan(&yoloCount); err != nil {
		return false, fmt.Errorf("verify Aion CLI YOLO default: %w", err)
	}
	if yoloCount != 1 {
		return false, fmt.Errorf("expected exactly one Aion CLI YOLO default, found %d", yoloCount)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit initial AionUi agent defaults: %w", err)
	}
	if err := writeAgentDefaultsMarker(markerPath); err != nil {
		return false, err
	}
	return true, nil
}

func applyInitialAssistantVisibilityDefaults(ctx context.Context, tx *sql.Tx, now time.Time) error {
	for table, required := range map[string][]string{
		"assistant_overlays":  {"assistant_definition_id", "enabled", "updated_at"},
		"assistant_overrides": {"assistant_id", "enabled", "updated_at"},
	} {
		columns, err := tableColumns(ctx, tx, table)
		if err != nil {
			return err
		}
		for _, column := range required {
			if !containsColumn(columns, column) {
				return fmt.Errorf("unsupported AionCore %s schema: missing %s", table, column)
			}
		}
	}

	stamp := now.UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE assistant_overlays
SET enabled=CASE WHEN assistant_definition_id IN (
    SELECT ad.id
    FROM assistant_definitions ad
    JOIN agent_metadata am ON am.id=ad.source_ref
    WHERE ad.source='generated' AND ad.deleted_at IS NULL
      AND am.agent_source IN ('builtin','internal')
      AND am.backend IN ('codex','kimi')
) THEN 1 ELSE 0 END,
updated_at=?
WHERE assistant_definition_id IN (
    SELECT id FROM assistant_definitions WHERE source='generated' AND deleted_at IS NULL
)`, stamp); err != nil {
		return fmt.Errorf("set initial generated assistant visibility: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assistant_overlays
SET enabled=CASE WHEN assistant_definition_id IN (
    SELECT id FROM assistant_definitions
    WHERE source='builtin' AND deleted_at IS NULL AND source_ref='aionui-assistant'
) THEN 1 ELSE 0 END,
updated_at=?
WHERE assistant_definition_id IN (
    SELECT id FROM assistant_definitions WHERE source='builtin' AND deleted_at IS NULL
)`, stamp); err != nil {
		return fmt.Errorf("set initial builtin assistant visibility: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assistant_overrides
SET enabled=CASE WHEN assistant_id='aionui-assistant' THEN 1 ELSE 0 END,
updated_at=?
WHERE assistant_id IN (
    SELECT assistant_id FROM assistant_definitions WHERE source='builtin' AND deleted_at IS NULL
)`, stamp); err != nil {
		return fmt.Errorf("set initial legacy builtin assistant visibility: %w", err)
	}

	var workagentCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions
WHERE source='builtin' AND deleted_at IS NULL AND source_ref='aionui-assistant'`).Scan(&workagentCount); err != nil {
		return fmt.Errorf("verify WorkAgent assistant definition: %w", err)
	}
	if workagentCount != 1 {
		return fmt.Errorf("expected exactly one WorkAgent assistant definition, found %d", workagentCount)
	}
	var missingGeneratedOverlays int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
FROM assistant_definitions ad
LEFT JOIN assistant_overlays ao ON ao.assistant_definition_id=ad.id
WHERE ad.source='generated' AND ad.deleted_at IS NULL
  AND ao.assistant_definition_id IS NULL`).Scan(&missingGeneratedOverlays); err != nil {
		return fmt.Errorf("verify generated assistant overlays: %w", err)
	}
	if missingGeneratedOverlays != 0 {
		return fmt.Errorf("expected overlays for every generated assistant, missing %d", missingGeneratedOverlays)
	}
	enabledGenerated, err := enabledGeneratedAssistantTargets(ctx, tx)
	if err != nil {
		return err
	}
	if len(enabledGenerated) != 2 || enabledGenerated[0] != "codex" || enabledGenerated[1] != "kimi" {
		return fmt.Errorf("expected only generated Codex and Kimi assistants enabled, found %v", enabledGenerated)
	}
	var mismatchedBuiltinOverlays int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
FROM assistant_overlays ao
JOIN assistant_definitions ad ON ad.id=ao.assistant_definition_id
WHERE ad.source='builtin' AND ad.deleted_at IS NULL
  AND ao.enabled<>CASE WHEN ad.source_ref='aionui-assistant' THEN 1 ELSE 0 END`).Scan(&mismatchedBuiltinOverlays); err != nil {
		return fmt.Errorf("verify builtin assistant overlays: %w", err)
	}
	if mismatchedBuiltinOverlays != 0 {
		return fmt.Errorf("builtin assistant overlay verification failed for %d rows", mismatchedBuiltinOverlays)
	}
	var mismatchedLegacyOverrides int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
FROM assistant_overrides ao
JOIN assistant_definitions ad ON ad.assistant_id=ao.assistant_id
WHERE ad.source='builtin' AND ad.deleted_at IS NULL
  AND ao.enabled<>CASE WHEN ad.source_ref='aionui-assistant' THEN 1 ELSE 0 END`).Scan(&mismatchedLegacyOverrides); err != nil {
		return fmt.Errorf("verify legacy builtin assistant visibility: %w", err)
	}
	if mismatchedLegacyOverrides != 0 {
		return fmt.Errorf("legacy builtin assistant visibility verification failed for %d rows", mismatchedLegacyOverrides)
	}
	return nil
}

func enabledGeneratedAssistantTargets(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT COALESCE(am.backend,'')
FROM assistant_overlays ao
JOIN assistant_definitions ad ON ad.id=ao.assistant_definition_id
JOIN agent_metadata am ON am.id=ad.source_ref
WHERE ad.source='generated' AND ad.deleted_at IS NULL AND ao.enabled<>0`)
	if err != nil {
		return nil, fmt.Errorf("read enabled generated assistants: %w", err)
	}
	defer rows.Close()
	var backends []string
	for rows.Next() {
		var backend string
		if err := rows.Scan(&backend); err != nil {
			return nil, err
		}
		backends = append(backends, backend)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(backends)
	return backends, nil
}

func managedAgentTargets(ctx context.Context, tx *sql.Tx, predicate string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN agent_type='aionrs' THEN 'aion' ELSE backend END
FROM agent_metadata WHERE agent_source IN ('builtin','internal') AND (`+predicate+`)`)
	if err != nil {
		return nil, fmt.Errorf("read managed AionUi agents: %w", err)
	}
	defer rows.Close()
	var backends []string
	for rows.Next() {
		var backend sql.NullString
		if err := rows.Scan(&backend); err != nil {
			return nil, err
		}
		if !backend.Valid {
			backends = append(backends, "<none>")
		} else {
			backends = append(backends, backend.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(backends)
	return backends, nil
}

func containsColumn(columns []string, required string) bool {
	for _, column := range columns {
		if column == required {
			return true
		}
	}
	return false
}

func agentDefaultsAlreadyApplied(path string) (bool, error) {
	return markerHasContent(path, agentDefaultsMarkerContent)
}

func markerHasContent(path, expected string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect AionUi agent defaults marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("AionUi agent defaults marker must be a regular non-symlink file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read AionUi agent defaults marker: %w", err)
	}
	if string(content) != expected {
		return false, errors.New("AionUi agent defaults marker has unexpected content")
	}
	return true, nil
}

func writeAgentDefaultsMarker(path string) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".agent-defaults-v3.tmp-*")
	if err != nil {
		return fmt.Errorf("create AionUi agent defaults marker: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect AionUi agent defaults marker: %w", err)
	}
	if _, err := temporary.WriteString(agentDefaultsMarkerContent); err != nil {
		temporary.Close()
		return fmt.Errorf("write AionUi agent defaults marker: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("flush AionUi agent defaults marker: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close AionUi agent defaults marker: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish AionUi agent defaults marker: %w", err)
	}
	return nil
}
