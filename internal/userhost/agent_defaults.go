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
	agentDefaultsMarkerName          = "agent-defaults-v2.applied"
	agentDefaultsMarkerContent       = "builtin-enabled=aion,codex,kimi\n"
	legacyAgentDefaultsMarkerName    = "agent-defaults-v1.applied"
	legacyAgentDefaultsMarkerContent = "builtin-enabled=codex,kimi\n"
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
	if legacyApplied {
		query = `UPDATE agent_metadata SET enabled=1,updated_at=?
WHERE agent_source='internal' AND agent_type='aionrs' AND enabled=0`
	}
	if _, err := tx.ExecContext(ctx, query, now.UnixMilli()); err != nil {
		return false, fmt.Errorf("set initial AionUi agent defaults: %w", err)
	}
	enabled, err := managedAgentTargets(ctx, tx, `enabled<>0 AND (backend IN ('codex','kimi') OR agent_type='aionrs')`)
	if err != nil {
		return false, err
	}
	if len(enabled) != 3 || enabled[0] != "aion" || enabled[1] != "codex" || enabled[2] != "kimi" {
		return false, fmt.Errorf("verify initial AionUi agent defaults: enabled=%v", enabled)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit initial AionUi agent defaults: %w", err)
	}
	if err := writeAgentDefaultsMarker(markerPath); err != nil {
		return false, err
	}
	return true, nil
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
	temporary, err := os.CreateTemp(filepath.Dir(path), ".agent-defaults-v1.tmp-*")
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
