package userhost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aionuiportal/internal/modelbootstrap"

	_ "modernc.org/sqlite"
)

const (
	codexAssistantDefaultsMarkerName = "codex-assistant-defaults-v1.applied"
	codexAssistantDefaultsMarkerContent = "model=" + modelbootstrap.DefaultCodexModel +
		"\nreasoning=" + modelbootstrap.DefaultCodexReasoningEffort +
		"\npermission=agent-full-access\n"
)

func applyCodexAssistantDefaults(ctx context.Context, dbPath, markerPath string, now time.Time) (bool, error) {
	applied, err := markerHasContent(markerPath, codexAssistantDefaultsMarkerContent)
	if err != nil || applied {
		return false, err
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return false, fmt.Errorf("inspect AionCore database for Codex defaults: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("AionCore database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(0)&_pragma=foreign_keys(1)&_pragma=locking_mode(EXCLUSIVE)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return false, fmt.Errorf("open AionCore database for Codex defaults: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin Codex defaults transaction: %w", err)
	}
	defer tx.Rollback()

	for table, required := range map[string][]string{
		"agent_metadata": {"id", "backend", "agent_source"},
		"assistant_definitions": {"id", "source", "source_ref", "agent_id", "default_model_mode", "default_model_value", "default_permission_mode", "default_permission_value", "updated_at", "deleted_at"},
	} {
		columns, err := tableColumns(ctx, tx, table)
		if err != nil {
			return false, err
		}
		for _, column := range required {
			if !containsColumn(columns, column) {
				return false, fmt.Errorf("unsupported AionCore %s schema: missing %s", table, column)
			}
		}
	}

	const targetPredicate = `d.source='generated' AND d.deleted_at IS NULL AND d.source_ref=d.agent_id
  AND a.agent_source='builtin' AND a.backend='codex'`
	var targetCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions d
JOIN agent_metadata a ON a.id=d.agent_id WHERE `+targetPredicate).Scan(&targetCount); err != nil {
		return false, fmt.Errorf("count managed Codex assistant: %w", err)
	}
	if targetCount != 1 {
		return false, fmt.Errorf("expected exactly one managed Codex assistant, found %d", targetCount)
	}
	result, err := tx.ExecContext(ctx, `UPDATE assistant_definitions
SET default_model_mode='fixed',default_model_value=?,
    default_permission_mode='fixed',default_permission_value='agent-full-access',updated_at=?
WHERE source='generated' AND deleted_at IS NULL AND source_ref=agent_id
  AND agent_id IN (SELECT id FROM agent_metadata WHERE agent_source='builtin' AND backend='codex')`, modelbootstrap.DefaultCodexModel, now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("set managed Codex assistant defaults: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed < 0 || changed > 1 {
		return false, fmt.Errorf("unexpected managed Codex defaults update count: %d (%v)", changed, err)
	}
	var verified int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assistant_definitions d
JOIN agent_metadata a ON a.id=d.agent_id WHERE `+targetPredicate+`
  AND d.default_model_mode='fixed' AND d.default_model_value=?
  AND d.default_permission_mode='fixed' AND d.default_permission_value='agent-full-access'`, modelbootstrap.DefaultCodexModel).Scan(&verified); err != nil {
		return false, fmt.Errorf("verify managed Codex assistant defaults: %w", err)
	}
	if verified != 1 {
		return false, errors.New("managed Codex assistant defaults were not applied exactly once")
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit managed Codex assistant defaults: %w", err)
	}
	if err := writePrivateFileAtomic(markerPath, []byte(codexAssistantDefaultsMarkerContent)); err != nil {
		return false, fmt.Errorf("write managed Codex assistant defaults marker: %w", err)
	}
	return true, nil
}
