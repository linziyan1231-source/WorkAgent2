package userhost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// repairLegacyDataRootPaths rebases only product-owned path fields from the
// former profile-local root to the configured SID-private root. It is
// intentionally idempotent and runs on every startup so restored databases
// cannot silently reintroduce C: paths after a data-root migration.
func repairLegacyDataRootPaths(ctx context.Context, dbPath, legacyRoot, targetRoot string) (int64, error) {
	legacyRoot = filepath.Clean(legacyRoot)
	targetRoot = filepath.Clean(targetRoot)
	if strings.EqualFold(legacyRoot, targetRoot) {
		return 0, nil
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return 0, fmt.Errorf("inspect AionCore database for data-root repair: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("AionCore database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=locking_mode(EXCLUSIVE)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, fmt.Errorf("open AionCore database for data-root repair: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, fmt.Errorf("begin data-root repair transaction: %w", err)
	}
	defer tx.Rollback()

	// These are the product-owned text fields that can persist absolute paths.
	targets := map[string][]string{
		"conversations":  {"name", "extra"},
		"messages":       {"content"},
		"agent_metadata": {"auth_methods"},
		"teams":          {"workspace"},
		"skills":         {"path"},
	}
	var changed int64
	for table, candidates := range targets {
		columns, err := tableColumns(ctx, tx, table)
		if err != nil {
			return 0, err
		}
		for _, column := range candidates {
			if !containsColumn(columns, column) {
				continue
			}
			// SQLite JSON text contains doubled backslashes. Repair both its
			// serialized representation and ordinary path strings.
			for _, pair := range [][2]string{
				{strings.ReplaceAll(legacyRoot, `\`, `\\`), strings.ReplaceAll(targetRoot, `\`, `\\`)},
				{legacyRoot, targetRoot},
			} {
				result, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE "%s" SET "%s"=replace("%s", ?, ?) WHERE instr("%s", ?) > 0`, table, column, column, column), pair[0], pair[1], pair[0])
				if err != nil {
					return 0, fmt.Errorf("repair %s.%s data-root paths: %w", table, column, err)
				}
				rows, err := result.RowsAffected()
				if err != nil {
					return 0, err
				}
				changed += rows
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit data-root repair: %w", err)
	}
	return changed, nil
}
