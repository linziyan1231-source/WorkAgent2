package winmigration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var aionPathSchema = map[string][]string{
	"skills":             {"path"},
	"teams":              {"workspace"},
	"assistant_sessions": {"workspace"},
	"conversations":      {"extra"},
	"cron_jobs":          {"agent_config"},
	"messages":           {"content"},
	"providers":          {"id", "api_key_encrypted"},
}

type sqlRunner interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func inspectAionDatabase(ctx context.Context, databasePath string, identity pathIdentity) (RewriteReport, error) {
	database, err := openReadOnlySQLite(databasePath)
	if err != nil {
		return RewriteReport{}, err
	}
	defer database.Close()
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return RewriteReport{}, err
	}
	if err := validateColumns(ctx, database, aionPathSchema); err != nil {
		return RewriteReport{}, err
	}
	return scanAionRewrites(ctx, database, identity, false)
}

func rewriteAionDatabase(ctx context.Context, databasePath string, identity pathIdentity) (RewriteReport, error) {
	dsn := "file:" + filepath.ToSlash(databasePath) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return RewriteReport{}, err
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	if _, err := database.ExecContext(ctx, `PRAGMA journal_mode=DELETE`); err != nil {
		return RewriteReport{}, fmt.Errorf("select durable SQLite journal mode: %w", err)
	}
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return RewriteReport{}, fmt.Errorf("pre-migration integrity check: %w", err)
	}
	if err := validateColumns(ctx, database, aionPathSchema); err != nil {
		return RewriteReport{}, err
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return RewriteReport{}, err
	}
	defer transaction.Rollback()
	report, err := scanAionRewrites(ctx, transaction, identity, true)
	if err != nil {
		return RewriteReport{}, err
	}
	if err := validateSQLiteIntegrity(ctx, transaction); err != nil {
		return RewriteReport{}, fmt.Errorf("transactional integrity check: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return RewriteReport{}, err
	}
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return RewriteReport{}, fmt.Errorf("post-migration integrity check: %w", err)
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return RewriteReport{}, err
	}
	return report, nil
}

func scanAionRewrites(ctx context.Context, runner sqlRunner, identity pathIdentity, apply bool) (RewriteReport, error) {
	var report RewriteReport
	for _, target := range []struct {
		table, column string
		counter       *int
	}{
		{"skills", "path", &report.SkillPaths},
		{"teams", "workspace", &report.TeamWorkspaces},
		{"assistant_sessions", "workspace", &report.ChannelWorkspaces},
	} {
		if err := rewriteDirectColumn(ctx, runner, target.table, target.column, identity, apply, target.counter); err != nil {
			return RewriteReport{}, err
		}
	}
	if err := rewriteJSONColumn(ctx, runner, "conversations", "extra", identity, apply, func(value map[string]any) (bool, error) {
		changed := false
		if raw, exists := value["workspace"]; exists {
			text, ok := raw.(string)
			if !ok && raw != nil {
				return false, errors.New("conversations.extra.workspace is not a string")
			}
			if ok {
				rewritten, oneChanged, err := rewriteWindowsTenantPath(text, identity)
				if errors.Is(err, errExternalWindowsPath) {
					report.UnmappedExternalWindowsPaths++
				} else if err != nil {
					return false, err
				} else if oneChanged {
					value["workspace"] = rewritten
					report.ConversationWorkspaces++
					changed = true
				}
			}
		}
		if raw, exists := value["default_files"]; exists {
			files, ok := raw.([]any)
			if !ok && raw != nil {
				return false, errors.New("conversations.extra.default_files is not an array")
			}
			for index, item := range files {
				text, ok := item.(string)
				if !ok {
					continue
				}
				rewritten, oneChanged, err := rewriteWindowsTenantPath(text, identity)
				if errors.Is(err, errExternalWindowsPath) {
					report.UnmappedExternalWindowsPaths++
					continue
				}
				if err != nil {
					return false, err
				}
				if oneChanged {
					files[index] = rewritten
					report.ConversationDefaultFiles++
					changed = true
				}
			}
		}
		return changed, nil
	}); err != nil {
		return RewriteReport{}, err
	}
	if err := rewriteJSONColumn(ctx, runner, "cron_jobs", "agent_config", identity, apply, func(value map[string]any) (bool, error) {
		raw, exists := value["workspace"]
		if !exists || raw == nil {
			return false, nil
		}
		text, ok := raw.(string)
		if !ok {
			return false, errors.New("cron_jobs.agent_config.workspace is not a string")
		}
		rewritten, changed, err := rewriteWindowsTenantPath(text, identity)
		if err == nil && changed {
			value["workspace"] = rewritten
			report.CronWorkspaces++
		}
		return changed, err
	}); err != nil {
		return RewriteReport{}, err
	}
	rows, err := runner.QueryContext(ctx, `SELECT rowid FROM providers WHERE id IN (?,?)`, "managed-cliproxy-chatgpt", "managed-cliproxy-kimi")
	if err != nil {
		return RewriteReport{}, err
	}
	var providerRows []int64
	for rows.Next() {
		var rowID int64
		if err := rows.Scan(&rowID); err != nil {
			rows.Close()
			return RewriteReport{}, err
		}
		providerRows = append(providerRows, rowID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return RewriteReport{}, err
	}
	rows.Close()
	report.InvalidatedManagedProviders = len(providerRows)
	if apply {
		for _, rowID := range providerRows {
			if _, err := runner.ExecContext(ctx, `DELETE FROM providers WHERE rowid=?`, rowID); err != nil {
				return RewriteReport{}, err
			}
		}
	}
	return report, nil
}

func rewriteDirectColumn(ctx context.Context, runner sqlRunner, table, column string, identity pathIdentity, apply bool, counter *int) error {
	query := fmt.Sprintf(`SELECT rowid,%s FROM %s WHERE %s IS NOT NULL AND %s != '' ORDER BY rowid`, column, table, column, column)
	rows, err := runner.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	type update struct {
		rowID int64
		value string
	}
	var updates []update
	for rows.Next() {
		var item update
		if err := rows.Scan(&item.rowID, &item.value); err != nil {
			rows.Close()
			return err
		}
		rewritten, changed, err := rewriteWindowsTenantPath(item.value, identity)
		if err != nil {
			rows.Close()
			return fmt.Errorf("%s.%s row %d: %w", table, column, item.rowID, err)
		}
		if changed {
			item.value = rewritten
			updates = append(updates, item)
			*counter++
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if apply {
		statement := fmt.Sprintf(`UPDATE %s SET %s=? WHERE rowid=?`, table, column)
		for _, item := range updates {
			if _, err := runner.ExecContext(ctx, statement, item.value, item.rowID); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteJSONColumn(ctx context.Context, runner sqlRunner, table, column string, _ pathIdentity, apply bool, rewrite func(map[string]any) (bool, error)) error {
	query := fmt.Sprintf(`SELECT rowid,%s FROM %s WHERE %s IS NOT NULL AND TRIM(%s) != '' ORDER BY rowid`, column, table, column, column)
	rows, err := runner.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	type update struct {
		rowID   int64
		payload []byte
	}
	var updates []update
	for rows.Next() {
		var rowID int64
		var payload string
		if err := rows.Scan(&rowID, &payload); err != nil {
			rows.Close()
			return err
		}
		var value map[string]any
		if err := decodeJSONObject(payload, &value); err != nil || value == nil {
			rows.Close()
			return fmt.Errorf("%s.%s row %d contains invalid JSON", table, column, rowID)
		}
		changed, err := rewrite(value)
		if err != nil {
			rows.Close()
			return fmt.Errorf("%s.%s row %d: %w", table, column, rowID, err)
		}
		if changed {
			encoded, err := json.Marshal(value)
			if err != nil {
				rows.Close()
				return err
			}
			updates = append(updates, update{rowID, encoded})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if apply {
		statement := fmt.Sprintf(`UPDATE %s SET %s=? WHERE rowid=?`, table, column)
		for _, item := range updates {
			if _, err := runner.ExecContext(ctx, statement, string(item.payload), item.rowID); err != nil {
				return err
			}
		}
	}
	return nil
}
