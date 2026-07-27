package winmigration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

var windowsPortalSchema = map[string][]string{
	"portal_users":       {"id", "username", "username_norm", "password_hash", "windows_sid", "windows_username", "enabled", "is_admin", "auth_version", "created_at", "updated_at", "last_login_at"},
	"portal_sessions":    {"token_hash", "user_id", "auth_version", "created_at", "expires_at", "last_seen_at", "remote_ip", "user_agent_hash"},
	"login_limits":       {"limit_key", "window_start", "failures", "blocked_until"},
	"oauth_states":       {"state_hash", "session_token_hash", "windows_sid", "instance_id", "target", "expires_at", "used_at", "flow_id"},
	"audit_events":       {"id", "occurred_at", "action", "outcome", "username", "windows_sid", "remote_ip", "details_json"},
	"chatgpt_pro_limits": {"user_id", "weekly_limit", "updated_at"},
	"chatgpt_pro_usage":  {"id", "user_id", "logical_send_id", "week_start", "requested_model", "thinking_effort", "status", "reserved_at", "finished_at", "upstream_status", "stream_completed", "served_models_json"},
	"chatgpt_pro_events": {"id", "user_id", "usage_id", "kind", "occurred_at", "acknowledged_at"},
}

func readPortalPlan(ctx context.Context, databasePath string) ([]sourceUser, PortalReport, error) {
	database, err := openWALAwareReadOnlySQLite(databasePath)
	if err != nil {
		return nil, PortalReport{}, fmt.Errorf("open Windows Portal database: %w", err)
	}
	defer database.Close()
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return nil, PortalReport{}, fmt.Errorf("validate Windows Portal database: %w", err)
	}
	var version int
	if err := database.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
		return nil, PortalReport{}, fmt.Errorf("Windows Portal schema version must be 3 (found %d)", version)
	}
	if err := validateColumns(ctx, database, windowsPortalSchema); err != nil {
		return nil, PortalReport{}, fmt.Errorf("validate Windows Portal schema: %w", err)
	}
	rows, err := database.QueryContext(ctx, `SELECT id,username,username_norm,password_hash,windows_sid,windows_username,enabled,is_admin,auth_version,created_at,updated_at,last_login_at FROM portal_users ORDER BY id`)
	if err != nil {
		return nil, PortalReport{}, err
	}
	var users []sourceUser
	for rows.Next() {
		var user sourceUser
		var last sql.NullInt64
		if err := rows.Scan(&user.ID, &user.Username, &user.UsernameNorm, &user.PasswordHash, &user.WindowsSID, &user.WindowsUsername, &user.Enabled, &user.Admin, &user.AuthVersion, &user.CreatedAt, &user.UpdatedAt, &last); err != nil {
			rows.Close()
			return nil, PortalReport{}, err
		}
		if last.Valid {
			stamp := last.Int64
			user.LastLoginAt = &stamp
		}
		if err := validateSourceUser(user); err != nil {
			rows.Close()
			return nil, PortalReport{}, fmt.Errorf("validate Portal user %d: %w", user.ID, err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, PortalReport{}, err
	}
	rows.Close()
	if len(users) == 0 {
		return nil, PortalReport{}, errors.New("Windows Portal database contains no users")
	}
	sidSet := make(map[string]bool, len(users))
	for _, user := range users {
		sidSet[user.WindowsSID] = true
	}
	auditRows, err := database.QueryContext(ctx, `SELECT id,windows_sid,details_json FROM audit_events ORDER BY id`)
	if err != nil {
		return nil, PortalReport{}, err
	}
	for auditRows.Next() {
		var id int64
		var sid sql.NullString
		var details string
		if err := auditRows.Scan(&id, &sid, &details); err != nil {
			auditRows.Close()
			return nil, PortalReport{}, err
		}
		if sid.Valid && strings.TrimSpace(sid.String) != "" && !sidSet[sid.String] {
			auditRows.Close()
			return nil, PortalReport{}, fmt.Errorf("audit event %d references an unknown Windows SID", id)
		}
		var value any
		if err := decodeJSONObject(details, &value); err != nil {
			auditRows.Close()
			return nil, PortalReport{}, fmt.Errorf("audit event %d has invalid details JSON", id)
		}
	}
	if err := auditRows.Err(); err != nil {
		auditRows.Close()
		return nil, PortalReport{}, err
	}
	auditRows.Close()
	report := PortalReport{Users: len(users)}
	for query, destination := range map[string]*int{
		`SELECT COUNT(*) FROM audit_events`:       &report.AuditEvents,
		`SELECT COUNT(*) FROM login_limits`:       &report.LoginLimits,
		`SELECT COUNT(*) FROM chatgpt_pro_limits`: &report.ProLimits,
		`SELECT COUNT(*) FROM chatgpt_pro_usage`:  &report.ProUsage,
		`SELECT COUNT(*) FROM chatgpt_pro_events`: &report.ProEvents,
		`SELECT COUNT(*) FROM portal_sessions`:    &report.InvalidatedSessions,
		`SELECT COUNT(*) FROM oauth_states`:       &report.InvalidatedOAuthStates,
	} {
		if err := database.QueryRowContext(ctx, query).Scan(destination); err != nil {
			return nil, PortalReport{}, err
		}
	}
	return users, report, nil
}

func openReadOnlySQLite(databasePath string) (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(databasePath) + "?mode=ro&immutable=1&_pragma=query_only(1)&_pragma=foreign_keys(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	return database, nil
}

// openWALAwareReadOnlySQLite is used only with the private DB/WAL/SHM working
// copy. immutable=1 must not be used here because it deliberately ignores WAL.
func openWALAwareReadOnlySQLite(databasePath string) (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(databasePath) + "?mode=ro&_pragma=query_only(1)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	return database, nil
}

func validateSourceUser(user sourceUser) error {
	if user.ID <= 0 || strings.TrimSpace(user.Username) == "" || strings.ToLower(strings.TrimSpace(user.Username)) != user.UsernameNorm || strings.TrimSpace(user.PasswordHash) == "" || !windowsSIDPattern.MatchString(user.WindowsSID) || strings.TrimSpace(user.WindowsUsername) == "" {
		return errors.New("identity fields are malformed")
	}
	if (user.Enabled != 0 && user.Enabled != 1) || (user.Admin != 0 && user.Admin != 1) || user.AuthVersion < 1 || user.CreatedAt <= 0 || user.UpdatedAt <= 0 {
		return errors.New("identity state is malformed")
	}
	return nil
}

type sqliteQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func validateSQLiteIntegrity(ctx context.Context, database sqliteQueryer) error {
	rows, err := database.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return err
	}
	quickOK := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			rows.Close()
			return err
		}
		if result != "ok" {
			rows.Close()
			return errors.New("SQLite quick_check failed")
		}
		quickOK = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if !quickOK {
		return errors.New("SQLite quick_check returned no result")
	}
	rows, err = database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("SQLite foreign_key_check failed")
	}
	return rows.Err()
}

func validateColumns(ctx context.Context, database *sql.DB, expected map[string][]string) error {
	for table, columns := range expected {
		rows, err := database.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return err
		}
		found := make(map[string]bool)
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			found[name] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, column := range columns {
			if !found[column] {
				return fmt.Errorf("table %s is missing column %s", table, column)
			}
		}
	}
	return nil
}

func decodeJSONObject(payload string, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}
