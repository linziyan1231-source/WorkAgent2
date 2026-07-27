package winmigration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

func migratePortalDatabase(ctx context.Context, plan *migrationPlan, destinationDirectory string) error {
	databasePath := filepath.Join(destinationDirectory, "portal.db")
	auditPath := filepath.Join(destinationDirectory, "audit.jsonl")
	portalStore, err := store.Open(databasePath, auditPath)
	if err != nil {
		return fmt.Errorf("initialize Linux Portal schema: %w", err)
	}
	if err := portalStore.Close(); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(destinationDirectory, ".runtime.lock"))
	dsn := "file:" + filepath.ToSlash(databasePath) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	if _, err := database.ExecContext(ctx, `PRAGMA journal_mode=DELETE`); err != nil {
		return err
	}
	// plan.portalPath is a private working copy of the complete frozen
	// DB/WAL/SHM set. Leaving immutable disabled is required for SQLite to replay
	// committed rows that have not yet been checkpointed into the main file.
	sourceURI := "file:" + filepath.ToSlash(plan.portalPath) + "?mode=ro"
	if _, err := database.ExecContext(ctx, `ATTACH DATABASE ? AS win`, sourceURI); err != nil {
		return fmt.Errorf("attach read-only Windows Portal snapshot: %w", err)
	}
	attached := true
	defer func() {
		if attached {
			_, _ = database.Exec(`DETACH DATABASE win`)
		}
	}()
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `CREATE TEMP TABLE sid_map (
windows_sid TEXT PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE, runtime_user TEXT NOT NULL UNIQUE, data_root TEXT NOT NULL UNIQUE
)`); err != nil {
		return err
	}
	for _, tenant := range plan.tenants {
		if _, err := transaction.ExecContext(ctx, `INSERT INTO sid_map(windows_sid,tenant_id,runtime_user,data_root) VALUES(?,?,?,?)`, tenant.user.WindowsSID, tenant.report.TenantID, tenant.report.RuntimeUser, tenant.report.DataRoot); err != nil {
			return err
		}
	}
	result, err := transaction.ExecContext(ctx, `INSERT INTO portal_users
(id,username,username_norm,password_hash,tenant_id,runtime_user,data_root,enabled,is_admin,auth_version,created_at,updated_at,last_login_at)
SELECT u.id,u.username,u.username_norm,u.password_hash,m.tenant_id,m.runtime_user,m.data_root,u.enabled,u.is_admin,u.auth_version,u.created_at,u.updated_at,u.last_login_at
FROM win.portal_users u JOIN sid_map m ON m.windows_sid=u.windows_sid ORDER BY u.id`)
	if err != nil {
		return fmt.Errorf("migrate Portal identities: %w", err)
	}
	if err := requireAffected(result, int64(plan.report.Portal.Users), "Portal identities"); err != nil {
		return err
	}
	for _, item := range []struct {
		label, statement string
		expected         int
	}{
		{"login limits", `INSERT INTO login_limits(limit_key,window_start,failures,blocked_until) SELECT limit_key,window_start,failures,blocked_until FROM win.login_limits`, plan.report.Portal.LoginLimits},
		{"audit events", `INSERT INTO audit_events(id,occurred_at,action,outcome,username,tenant_id,remote_ip,details_json)
SELECT a.id,a.occurred_at,a.action,a.outcome,a.username,m.tenant_id,a.remote_ip,a.details_json FROM win.audit_events a LEFT JOIN sid_map m ON m.windows_sid=a.windows_sid ORDER BY a.id`, plan.report.Portal.AuditEvents},
		{"ChatGPT Pro limits", `INSERT INTO chatgpt_pro_limits(user_id,weekly_limit,updated_at) SELECT user_id,weekly_limit,updated_at FROM win.chatgpt_pro_limits`, plan.report.Portal.ProLimits},
		{"ChatGPT Pro usage", `INSERT INTO chatgpt_pro_usage(id,user_id,logical_send_id,week_start,requested_model,thinking_effort,status,reserved_at,finished_at,upstream_status,stream_completed,served_models_json)
SELECT id,user_id,logical_send_id,week_start,requested_model,thinking_effort,status,reserved_at,finished_at,upstream_status,stream_completed,served_models_json FROM win.chatgpt_pro_usage ORDER BY id`, plan.report.Portal.ProUsage},
		{"ChatGPT Pro events", `INSERT INTO chatgpt_pro_events(id,user_id,usage_id,kind,occurred_at,acknowledged_at)
SELECT id,user_id,usage_id,kind,occurred_at,acknowledged_at FROM win.chatgpt_pro_events ORDER BY id`, plan.report.Portal.ProEvents},
	} {
		result, err := transaction.ExecContext(ctx, item.statement)
		if err != nil {
			return fmt.Errorf("migrate %s: %w", item.label, err)
		}
		if err := requireAffected(result, int64(item.expected), item.label); err != nil {
			return err
		}
	}
	if err := validateSQLiteIntegrity(ctx, transaction); err != nil {
		return fmt.Errorf("validate migrated Portal transaction: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, `DETACH DATABASE win`); err != nil {
		return err
	}
	attached = false
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return fmt.Errorf("validate migrated Portal database: %w", err)
	}
	if err := rebuildAuditJSONL(ctx, database, auditPath); err != nil {
		return err
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return err
	}
	return verifyStagedPortal(ctx, databasePath, plan.report.Portal)
}

func requireAffected(result sql.Result, expected int64, label string) error {
	affected, err := result.RowsAffected()
	if err != nil || affected != expected {
		return fmt.Errorf("migrated %s row count does not match the plan", label)
	}
	return nil
}

func rebuildAuditJSONL(ctx context.Context, database *sql.DB, auditPath string) error {
	rows, err := database.QueryContext(ctx, `SELECT occurred_at,action,outcome,username,tenant_id,remote_ip,details_json FROM audit_events ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	parent := filepath.Dir(auditPath)
	temporary, err := os.CreateTemp(parent, ".audit-migration-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	for rows.Next() {
		var occurred int64
		var action, outcome, detailsJSON string
		var username, tenantID, remoteIP sql.NullString
		if err := rows.Scan(&occurred, &action, &outcome, &username, &tenantID, &remoteIP, &detailsJSON); err != nil {
			temporary.Close()
			return err
		}
		var details map[string]any
		if err := decodeJSONObject(detailsJSON, &details); err != nil {
			temporary.Close()
			return errors.New("migrated audit details are invalid")
		}
		event := store.AuditEvent{OccurredAt: time.Unix(occurred, 0).UTC(), Action: action, Outcome: outcome, Details: details}
		if username.Valid {
			event.Username = username.String
		}
		if tenantID.Valid {
			event.TenantID = tenantID.String
		}
		if remoteIP.Valid {
			event.RemoteIP = remoteIP.String
		}
		if err := encoder.Encode(event); err != nil {
			temporary.Close()
			return err
		}
	}
	if err := rows.Err(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, auditPath); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func verifyStagedPortal(ctx context.Context, databasePath string, expected PortalReport) error {
	database, err := openReadOnlySQLite(databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := validateSQLiteIntegrity(ctx, database); err != nil {
		return err
	}
	var version int
	if err := database.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != 4 {
		return errors.New("staged Portal database is not schema v4")
	}
	for _, item := range []struct {
		label, query string
		wanted       int
	}{
		{"users", `SELECT COUNT(*) FROM portal_users`, expected.Users},
		{"audit events", `SELECT COUNT(*) FROM audit_events`, expected.AuditEvents},
		{"login limits", `SELECT COUNT(*) FROM login_limits`, expected.LoginLimits},
		{"Pro limits", `SELECT COUNT(*) FROM chatgpt_pro_limits`, expected.ProLimits},
		{"Pro usage", `SELECT COUNT(*) FROM chatgpt_pro_usage`, expected.ProUsage},
		{"Pro events", `SELECT COUNT(*) FROM chatgpt_pro_events`, expected.ProEvents},
		{"sessions", `SELECT COUNT(*) FROM portal_sessions`, 0},
		{"OAuth states", `SELECT COUNT(*) FROM oauth_states`, 0},
	} {
		var count int
		if err := database.QueryRowContext(ctx, item.query).Scan(&count); err != nil || count != item.wanted {
			return fmt.Errorf("staged Portal %s count is invalid", item.label)
		}
	}
	return nil
}
