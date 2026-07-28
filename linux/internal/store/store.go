package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"

	_ "modernc.org/sqlite"
)

const schemaVersion = 4

var ErrNotFound = errors.New("not found")

type Store struct {
	db        *sql.DB
	auditPath string
	auditMu   sync.Mutex
	runtime   *servicelock.Lock
}

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	UsernameNorm string     `json:"-"`
	PasswordHash string     `json:"-"`
	TenantID     string     `json:"tenant_id"`
	RuntimeUser  string     `json:"runtime_user"`
	DataRoot     string     `json:"data_root"`
	Enabled      bool       `json:"enabled"`
	Admin        bool       `json:"admin"`
	AuthVersion  int64      `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

type Session struct {
	TokenHash     []byte
	CSRFHash      []byte
	UserID        int64
	AuthVersion   int64
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastSeenAt    time.Time
	RemoteIP      string
	UserAgentHash string
	User          User
}

type RatePolicy struct {
	Window          time.Duration
	Block           time.Duration
	AccountFailures int
	IPFailures      int
}

type AuditEvent struct {
	OccurredAt time.Time      `json:"occurred_at"`
	Action     string         `json:"action"`
	Outcome    string         `json:"outcome"`
	Username   string         `json:"username,omitempty"`
	TenantID   string         `json:"tenant_id,omitempty"`
	RemoteIP   string         `json:"remote_ip,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type OAuthBinding struct {
	SessionTokenHash []byte
	TenantID         string
	RuntimeStartedAt string
	FlowID           string
	Target           string
	ExpiresAt        time.Time
}

func Open(path, auditPath string) (*Store, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(auditPath) {
		return nil, errors.New("database and audit paths must be absolute")
	}
	if filepath.Clean(path) != path || filepath.Clean(auditPath) != auditPath {
		return nil, errors.New("database and audit paths must be clean")
	}
	for _, directory := range []string{filepath.Dir(path), filepath.Dir(auditPath)} {
		if err := secureDirectory(directory); err != nil {
			return nil, err
		}
	}
	for _, candidate := range []string{path, auditPath} {
		if info, err := os.Lstat(candidate); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
			return nil, fmt.Errorf("state path is not a regular file: %s", candidate)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	stateInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	stateStat, ok := stateInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("Portal state ownership is unavailable")
	}
	runtimeLock, err := servicelock.AcquireShared(filepath.Join(filepath.Dir(path), ".runtime.lock"), stateStat.Uid)
	if err != nil {
		return nil, fmt.Errorf("acquire Portal runtime lock: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		runtimeLock.Close()
		return nil, fmt.Errorf("open Portal database: %w", err)
	}
	database.SetMaxOpenConns(1)
	value := &Store{db: database, auditPath: auditPath, runtime: runtimeLock}
	if err := value.initialize(context.Background()); err != nil {
		database.Close()
		runtimeLock.Close()
		return nil, err
	}
	if err := assignPortalSQLiteFileSetToStateOwner(path, auditPath, stateStat.Uid, stateStat.Gid); err != nil {
		database.Close()
		runtimeLock.Close()
		return nil, err
	}
	if err := protectPortalSQLiteFileSet(path, stateStat.Uid, stateStat.Gid); err != nil {
		database.Close()
		runtimeLock.Close()
		return nil, err
	}
	if err := value.CheckAuditSink(); err != nil {
		database.Close()
		runtimeLock.Close()
		return nil, err
	}
	return value, nil
}

func secureDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("state directory is unsafe: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}
	return nil
}

func (s *Store) initialize(ctx context.Context) error {
	var current int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if current != 0 && current != 2 && current != 3 && current != schemaVersion {
		return fmt.Errorf("database schema version %d is not supported; expected fresh v%d or an upgrade from v2/v3", current, schemaVersion)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS portal_users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL,
 username_norm TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 tenant_id TEXT NOT NULL UNIQUE,
 runtime_user TEXT NOT NULL UNIQUE,
 data_root TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
 auth_version INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS portal_sessions (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),
 csrf_hash BLOB NOT NULL CHECK(length(csrf_hash)=32),
 user_id INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
 auth_version INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 last_seen_at INTEGER NOT NULL,
 remote_ip TEXT NOT NULL,
 user_agent_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS portal_sessions_user_id ON portal_sessions(user_id);
CREATE INDEX IF NOT EXISTS portal_sessions_expires_at ON portal_sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_limits (
 limit_key TEXT PRIMARY KEY,
 window_start INTEGER NOT NULL,
 failures INTEGER NOT NULL,
 blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 occurred_at INTEGER NOT NULL,
 action TEXT NOT NULL,
 outcome TEXT NOT NULL,
 username TEXT,
 tenant_id TEXT,
 remote_ip TEXT,
 details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (
 state_hash BLOB PRIMARY KEY CHECK(length(state_hash)=32),
 session_token_hash BLOB NOT NULL CHECK(length(session_token_hash)=32),
 tenant_id TEXT NOT NULL,
 runtime_started_at TEXT NOT NULL,
 flow_id TEXT NOT NULL,
 target TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_states_expires_at ON oauth_states(expires_at);
CREATE TABLE IF NOT EXISTS chatgpt_pro_limits (
 user_id INTEGER PRIMARY KEY REFERENCES portal_users(id) ON DELETE CASCADE,
 weekly_limit INTEGER NOT NULL CHECK(weekly_limit BETWEEN 1 AND 10000),
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chatgpt_pro_usage (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
 logical_send_id TEXT NOT NULL CHECK(length(logical_send_id)=64),
 week_start INTEGER NOT NULL,
 requested_model TEXT NOT NULL,
 thinking_effort TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('reserved','confirmed_pro','confirmed_fallback','unknown','upstream_rejected')),
 reserved_at INTEGER NOT NULL,
 finished_at INTEGER,
 upstream_status INTEGER,
 stream_completed INTEGER NOT NULL DEFAULT 0 CHECK(stream_completed IN (0,1)),
 served_models_json TEXT NOT NULL DEFAULT '[]',
 UNIQUE(user_id,logical_send_id)
);
CREATE INDEX IF NOT EXISTS chatgpt_pro_usage_user_week ON chatgpt_pro_usage(user_id,week_start,status);
CREATE TABLE IF NOT EXISTS chatgpt_pro_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
 usage_id INTEGER NOT NULL UNIQUE REFERENCES chatgpt_pro_usage(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind='confirmed_fallback'),
 occurred_at INTEGER NOT NULL,
 acknowledged_at INTEGER
);
CREATE INDEX IF NOT EXISTS chatgpt_pro_events_pending ON chatgpt_pro_events(user_id,acknowledged_at,id);
CREATE TABLE IF NOT EXISTS chatforward_replays (
 signature_hash BLOB PRIMARY KEY CHECK(length(signature_hash)=32),
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS chatforward_replays_expires_at ON chatforward_replays(expires_at);`
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin Portal schema migration: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize Portal database: %w", err)
	}
	if err := validatePortalSchema(ctx, transaction); err != nil {
		return fmt.Errorf("validate Portal database schema: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `PRAGMA user_version=4`); err != nil {
		return fmt.Errorf("record Portal database schema version: %w", err)
	}
	return transaction.Commit()
}

func validatePortalSchema(ctx context.Context, transaction *sql.Tx) error {
	required := []struct {
		table   string
		columns []string
	}{
		{"portal_users", []string{"id", "username", "username_norm", "password_hash", "tenant_id", "runtime_user", "data_root", "enabled", "is_admin", "auth_version", "created_at", "updated_at", "last_login_at"}},
		{"portal_sessions", []string{"token_hash", "csrf_hash", "user_id", "auth_version", "created_at", "expires_at", "last_seen_at", "remote_ip", "user_agent_hash"}},
		{"login_limits", []string{"limit_key", "window_start", "failures", "blocked_until"}},
		{"audit_events", []string{"id", "occurred_at", "action", "outcome", "username", "tenant_id", "remote_ip", "details_json"}},
		{"oauth_states", []string{"state_hash", "session_token_hash", "tenant_id", "runtime_started_at", "flow_id", "target", "expires_at", "created_at"}},
		{"chatgpt_pro_limits", []string{"user_id", "weekly_limit", "updated_at"}},
		{"chatgpt_pro_usage", []string{"id", "user_id", "logical_send_id", "week_start", "requested_model", "thinking_effort", "status", "reserved_at", "finished_at", "upstream_status", "stream_completed", "served_models_json"}},
		{"chatgpt_pro_events", []string{"id", "user_id", "usage_id", "kind", "occurred_at", "acknowledged_at"}},
		{"chatforward_replays", []string{"signature_hash", "expires_at"}},
	}
	for _, expected := range required {
		rows, err := transaction.QueryContext(ctx, `SELECT name FROM pragma_table_info('`+expected.table+`')`)
		if err != nil {
			return fmt.Errorf("inspect table %s: %w", expected.table, err)
		}
		columns := make(map[string]bool, len(expected.columns))
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return fmt.Errorf("inspect table %s columns: %w", expected.table, err)
			}
			columns[name] = true
		}
		rowsErr := rows.Err()
		rows.Close()
		if rowsErr != nil {
			return fmt.Errorf("inspect table %s columns: %w", expected.table, rowsErr)
		}
		for _, name := range expected.columns {
			if !columns[name] {
				return fmt.Errorf("table %s is missing required column %s", expected.table, name)
			}
		}
	}
	rows, err := transaction.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check foreign keys: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("database contains a foreign-key violation")
	}
	return rows.Err()
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	databaseErr := s.db.Close()
	lockErr := s.runtime.Close()
	if databaseErr != nil {
		return databaseErr
	}
	return lockErr
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) AuditEventCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&count)
	return count, err
}

// CheckAuditSink verifies and opens the append-only audit destination without
// writing a synthetic business event.  Calling it during Open also creates the
// initially empty file with its final permissions.
func (s *Store) CheckAuditSink() error {
	if s == nil || s.auditPath == "" {
		return errors.New("audit sink is not configured")
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if info, err := os.Lstat(s.auditPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("audit sink is not a protected regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect audit sink: %w", err)
	}
	file, err := os.OpenFile(s.auditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit sink: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("protect audit sink: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit sink: %w", err)
	}
	return nil
}

func NormalizeUsername(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM portal_users`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, tenantID, runtimeUser, dataRoot string, admin bool, now time.Time) (User, error) {
	return s.CreateUserWithEnabled(ctx, username, passwordHash, tenantID, runtimeUser, dataRoot, true, admin, now)
}

// CreateUserWithEnabled is used by the root administration workflow to make
// ordinary user creation fail closed: the durable DB row is initially
// disabled until the separately crash-safe systemd+DB enable transition is
// requested. Existing callers retain the historical enabled-by-default API.
func (s *Store) CreateUserWithEnabled(ctx context.Context, username, passwordHash, tenantID, runtimeUser, dataRoot string, enabled, admin bool, now time.Time) (User, error) {
	username = strings.TrimSpace(username)
	norm := NormalizeUsername(username)
	if norm == "" || strings.TrimSpace(passwordHash) == "" || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(runtimeUser) == "" || strings.TrimSpace(dataRoot) == "" {
		return User{}, errors.New("all user identity fields are required")
	}
	stamp := now.UTC().Unix()
	result, err := s.db.ExecContext(ctx, `INSERT INTO portal_users
 (username,username_norm,password_hash,tenant_id,runtime_user,data_root,enabled,is_admin,auth_version,created_at,updated_at)
 VALUES(?,?,?,?,?,?,?,?,1,?,?)`, username, norm, passwordHash, tenantID, runtimeUser, dataRoot, boolInt(enabled), boolInt(admin), stamp, stamp)
	if err != nil {
		return User{}, fmt.Errorf("create Portal user: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("read created user ID: %w", err)
	}
	return s.UserByID(ctx, id)
}

const userSelect = `SELECT id,username,username_norm,password_hash,tenant_id,runtime_user,data_root,enabled,is_admin,auth_version,created_at,updated_at,last_login_at FROM portal_users`

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE id=?`, id))
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE username_norm=?`, NormalizeUsername(username)))
}

func (s *Store) UserByTenantID(ctx context.Context, tenantID string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE tenant_id=?`, tenantID))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY username_norm`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanUser(row rowScanner) (User, error) {
	var value User
	var enabled, admin int
	var created, updated int64
	var last sql.NullInt64
	err := row.Scan(&value.ID, &value.Username, &value.UsernameNorm, &value.PasswordHash, &value.TenantID, &value.RuntimeUser, &value.DataRoot, &enabled, &admin, &value.AuthVersion, &created, &updated, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	value.Enabled, value.Admin = enabled == 1, admin == 1
	value.CreatedAt, value.UpdatedAt = unixTime(created), unixTime(updated)
	if last.Valid {
		stamp := unixTime(last.Int64)
		value.LastLoginAt = &stamp
	}
	return value, nil
}

func (s *Store) SetUserEnabled(ctx context.Context, username string, enabled bool, now time.Time) error {
	return s.updateIdentity(ctx, username, now, `UPDATE portal_users SET enabled=?,auth_version=auth_version+1,updated_at=? WHERE username_norm=?`, boolInt(enabled), now.UTC().Unix(), NormalizeUsername(username))
}

func (s *Store) SetPassword(ctx context.Context, username, passwordHash string, now time.Time) error {
	if strings.TrimSpace(passwordHash) == "" {
		return errors.New("password hash is required")
	}
	return s.updateIdentity(ctx, username, now, `UPDATE portal_users SET password_hash=?,auth_version=auth_version+1,updated_at=? WHERE username_norm=?`, passwordHash, now.UTC().Unix(), NormalizeUsername(username))
}

func (s *Store) updateIdentity(ctx context.Context, username string, now time.Time, statement string, arguments ...any) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM portal_sessions WHERE user_id=(SELECT id FROM portal_users WHERE username_norm=?)`, NormalizeUsername(username)); err != nil {
		return err
	}
	return transaction.Commit()
}

func TokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return append([]byte(nil), sum[:]...)
}

func UserAgentHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateSession(ctx context.Context, token, csrfToken string, user User, remoteIP, userAgent string, now, expires time.Time) error {
	if token == "" || csrfToken == "" || !user.Enabled || !expires.After(now) {
		return errors.New("invalid session")
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `DELETE FROM portal_sessions WHERE expires_at<=?`, now.UTC().Unix()); err != nil {
		return fmt.Errorf("clean expired sessions: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `INSERT INTO portal_sessions(token_hash,csrf_hash,user_id,auth_version,created_at,expires_at,last_seen_at,remote_ip,user_agent_hash)
 SELECT ?,?,id,auth_version,?,?,?,?,? FROM portal_users WHERE id=? AND enabled=1 AND auth_version=?`,
		TokenHash(token), TokenHash(csrfToken), now.UTC().Unix(), expires.UTC().Unix(), now.UTC().Unix(), remoteIP, UserAgentHash(userAgent), user.ID, user.AuthVersion)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.New("user changed while the session was being created")
	}
	return transaction.Commit()
}

func (s *Store) SessionByToken(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrNotFound
	}
	const query = `SELECT s.token_hash,s.csrf_hash,s.user_id,s.auth_version,s.created_at,s.expires_at,s.last_seen_at,s.remote_ip,s.user_agent_hash,
 u.id,u.username,u.username_norm,u.password_hash,u.tenant_id,u.runtime_user,u.data_root,u.enabled,u.is_admin,u.auth_version,u.created_at,u.updated_at,u.last_login_at
 FROM portal_sessions s JOIN portal_users u ON u.id=s.user_id WHERE s.token_hash=?`
	row := s.db.QueryRowContext(ctx, query, TokenHash(token))
	var value Session
	var sessionCreated, expires, lastSeen int64
	var enabled, admin int
	var userCreated, userUpdated int64
	var lastLogin sql.NullInt64
	err := row.Scan(&value.TokenHash, &value.CSRFHash, &value.UserID, &value.AuthVersion, &sessionCreated, &expires, &lastSeen, &value.RemoteIP, &value.UserAgentHash,
		&value.User.ID, &value.User.Username, &value.User.UsernameNorm, &value.User.PasswordHash, &value.User.TenantID, &value.User.RuntimeUser, &value.User.DataRoot,
		&enabled, &admin, &value.User.AuthVersion, &userCreated, &userUpdated, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	value.CreatedAt, value.ExpiresAt, value.LastSeenAt = unixTime(sessionCreated), unixTime(expires), unixTime(lastSeen)
	value.User.Enabled, value.User.Admin = enabled == 1, admin == 1
	value.User.CreatedAt, value.User.UpdatedAt = unixTime(userCreated), unixTime(userUpdated)
	if lastLogin.Valid {
		stamp := unixTime(lastLogin.Int64)
		value.User.LastLoginAt = &stamp
	}
	return value, nil
}

func (s *Store) TouchSession(ctx context.Context, token string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE portal_sessions SET last_seen_at=? WHERE token_hash=?`, now.UTC().Unix(), TokenHash(token))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RecordLogin(ctx context.Context, userID int64, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE portal_users SET last_login_at=?,updated_at=? WHERE id=?`, now.UTC().Unix(), now.UTC().Unix(), userID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	return nil
}

// RecordLoginSuccess commits the identity timestamp and account-scoped throttle
// reset together.  The source-IP throttle deliberately survives so one valid
// account cannot erase failures made against other accounts from the same IP.
func (s *Store) RecordLoginSuccess(ctx context.Context, userID int64, username string, now time.Time) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `UPDATE portal_users SET last_login_at=?,updated_at=? WHERE id=?`, now.UTC().Unix(), now.UTC().Unix(), userID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM login_limits WHERE limit_key=?`, "account:"+NormalizeUsername(username)); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE token_hash=?`, TokenHash(token))
	return err
}

func (s *Store) SessionCountForUser(ctx context.Context, userID int64, now time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM portal_sessions s JOIN portal_users u ON u.id=s.user_id
 WHERE s.user_id=? AND s.expires_at>? AND u.enabled=1 AND s.auth_version=u.auth_version`, userID, now.UTC().Unix()).Scan(&count)
	return count, err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE expires_at<=? OR last_seen_at<=?`, now.UTC().Unix(), now.Add(-idle).UTC().Unix())
	return err
}

func (s *Store) CreateOAuthState(ctx context.Context, state string, binding OAuthBinding, now time.Time) error {
	if state == "" || len(binding.SessionTokenHash) != sha256.Size || strings.TrimSpace(binding.TenantID) == "" || strings.TrimSpace(binding.RuntimeStartedAt) == "" || strings.TrimSpace(binding.FlowID) == "" || strings.TrimSpace(binding.Target) == "" || !binding.ExpiresAt.After(now) {
		return errors.New("invalid OAuth binding")
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at<=?`, now.UTC().Unix()); err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO oauth_states(state_hash,session_token_hash,tenant_id,runtime_started_at,flow_id,target,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		TokenHash(state), binding.SessionTokenHash, binding.TenantID, binding.RuntimeStartedAt, binding.FlowID, binding.Target, binding.ExpiresAt.UTC().Unix(), now.UTC().Unix())
	if err != nil {
		return fmt.Errorf("persist OAuth state: %w", err)
	}
	return transaction.Commit()
}

func (s *Store) ConsumeOAuthState(ctx context.Context, state string, sessionTokenHash []byte, now time.Time) (OAuthBinding, error) {
	if state == "" || len(sessionTokenHash) != sha256.Size {
		return OAuthBinding{}, ErrNotFound
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthBinding{}, err
	}
	defer transaction.Rollback()
	var binding OAuthBinding
	var expires int64
	err = transaction.QueryRowContext(ctx, `SELECT session_token_hash,tenant_id,runtime_started_at,flow_id,target,expires_at FROM oauth_states WHERE state_hash=? AND session_token_hash=? AND expires_at>?`,
		TokenHash(state), sessionTokenHash, now.UTC().Unix()).Scan(&binding.SessionTokenHash, &binding.TenantID, &binding.RuntimeStartedAt, &binding.FlowID, &binding.Target, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthBinding{}, ErrNotFound
	}
	if err != nil {
		return OAuthBinding{}, err
	}
	result, err := transaction.ExecContext(ctx, `DELETE FROM oauth_states WHERE state_hash=? AND session_token_hash=?`, TokenHash(state), sessionTokenHash)
	if err != nil {
		return OAuthBinding{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return OAuthBinding{}, ErrNotFound
	}
	binding.ExpiresAt = unixTime(expires)
	if err := transaction.Commit(); err != nil {
		return OAuthBinding{}, err
	}
	return binding, nil
}

func (s *Store) LoginAllowed(ctx context.Context, username, remoteIP string, now time.Time) (bool, time.Time, error) {
	var latest time.Time
	for _, key := range []string{"account:" + NormalizeUsername(username), "ip:" + remoteIP} {
		var blocked int64
		err := s.db.QueryRowContext(ctx, `SELECT blocked_until FROM login_limits WHERE limit_key=?`, key).Scan(&blocked)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, time.Time{}, err
		}
		until := unixTime(blocked)
		if until.After(latest) {
			latest = until
		}
	}
	return !latest.After(now), latest, nil
}

func (s *Store) RecordLoginFailure(ctx context.Context, username, remoteIP string, now time.Time, policy RatePolicy) error {
	if policy.Window <= 0 || policy.Block <= 0 || policy.AccountFailures < 1 || policy.IPFailures < 1 {
		return errors.New("invalid login rate policy")
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	for _, item := range []struct {
		key       string
		threshold int
	}{{"account:" + NormalizeUsername(username), policy.AccountFailures}, {"ip:" + remoteIP, policy.IPFailures}} {
		var start int64
		var failures int
		var blocked int64
		err := transaction.QueryRowContext(ctx, `SELECT window_start,failures,blocked_until FROM login_limits WHERE limit_key=?`, item.key).Scan(&start, &failures, &blocked)
		if errors.Is(err, sql.ErrNoRows) || now.Sub(unixTime(start)) >= policy.Window {
			start, failures, blocked = now.UTC().Unix(), 0, 0
		} else if err != nil {
			return err
		}
		failures++
		if failures >= item.threshold {
			blocked = now.Add(policy.Block).UTC().Unix()
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO login_limits(limit_key,window_start,failures,blocked_until) VALUES(?,?,?,?)
 ON CONFLICT(limit_key) DO UPDATE SET window_start=excluded.window_start,failures=excluded.failures,blocked_until=excluded.blocked_until`, item.key, start, failures, blocked); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (s *Store) ClearLoginFailures(ctx context.Context, username, remoteIP string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_limits WHERE limit_key IN (?,?)`, "account:"+NormalizeUsername(username), "ip:"+remoteIP)
	return err
}

// ClearAccountLoginFailures resets only the authenticated account.  An attacker
// must not be able to erase a shared source-IP throttle by successfully logging
// in to a different account from that address.
func (s *Store) ClearAccountLoginFailures(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_limits WHERE limit_key=?`, "account:"+NormalizeUsername(username))
	return err
}

func (s *Store) Audit(ctx context.Context, event AuditEvent) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	if event.Action == "" || event.Outcome == "" {
		return errors.New("audit action and outcome are required")
	}
	if containsSensitiveKey(event.Details) {
		return errors.New("audit details contain a sensitive key")
	}
	details, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	if len(details) > 16*1024 {
		return errors.New("audit details are too large")
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(occurred_at,action,outcome,username,tenant_id,remote_ip,details_json) VALUES(?,?,?,?,?,?,?)`,
		event.OccurredAt.Unix(), event.Action, event.Outcome, nullString(event.Username), nullString(event.TenantID), nullString(event.RemoteIP), string(details)); err != nil {
		return fmt.Errorf("write database audit event: %w", err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.auditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	return nil
}

// PruneAudit applies the configured retention window to both audit sinks while
// preserving at least minimumEvents newest database records. Invalid log lines
// abort the operation without modifying either sink.
func (s *Store) PruneAudit(ctx context.Context, before time.Time, minimumEvents int) (int64, error) {
	if s == nil || before.IsZero() || minimumEvents < 1 {
		return 0, errors.New("invalid audit retention request")
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	cutoff := before.UTC().Unix()
	var preserveFrom int64
	err := s.db.QueryRowContext(ctx, `SELECT occurred_at FROM audit_events ORDER BY id DESC LIMIT 1 OFFSET ?`, minimumEvents-1).Scan(&preserveFrom)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err == nil && preserveFrom < cutoff {
		cutoff = preserveFrom
	}

	input, err := os.Open(s.auditPath)
	if err != nil {
		return 0, fmt.Errorf("open audit log for retention: %w", err)
	}
	parent := filepath.Dir(s.auditPath)
	temporary, err := os.CreateTemp(parent, ".audit-retention-*")
	if err != nil {
		input.Close()
		return 0, err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		input.Close()
		temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return 0, err
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event AuditEvent
		if err := json.Unmarshal(line, &event); err != nil || event.OccurredAt.IsZero() || event.Action == "" || event.Outcome == "" {
			cleanup()
			return 0, errors.New("audit log contains an invalid record; retention aborted")
		}
		if event.OccurredAt.UTC().Unix() >= cutoff {
			if _, err := temporary.Write(append(line, '\n')); err != nil {
				cleanup()
				return 0, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		cleanup()
		return 0, err
	}
	if err := input.Close(); err != nil {
		cleanup()
		return 0, err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return 0, err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return 0, err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		_ = os.Remove(temporaryPath)
		return 0, err
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `DELETE FROM audit_events WHERE occurred_at < ?`, cutoff)
	if err != nil {
		_ = os.Remove(temporaryPath)
		return 0, err
	}
	if err := os.Rename(temporaryPath, s.auditPath); err != nil {
		_ = os.Remove(temporaryPath)
		return 0, err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return 0, err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return 0, syncErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if err := transaction.Commit(); err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func containsSensitiveKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(key)
			for _, fragment := range []string{"password", "token", "cookie", "api_key", "apikey", "secret", "authorization", "credential", "private_key"} {
				if strings.Contains(normalized, fragment) {
					return true
				}
			}
			if containsSensitiveKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSensitiveKey(child) {
				return true
			}
		}
	}
	return false
}

func unixTime(value int64) time.Time { return time.Unix(value, 0).UTC() }
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
