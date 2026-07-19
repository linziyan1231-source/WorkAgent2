package store

import (
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
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db        *sql.DB
	auditPath string
	auditMu   sync.Mutex
}

type User struct {
	ID              int64
	Username        string
	UsernameNorm    string
	PasswordHash    string
	WindowsSID      string
	WindowsUsername string
	Enabled         bool
	Admin           bool
	AuthVersion     int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLoginAt     *time.Time
}

type Session struct {
	TokenHash     []byte
	UserID        int64
	AuthVersion   int64
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastSeenAt    time.Time
	RemoteIP      string
	UserAgentHash string
	User          User
}

type OAuthBinding struct {
	SessionTokenHash []byte
	WindowsSID       string
	InstanceID       string
	FlowID           string
	Target           string
	ExpiresAt        time.Time
}

type RatePolicy struct {
	Window          time.Duration
	Block           time.Duration
	AccountFailures int
	IPFailures      int
}

func Open(path, auditPath string) (*Store, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(auditPath) {
		return nil, errors.New("database and audit paths must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open portal database: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, auditPath: auditPath}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS portal_users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL,
 username_norm TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 windows_sid TEXT NOT NULL UNIQUE,
 windows_username TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
 auth_version INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS portal_sessions (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),
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
CREATE TABLE IF NOT EXISTS oauth_states (
 state_hash BLOB PRIMARY KEY CHECK(length(state_hash)=32),
 session_token_hash BLOB NOT NULL CHECK(length(session_token_hash)=32),
 windows_sid TEXT NOT NULL,
 instance_id TEXT NOT NULL,
 flow_id TEXT NOT NULL,
 target TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 used_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 occurred_at INTEGER NOT NULL,
 action TEXT NOT NULL,
 outcome TEXT NOT NULL,
 username TEXT,
 windows_sid TEXT,
 remote_ip TEXT,
 details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chatgpt_pro_limits (
 user_id INTEGER PRIMARY KEY REFERENCES portal_users(id) ON DELETE CASCADE,
 weekly_limit INTEGER NOT NULL CHECK(weekly_limit BETWEEN 1 AND 10000),
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chatgpt_pro_usage (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
 logical_send_id TEXT NOT NULL UNIQUE CHECK(length(logical_send_id)=64),
 week_start INTEGER NOT NULL,
 requested_model TEXT NOT NULL,
 thinking_effort TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('reserved','confirmed_pro','confirmed_fallback','unknown','upstream_rejected')),
 reserved_at INTEGER NOT NULL,
 finished_at INTEGER,
 upstream_status INTEGER,
 stream_completed INTEGER NOT NULL DEFAULT 0 CHECK(stream_completed IN (0,1)),
 served_models_json TEXT NOT NULL DEFAULT '[]'
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
PRAGMA user_version=3;`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate portal database: %w", err)
	}
	var hasFlowID int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('oauth_states') WHERE name='flow_id'`).Scan(&hasFlowID); err != nil {
		return fmt.Errorf("inspect OAuth state schema: %w", err)
	}
	if hasFlowID == 0 {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE oauth_states ADD COLUMN flow_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add OAuth flow binding: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, `PRAGMA user_version=2`); err != nil {
			return fmt.Errorf("record Portal database migration: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA user_version=3`); err != nil {
		return fmt.Errorf("record Portal database migration: %w", err)
	}
	return nil
}

func NormalizeUsername(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, windowsSID, windowsUsername string, admin bool, now time.Time) (User, error) {
	username = strings.TrimSpace(username)
	norm := NormalizeUsername(username)
	if norm == "" || strings.TrimSpace(passwordHash) == "" || strings.TrimSpace(windowsSID) == "" || strings.TrimSpace(windowsUsername) == "" {
		return User{}, errors.New("all user identity fields are required")
	}
	stamp := now.Unix()
	result, err := s.db.ExecContext(ctx, `INSERT INTO portal_users
 (username,username_norm,password_hash,windows_sid,windows_username,enabled,is_admin,auth_version,created_at,updated_at)
 VALUES(?,?,?,?,?,1,?,1,?,?)`, username, norm, passwordHash, windowsSID, windowsUsername, boolInt(admin), stamp, stamp)
	if err != nil {
		return User{}, fmt.Errorf("create portal user: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("read created user id: %w", err)
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE id=?`, id))
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE username_norm=?`, NormalizeUsername(username)))
}

func (s *Store) UserBySID(ctx context.Context, sid string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE windows_sid=?`, sid))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY username_norm`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) SetUserEnabled(ctx context.Context, username string, enabled bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE portal_users SET enabled=?,auth_version=auth_version+1,updated_at=? WHERE username_norm=?`, boolInt(enabled), now.Unix(), NormalizeUsername(username))
	if err != nil {
		return fmt.Errorf("set user enabled: %w", err)
	}
	if err := requireChanged(res); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM portal_sessions WHERE user_id=(SELECT id FROM portal_users WHERE username_norm=?)`, NormalizeUsername(username)); err != nil {
		return fmt.Errorf("invalidate disabled user sessions: %w", err)
	}
	return tx.Commit()
}

func (s *Store) ResetPassword(ctx context.Context, username, hash string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE portal_users SET password_hash=?,auth_version=auth_version+1,updated_at=? WHERE username_norm=?`, hash, now.Unix(), NormalizeUsername(username))
	if err != nil {
		return fmt.Errorf("reset portal password: %w", err)
	}
	if err := requireChanged(res); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM portal_sessions WHERE user_id=(SELECT id FROM portal_users WHERE username_norm=?)`, NormalizeUsername(username)); err != nil {
		return fmt.Errorf("invalidate password-reset sessions: %w", err)
	}
	return tx.Commit()
}

func (s *Store) MapWindowsIdentity(ctx context.Context, username, sid, windowsUsername string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE portal_users SET windows_sid=?,windows_username=?,auth_version=auth_version+1,updated_at=? WHERE username_norm=?`, sid, windowsUsername, now.Unix(), NormalizeUsername(username))
	if err != nil {
		return fmt.Errorf("map Windows identity: %w", err)
	}
	return requireChanged(res)
}

func (s *Store) RecordLoginSuccess(ctx context.Context, userID int64, username, remoteIP string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE portal_users SET last_login_at=? WHERE id=?`, now.Unix(), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_limits WHERE limit_key IN (?,?)`, accountRateKey(username), ipRateKey(remoteIP)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LoginAllowed(ctx context.Context, username, remoteIP string, now time.Time) (bool, time.Time, error) {
	var latest int64
	for _, key := range []string{accountRateKey(username), ipRateKey(remoteIP)} {
		var blocked int64
		err := s.db.QueryRowContext(ctx, `SELECT blocked_until FROM login_limits WHERE limit_key=?`, key).Scan(&blocked)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, time.Time{}, err
		}
		if blocked > latest {
			latest = blocked
		}
	}
	return latest <= now.Unix(), time.Unix(latest, 0), nil
}

func (s *Store) RecordLoginFailure(ctx context.Context, username, remoteIP string, policy RatePolicy, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range []struct {
		key string
		max int
	}{{accountRateKey(username), policy.AccountFailures}, {ipRateKey(remoteIP), policy.IPFailures}} {
		if err := bumpRate(ctx, tx, item.key, item.max, policy, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func bumpRate(ctx context.Context, tx *sql.Tx, key string, max int, policy RatePolicy, now time.Time) error {
	var start, blocked int64
	var failures int
	err := tx.QueryRowContext(ctx, `SELECT window_start,failures,blocked_until FROM login_limits WHERE limit_key=?`, key).Scan(&start, &failures, &blocked)
	if errors.Is(err, sql.ErrNoRows) || now.Sub(time.Unix(start, 0)) >= policy.Window {
		start, failures, blocked = now.Unix(), 0, 0
	} else if err != nil {
		return err
	}
	failures++
	if failures >= max {
		blocked = now.Add(policy.Block).Unix()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO login_limits(limit_key,window_start,failures,blocked_until) VALUES(?,?,?,?)
 ON CONFLICT(limit_key) DO UPDATE SET window_start=excluded.window_start,failures=excluded.failures,blocked_until=excluded.blocked_until`, key, start, failures, blocked)
	return err
}

func TokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func (s *Store) CreateSession(ctx context.Context, token string, user User, ttl time.Duration, remoteIP, userAgent string, now time.Time) error {
	if !user.Enabled {
		return errors.New("cannot create session for disabled user")
	}
	ua := sha256.Sum256([]byte(userAgent))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM portal_sessions WHERE expires_at<=?`, now.Unix()); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO portal_sessions(token_hash,user_id,auth_version,created_at,expires_at,last_seen_at,remote_ip,user_agent_hash)
 SELECT ?,id,auth_version,?,?,?,?,? FROM portal_users WHERE id=? AND enabled=1 AND auth_version=?`,
		TokenHash(token), now.Unix(), now.Add(ttl).Unix(), now.Unix(), remoteIP, hex.EncodeToString(ua[:]), user.ID, user.AuthVersion)
	if err != nil {
		return fmt.Errorf("create portal session: %w", err)
	}
	if err := requireChanged(result); err != nil {
		return errors.New("Portal user was disabled or changed while the session was being created")
	}
	return tx.Commit()
}

func (s *Store) Session(ctx context.Context, token string, idle time.Duration, now time.Time) (Session, error) {
	const query = `SELECT s.token_hash,s.user_id,s.auth_version,s.created_at,s.expires_at,s.last_seen_at,s.remote_ip,s.user_agent_hash,
 u.id,u.username,u.username_norm,u.password_hash,u.windows_sid,u.windows_username,u.enabled,u.is_admin,u.auth_version,u.created_at,u.updated_at,u.last_login_at
 FROM portal_sessions s JOIN portal_users u ON u.id=s.user_id
 WHERE s.token_hash=? AND s.expires_at>? AND s.last_seen_at>? AND u.enabled=1 AND s.auth_version=u.auth_version`
	row := s.db.QueryRowContext(ctx, query, TokenHash(token), now.Unix(), now.Add(-idle).Unix())
	var out Session
	var created, expires, lastSeen int64
	var userCreated, userUpdated int64
	var userLast sql.NullInt64
	var enabled, admin int
	err := row.Scan(&out.TokenHash, &out.UserID, &out.AuthVersion, &created, &expires, &lastSeen, &out.RemoteIP, &out.UserAgentHash,
		&out.User.ID, &out.User.Username, &out.User.UsernameNorm, &out.User.PasswordHash, &out.User.WindowsSID, &out.User.WindowsUsername,
		&enabled, &admin, &out.User.AuthVersion, &userCreated, &userUpdated, &userLast)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("read portal session: %w", err)
	}
	out.CreatedAt, out.ExpiresAt, out.LastSeenAt = time.Unix(created, 0), time.Unix(expires, 0), time.Unix(lastSeen, 0)
	out.User.Enabled, out.User.Admin = enabled == 1, admin == 1
	out.User.CreatedAt, out.User.UpdatedAt = time.Unix(userCreated, 0), time.Unix(userUpdated, 0)
	if userLast.Valid {
		t := time.Unix(userLast.Int64, 0)
		out.User.LastLoginAt = &t
	}
	return out, nil
}

func (s *Store) TouchSession(ctx context.Context, token string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE portal_sessions SET last_seen_at=? WHERE token_hash=?`, now.Unix(), TokenHash(token))
	return err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE token_hash=?`, TokenHash(token))
	return err
}

func (s *Store) SessionCountForUser(ctx context.Context, userID int64, now time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM portal_sessions s JOIN portal_users u ON u.id=s.user_id
 WHERE s.user_id=? AND s.expires_at>? AND u.enabled=1 AND s.auth_version=u.auth_version`, userID, now.Unix()).Scan(&count)
	return count, err
}

func (s *Store) CreateOAuthState(ctx context.Context, state string, binding OAuthBinding) error {
	if len(binding.SessionTokenHash) != sha256.Size || strings.TrimSpace(binding.WindowsSID) == "" || strings.TrimSpace(binding.InstanceID) == "" ||
		strings.TrimSpace(binding.FlowID) == "" || strings.TrimSpace(binding.Target) == "" || !binding.ExpiresAt.After(time.Unix(0, 0)) {
		return errors.New("incomplete OAuth state binding")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at<=? OR (used_at IS NOT NULL AND used_at<=?)`,
		binding.ExpiresAt.Add(-5*time.Minute).Unix(), binding.ExpiresAt.Add(-24*time.Hour).Unix()); err != nil {
		return fmt.Errorf("clean expired OAuth states: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_states(state_hash,session_token_hash,windows_sid,instance_id,flow_id,target,expires_at)
 VALUES(?,?,?,?,?,?,?)`, TokenHash(state), binding.SessionTokenHash, binding.WindowsSID, binding.InstanceID, binding.FlowID, binding.Target, binding.ExpiresAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeOAuthState(ctx context.Context, state string, sessionTokenHash []byte, now time.Time) (OAuthBinding, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthBinding{}, err
	}
	defer tx.Rollback()
	var out OAuthBinding
	var expires int64
	err = tx.QueryRowContext(ctx, `SELECT session_token_hash,windows_sid,instance_id,flow_id,target,expires_at FROM oauth_states
 WHERE state_hash=? AND used_at IS NULL AND expires_at>?`, TokenHash(state), now.Unix()).Scan(&out.SessionTokenHash, &out.WindowsSID, &out.InstanceID, &out.FlowID, &out.Target, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return OAuthBinding{}, ErrNotFound
	}
	if err != nil {
		return OAuthBinding{}, err
	}
	if !equalBytes(out.SessionTokenHash, sessionTokenHash) {
		return OAuthBinding{}, ErrNotFound
	}
	res, err := tx.ExecContext(ctx, `UPDATE oauth_states SET used_at=? WHERE state_hash=? AND used_at IS NULL`, now.Unix(), TokenHash(state))
	if err != nil {
		return OAuthBinding{}, err
	}
	if err := requireChanged(res); err != nil {
		return OAuthBinding{}, ErrNotFound
	}
	out.ExpiresAt = time.Unix(expires, 0)
	if err := tx.Commit(); err != nil {
		return OAuthBinding{}, err
	}
	return out, nil
}

func (s *Store) Audit(ctx context.Context, action, outcome, username, sid, remoteIP string, details map[string]any, now time.Time) error {
	if containsSensitiveKey(details) {
		return errors.New("audit details contain a sensitive key")
	}
	b, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(occurred_at,action,outcome,username,windows_sid,remote_ip,details_json)
 VALUES(?,?,?,?,?,?,?)`, now.Unix(), action, outcome, nullString(username), nullString(sid), nullString(remoteIP), string(b)); err != nil {
		return fmt.Errorf("write audit database event: %w", err)
	}
	line, err := json.Marshal(map[string]any{"occurred_at": now.UTC().Format(time.RFC3339Nano), "action": action, "outcome": outcome,
		"username": username, "windows_sid": sid, "remote_ip": remoteIP, "details": details})
	if err != nil {
		return err
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	f, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return f.Sync()
}

const userSelect = `SELECT id,username,username_norm,password_hash,windows_sid,windows_username,enabled,is_admin,auth_version,created_at,updated_at,last_login_at FROM portal_users`

type scanner interface{ Scan(...any) error }

func scanUser(row scanner) (User, error) {
	var u User
	var enabled, admin int
	var created, updated int64
	var last sql.NullInt64
	err := row.Scan(&u.ID, &u.Username, &u.UsernameNorm, &u.PasswordHash, &u.WindowsSID, &u.WindowsUsername, &enabled, &admin, &u.AuthVersion, &created, &updated, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.Enabled, u.Admin = enabled == 1, admin == 1
	u.CreatedAt, u.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	if last.Valid {
		t := time.Unix(last.Int64, 0)
		u.LastLoginAt = &t
	}
	return u, nil
}

func accountRateKey(username string) string { return "account:" + NormalizeUsername(username) }
func ipRateKey(ip string) string            { return "ip:" + strings.TrimSpace(ip) }
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func requireChanged(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func containsSensitiveKey(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			n := strings.ToLower(k)
			if strings.Contains(n, "password") || strings.Contains(n, "token") || strings.Contains(n, "cookie") || strings.Contains(n, "api_key") || strings.Contains(n, "secret") {
				return true
			}
			if containsSensitiveKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if containsSensitiveKey(child) {
				return true
			}
		}
	}
	return false
}
