package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testTenantID = "11111111-1111-4111-8111-111111111111"

const schemaV2Fixture = `
CREATE TABLE portal_users (
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
CREATE TABLE portal_sessions (
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
CREATE INDEX portal_sessions_user_id ON portal_sessions(user_id);
CREATE INDEX portal_sessions_expires_at ON portal_sessions(expires_at);
CREATE TABLE login_limits (
 limit_key TEXT PRIMARY KEY,
 window_start INTEGER NOT NULL,
 failures INTEGER NOT NULL,
 blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 occurred_at INTEGER NOT NULL,
 action TEXT NOT NULL,
 outcome TEXT NOT NULL,
 username TEXT,
 tenant_id TEXT,
 remote_ip TEXT,
 details_json TEXT NOT NULL
);
PRAGMA user_version=2;`

func openTestStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	value, err := Open(filepath.Join(root, "state", "portal.db"), filepath.Join(root, "state", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { value.Close() })
	return value
}

func TestOpenMigratesV2WithoutLosingIdentity(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "portal.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(schemaV2Fixture); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO portal_users
(username,username_norm,password_hash,tenant_id,runtime_user,data_root,enabled,is_admin,auth_version,created_at,updated_at)
VALUES('Alice','alice','hash-placeholder',?,'workagent_alice',?,1,1,7,1700000000,1700000001)`, testTenantID, "/srv/workagent/users/"+testTenantID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := Open(path, filepath.Join(state, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	userValue, err := value.UserByUsername(context.Background(), "alice")
	if err != nil || userValue.TenantID != testTenantID || userValue.AuthVersion != 7 {
		t.Fatalf("v2 identity did not survive migration: %+v err=%v", userValue, err)
	}
	var version int
	if err := value.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("unexpected migrated schema version: %d err=%v", version, err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := value.ConsumeChatForwardSignature(context.Background(), make([]byte, 32), now, time.Minute); err != nil {
		t.Fatalf("v4 replay table is unavailable after migration: %v", err)
	}
	binding := OAuthBinding{SessionTokenHash: TokenHash("session"), TenantID: testTenantID, RuntimeStartedAt: now.Format(time.RFC3339Nano), FlowID: "flow", Target: "https://mcp.example.test", ExpiresAt: now.Add(time.Minute)}
	if err := value.CreateOAuthState(context.Background(), "state", binding, now); err != nil {
		t.Fatalf("v4 OAuth table is unavailable after migration: %v", err)
	}
}

func TestOpenRejectsMalformedSupportedSchemaWithoutAdvancingVersion(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "portal.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE portal_users (id INTEGER PRIMARY KEY); PRAGMA user_version=2;`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, filepath.Join(state, "audit.jsonl")); err == nil {
		t.Fatal("malformed v2 database was accepted and relabelled")
	}
	database, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var version int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 2 {
		t.Fatalf("failed migration advanced schema version: %d err=%v", version, err)
	}
	var tableCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='oauth_states'`).Scan(&tableCount); err != nil || tableCount != 0 {
		t.Fatalf("failed migration was not rolled back: table_count=%d err=%v", tableCount, err)
	}
}

func TestFreshUserAndSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	value := openTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	user, err := value.CreateUser(ctx, "Alice", "hash-placeholder", testTenantID, "workagent_alice", "/srv/workagent/users/"+testTenantID, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if !user.Enabled || !user.Admin || user.TenantID != testTenantID {
		t.Fatalf("unexpected user: %+v", user)
	}
	if err := value.CreateSession(ctx, "opaque-session-token", "opaque-csrf-token", user, "192.0.2.10", "test-agent", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	session, err := value.SessionByToken(ctx, "opaque-session-token")
	if err != nil || session.User.ID != user.ID || session.UserAgentHash == "test-agent" {
		t.Fatalf("unexpected session: %+v, %v", session, err)
	}
	if err := value.SetUserEnabled(ctx, "alice", false, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := value.SessionByToken(ctx, "opaque-session-token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("identity change did not invalidate sessions: %v", err)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ctx := context.Background()
	value := openTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	policy := RatePolicy{Window: time.Minute, Block: 5 * time.Minute, AccountFailures: 2, IPFailures: 5}
	for index := 0; index < 2; index++ {
		if err := value.RecordLoginFailure(ctx, "alice", "192.0.2.20", now, policy); err != nil {
			t.Fatal(err)
		}
	}
	allowed, until, err := value.LoginAllowed(ctx, "alice", "192.0.2.20", now)
	if err != nil || allowed || !until.Equal(now.Add(policy.Block)) {
		t.Fatalf("unexpected rate result: allowed=%v until=%v err=%v", allowed, until, err)
	}
	if err := value.ClearLoginFailures(ctx, "alice", "192.0.2.20"); err != nil {
		t.Fatal(err)
	}
	allowed, _, err = value.LoginAllowed(ctx, "alice", "192.0.2.20", now)
	if err != nil || !allowed {
		t.Fatalf("rate limit did not clear: allowed=%v err=%v", allowed, err)
	}
}

func TestAuditIsPersistedToDatabaseAndJSONL(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	auditPath := filepath.Join(root, "state", "audit.jsonl")
	value, err := Open(filepath.Join(root, "state", "portal.db"), auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	if err := value.Audit(ctx, AuditEvent{Action: "login", Outcome: "success", Username: "alice", TenantID: testTenantID, Details: map[string]any{"method": "password"}}); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(auditPath)
	if err != nil || len(payload) == 0 {
		t.Fatalf("audit log was not persisted: %v", err)
	}
	info, err := os.Stat(auditPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe audit mode: %v %v", info, err)
	}
}

func TestAuditRejectsNestedSensitiveDetails(t *testing.T) {
	value := openTestStore(t)
	err := value.Audit(context.Background(), AuditEvent{Action: "provider", Outcome: "denied", Details: map[string]any{"request": map[string]any{"api_key": "must-not-be-recorded"}}})
	if err == nil {
		t.Fatal("sensitive audit details were accepted")
	}
}

func TestCreateSessionRejectsStaleIdentityAndCleansExpiredSessions(t *testing.T) {
	ctx := context.Background()
	value := openTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	userValue, err := value.CreateUser(ctx, "alice", "hash-placeholder", testTenantID, "workagent_alice", "/srv/workagent/users/"+testTenantID, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := value.CreateSession(ctx, "expired", "expired-csrf", userValue, "192.0.2.10", "agent", now.Add(-2*time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := value.SetUserEnabled(ctx, "alice", false, now); err != nil {
		t.Fatal(err)
	}
	if err := value.CreateSession(ctx, "stale", "stale-csrf", userValue, "192.0.2.10", "agent", now, now.Add(time.Hour)); err == nil {
		t.Fatal("session was created from a stale enabled identity")
	}
}

func TestLoginSuccessDoesNotClearSharedIPThrottle(t *testing.T) {
	ctx := context.Background()
	value := openTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	userValue, err := value.CreateUser(ctx, "alice", "hash-placeholder", testTenantID, "workagent_alice", "/srv/workagent/users/"+testTenantID, false, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := RatePolicy{Window: time.Minute, Block: 5 * time.Minute, AccountFailures: 10, IPFailures: 1}
	if err := value.RecordLoginFailure(ctx, "someone-else", "192.0.2.44", now, policy); err != nil {
		t.Fatal(err)
	}
	if err := value.RecordLoginSuccess(ctx, userValue.ID, userValue.Username, now); err != nil {
		t.Fatal(err)
	}
	allowed, _, err := value.LoginAllowed(ctx, "alice", "192.0.2.44", now)
	if err != nil || allowed {
		t.Fatalf("successful account login erased shared IP throttle: allowed=%v err=%v", allowed, err)
	}
}

func TestOAuthStateIsSessionBoundExpiringAndSingleUse(t *testing.T) {
	value := openTestStore(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	sessionHash := TokenHash("session-one")
	binding := OAuthBinding{SessionTokenHash: sessionHash, TenantID: testTenantID, RuntimeStartedAt: now.Format(time.RFC3339Nano), FlowID: "flow-one", Target: "https://mcp.example.test", ExpiresAt: now.Add(2 * time.Minute)}
	if err := value.CreateOAuthState(context.Background(), "state-one", binding, now); err != nil {
		t.Fatal(err)
	}
	if _, err := value.ConsumeOAuthState(context.Background(), "state-one", TokenHash("other-session"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session OAuth state returned %v", err)
	}
	consumed, err := value.ConsumeOAuthState(context.Background(), "state-one", sessionHash, now)
	if err != nil || consumed.TenantID != binding.TenantID || consumed.FlowID != binding.FlowID || consumed.RuntimeStartedAt != binding.RuntimeStartedAt {
		t.Fatalf("unexpected OAuth binding: %+v err=%v", consumed, err)
	}
	if _, err := value.ConsumeOAuthState(context.Background(), "state-one", sessionHash, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed OAuth state returned %v", err)
	}
	if err := value.CreateOAuthState(context.Background(), "expired-state", binding, now); err != nil {
		t.Fatal(err)
	}
	if _, err := value.ConsumeOAuthState(context.Background(), "expired-state", sessionHash, binding.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired OAuth state returned %v", err)
	}
}

func TestOpenRejectsSymlinkedState(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(real, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(linked, "portal.db"), filepath.Join(linked, "audit.jsonl")); err == nil {
		t.Fatal("symlinked state directory was accepted")
	}
}

func TestAuditRetentionPreservesConfiguredMinimum(t *testing.T) {
	value := openTestStore(t)
	ctx := context.Background()
	start := time.Unix(1_700_000_000, 0).UTC()
	for index := 0; index < 5; index++ {
		if err := value.Audit(ctx, AuditEvent{OccurredAt: start.Add(time.Duration(index) * time.Hour), Action: "fixture", Outcome: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := value.PruneAudit(ctx, start.Add(24*time.Hour), 3)
	if err != nil {
		t.Fatal(err)
	}
	count, err := value.AuditEventCount(ctx)
	if err != nil || deleted != 2 || count != 3 {
		t.Fatalf("unexpected retained audit counts: deleted=%d count=%d err=%v", deleted, count, err)
	}
	payload, err := os.ReadFile(value.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if line != "" {
			lines++
		}
	}
	if lines != 3 {
		t.Fatalf("audit file retained %d events", lines)
	}
}
