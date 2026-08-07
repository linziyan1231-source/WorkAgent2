package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenMigratesExistingOAuthStateTableWithFlowBinding(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "portal.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE oauth_states (
 state_hash BLOB PRIMARY KEY, session_token_hash BLOB NOT NULL, windows_sid TEXT NOT NULL,
 instance_id TEXT NOT NULL, target TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path, filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('oauth_states') WHERE name='flow_id' AND "notnull"=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("flow_id migration missing: count=%d err=%v", count, err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	s, err := Open(filepath.Join(root, "portal.db"), filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAdministratorIsSeparateFromManagedUsers(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	admin, err := s.CreateAdministrator(ctx, "admin", "admin-hash", now)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.Admin || admin.WindowsSID != "portal-admin:admin" || admin.WindowsUsername != "portal-admin:admin" {
		t.Fatalf("administrator identity mismatch: %+v", admin)
	}
	if _, err := s.CreateAdministrator(ctx, "second-admin", "admin-hash", now); err == nil {
		t.Fatal("second Portal administrator was accepted")
	}
	if _, err := s.CreateUser(ctx, "employee", "employee-hash", "S-1-5-21-1-1009", `SERVER\employee`, false, now); err != nil {
		t.Fatal(err)
	}
	users, err := s.ListManagedUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "employee" || users[0].Admin {
		t.Fatalf("managed users included the administrator: %+v", users)
	}
}

func TestSessionInvalidatedByPasswordResetAndDisable(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	u, err := s.CreateUser(ctx, "Alice", "hash-one", "S-1-5-21-1-1001", `SERVER\alice-run`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "token-one", u, time.Hour, "192.0.2.1", "browser-a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, "token-one", 30*time.Minute, now.Add(time.Minute)); err != nil {
		t.Fatalf("fresh session not found: %v", err)
	}
	if err := s.ResetPassword(ctx, "ALICE", "hash-two", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, "token-one", 30*time.Minute, now.Add(3*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password reset did not invalidate session: %v", err)
	}
	u, _ = s.UserByUsername(ctx, "alice")
	if err := s.CreateSession(ctx, "token-two", u, time.Hour, "192.0.2.1", "browser-b", now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserEnabled(ctx, "alice", false, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, "token-two", 30*time.Minute, now.Add(6*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable did not invalidate session: %v", err)
	}
}

func TestStaleUserCannotCreateSessionAfterDisable(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	stale, err := s.CreateUser(ctx, "stale-user", "hash-one", "S-1-5-21-1-1002", `SERVER\stale-run`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserEnabled(ctx, stale.Username, false, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, "must-not-exist", stale, time.Hour, "192.0.2.2", "browser", now.Add(2*time.Second)); err == nil {
		t.Fatal("stale enabled user object created a session after the database account was disabled")
	}
	if _, err := s.Session(ctx, "must-not-exist", time.Hour, now.Add(3*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled-user session row was usable: %v", err)
	}
}

func TestLoginRateLimitThresholdIsDeterministic(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	policy := RatePolicy{Window: 15 * time.Minute, Block: 10 * time.Minute, AccountFailures: 3, IPFailures: 10}
	for i := 0; i < 2; i++ {
		if err := s.RecordLoginFailure(ctx, "alice", "192.0.2.10", policy, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
		allowed, _, err := s.LoginAllowed(ctx, "alice", "192.0.2.10", now.Add(time.Duration(i+1)*time.Second))
		if err != nil || !allowed {
			t.Fatalf("blocked before threshold: allowed=%v err=%v", allowed, err)
		}
	}
	if err := s.RecordLoginFailure(ctx, "alice", "192.0.2.10", policy, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	allowed, until, err := s.LoginAllowed(ctx, "alice", "192.0.2.10", now.Add(3*time.Second))
	if err != nil || allowed || !until.Equal(now.Add(2*time.Second+policy.Block)) {
		t.Fatalf("threshold block mismatch: allowed=%v until=%v err=%v", allowed, until, err)
	}
}

func TestOAuthStateIsSessionBoundAndSingleUse(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	binding := OAuthBinding{SessionTokenHash: TokenHash("portal-session"), WindowsSID: "S-1-5-21-1-1001", InstanceID: "instance-7", FlowID: "opaque-flow-9", Target: "https://mcp.example.test", ExpiresAt: now.Add(5 * time.Minute)}
	if err := s.CreateOAuthState(ctx, "oauth-state", binding); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOAuthState(ctx, "oauth-state", TokenHash("other-session"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("state accepted for another session: %v", err)
	}
	got, err := s.ConsumeOAuthState(ctx, "oauth-state", TokenHash("portal-session"), now)
	if err != nil || got.WindowsSID != binding.WindowsSID || got.InstanceID != binding.InstanceID || got.FlowID != binding.FlowID || got.Target != binding.Target {
		t.Fatalf("valid state failed: got=%+v err=%v", got, err)
	}
	if _, err := s.ConsumeOAuthState(ctx, "oauth-state", TokenHash("portal-session"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("state was reusable: %v", err)
	}
}

func TestOAuthStateExpiresWithoutBecomingConsumable(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Unix(1_700_000_000, 0)
	binding := OAuthBinding{SessionTokenHash: TokenHash("portal-session"), WindowsSID: "S-1-5-21-1-1001", InstanceID: "instance-8",
		FlowID: "opaque-flow-10", Target: "https://mcp.example.test", ExpiresAt: now.Add(2 * time.Minute)}
	if err := s.CreateOAuthState(ctx, "expiring-oauth-state", binding); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOAuthState(ctx, "expiring-oauth-state", TokenHash("portal-session"), binding.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired OAuth state was accepted: %v", err)
	}
}

func TestAuditRejectsSensitiveKeys(t *testing.T) {
	s := openTestStore(t)
	err := s.Audit(context.Background(), "login", "failure", "alice", "", "192.0.2.2", map[string]any{"internal_cookie": "must-not-log"}, time.Now())
	if err == nil {
		t.Fatal("sensitive audit details were accepted")
	}
}
