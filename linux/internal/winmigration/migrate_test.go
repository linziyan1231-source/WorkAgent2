//go:build linux

package winmigration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type migrationFixture struct {
	options              Options
	sid                  string
	tenantSource         string
	externalWindowsPath  string
	externalCapture      string
	manifestPath         string
	codexSecret          string
	kimiSecret           string
	messageWindowsText   string
	externalFileContents string
}

func TestMigrationEndToEnd(t *testing.T) {
	fixture := createMigrationFixture(t)

	withoutManifest := fixture.options
	withoutManifest.ExternalWorkspaceManifest = ""
	withoutManifest.DryRun = true
	if _, err := Migrate(context.Background(), withoutManifest); err == nil || !strings.Contains(err.Error(), "without an exact external-workspace mapping") {
		t.Fatalf("missing manifest error = %v", err)
	}

	dryRun := fixture.options
	dryRun.DryRun = true
	planned, err := Migrate(context.Background(), dryRun)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if planned.Status != "planned" || planned.Portal.Users != 1 || planned.Portal.InvalidatedSessions != 1 || planned.Portal.InvalidatedOAuthStates != 1 {
		t.Fatalf("unexpected dry-run report: %+v", planned)
	}
	if _, err := os.Lstat(fixture.options.StagingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run created staging output: %v", err)
	}
	tenantPlan := planned.Tenants[0]
	if tenantPlan.PathRewrites.UnmappedExternalWindowsPaths != 0 || tenantPlan.PathRewrites.ConversationWorkspaces != 1 || len(tenantPlan.ExternalWorkspaces) != 1 {
		t.Fatalf("unexpected external path plan: %+v", tenantPlan)
	}
	workspacePlan := tenantPlan.ExternalWorkspaces[0]
	if workspacePlan.Files != 2 || workspacePlan.Directories != 1 || workspacePlan.DestinationRelative != "workspace/imported/project" {
		t.Fatalf("unexpected external workspace plan: %+v", workspacePlan)
	}

	complete, err := Migrate(context.Background(), fixture.options)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if complete.Status != "complete" || complete.OutputFingerprint == "" {
		t.Fatalf("migration did not complete: %+v", complete)
	}
	publication, err := VerifyPublicationStage(context.Background(), fixture.options.StagingDir, complete.SourceFingerprint, complete.OutputFingerprint, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("verify publication stage: %v", err)
	}
	if publication.PortalSHA256 == "" || len(publication.Tenants) != 1 || publication.Tenants[complete.Tenants[0].TenantID].Payload.Files == 0 {
		t.Fatalf("unexpected publication inventory: %+v", publication)
	}
	tenantID := complete.Tenants[0].TenantID
	tenantRoot := filepath.Join(fixture.options.StagingDir, "tenants", tenantID)
	verifyMigratedPortalFixture(t, fixture, tenantID)
	verifyMigratedAionFixture(t, fixture, tenantRoot, tenantID)
	verifyMigratedFilesFixture(t, fixture, tenantRoot)

	resultAgain, err := Migrate(context.Background(), fixture.options)
	if err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	if resultAgain.OutputFingerprint != complete.OutputFingerprint || resultAgain.SourceFingerprint != complete.SourceFingerprint {
		t.Fatal("idempotent rerun returned different fingerprints")
	}
}

func TestMigrationIncludesUncheckpointedPortalWALAndArchivesExactTrio(t *testing.T) {
	fixture := createMigrationFixture(t)
	snapshotPath := filepath.Join(fixture.options.SnapshotRoot, filepath.FromSlash(sourcePortalRelative))
	installUncheckpointedPortalWALFixture(t, snapshotPath, fixture.sid)
	before := snapshotFileDigests(t, snapshotPath)

	workBase := filepath.Join(filepath.Dir(fixture.options.SnapshotRoot), "portal-working-copies")
	if err := os.Mkdir(workBase, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", workBase)

	dryRun := fixture.options
	dryRun.DryRun = true
	planned, err := Migrate(context.Background(), dryRun)
	if err != nil {
		t.Fatalf("plan WAL-backed Portal snapshot: %v", err)
	}
	if planned.Portal.AuditEvents != 2 {
		t.Fatalf("planned audit rows = %d, want 2 including WAL", planned.Portal.AuditEvents)
	}
	wantedHashes := []string{
		hex.EncodeToString(before[0][:]),
		hex.EncodeToString(before[1][:]),
		hex.EncodeToString(before[2][:]),
	}
	if got := []string{planned.SourcePortalSHA256, planned.SourcePortalWALSHA256, planned.SourcePortalSHMSHA256}; !slicesEqual(got, wantedHashes) {
		t.Fatalf("planned Portal source hashes = %v, want %v", got, wantedHashes)
	}
	assertDirectoryEmpty(t, workBase)

	completed, err := Migrate(context.Background(), fixture.options)
	if err != nil {
		t.Fatalf("migrate WAL-backed Portal snapshot: %v", err)
	}
	if completed.Portal.AuditEvents != 2 {
		t.Fatalf("migrated audit rows = %d, want 2 including WAL", completed.Portal.AuditEvents)
	}
	if after := snapshotFileDigests(t, snapshotPath); after != before {
		t.Fatalf("migration mutated the frozen DB/WAL/SHM source: before=%v after=%v", before, after)
	}
	backupPath := filepath.Join(fixture.options.StagingDir, "backups", "portal.windows.db")
	if archived := snapshotFileDigests(t, backupPath); archived != before {
		t.Fatalf("archived DB/WAL/SHM set differs from source: got=%v want=%v", archived, before)
	}
	assertDirectoryEmpty(t, workBase)

	database := openReadOnlyFixture(t, filepath.Join(fixture.options.StagingDir, "portal", "portal.db"))
	defer database.Close()
	var details string
	if err := database.QueryRow(`SELECT details_json FROM audit_events WHERE id=10`).Scan(&details); err != nil || details != `{"from":"wal"}` {
		t.Fatalf("WAL-only audit row was not migrated: details=%q err=%v", details, err)
	}
}

func TestPlanRequiresCompletePortalSQLiteTrioAndCleansWorkingCopy(t *testing.T) {
	for _, missing := range []string{sourcePortalWALRelative, sourcePortalSHMRelative} {
		t.Run(filepath.Base(missing), func(t *testing.T) {
			fixture := createMigrationFixture(t)
			if err := os.Remove(filepath.Join(fixture.options.SnapshotRoot, filepath.FromSlash(missing))); err != nil {
				t.Fatal(err)
			}
			options := fixture.options
			options.DryRun = true
			if _, err := Migrate(context.Background(), options); err == nil || !strings.Contains(err.Error(), "inspect Windows Portal") {
				t.Fatalf("missing SQLite companion error = %v", err)
			}
		})
	}

	t.Run("later planning failure", func(t *testing.T) {
		fixture := createMigrationFixture(t)
		workBase := filepath.Join(filepath.Dir(fixture.options.SnapshotRoot), "failed-portal-working-copies")
		if err := os.Mkdir(workBase, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TMPDIR", workBase)
		if err := os.Remove(fixture.manifestPath); err != nil {
			t.Fatal(err)
		}
		options := fixture.options
		options.DryRun = true
		if _, err := Migrate(context.Background(), options); err == nil {
			t.Fatal("planning unexpectedly succeeded without its external workspace manifest")
		}
		assertDirectoryEmpty(t, workBase)
	})

	t.Run("unsafe temporary parent", func(t *testing.T) {
		fixture := createMigrationFixture(t)
		unsafeBase := filepath.Join(filepath.Dir(fixture.options.SnapshotRoot), "unsafe-portal-working-copies")
		if err := os.Mkdir(unsafeBase, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafeBase, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TMPDIR", unsafeBase)
		options := fixture.options
		options.DryRun = true
		if _, err := Migrate(context.Background(), options); err == nil || !strings.Contains(err.Error(), "not private or root-owned sticky") {
			t.Fatalf("unsafe temporary parent error = %v", err)
		}
		assertDirectoryEmpty(t, unsafeBase)
	})
}

func installUncheckpointedPortalWALFixture(t *testing.T, snapshotPath, sid string) {
	t.Helper()
	livePath := filepath.Join(t.TempDir(), "portal-live.db")
	createPortalFixture(t, livePath, sid)
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(livePath)+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA wal_autocheckpoint=0`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
	} {
		if _, err := database.Exec(statement); err != nil {
			database.Close()
			t.Fatalf("prepare WAL fixture with %q: %v", statement, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO audit_events VALUES(10,1020,'wal-fixture','success','Alice',?, '127.0.0.1','{"from":"wal"}')`, sid); err != nil {
		database.Close()
		t.Fatal(err)
	}
	walInfo, err := os.Stat(livePath + "-wal")
	if err != nil || walInfo.Size() == 0 {
		database.Close()
		t.Fatalf("fixture has no uncheckpointed WAL: info=%v err=%v", walInfo, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(snapshotPath + suffix); err != nil {
			database.Close()
			t.Fatal(err)
		}
		writeFixture(t, snapshotPath+suffix, readFixture(t, livePath+suffix), 0o600)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("private Portal working directory leaked entries: %v", entries)
	}
}

func slicesEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func TestPlanRejectsUnsafeTenantEntries(t *testing.T) {
	t.Run("unapproved symlink", func(t *testing.T) {
		fixture := createMigrationFixture(t)
		if err := os.Symlink("/etc/passwd", filepath.Join(fixture.tenantSource, "bad-link")); err != nil {
			t.Fatal(err)
		}
		options := fixture.options
		options.DryRun = true
		if _, err := Migrate(context.Background(), options); err == nil || !strings.Contains(err.Error(), "not an approved same-tenant builtin-skills link") {
			t.Fatalf("unsafe symlink error = %v", err)
		}
	})

	t.Run("special file", func(t *testing.T) {
		fixture := createMigrationFixture(t)
		if err := unix.Mkfifo(filepath.Join(fixture.tenantSource, "unsafe-fifo"), 0o600); err != nil {
			t.Fatal(err)
		}
		options := fixture.options
		options.DryRun = true
		if _, err := Migrate(context.Background(), options); err == nil || !strings.Contains(err.Error(), "not a regular file, directory, or symbolic link") {
			t.Fatalf("special file error = %v", err)
		}
	})

	t.Run("non-private manifest", func(t *testing.T) {
		fixture := createMigrationFixture(t)
		if err := os.Chmod(fixture.manifestPath, 0o644); err != nil {
			t.Fatal(err)
		}
		options := fixture.options
		options.DryRun = true
		if _, err := Migrate(context.Background(), options); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
			t.Fatalf("public manifest error = %v", err)
		}
	})
}

func createMigrationFixture(t *testing.T) migrationFixture {
	t.Helper()
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot")
	stage := filepath.Join(root, "stage")
	sid := "S-1-5-21-111-222-333-1001"
	tenantSource := filepath.Join(snapshot, "tenants", "raw", sid, "AionUiPortal")
	for _, directory := range []string{
		filepath.Join(snapshot, "global"),
		filepath.Join(snapshot, "cliproxy"),
		filepath.Join(tenantSource, "config", "codex"),
		filepath.Join(tenantSource, "credentials"),
		filepath.Join(tenantSource, "profile", ".kimi-code"),
		filepath.Join(tenantSource, "data", "builtin-skills"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	createPortalFixture(t, filepath.Join(snapshot, sourcePortalRelative), sid)
	// A frozen capture always contains the complete SQLite trio. DELETE-mode
	// fixtures have no pending WAL, so represent that valid state with empty
	// companion files.
	writeFixture(t, filepath.Join(snapshot, sourcePortalWALRelative), nil, 0o600)
	writeFixture(t, filepath.Join(snapshot, sourcePortalSHMRelative), nil, 0o600)

	codexSecret := "test-codex-secret"
	kimiSecret := "test-kimi-secret"
	legacyState := map[string]any{
		"version": 1,
		"keys": []map[string]any{
			{"id": "alice-chatgpt", "name": "alice Codex", "enabled": true, "key_hash": keyHash(codexSecret), "daily_limit_usd": 20, "weekly_limit_usd": 40},
			{"id": "alice-kimi", "name": "alice Kimi", "enabled": true, "key_hash": keyHash(kimiSecret), "daily_limit_usd": 5, "weekly_limit_usd": 10},
		},
		"usage": map[string]any{
			"alice-chatgpt": map[string]any{"daily_spend_usd": "3.5"},
			"alice-kimi":    map[string]any{"daily_spend_usd": "1.0"},
		},
	}
	writeJSONFixture(t, filepath.Join(snapshot, legacyCPAStateRelative), legacyState, 0o600)
	marker := legacyBootstrapMarker{FormatVersion: 1, BaseURL: "http://127.0.0.1:8317/v1", CodexKeyID: "alice-chatgpt", KimiKeyID: "alice-kimi", CodexDefaultModel: "model-a", KimiDefaultModel: "model-b", CodexModels: []string{"model-a"}, KimiModels: []string{"model-b"}}
	writeJSONFixture(t, filepath.Join(tenantSource, "config", "model-bootstrap-v1.applied.json"), marker, 0o600)
	writeJSONFixture(t, filepath.Join(tenantSource, "config", "codex", "auth.json"), map[string]any{"auth_mode": "apikey", "OPENAI_API_KEY": codexSecret}, 0o600)
	writeFixture(t, filepath.Join(tenantSource, "config", "codex", "config.toml"), []byte("# custom comment\ncustom_setting = \"keep\"\n# Initial CLIProxyAPI settings managed by WorkAgent2.\nopenai_base_url = \"http://legacy.invalid/v1\"\nmodel = \"managed-model\"\n[profiles.custom]\nmodel = \"custom-model\"\n"), 0o600)
	writeFixture(t, filepath.Join(tenantSource, "profile", ".kimi-code", "config.toml"), []byte("default_model = \"managed:kimi-code\"\ncustom_setting = \"keep\"\n[providers.\"managed:kimi-code\"]\napi_key = \""+kimiSecret+"\"\nbase_url = \"http://legacy.invalid/v1\"\n[providers.custom]\napi_key = \"custom-preserved\"\n"), 0o600)
	writeFixture(t, filepath.Join(tenantSource, "data", "builtin-skills", "actual.txt"), []byte("builtin\n"), 0o600)
	if err := os.Symlink(`C:\Users\alice\AionUiPortal\data\builtin-skills\actual.txt`, filepath.Join(tenantSource, "data", "builtin-skills", "alias.txt")); err != nil {
		t.Fatal(err)
	}

	externalWindowsPath := `C:\projects\external-fixture`
	messageWindowsText := "message mentions " + externalWindowsPath + " and must remain unchanged"
	createAionFixture(t, filepath.Join(tenantSource, "data", "aionui-backend.db"), externalWindowsPath, messageWindowsText)

	externalCapture := filepath.Join(snapshot, "external-workspaces", "alice-project")
	if err := os.MkdirAll(filepath.Join(externalCapture, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	externalFileContents := "production source fixture\n"
	writeFixture(t, filepath.Join(externalCapture, "README.md"), []byte(externalFileContents), 0o600)
	writeFixture(t, filepath.Join(externalCapture, "src", "main.js"), []byte("export const ready = true;\n"), 0o600)
	totalBytes := int64(len(externalFileContents) + len("export const ready = true;\n"))
	largest := int64(len(externalFileContents))
	if candidate := int64(len("export const ready = true;\n")); candidate > largest {
		largest = candidate
	}
	manifest := externalWorkspaceManifest{
		SchemaVersion: 1,
		Workspaces: []externalWorkspaceManifestEntry{{
			TenantWindowsSID: sid, WindowsPath: externalWindowsPath,
			SourceRelative: "external-workspaces/alice-project", DestinationRelative: "workspace/imported/project",
			ExcludedPaths: []string{"node_modules", "backend/.venv"},
			SourceSummary: ExternalWorkspaceSourceSummary{Files: 2, Directories: 2, Bytes: totalBytes, LargestFileBytes: largest, GitBranch: "main", GitTrackedFiles: 2},
		}},
	}
	manifestPath := filepath.Join(snapshot, "external-workspaces.json")
	writeJSONFixture(t, manifestPath, manifest, 0o600)
	return migrationFixture{
		options: Options{SnapshotRoot: snapshot, StagingDir: stage, TenantDataRoot: "/srv/workagent/users", ExternalWorkspaceManifest: manifestPath},
		sid:     sid, tenantSource: tenantSource, externalWindowsPath: externalWindowsPath, externalCapture: externalCapture,
		manifestPath: manifestPath, codexSecret: codexSecret, kimiSecret: kimiSecret, messageWindowsText: messageWindowsText,
		externalFileContents: externalFileContents,
	}
}

func createPortalFixture(t *testing.T, target, sid string) {
	t.Helper()
	database := openFixtureDatabase(t, target)
	defer database.Close()
	const schema = `
CREATE TABLE portal_users (id INTEGER PRIMARY KEY, username TEXT, username_norm TEXT, password_hash TEXT, windows_sid TEXT, windows_username TEXT, enabled INTEGER, is_admin INTEGER, auth_version INTEGER, created_at INTEGER, updated_at INTEGER, last_login_at INTEGER);
CREATE TABLE portal_sessions (token_hash BLOB, user_id INTEGER, auth_version INTEGER, created_at INTEGER, expires_at INTEGER, last_seen_at INTEGER, remote_ip TEXT, user_agent_hash TEXT);
CREATE TABLE login_limits (limit_key TEXT, window_start INTEGER, failures INTEGER, blocked_until INTEGER);
CREATE TABLE oauth_states (state_hash BLOB, session_token_hash BLOB, windows_sid TEXT, instance_id TEXT, target TEXT, expires_at INTEGER, used_at INTEGER, flow_id TEXT);
CREATE TABLE audit_events (id INTEGER PRIMARY KEY, occurred_at INTEGER, action TEXT, outcome TEXT, username TEXT, windows_sid TEXT, remote_ip TEXT, details_json TEXT);
CREATE TABLE chatgpt_pro_limits (user_id INTEGER, weekly_limit INTEGER, updated_at INTEGER);
CREATE TABLE chatgpt_pro_usage (id INTEGER PRIMARY KEY, user_id INTEGER, logical_send_id TEXT, week_start INTEGER, requested_model TEXT, thinking_effort TEXT, status TEXT, reserved_at INTEGER, finished_at INTEGER, upstream_status INTEGER, stream_completed INTEGER, served_models_json TEXT);
CREATE TABLE chatgpt_pro_events (id INTEGER PRIMARY KEY, user_id INTEGER, usage_id INTEGER, kind TEXT, occurred_at INTEGER, acknowledged_at INTEGER);
PRAGMA user_version=3;`
	if _, err := database.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO portal_users VALUES(1,'Alice','alice','$fixture-password-hash',?,'MACHINE\alice',1,1,7,1000,1100,1050)`, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO portal_sessions VALUES(zeroblob(32),1,7,1000,2000,1100,'127.0.0.1','ua')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO oauth_states VALUES(zeroblob(32),zeroblob(32),?,'instance','codex',2000,NULL,'flow')`, sid); err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`INSERT INTO login_limits VALUES('account:alice',1000,2,0)`,
		`INSERT INTO audit_events VALUES(9,1010,'login','success','Alice',?, '127.0.0.1','{"fixture":true}')`,
		`INSERT INTO chatgpt_pro_limits VALUES(1,50,1000)`,
		`INSERT INTO chatgpt_pro_usage VALUES(3,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1000,'gpt-fixture','low','confirmed_fallback',1000,1010,200,1,'["gpt-fixture"]')`,
		`INSERT INTO chatgpt_pro_events VALUES(4,1,3,'confirmed_fallback',1010,NULL)`,
	}
	for _, statement := range statements {
		var err error
		if strings.Contains(statement, "audit_events") {
			_, err = database.Exec(statement, sid)
		} else {
			_, err = database.Exec(statement)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func createAionFixture(t *testing.T, target, externalWindowsPath, messageWindowsText string) {
	t.Helper()
	database := openFixtureDatabase(t, target)
	defer database.Close()
	const schema = `
CREATE TABLE skills (path TEXT);
CREATE TABLE teams (workspace TEXT);
CREATE TABLE assistant_sessions (workspace TEXT);
CREATE TABLE conversations (extra TEXT);
CREATE TABLE cron_jobs (agent_config TEXT);
CREATE TABLE messages (content TEXT);
CREATE TABLE providers (id TEXT, api_key_encrypted TEXT);`
	if _, err := database.Exec(schema); err != nil {
		t.Fatal(err)
	}
	conversationExtra, err := json.Marshal(map[string]any{
		"workspace":     externalWindowsPath,
		"default_files": []string{`C:\Users\alice\AionUiPortal\profile\project\file.txt`, externalWindowsPath + `\src\main.js`},
		"custom":        "preserve",
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO skills VALUES(?)`, []any{`C:\Users\alice\AionUiPortal\data\builtin-skills\actual.txt`}},
		{`INSERT INTO teams VALUES(?)`, []any{`C:\Users\alice\AionUiPortal\profile\project`}},
		{`INSERT INTO assistant_sessions VALUES(?)`, []any{`C:\Users\alice\AionUiPortal\profile\project`}},
		{`INSERT INTO conversations VALUES(?)`, []any{string(conversationExtra)}},
		{`INSERT INTO cron_jobs VALUES(?)`, []any{`{"workspace":"C:\\Users\\alice\\AionUiPortal\\profile\\cron"}`}},
		{`INSERT INTO messages VALUES(?)`, []any{messageWindowsText}},
		{`INSERT INTO providers VALUES('managed-cliproxy-chatgpt','ciphertext')`, nil},
		{`INSERT INTO providers VALUES('managed-cliproxy-kimi','ciphertext')`, nil},
		{`INSERT INTO providers VALUES('custom-provider','custom-ciphertext')`, nil},
	}
	for _, row := range rows {
		if _, err := database.Exec(row.query, row.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func openFixtureDatabase(t *testing.T, target string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(target)+"?_pragma=foreign_keys(1)&_pragma=journal_mode(DELETE)")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	return database
}

func verifyMigratedPortalFixture(t *testing.T, fixture migrationFixture, tenantID string) {
	t.Helper()
	database := openReadOnlyFixture(t, filepath.Join(fixture.options.StagingDir, "portal", "portal.db"))
	defer database.Close()
	var username, passwordHash, migratedTenant string
	var authVersion int64
	if err := database.QueryRow(`SELECT username,password_hash,tenant_id,auth_version FROM portal_users WHERE id=1`).Scan(&username, &passwordHash, &migratedTenant, &authVersion); err != nil {
		t.Fatal(err)
	}
	if username != "Alice" || passwordHash != "$fixture-password-hash" || migratedTenant != tenantID || authVersion != 7 {
		t.Fatal("Portal identity fields were not preserved")
	}
	for _, table := range []string{"portal_sessions", "oauth_states"} {
		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s was not invalidated", table)
		}
	}
	var auditTenant string
	if err := database.QueryRow(`SELECT tenant_id FROM audit_events WHERE id=9`).Scan(&auditTenant); err != nil || auditTenant != tenantID {
		t.Fatal("audit SID was not mapped to the tenant ID")
	}
}

func verifyMigratedAionFixture(t *testing.T, fixture migrationFixture, tenantRoot, tenantID string) {
	t.Helper()
	database := openReadOnlyFixture(t, filepath.Join(tenantRoot, "data", "aionui-backend.db"))
	defer database.Close()
	wantedTenantRoot := filepath.Join(fixture.options.TenantDataRoot, tenantID)
	var workspace string
	if err := database.QueryRow(`SELECT json_extract(extra,'$.workspace') FROM conversations`).Scan(&workspace); err != nil {
		t.Fatal(err)
	}
	if workspace != filepath.Join(wantedTenantRoot, "workspace", "imported", "project") {
		t.Fatalf("external workspace = %q", workspace)
	}
	var firstDefault, secondDefault, custom string
	if err := database.QueryRow(`SELECT json_extract(extra,'$.default_files[0]'),json_extract(extra,'$.default_files[1]'),json_extract(extra,'$.custom') FROM conversations`).Scan(&firstDefault, &secondDefault, &custom); err != nil {
		t.Fatal(err)
	}
	if firstDefault != filepath.Join(wantedTenantRoot, "home", "project", "file.txt") || secondDefault != filepath.Join(wantedTenantRoot, "workspace", "imported", "project", "src", "main.js") || custom != "preserve" {
		t.Fatal("conversation JSON path fields were not rewritten precisely")
	}
	var message string
	if err := database.QueryRow(`SELECT content FROM messages`).Scan(&message); err != nil || message != fixture.messageWindowsText {
		t.Fatal("message content was unexpectedly rewritten")
	}
	var managed, customProviders int
	if err := database.QueryRow(`SELECT COUNT(*) FROM providers WHERE id LIKE 'managed-cliproxy-%'`).Scan(&managed); err != nil || managed != 0 {
		t.Fatal("managed providers remain")
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM providers WHERE id='custom-provider'`).Scan(&customProviders); err != nil || customProviders != 1 {
		t.Fatal("custom provider was removed")
	}
}

func verifyMigratedFilesFixture(t *testing.T, fixture migrationFixture, tenantRoot string) {
	t.Helper()
	for _, relative := range []string{"config/model-bootstrap-v1.applied.json", "config/codex/auth.json", "credentials/model-bootstrap-v1.pending.json"} {
		if _, err := os.Lstat(filepath.Join(tenantRoot, filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalidated file remains: %s", relative)
		}
	}
	codexConfig := readFixture(t, filepath.Join(tenantRoot, "config", "codex", "config.toml"))
	if !bytes.Contains(codexConfig, []byte(`custom_setting = "keep"`)) || !bytes.Contains(codexConfig, []byte(`[profiles.custom]`)) || bytes.Contains(codexConfig, []byte("legacy.invalid")) {
		t.Fatal("Codex custom configuration was not preserved precisely")
	}
	kimiConfig := readFixture(t, filepath.Join(tenantRoot, "home", ".kimi-code", "config.toml"))
	if !bytes.Contains(kimiConfig, []byte(`[providers.custom]`)) || !bytes.Contains(kimiConfig, []byte("custom-preserved")) || bytes.Contains(kimiConfig, []byte(fixture.kimiSecret)) {
		t.Fatal("Kimi custom configuration was not preserved precisely")
	}
	linkTarget, err := os.Readlink(filepath.Join(tenantRoot, "data", "builtin-skills", "alias.txt"))
	if err != nil || filepath.IsAbs(linkTarget) || linkTarget != "actual.txt" {
		t.Fatalf("rewritten builtin link = %q, %v", linkTarget, err)
	}
	externalReadme := readFixture(t, filepath.Join(tenantRoot, "workspace", "imported", "project", "README.md"))
	if string(externalReadme) != fixture.externalFileContents {
		t.Fatal("external workspace file was not copied")
	}
	for _, relative := range []string{"node_modules", "backend/.venv"} {
		if _, err := os.Lstat(filepath.Join(tenantRoot, "workspace", "imported", "project", filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("excluded workspace path was staged: %s", relative)
		}
	}
	cutover := readFixture(t, filepath.Join(fixture.options.StagingDir, "cutover", "cliproxy-quota-overrides.json"))
	if bytes.Contains(cutover, []byte(fixture.codexSecret)) || bytes.Contains(cutover, []byte(fixture.kimiSecret)) || !bytes.Contains(cutover, []byte(`"daily_limit_usd": "20"`)) {
		t.Fatal("cutover plan leaks a key or omits quota state")
	}
	report := readFixture(t, filepath.Join(fixture.options.StagingDir, "report.json"))
	if bytes.Contains(report, []byte(fixture.externalWindowsPath)) || bytes.Contains(report, []byte(strings.ReplaceAll(fixture.externalWindowsPath, `\`, "/"))) {
		t.Fatal("public report contains the external Windows path")
	}
	if err := filepath.WalkDir(fixture.options.StagingDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 != 0 {
			return errors.New("staged entry is not private")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func openReadOnlyFixture(t *testing.T, target string) *sql.DB {
	t.Helper()
	database, err := openReadOnlySQLite(target)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func writeJSONFixture(t *testing.T, target string, value any, mode os.FileMode) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, target, append(payload, '\n'), mode)
}

func writeFixture(t *testing.T, target string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, payload, mode); err != nil {
		t.Fatal(err)
	}
}

func readFixture(t *testing.T, target string) []byte {
	t.Helper()
	payload, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
