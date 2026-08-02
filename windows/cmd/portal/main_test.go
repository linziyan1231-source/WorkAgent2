package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aionuiportal/internal/admin"
	"aionuiportal/internal/store"
)

func TestKimiOAuthCommandIsDisabled(t *testing.T) {
	err := dispatch(context.Background(), nil, []string{"kimi-oauth", "seed", "test1"})
	if err == nil || err.Error() != "native Kimi OAuth has been removed; use model-bootstrap provision --update with the user's CLIProxyAPI keys" {
		t.Fatalf("disabled Kimi OAuth command returned %v", err)
	}
}

func TestProvisionErrorCodeClassifiesAccountConflicts(t *testing.T) {
	tests := map[string]string{
		"Portal username already exists":                                "PORTAL_USERNAME_EXISTS",
		"an unmanaged Windows account already uses this username":       "WINDOWS_USERNAME_EXISTS",
		"Windows account is already mapped to Portal user employee-two": "WINDOWS_ACCOUNT_MAPPED",
		"existing Portal account does not match the Windows account":    "ACCOUNT_CONFLICT",
		"Set-UserDiskQuota.ps1 failed":                                  "PROVISION_FAILED",
	}
	for message, want := range tests {
		if got := provisionErrorCode(errors.New(message)); got != want {
			t.Errorf("provisionErrorCode(%q)=%q want %q", message, got, want)
		}
	}
}

func TestCopyFileHashVerifiesDurableBackup(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "aionui-backend.db")
	destination := filepath.Join(root, "backup", "aionui-backend.db")
	if err := os.Mkdir(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3<<20)
	for index := range data {
		data[index] = byte(index % 251)
	}
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := copyFile(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	if hash != hex.EncodeToString(expected[:]) {
		t.Fatalf("backup hash=%s want=%x", hash, expected)
	}
	copied, err := os.ReadFile(destination)
	if err != nil || len(copied) != len(data) {
		t.Fatalf("backup copy size=%d err=%v", len(copied), err)
	}
	if _, err := copyFile(source, destination); err == nil {
		t.Fatal("existing immutable backup was overwritten")
	}
}

func TestSnapshotSQLiteDatabaseCapturesCommittedWALData(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "live.db")
	destination := filepath.Join(root, "backup.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(source)+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE work (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO work(value) VALUES ('completed')`); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotSQLiteDatabase(context.Background(), source, destination); err != nil {
		t.Fatal(err)
	}
	backup, err := sql.Open("sqlite", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var value string
	if err := backup.QueryRow(`SELECT value FROM work WHERE id=1`).Scan(&value); err != nil || value != "completed" {
		t.Fatalf("snapshot value=%q err=%v", value, err)
	}
	if _, err := snapshotSQLiteDatabase(context.Background(), source, destination); err == nil {
		t.Fatal("existing immutable SQLite snapshot was overwritten")
	}
}

func TestReleaseBackupSkipsPortalAdministrator(t *testing.T) {
	data, err := store.Open(filepath.Join(t.TempDir(), "portal.db"), filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	if _, err := data.CreateAdministrator(context.Background(), "admin", "password-hash", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := backupUserDatabases(context.Background(), &admin.Manager{Store: data}, "test"); err != nil {
		t.Fatalf("Portal-only administrator reached employee database backup: %v", err)
	}
}

func TestExecuteKimiOAuthBatchSeedsOnlyMissingAndContinuesFailures(t *testing.T) {
	users := []string{"existing", "missing", "malformed", "later"}
	seeded := make([]string, 0)
	rows := executeKimiOAuthBatch(users, true, "expected",
		func(username string) (bool, error) {
			switch username {
			case "existing":
				return true, nil
			case "malformed":
				return false, errors.New("existing credential is malformed")
			default:
				return false, nil
			}
		},
		func(username string) (admin.KimiOAuthSeedResult, error) {
			seeded = append(seeded, username)
			return admin.KimiOAuthSeedResult{SHA256: "expected", Restarted: username == "later"}, nil
		})
	if got, want := len(rows), len(users); got != want {
		t.Fatalf("rows=%d want=%d", got, want)
	}
	if rows[0].Outcome != "SKIP" || rows[1].Outcome != "SEEDED" || rows[2].Outcome != "FAIL" || rows[3].Outcome != "SEEDED" {
		t.Fatalf("unexpected outcomes: %+v", rows)
	}
	if len(seeded) != 2 || seeded[0] != "missing" || seeded[1] != "later" || !rows[3].Restarted {
		t.Fatalf("seed calls=%v rows=%+v", seeded, rows)
	}
}

func TestExecuteKimiOAuthBatchUpdateAllOverwritesEveryUser(t *testing.T) {
	users := []string{"test1", "test2"}
	hasCalls := 0
	seeded := make([]string, 0, len(users))
	rows := executeKimiOAuthBatch(users, false, "same-hash",
		func(string) (bool, error) {
			hasCalls++
			return true, nil
		},
		func(username string) (admin.KimiOAuthSeedResult, error) {
			seeded = append(seeded, username)
			return admin.KimiOAuthSeedResult{SHA256: "same-hash"}, nil
		})
	if hasCalls != 0 {
		t.Fatalf("update-all unexpectedly checked for missing credentials %d time(s)", hasCalls)
	}
	if len(seeded) != len(users) || seeded[0] != "test1" || seeded[1] != "test2" {
		t.Fatalf("update-all seed calls=%v", seeded)
	}
	for _, row := range rows {
		if row.Outcome != "SEEDED" {
			t.Fatalf("update-all row=%+v", row)
		}
	}
}
