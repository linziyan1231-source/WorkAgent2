package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"aionuiportal/internal/admin"
)

func TestKimiOAuthCommandIsDisabled(t *testing.T) {
	err := dispatch(context.Background(), nil, []string{"kimi-oauth", "seed", "test1"})
	if err == nil || err.Error() != "native Kimi OAuth has been removed; use model-bootstrap provision --update with the user's CLIProxyAPI keys" {
		t.Fatalf("disabled Kimi OAuth command returned %v", err)
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
