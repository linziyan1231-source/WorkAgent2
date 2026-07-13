package userhost

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func createAionDB(t *testing.T, columns string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aionui-backend.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if columns == "" {
		columns = `id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE, email TEXT UNIQUE, password_hash TEXT NOT NULL,
 avatar_path TEXT, jwt_secret TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login INTEGER`
	}
	if _, err := db.Exec(`CREATE TABLE users (` + columns + `)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users(id,username,password_hash,jwt_secret,created_at,updated_at) VALUES('system_default_user','admin','','old-secret',1,1)`); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRotateInternalCredentialsMatchesRealAionCoreSchema(t *testing.T) {
	path := createAionDB(t, "")
	username, password, err := rotateInternalCredentials(context.Background(), path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer zero(password)
	if username != "admin" || len(password) != 43 {
		t.Fatalf("unexpected credential result username=%q length=%d", username, len(password))
	}
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var hash, jwt string
	var updated int64
	if err := db.QueryRow(`SELECT password_hash,jwt_secret,updated_at FROM users WHERE id='system_default_user'`).Scan(&hash, &jwt, &updated); err != nil {
		t.Fatal(err)
	}
	cost, costErr := bcrypt.Cost([]byte(hash))
	if bcrypt.CompareHashAndPassword([]byte(hash), password) != nil || costErr != nil || cost != internalBcryptCost {
		t.Fatal("stored bcrypt hash does not match returned high-entropy password at cost 12")
	}
	if jwt == "old-secret" || len(jwt) < 80 || updated != 1_700_000_000_000 {
		t.Fatalf("JWT rotation or timestamp mismatch: jwt length=%d updated=%d", len(jwt), updated)
	}
}

func TestRotateInternalCredentialsRejectsUnknownSchemaWithoutMutation(t *testing.T) {
	path := createAionDB(t, `id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 jwt_secret TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login INTEGER`)
	if _, _, err := rotateInternalCredentials(context.Background(), path, time.Now()); err == nil {
		t.Fatal("unknown AionCore schema was accepted")
	}
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var passwordHash string
	if err := db.QueryRow(`SELECT password_hash FROM users WHERE id='system_default_user'`).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if passwordHash != "" {
		t.Fatal("unknown schema was mutated")
	}
}

func TestRotateInternalCredentialsRejectsSymlink(t *testing.T) {
	target := createAionDB(t, "")
	link := filepath.Join(filepath.Dir(target), "linked.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := rotateInternalCredentials(context.Background(), link, time.Now()); err == nil {
		t.Fatal("symlink database was accepted")
	}
}
