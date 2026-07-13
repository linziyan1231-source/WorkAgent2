package userhost

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	internalBcryptCost = 12
	preferredLanguage  = "zh-CN"
)

var expectedUserColumns = []string{"id", "username", "email", "password_hash", "avatar_path", "jwt_secret", "created_at", "updated_at", "last_login"}

func rotateInternalCredentials(ctx context.Context, dbPath string, now time.Time) (string, []byte, error) {
	info, err := os.Lstat(dbPath)
	if err != nil {
		return "", nil, fmt.Errorf("inspect AionCore database: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("AionCore database must be a regular non-symlink file")
	}
	password, err := randomBase64(32)
	if err != nil {
		return "", nil, err
	}
	fail := func(err error) (string, []byte, error) {
		zero(password)
		return "", nil, err
	}
	hash, err := bcrypt.GenerateFromPassword(password, internalBcryptCost)
	if err != nil {
		return fail(fmt.Errorf("hash internal AionUi password: %w", err))
	}
	jwtSecret, err := randomBase64(64)
	if err != nil {
		return fail(err)
	}
	defer zero(jwtSecret)
	dsn := "file:" + filepath.ToSlash(dbPath) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(0)&_pragma=foreign_keys(1)&_pragma=locking_mode(EXCLUSIVE)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fail(fmt.Errorf("open AionCore database exclusively: %w", err))
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fail(fmt.Errorf("begin internal credential transaction: %w", err))
	}
	defer tx.Rollback()
	columns, err := tableColumns(ctx, tx, "users")
	if err != nil {
		return fail(err)
	}
	if len(columns) != len(expectedUserColumns) {
		return fail(fmt.Errorf("unsupported AionCore users schema: got %v", columns))
	}
	for i := range columns {
		if columns[i] != expectedUserColumns[i] {
			return fail(fmt.Errorf("unsupported AionCore users schema: got %v", columns))
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return fail(fmt.Errorf("count AionCore users: %w", err))
	}
	if count != 1 {
		return fail(fmt.Errorf("expected exactly one internal AionCore user, found %d", count))
	}
	var username string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE id='system_default_user'`).Scan(&username); err != nil {
		return fail(fmt.Errorf("find system_default_user: %w", err))
	}
	if strings.TrimSpace(username) == "" {
		return fail(errors.New("internal AionCore username is empty"))
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,jwt_secret=?,updated_at=?,last_login=NULL WHERE id='system_default_user'`,
		string(hash), string(jwtSecret), now.UnixMilli())
	if err != nil {
		return fail(fmt.Errorf("rotate internal AionCore credentials: %w", err))
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fail(errors.New("internal AionCore credential update did not affect exactly one row"))
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO system_settings(id,language,updated_at) VALUES(1,?,?)
ON CONFLICT(id) DO UPDATE SET language=excluded.language,updated_at=excluded.updated_at`, preferredLanguage, now.UnixMilli())
	if err != nil {
		return fail(fmt.Errorf("set preferred AionUi language: %w", err))
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		return fail(errors.New("preferred AionUi language update did not affect exactly one row"))
	}
	if err := tx.Commit(); err != nil {
		return fail(fmt.Errorf("commit internal AionCore credential rotation: %w", err))
	}
	return username, password, nil
}

func tableColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, fmt.Errorf("read %s schema: %w", table, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func randomBase64(bytes int) ([]byte, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate internal credential: %w", err)
	}
	defer zero(raw)
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	return encoded, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
