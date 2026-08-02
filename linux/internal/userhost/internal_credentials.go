package userhost

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	_ "modernc.org/sqlite"
)

const internalCredentialBcryptCost = 12

var supportedInternalUserColumns = []string{"id", "username", "email", "password_hash", "avatar_path", "jwt_secret", "created_at", "updated_at", "last_login"}

func rotateBackendCredential(ctx context.Context, root *projectfs.Root, relative string, expectedUID uint32, now time.Time) (string, []byte, error) {
	file, err := root.Open(relative, unix.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, fmt.Errorf("open internal authentication database: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || stat.Uid != expectedUID || info.Size() <= 0 || info.Size() > 8*1024*1024*1024 {
		return "", nil, errors.New("internal authentication database is not a protected tenant-owned regular file")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return "", nil, errors.New("internal authentication database is already in use")
	}
	defer unix.Flock(int(file.Fd()), unix.LOCK_UN)

	password := make([]byte, base64.RawURLEncoding.EncodedLen(32))
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate internal credential: %w", err)
	}
	base64.RawURLEncoding.Encode(password, raw)
	clear(raw)
	fail := func(err error) (string, []byte, error) {
		clear(password)
		return "", nil, err
	}
	hash, err := bcrypt.GenerateFromPassword(password, internalCredentialBcryptCost)
	if err != nil {
		return fail(fmt.Errorf("hash internal credential: %w", err))
	}
	defer clear(hash)
	dsn := "file:" + filepath.ToSlash(filepath.Join(root.Path(), relative)) + "?mode=rw&_txlock=immediate&_pragma=busy_timeout(0)&_pragma=foreign_keys(1)&_pragma=locking_mode(EXCLUSIVE)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fail(fmt.Errorf("open internal authentication database: %w", err))
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fail(fmt.Errorf("begin internal credential transaction: %w", err))
	}
	defer tx.Rollback()
	columns, err := sqliteTableColumns(ctx, tx, "users")
	if err != nil || !slices.Equal(columns, supportedInternalUserColumns) {
		return fail(fmt.Errorf("unsupported internal users schema: %v", columns))
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil || count != 1 {
		return fail(fmt.Errorf("internal users table must contain exactly one row (count=%d): %w", count, err))
	}
	var username string
	var jwtPresent int
	if err := tx.QueryRowContext(ctx, `SELECT username, CASE WHEN LENGTH(TRIM(COALESCE(jwt_secret,''))) > 0 THEN 1 ELSE 0 END FROM users WHERE id='system_default_user'`).Scan(&username, &jwtPresent); err != nil {
		return fail(fmt.Errorf("read internal system user: %w", err))
	}
	if strings.TrimSpace(username) == "" || jwtPresent != 1 {
		return fail(errors.New("internal system user or persistent JWT secret is missing"))
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?, updated_at=?, last_login=NULL WHERE id='system_default_user'`, string(hash), now.UnixMilli())
	if err != nil {
		return fail(fmt.Errorf("rotate internal credential: %w", err))
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return fail(errors.New("internal credential rotation did not update exactly one user"))
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO system_settings(id,language,updated_at) VALUES(1,'zh-CN',?) ON CONFLICT(id) DO UPDATE SET language=excluded.language,updated_at=excluded.updated_at`, now.UnixMilli())
	if err != nil {
		return fail(fmt.Errorf("set internal UI language: %w", err))
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		return fail(errors.New("internal UI language update did not affect exactly one row"))
	}
	if err := tx.Commit(); err != nil {
		return fail(fmt.Errorf("commit internal credential rotation: %w", err))
	}
	reopened, err := root.Open(relative, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fail(errors.New("internal database path changed during credential rotation"))
	}
	reopenedInfo, reopenedErr := reopened.Stat()
	reopened.Close()
	if reopenedErr != nil {
		return fail(errors.New("internal database could not be re-inspected after credential rotation"))
	}
	reopenedStat, reopenedOK := reopenedInfo.Sys().(*syscall.Stat_t)
	if !reopenedOK || reopenedStat.Dev != stat.Dev || reopenedStat.Ino != stat.Ino {
		return fail(errors.New("internal database inode changed during credential rotation"))
	}
	return username, password, nil
}

func sqliteTableColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	if table != "users" && table != "conversations" {
		return nil, errors.New("unsupported schema table")
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}
