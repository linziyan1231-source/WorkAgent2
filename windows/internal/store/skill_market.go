package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SkillMarketEntry struct {
	ID                   string
	PublisherUserID      int64
	PublisherUsername    string
	PublisherDisplayName string
	SkillName            string
	Description          string
	ArchiveName          string
	ArchiveSHA256        string
	ArchiveBytes         int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (s *Store) PublishSkillMarketEntry(ctx context.Context, entry SkillMarketEntry, now time.Time) (SkillMarketEntry, string, error) {
	entry.ID = strings.TrimSpace(entry.ID)
	entry.SkillName = strings.TrimSpace(entry.SkillName)
	entry.Description = strings.TrimSpace(entry.Description)
	entry.ArchiveName = strings.TrimSpace(entry.ArchiveName)
	entry.ArchiveSHA256 = strings.ToLower(strings.TrimSpace(entry.ArchiveSHA256))
	if entry.ID == "" || entry.PublisherUserID <= 0 || entry.SkillName == "" || entry.ArchiveName == "" || len(entry.ArchiveSHA256) != 64 || entry.ArchiveBytes <= 0 {
		return SkillMarketEntry{}, "", errors.New("incomplete skill market entry")
	}
	nameNorm := strings.ToLower(entry.SkillName)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SkillMarketEntry{}, "", err
	}
	defer tx.Rollback()
	var previousArchive string
	err = tx.QueryRowContext(ctx, `SELECT archive_name FROM skill_market_entries WHERE publisher_user_id=? AND skill_name_norm=?`, entry.PublisherUserID, nameNorm).Scan(&previousArchive)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SkillMarketEntry{}, "", err
	}
	stamp := now.Unix()
	result, err := tx.ExecContext(ctx, `INSERT INTO skill_market_entries
 (id,publisher_user_id,skill_name,skill_name_norm,description,archive_name,archive_sha256,archive_bytes,created_at,updated_at)
 SELECT ?,?,?,?,?,?,?,?,?,? FROM portal_users WHERE id=? AND enabled=1 AND is_admin=0
 ON CONFLICT(publisher_user_id,skill_name_norm) DO UPDATE SET skill_name=excluded.skill_name,description=excluded.description,
 archive_name=excluded.archive_name,archive_sha256=excluded.archive_sha256,archive_bytes=excluded.archive_bytes,updated_at=excluded.updated_at`,
		entry.ID, entry.PublisherUserID, entry.SkillName, nameNorm, entry.Description, entry.ArchiveName, entry.ArchiveSHA256, entry.ArchiveBytes,
		stamp, stamp, entry.PublisherUserID)
	if err != nil {
		return SkillMarketEntry{}, "", fmt.Errorf("publish skill market entry: %w", err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		if rowsErr != nil {
			return SkillMarketEntry{}, "", rowsErr
		}
		return SkillMarketEntry{}, "", ErrForbidden
	}
	if err := tx.Commit(); err != nil {
		return SkillMarketEntry{}, "", err
	}
	published, err := s.SkillMarketEntryByPublisherAndName(ctx, entry.PublisherUserID, entry.SkillName)
	return published, previousArchive, err
}

func (s *Store) ListSkillMarketEntries(ctx context.Context) ([]SkillMarketEntry, error) {
	rows, err := s.db.QueryContext(ctx, skillMarketSelect+` ORDER BY e.updated_at DESC,e.id`)
	if err != nil {
		return nil, fmt.Errorf("list skill market: %w", err)
	}
	defer rows.Close()
	var entries []SkillMarketEntry
	for rows.Next() {
		entry, err := scanSkillMarketEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) SkillMarketEntryByID(ctx context.Context, id string) (SkillMarketEntry, error) {
	return scanSkillMarketEntry(s.db.QueryRowContext(ctx, skillMarketSelect+` WHERE e.id=?`, strings.TrimSpace(id)))
}

func (s *Store) SkillMarketEntryByPublisherAndName(ctx context.Context, publisherID int64, name string) (SkillMarketEntry, error) {
	return scanSkillMarketEntry(s.db.QueryRowContext(ctx, skillMarketSelect+` WHERE e.publisher_user_id=? AND e.skill_name_norm=?`, publisherID, strings.ToLower(strings.TrimSpace(name))))
}

func (s *Store) DeleteSkillMarketEntry(ctx context.Context, id string, actorUserID int64, actorAdmin bool) (SkillMarketEntry, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SkillMarketEntry{}, err
	}
	defer tx.Rollback()
	entry, err := scanSkillMarketEntry(tx.QueryRowContext(ctx, skillMarketSelect+` WHERE e.id=?`, strings.TrimSpace(id)))
	if err != nil {
		return SkillMarketEntry{}, err
	}
	if !actorAdmin && entry.PublisherUserID != actorUserID {
		return SkillMarketEntry{}, ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM skill_market_entries WHERE id=?`, entry.ID); err != nil {
		return SkillMarketEntry{}, fmt.Errorf("delete skill market entry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SkillMarketEntry{}, err
	}
	return entry, nil
}

const skillMarketSelect = `SELECT e.id,e.publisher_user_id,u.username,u.display_name,e.skill_name,e.description,e.archive_name,e.archive_sha256,e.archive_bytes,e.created_at,e.updated_at
 FROM skill_market_entries e JOIN portal_users u ON u.id=e.publisher_user_id`

func scanSkillMarketEntry(row scanner) (SkillMarketEntry, error) {
	var entry SkillMarketEntry
	var created, updated int64
	err := row.Scan(&entry.ID, &entry.PublisherUserID, &entry.PublisherUsername, &entry.PublisherDisplayName, &entry.SkillName,
		&entry.Description, &entry.ArchiveName, &entry.ArchiveSHA256, &entry.ArchiveBytes, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return SkillMarketEntry{}, ErrNotFound
	}
	if err != nil {
		return SkillMarketEntry{}, err
	}
	entry.CreatedAt, entry.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return entry, nil
}
