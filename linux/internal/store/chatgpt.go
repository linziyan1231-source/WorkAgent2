package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProStatusReserved         = "reserved"
	ProStatusConfirmed        = "confirmed_pro"
	ProStatusFallback         = "confirmed_fallback"
	ProStatusUnknown          = "unknown"
	ProStatusUpstreamRejected = "upstream_rejected"
)

var ErrReplay = errors.New("authenticated request was already consumed")

type ChatGPTProQuota struct {
	Confirmed int
	Limit     int
	Pending   int
	ResetAt   time.Time
	WeekStart time.Time
}

type ChatGPTProReservationState string

const (
	ChatGPTProReserved          ChatGPTProReservationState = "reserved"
	ChatGPTProDuplicateComplete ChatGPTProReservationState = "duplicate_complete"
	ChatGPTProDuplicatePending  ChatGPTProReservationState = "duplicate_pending"
	ChatGPTProQuotaExceeded     ChatGPTProReservationState = "quota_exceeded"
)

type ChatGPTProReservation struct {
	State ChatGPTProReservationState
	Quota ChatGPTProQuota
}

type ChatGPTProEvent struct {
	ID         int64     `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
}

func (s *Store) ConsumeChatForwardSignature(ctx context.Context, signature []byte, now time.Time, validity time.Duration) error {
	if len(signature) != sha256.Size || validity <= 0 || validity > 5*time.Minute {
		return errors.New("invalid ChatForward replay marker")
	}
	digest := sha256.Sum256(signature)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM chatforward_replays WHERE expires_at<=?`, now.UTC().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO chatforward_replays(signature_hash,expires_at) VALUES(?,?)`, digest[:], now.Add(validity).UTC().Unix()); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "constraint") {
			return ErrReplay
		}
		return fmt.Errorf("persist ChatForward replay marker: %w", err)
	}
	return tx.Commit()
}

func (s *Store) SetChatGPTProWeeklyLimit(ctx context.Context, userID int64, limit int, now time.Time) error {
	if userID <= 0 || limit < 1 || limit > 10000 {
		return errors.New("ChatGPT Pro weekly limit must be between 1 and 10000")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO chatgpt_pro_limits(user_id,weekly_limit,updated_at)
VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET weekly_limit=excluded.weekly_limit,updated_at=excluded.updated_at`, userID, limit, now.UTC().Unix())
	if err != nil {
		return fmt.Errorf("set ChatGPT Pro weekly limit: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return fmt.Errorf("unexpected ChatGPT Pro limit update count: %d (%v)", changed, err)
	}
	return nil
}

func (s *Store) ChatGPTProQuota(ctx context.Context, userID int64, defaultLimit int, now time.Time) (ChatGPTProQuota, error) {
	if userID <= 0 || defaultLimit < 1 || defaultLimit > 10000 {
		return ChatGPTProQuota{}, errors.New("invalid ChatGPT Pro quota request")
	}
	weekStart, resetAt := shanghaiWeek(now)
	return s.chatGPTProQuotaQuery(ctx, s.db, userID, defaultLimit, weekStart, resetAt)
}

func (s *Store) ReserveChatGPTPro(ctx context.Context, userID int64, defaultLimit int, logicalSendID, requestedModel, thinkingEffort string, now time.Time) (ChatGPTProReservation, error) {
	if userID <= 0 || defaultLimit < 1 || defaultLimit > 10000 || len(logicalSendID) != 64 || strings.TrimSpace(requestedModel) == "" {
		return ChatGPTProReservation{}, errors.New("invalid ChatGPT Pro reservation")
	}
	weekStart, resetAt := shanghaiWeek(now)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ChatGPTProReservation{}, err
	}
	defer tx.Rollback()
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT status FROM chatgpt_pro_usage WHERE user_id=? AND logical_send_id=?`, userID, logicalSendID).Scan(&existing)
	if err == nil {
		quota, quotaErr := s.chatGPTProQuotaQuery(ctx, tx, userID, defaultLimit, weekStart, resetAt)
		if quotaErr != nil {
			return ChatGPTProReservation{}, quotaErr
		}
		state := ChatGPTProDuplicateComplete
		if existing == ProStatusReserved || existing == ProStatusUnknown {
			state = ChatGPTProDuplicatePending
		}
		return ChatGPTProReservation{State: state, Quota: quota}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ChatGPTProReservation{}, fmt.Errorf("inspect ChatGPT Pro logical send: %w", err)
	}
	quota, err := s.chatGPTProQuotaQuery(ctx, tx, userID, defaultLimit, weekStart, resetAt)
	if err != nil {
		return ChatGPTProReservation{}, err
	}
	if quota.Confirmed+quota.Pending >= quota.Limit {
		return ChatGPTProReservation{State: ChatGPTProQuotaExceeded, Quota: quota}, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO chatgpt_pro_usage
(user_id,logical_send_id,week_start,requested_model,thinking_effort,status,reserved_at)
VALUES(?,?,?,?,?,'reserved',?)`, userID, logicalSendID, weekStart.Unix(), strings.TrimSpace(requestedModel), strings.TrimSpace(thinkingEffort), now.UTC().Unix())
	if err != nil {
		return ChatGPTProReservation{}, fmt.Errorf("reserve ChatGPT Pro usage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ChatGPTProReservation{}, err
	}
	quota.Pending++
	return ChatGPTProReservation{State: ChatGPTProReserved, Quota: quota}, nil
}

func (s *Store) SettleChatGPTPro(ctx context.Context, userID int64, logicalSendID, status string, upstreamStatus int, streamCompleted bool, servedModels []string, now time.Time) error {
	if userID <= 0 || len(logicalSendID) != 64 || (status != ProStatusConfirmed && status != ProStatusFallback && status != ProStatusUnknown && status != ProStatusUpstreamRejected) || len(servedModels) > 64 {
		return errors.New("invalid ChatGPT Pro settlement")
	}
	models, err := json.Marshal(servedModels)
	if err != nil || len(models) > 16*1024 {
		return errors.New("invalid ChatGPT Pro served models")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if status == ProStatusUpstreamRejected {
		result, err := tx.ExecContext(ctx, `DELETE FROM chatgpt_pro_usage WHERE user_id=? AND logical_send_id=? AND status='reserved'`, userID, logicalSendID)
		if err != nil {
			return fmt.Errorf("release rejected ChatGPT Pro reservation: %w", err)
		}
		if changed, err := result.RowsAffected(); err != nil || changed > 1 {
			return fmt.Errorf("unexpected rejected ChatGPT Pro release count: %d (%v)", changed, err)
		}
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `UPDATE chatgpt_pro_usage SET status=?,finished_at=?,upstream_status=?,stream_completed=?,served_models_json=?
WHERE user_id=? AND logical_send_id=? AND status='reserved'`, status, now.UTC().Unix(), nullablePositiveInt(upstreamStatus), boolInt(streamCompleted), string(models), userID, logicalSendID)
	if err != nil {
		return fmt.Errorf("settle ChatGPT Pro usage: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return tx.Commit()
	}
	if changed != 1 {
		return fmt.Errorf("unexpected ChatGPT Pro settlement count: %d", changed)
	}
	if status == ProStatusFallback {
		_, err = tx.ExecContext(ctx, `INSERT INTO chatgpt_pro_events(user_id,usage_id,kind,occurred_at)
SELECT user_id,id,'confirmed_fallback',? FROM chatgpt_pro_usage WHERE user_id=? AND logical_send_id=?`, now.UTC().Unix(), userID, logicalSendID)
		if err != nil {
			return fmt.Errorf("record ChatGPT Pro fallback event: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) PendingChatGPTProEvents(ctx context.Context, userID int64, limit int) ([]ChatGPTProEvent, error) {
	if userID <= 0 || limit < 1 || limit > 100 {
		return nil, errors.New("invalid ChatGPT Pro event limit")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,occurred_at FROM chatgpt_pro_events WHERE user_id=? AND acknowledged_at IS NULL ORDER BY id LIMIT ?`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list ChatGPT Pro events: %w", err)
	}
	defer rows.Close()
	var events []ChatGPTProEvent
	for rows.Next() {
		var event ChatGPTProEvent
		var occurred int64
		if err := rows.Scan(&event.ID, &occurred); err != nil {
			return nil, err
		}
		event.OccurredAt = time.Unix(occurred, 0).UTC()
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) AcknowledgeChatGPTProEvents(ctx context.Context, userID int64, ids []int64, now time.Time) error {
	if userID <= 0 || len(ids) == 0 || len(ids) > 100 {
		return errors.New("invalid ChatGPT Pro event acknowledgement")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return errors.New("invalid ChatGPT Pro event id")
		}
		seen[id] = true
		if _, err := tx.ExecContext(ctx, `UPDATE chatgpt_pro_events SET acknowledged_at=? WHERE id=? AND user_id=? AND acknowledged_at IS NULL`, now.UTC().Unix(), id, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type chatGPTProQuotaQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) chatGPTProQuotaQuery(ctx context.Context, query chatGPTProQuotaQuerier, userID int64, defaultLimit int, weekStart, resetAt time.Time) (ChatGPTProQuota, error) {
	quota := ChatGPTProQuota{Limit: defaultLimit, WeekStart: weekStart, ResetAt: resetAt}
	err := query.QueryRowContext(ctx, `SELECT weekly_limit FROM chatgpt_pro_limits WHERE user_id=?`, userID).Scan(&quota.Limit)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ChatGPTProQuota{}, fmt.Errorf("read ChatGPT Pro weekly limit: %w", err)
	}
	if err := query.QueryRowContext(ctx, `SELECT
COALESCE(SUM(CASE WHEN status='confirmed_pro' THEN 1 ELSE 0 END),0),
COALESCE(SUM(CASE WHEN status IN ('reserved','unknown') THEN 1 ELSE 0 END),0)
FROM chatgpt_pro_usage WHERE user_id=? AND week_start=?`, userID, weekStart.Unix()).Scan(&quota.Confirmed, &quota.Pending); err != nil {
		return ChatGPTProQuota{}, fmt.Errorf("read ChatGPT Pro weekly usage: %w", err)
	}
	return quota, nil
}

func shanghaiWeek(now time.Time) (time.Time, time.Time) {
	shanghai := time.FixedZone("Asia/Shanghai", 8*60*60)
	local := now.In(shanghai)
	daysSinceMonday := (int(local.Weekday()) + 6) % 7
	start := time.Date(local.Year(), local.Month(), local.Day()-daysSinceMonday, 0, 0, 0, 0, shanghai)
	return start.UTC(), start.AddDate(0, 0, 7).UTC()
}

func nullablePositiveInt(value int) any {
	if value <= 0 {
		return nil
	}
	return value
}
