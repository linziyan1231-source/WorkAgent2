package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	ErrKimiDatasourceDisabled        = errors.New("Kimi datasource access is disabled")
	ErrKimiDatasourceSourceDenied    = errors.New("Kimi datasource source is not allowed")
	ErrKimiDatasourceDailyExceeded   = errors.New("Kimi datasource daily quota is exhausted")
	ErrKimiDatasourceMonthlyExceeded = errors.New("Kimi datasource monthly quota is exhausted")
)

var KimiDatasourceSources = []string{
	"stock_finance_data",
	"yahoo_finance",
	"world_bank_open_data",
	"tianyancha",
	"arxiv",
	"scholar",
	"yuandian_law",
	"wind",
	"imf",
	"gildata",
	"sec_edgar",
	"sp_data",
}

type KimiDatasourceGrant struct {
	Enabled        bool      `json:"enabled"`
	AllowedSources []string  `json:"allowed_sources"`
	DailyLimit     int       `json:"daily_limit"`
	MonthlyLimit   int       `json:"monthly_limit"`
	DailyUsed      int       `json:"daily_used"`
	MonthlyUsed    int       `json:"monthly_used"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func NormalizeKimiDatasourceSources(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !slices.Contains(KimiDatasourceSources, value) {
			return nil, fmt.Errorf("unknown Kimi datasource source %q", value)
		}
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for _, source := range KimiDatasourceSources {
		if _, ok := seen[source]; ok {
			result = append(result, source)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one Kimi datasource source is required")
	}
	return result, nil
}

func ValidateKimiDatasourceLimits(daily, monthly int) error {
	if daily < 1 || daily > 10000 {
		return errors.New("Kimi datasource daily limit must be between 1 and 10000")
	}
	if monthly < daily || monthly > 100000 {
		return errors.New("Kimi datasource monthly limit must be between the daily limit and 100000")
	}
	return nil
}

func (s *Store) SetKimiDatasourceGrant(ctx context.Context, userID int64, enabled bool, sources []string, daily, monthly int, token string, now time.Time) error {
	if userID <= 0 {
		return errors.New("Kimi datasource grant requires a managed user")
	}
	normalized, err := NormalizeKimiDatasourceSources(sources)
	if err != nil {
		return err
	}
	if err := ValidateKimiDatasourceLimits(daily, monthly); err != nil {
		return err
	}
	encoded, _ := json.Marshal(normalized)
	var tokenHash any
	if enabled {
		if strings.TrimSpace(token) == "" {
			return errors.New("enabled Kimi datasource grant requires an access token")
		}
		tokenHash = TokenHash(token)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO kimi_datasource_grants
 (user_id,enabled,allowed_sources_json,daily_limit,monthly_limit,token_hash,updated_at)
 VALUES(?,?,?,?,?,?,?)
 ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,allowed_sources_json=excluded.allowed_sources_json,
 daily_limit=excluded.daily_limit,monthly_limit=excluded.monthly_limit,token_hash=excluded.token_hash,updated_at=excluded.updated_at`,
		userID, boolInt(enabled), string(encoded), daily, monthly, tokenHash, now.Unix())
	return err
}

func (s *Store) KimiDatasourceGrantForUser(ctx context.Context, userID int64, now time.Time) (KimiDatasourceGrant, error) {
	row := s.db.QueryRowContext(ctx, `SELECT enabled,allowed_sources_json,daily_limit,monthly_limit,updated_at,
 COALESCE((SELECT used FROM kimi_datasource_usage WHERE user_id=g.user_id AND period_type='day' AND period_key=?),0),
 COALESCE((SELECT used FROM kimi_datasource_usage WHERE user_id=g.user_id AND period_type='month' AND period_key=?),0)
 FROM kimi_datasource_grants g WHERE user_id=?`, dayKey(now), monthKey(now), userID)
	grant, err := scanKimiDatasourceGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KimiDatasourceGrant{}, nil
	}
	return grant, err
}

func (s *Store) KimiDatasourceGrantForToken(ctx context.Context, token string, now time.Time) (KimiDatasourceGrant, int64, error) {
	if strings.TrimSpace(token) == "" {
		return KimiDatasourceGrant{}, 0, ErrKimiDatasourceDisabled
	}
	row := s.db.QueryRowContext(ctx, `SELECT g.enabled,g.allowed_sources_json,g.daily_limit,g.monthly_limit,g.updated_at,
 COALESCE((SELECT used FROM kimi_datasource_usage WHERE user_id=g.user_id AND period_type='day' AND period_key=?),0),
 COALESCE((SELECT used FROM kimi_datasource_usage WHERE user_id=g.user_id AND period_type='month' AND period_key=?),0),g.user_id
 FROM kimi_datasource_grants g JOIN portal_users u ON u.id=g.user_id
 WHERE g.token_hash=? AND g.enabled=1 AND u.enabled=1`, dayKey(now), monthKey(now), TokenHash(token))
	var grant KimiDatasourceGrant
	var encoded string
	var stamp int64
	var userID int64
	if err := row.Scan(&grant.Enabled, &encoded, &grant.DailyLimit, &grant.MonthlyLimit, &stamp, &grant.DailyUsed, &grant.MonthlyUsed, &userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KimiDatasourceGrant{}, 0, ErrKimiDatasourceDisabled
		}
		return KimiDatasourceGrant{}, 0, err
	}
	if err := json.Unmarshal([]byte(encoded), &grant.AllowedSources); err != nil {
		return KimiDatasourceGrant{}, 0, fmt.Errorf("decode Kimi datasource sources: %w", err)
	}
	grant.UpdatedAt = time.Unix(stamp, 0)
	return grant, userID, nil
}

func (s *Store) ReserveKimiDatasourceCall(ctx context.Context, token, source string, now time.Time) (KimiDatasourceGrant, int64, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return KimiDatasourceGrant{}, 0, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `SELECT g.enabled,g.allowed_sources_json,g.daily_limit,g.monthly_limit,g.updated_at,g.user_id
 FROM kimi_datasource_grants g JOIN portal_users u ON u.id=g.user_id
 WHERE g.token_hash=? AND g.enabled=1 AND u.enabled=1`, TokenHash(token))
	var grant KimiDatasourceGrant
	var encoded string
	var stamp int64
	var userID int64
	if err := row.Scan(&grant.Enabled, &encoded, &grant.DailyLimit, &grant.MonthlyLimit, &stamp, &userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KimiDatasourceGrant{}, 0, ErrKimiDatasourceDisabled
		}
		return KimiDatasourceGrant{}, 0, err
	}
	if err := json.Unmarshal([]byte(encoded), &grant.AllowedSources); err != nil {
		return KimiDatasourceGrant{}, 0, fmt.Errorf("decode Kimi datasource sources: %w", err)
	}
	if !slices.Contains(grant.AllowedSources, source) {
		return KimiDatasourceGrant{}, 0, ErrKimiDatasourceSourceDenied
	}
	grant.UpdatedAt = time.Unix(stamp, 0)
	for _, period := range []struct {
		typeName string
		key      string
		limit    int
		exceeded error
	}{
		{"day", dayKey(now), grant.DailyLimit, ErrKimiDatasourceDailyExceeded},
		{"month", monthKey(now), grant.MonthlyLimit, ErrKimiDatasourceMonthlyExceeded},
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO kimi_datasource_usage(user_id,period_type,period_key,used,updated_at)
 VALUES(?,?,?,?,?) ON CONFLICT(user_id,period_type,period_key) DO NOTHING`, userID, period.typeName, period.key, 0, now.Unix()); err != nil {
			return KimiDatasourceGrant{}, 0, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE kimi_datasource_usage SET used=used+1,updated_at=?
 WHERE user_id=? AND period_type=? AND period_key=? AND used<?`, now.Unix(), userID, period.typeName, period.key, period.limit)
		if err != nil {
			return KimiDatasourceGrant{}, 0, err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return KimiDatasourceGrant{}, 0, err
		}
		if changed != 1 {
			return KimiDatasourceGrant{}, 0, period.exceeded
		}
	}
	if err := tx.Commit(); err != nil {
		return KimiDatasourceGrant{}, 0, err
	}
	grant.DailyUsed++
	grant.MonthlyUsed++
	return grant, userID, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanKimiDatasourceGrant(row rowScanner) (KimiDatasourceGrant, error) {
	var grant KimiDatasourceGrant
	var encoded string
	var stamp int64
	if err := row.Scan(&grant.Enabled, &encoded, &grant.DailyLimit, &grant.MonthlyLimit, &stamp, &grant.DailyUsed, &grant.MonthlyUsed); err != nil {
		return KimiDatasourceGrant{}, err
	}
	if err := json.Unmarshal([]byte(encoded), &grant.AllowedSources); err != nil {
		return KimiDatasourceGrant{}, fmt.Errorf("decode Kimi datasource sources: %w", err)
	}
	grant.UpdatedAt = time.Unix(stamp, 0)
	return grant, nil
}

func dayKey(now time.Time) string   { return now.UTC().Format("2006-01-02") }
func monthKey(now time.Time) string { return now.UTC().Format("2006-01") }
