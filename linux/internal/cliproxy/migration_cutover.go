package cliproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"

	_ "modernc.org/sqlite"
)

const (
	migrationPlanSchemaVersion = 1
	maxMigrationReportBytes    = 8 * 1024 * 1024
	maxMigrationPlanBytes      = 32 * 1024 * 1024
	maxPortalDatabaseBytes     = 4 * 1024 * 1024 * 1024
	migrationApplyAfter        = "Portal has provisioned and verified both deterministic Linux tenant keys"
	migrationKeyPolicy         = "patch only quota limits and transfer the archived usage window to each matching new_key_id; never restore legacy key hashes or plaintext"
)

var (
	fingerprintPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	migrationRuntimePattern  = regexp.MustCompile(`^workagent_[a-z0-9][a-z0-9_-]{0,25}$`)
	migrationUsernamePattern = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)
	migrationAliasPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	migrationUSDPattern      = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)
	stateKeyHashPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	effectiveUID             = os.Geteuid
)

type migrationQuotaPlan struct {
	SchemaVersion     int                      `json:"schema_version"`
	SourceFingerprint string                   `json:"source_fingerprint"`
	ApplyAfter        string                   `json:"apply_after"`
	KeyPolicy         string                   `json:"key_policy"`
	Overrides         []migrationQuotaOverride `json:"overrides"`
}

type migrationQuotaOverride struct {
	Username       string          `json:"username"`
	TenantID       string          `json:"tenant_id"`
	Provider       string          `json:"provider"`
	NewKeyID       string          `json:"new_key_id"`
	DailyLimitUSD  string          `json:"daily_limit_usd"`
	WeeklyLimitUSD string          `json:"weekly_limit_usd"`
	LegacyUsage    json.RawMessage `json:"legacy_usage"`
	usage          usageState
}

type portalMigrationUser struct {
	Username     string
	UsernameNorm string
	TenantID     string
	RuntimeUser  string
	DataRoot     string
	Enabled      bool
}

type migrationArtifacts struct {
	report       winmigration.Report
	plan         migrationQuotaPlan
	users        []portalMigrationUser
	byTenant     map[string][2]migrationQuotaOverride
	reportSHA256 string
	planSHA256   string
}

type usageState struct {
	Daily   usageWindow
	Weekly  usageWindow
	ByAlias map[string]aliasUsageWindows
}

type aliasUsageWindows struct {
	Daily  usageWindow `json:"daily"`
	Weekly usageWindow `json:"weekly"`
}

type usageWindow struct {
	TotalUSD        float64   `json:"total_usd"`
	WindowStart     time.Time `json:"window_start,omitempty"`
	CacheReadTokens int64     `json:"cache_read_tokens,omitempty"`
	CacheCostUSD    float64   `json:"cache_cost_usd,omitempty"`
	InputTokens     int64     `json:"input_tokens,omitempty"`
	OutputTokens    int64     `json:"output_tokens,omitempty"`
	CallCount       int64     `json:"call_count,omitempty"`
}

func loadMigrationArtifacts(ctx context.Context, reportPath, planPath, portalDatabasePath string) (migrationArtifacts, error) {
	if effectiveUID() != 0 {
		return migrationArtifacts{}, errors.New("CLIProxy migration cutover commands must run as root")
	}
	reportPayload, _, err := readProtectedMigrationFile(reportPath, maxMigrationReportBytes, true)
	if err != nil {
		return migrationArtifacts{}, fmt.Errorf("migration report: %w", err)
	}
	defer clear(reportPayload)
	planPayload, _, err := readProtectedMigrationFile(planPath, maxMigrationPlanBytes, true)
	if err != nil {
		return migrationArtifacts{}, fmt.Errorf("migration quota plan: %w", err)
	}
	defer clear(planPayload)
	var report winmigration.Report
	if err := decodeStrictJSON(reportPayload, &report); err != nil {
		return migrationArtifacts{}, errors.New("migration report is invalid")
	}
	var plan migrationQuotaPlan
	if err := decodeStrictJSON(planPayload, &plan); err != nil {
		return migrationArtifacts{}, errors.New("migration quota plan is invalid")
	}
	if err := validateMigrationReportAndPlan(report, &plan); err != nil {
		return migrationArtifacts{}, err
	}
	users, err := readMigrationPortalUsers(ctx, portalDatabasePath)
	if err != nil {
		return migrationArtifacts{}, err
	}
	if err := crossCheckMigrationUsers(report, users); err != nil {
		return migrationArtifacts{}, err
	}
	byTenant := make(map[string][2]migrationQuotaOverride, len(report.Tenants))
	for _, override := range plan.Overrides {
		pair := byTenant[override.TenantID]
		if override.Provider == "codex" {
			pair[0] = override
		} else {
			pair[1] = override
		}
		byTenant[override.TenantID] = pair
	}
	return migrationArtifacts{
		report: report, plan: plan, users: users, byTenant: byTenant,
		reportSHA256: sha256Hex(reportPayload), planSHA256: sha256Hex(planPayload),
	}, nil
}

func validateMigrationReportAndPlan(report winmigration.Report, plan *migrationQuotaPlan) error {
	if err := winmigration.ValidateReportSourceFingerprint(report); err != nil {
		return fmt.Errorf("migration report frozen source binding is invalid: %w", err)
	}
	if report.SchemaVersion != winmigration.ReportSchemaVersion || report.Status != "complete" || !fingerprintPattern.MatchString(report.SourceFingerprint) ||
		!fingerprintPattern.MatchString(report.OutputFingerprint) || report.Portal.Users < 1 || report.Portal.Users != len(report.Tenants) {
		return errors.New("migration report is not a completed production stage")
	}
	if report.TenantDataRoot == string(filepath.Separator) || !filepath.IsAbs(report.TenantDataRoot) || filepath.Clean(report.TenantDataRoot) != report.TenantDataRoot {
		return errors.New("migration report tenant data root is invalid")
	}
	if plan.SchemaVersion != migrationPlanSchemaVersion || plan.SourceFingerprint != report.SourceFingerprint || plan.ApplyAfter != migrationApplyAfter || plan.KeyPolicy != migrationKeyPolicy || len(plan.Overrides) != len(report.Tenants)*2 {
		return errors.New("migration quota plan does not match the completed stage")
	}
	reportTenants := make(map[string]winmigration.TenantReport, len(report.Tenants))
	usernames := make(map[string]bool, len(report.Tenants))
	for _, tenant := range report.Tenants {
		parsed, err := uuid.Parse(tenant.TenantID)
		expectedRoot := filepath.Join(report.TenantDataRoot, tenant.TenantID)
		if err != nil || parsed.String() != tenant.TenantID || !migrationUsernamePattern.MatchString(tenant.Username) ||
			!migrationRuntimePattern.MatchString(tenant.RuntimeUser) || tenant.DataRoot != expectedRoot || reportTenants[tenant.TenantID].TenantID != "" ||
			usernames[store.NormalizeUsername(tenant.Username)] || len(tenant.QuotaOverrides) != 2 {
			return errors.New("migration report contains an invalid or duplicate tenant identity")
		}
		reportTenants[tenant.TenantID] = tenant
		usernames[store.NormalizeUsername(tenant.Username)] = true
	}
	seenKeys := make(map[string]bool, len(plan.Overrides))
	seenProviders := make(map[string]bool, len(plan.Overrides))
	for index := range plan.Overrides {
		override := &plan.Overrides[index]
		tenant, ok := reportTenants[override.TenantID]
		if !ok || override.Username != tenant.Username || (override.Provider != "codex" && override.Provider != "kimi") {
			return errors.New("migration quota plan contains an unmapped tenant override")
		}
		ids := modelbootstrap.KeyIDsForTenant(override.TenantID)
		expectedID := ids.CodexKeyID
		if override.Provider == "kimi" {
			expectedID = ids.KimiKeyID
		}
		providerKey := override.TenantID + "\x00" + override.Provider
		if override.NewKeyID != expectedID || seenKeys[override.NewKeyID] || seenProviders[providerKey] {
			return errors.New("migration quota plan key identities are not deterministic and unique")
		}
		if err := validateMigrationUSD(override.DailyLimitUSD); err != nil {
			return errors.New("migration quota plan contains an invalid daily limit")
		}
		if err := validateMigrationUSD(override.WeeklyLimitUSD); err != nil {
			return errors.New("migration quota plan contains an invalid weekly limit")
		}
		usage, err := decodeUsageState(override.LegacyUsage)
		if err != nil {
			return fmt.Errorf("migration quota plan contains invalid archived usage: %w", err)
		}
		override.usage = usage
		seenKeys[override.NewKeyID], seenProviders[providerKey] = true, true
		matchedReport := false
		for _, summary := range tenant.QuotaOverrides {
			if summary.Provider == override.Provider && summary.NewKeyID == override.NewKeyID && summary.DailyLimitUSD == override.DailyLimitUSD && summary.WeeklyLimitUSD == override.WeeklyLimitUSD {
				matchedReport = true
			}
		}
		if !matchedReport {
			return errors.New("migration quota plan conflicts with the public tenant report")
		}
	}
	return nil
}

func validateMigrationUSD(value string) error {
	if value == "" || len(value) > 32 || !migrationUSDPattern.MatchString(value) {
		return errors.New("USD value must be a bounded plain decimal")
	}
	rational, ok := new(big.Rat).SetString(value)
	if !ok || rational.Sign() <= 0 || rational.Cmp(big.NewRat(1_000_000, 1)) > 0 {
		return errors.New("USD value is outside the migration range")
	}
	return nil
}

func decodeUsageState(raw json.RawMessage) (usageState, error) {
	if len(raw) == 0 {
		return usageState{}, errors.New("archived usage is missing")
	}
	var envelope struct {
		Daily   json.RawMessage            `json:"daily"`
		Weekly  json.RawMessage            `json:"weekly"`
		ByAlias map[string]json.RawMessage `json:"by_alias,omitempty"`
	}
	if err := decodeStrictJSON(raw, &envelope); err != nil {
		return usageState{}, errors.New("usage object has an invalid shape")
	}
	result := usageState{ByAlias: make(map[string]aliasUsageWindows, len(envelope.ByAlias))}
	var err error
	if len(envelope.Daily) > 0 {
		result.Daily, err = decodeUsageWindow(envelope.Daily)
		if err != nil {
			return usageState{}, err
		}
	}
	if len(envelope.Weekly) > 0 {
		result.Weekly, err = decodeUsageWindow(envelope.Weekly)
		if err != nil {
			return usageState{}, err
		}
	}
	for alias, entry := range envelope.ByAlias {
		if !migrationAliasPattern.MatchString(alias) {
			return usageState{}, errors.New("usage contains an invalid alias")
		}
		var dual struct {
			Daily  json.RawMessage `json:"daily"`
			Weekly json.RawMessage `json:"weekly"`
		}
		if err := decodeStrictJSON(entry, &dual); err == nil && (len(dual.Daily) > 0 || len(dual.Weekly) > 0) {
			windows := aliasUsageWindows{}
			if len(dual.Daily) > 0 {
				windows.Daily, err = decodeUsageWindow(dual.Daily)
				if err != nil {
					return usageState{}, err
				}
			}
			if len(dual.Weekly) > 0 {
				windows.Weekly, err = decodeUsageWindow(dual.Weekly)
				if err != nil {
					return usageState{}, err
				}
			}
			result.ByAlias[alias] = windows
			continue
		}
		window, windowErr := decodeUsageWindow(entry)
		if windowErr != nil {
			return usageState{}, errors.New("usage alias entry has an invalid shape")
		}
		result.ByAlias[alias] = aliasUsageWindows{Daily: window}
	}
	return result, nil
}

func decodeUsageWindow(raw json.RawMessage) (usageWindow, error) {
	var window usageWindow
	if err := decodeStrictJSON(raw, &window); err != nil {
		return usageWindow{}, errors.New("usage window has an invalid shape")
	}
	if !finiteNonnegative(window.TotalUSD) || !finiteNonnegative(window.CacheCostUSD) || window.TotalUSD > 1_000_000_000 || window.CacheCostUSD > 1_000_000_000 ||
		window.CacheReadTokens < 0 || window.InputTokens < 0 || window.OutputTokens < 0 || window.CallCount < 0 {
		return usageWindow{}, errors.New("usage window contains a negative, non-finite, or oversized value")
	}
	if !window.WindowStart.IsZero() && (window.WindowStart.Year() < 2000 || window.WindowStart.Year() > 2200) {
		return usageWindow{}, errors.New("usage window timestamp is outside the supported range")
	}
	if !window.WindowStart.IsZero() && window.WindowStart.After(time.Now().UTC().Add(5*time.Minute)) {
		return usageWindow{}, errors.New("usage window timestamp is unexpectedly in the future")
	}
	if usageWindowHasMeasurements(window) && window.WindowStart.IsZero() {
		return usageWindow{}, errors.New("non-zero usage window is missing its window_start")
	}
	return window, nil
}

func usageWindowHasMeasurements(value usageWindow) bool {
	return value.TotalUSD != 0 || value.CacheReadTokens != 0 || value.CacheCostUSD != 0 || value.InputTokens != 0 || value.OutputTokens != 0 || value.CallCount != 0
}

func finiteNonnegative(value float64) bool {
	return value >= 0 && !math.IsInf(value, 0) && !math.IsNaN(value)
}

func readMigrationPortalUsers(ctx context.Context, databasePath string) ([]portalMigrationUser, error) {
	file, before, err := openProtectedMigrationFile(databasePath, maxPortalDatabaseBytes, false)
	if err != nil {
		return nil, fmt.Errorf("migrated Portal database: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, errors.New("migrated Portal database could not be closed after inspection")
	}
	query := url.URL{Scheme: "file", Path: databasePath, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"}
	database, err := sql.Open("sqlite", query.String())
	if err != nil {
		return nil, errors.New("open migrated Portal database read-only")
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	var version int
	if err := database.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != 4 {
		return nil, errors.New("migrated Portal database schema is not v4")
	}
	var quick string
	if err := database.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&quick); err != nil || quick != "ok" {
		return nil, errors.New("migrated Portal database quick_check failed")
	}
	foreignRows, err := database.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return nil, errors.New("migrated Portal database foreign-key check failed")
	}
	if foreignRows.Next() {
		foreignRows.Close()
		return nil, errors.New("migrated Portal database contains a foreign-key violation")
	}
	if err := foreignRows.Close(); err != nil {
		return nil, err
	}
	rows, err := database.QueryContext(ctx, `SELECT username,username_norm,tenant_id,runtime_user,data_root,enabled FROM portal_users ORDER BY username_norm`)
	if err != nil {
		return nil, errors.New("list migrated Portal users")
	}
	defer rows.Close()
	var users []portalMigrationUser
	for rows.Next() {
		var user portalMigrationUser
		var enabled int
		if err := rows.Scan(&user.Username, &user.UsernameNorm, &user.TenantID, &user.RuntimeUser, &user.DataRoot, &enabled); err != nil || (enabled != 0 && enabled != 1) {
			return nil, errors.New("read migrated Portal identity")
		}
		user.Enabled = enabled == 1
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := verifyMigrationFileIdentity(databasePath, before); err != nil {
		return nil, errors.New("migrated Portal database changed during validation")
	}
	return users, nil
}

func crossCheckMigrationUsers(report winmigration.Report, users []portalMigrationUser) error {
	if len(users) != len(report.Tenants) || len(users) != report.Portal.Users {
		return errors.New("migrated Portal user count does not match the migration report")
	}
	reported := make(map[string]winmigration.TenantReport, len(report.Tenants))
	for _, tenant := range report.Tenants {
		reported[tenant.TenantID] = tenant
	}
	seen := make(map[string]bool, len(users))
	for _, user := range users {
		tenant, ok := reported[user.TenantID]
		if !ok || seen[user.TenantID] || user.Username != tenant.Username || user.UsernameNorm != store.NormalizeUsername(user.Username) ||
			user.RuntimeUser != tenant.RuntimeUser || user.DataRoot != tenant.DataRoot {
			return errors.New("migrated Portal identity does not match the migration report")
		}
		seen[user.TenantID] = true
	}
	return nil
}

func readProtectedMigrationFile(path string, maximum int64, rootOwned bool) ([]byte, syscall.Stat_t, error) {
	file, stat, err := openProtectedMigrationFile(path, maximum, rootOwned)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		clear(payload)
		return nil, syscall.Stat_t{}, errors.New("protected file could not be read safely")
	}
	return payload, stat, nil
}

func openProtectedMigrationFile(path string, maximum int64, rootOwned bool) (*os.File, syscall.Stat_t, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || maximum < 1 {
		return nil, syscall.Stat_t{}, errors.New("path must be clean, absolute, and bounded")
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, syscall.Stat_t{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, errors.New("protected file could not be opened")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximum {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file is missing, oversized, or has unsafe mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (rootOwned && stat.Uid != 0) {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file ownership is invalid")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file parent is unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != stat.Uid {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file parent ownership does not match")
	}
	return file, *stat, nil
}

func rejectSymlinkAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("protected path component is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("protected path must not contain a symbolic link")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func verifyMigrationFileIdentity(path string, before syscall.Stat_t) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("protected file identity changed")
	}
	after, ok := info.Sys().(*syscall.Stat_t)
	if !ok || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size || after.Mtim != before.Mtim {
		return errors.New("protected file identity changed")
	}
	return nil
}

func decodeStrictJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func usageStateEqual(left, right usageState) bool {
	if !usageWindowEqual(left.Daily, right.Daily) || !usageWindowEqual(left.Weekly, right.Weekly) || len(left.ByAlias) != len(right.ByAlias) {
		return false
	}
	for alias, expected := range left.ByAlias {
		actual, ok := right.ByAlias[alias]
		if !ok || !usageWindowEqual(expected.Daily, actual.Daily) || !usageWindowEqual(expected.Weekly, actual.Weekly) {
			return false
		}
	}
	return true
}

func usageWindowEqual(left, right usageWindow) bool {
	return floatEqual(left.TotalUSD, right.TotalUSD) && left.WindowStart.Equal(right.WindowStart) && left.CacheReadTokens == right.CacheReadTokens &&
		floatEqual(left.CacheCostUSD, right.CacheCostUSD) && left.InputTokens == right.InputTokens && left.OutputTokens == right.OutputTokens && left.CallCount == right.CallCount
}

func usageIsZero(value usageState) bool {
	if !usageWindowZero(value.Daily) || !usageWindowZero(value.Weekly) {
		return false
	}
	for _, windows := range value.ByAlias {
		if !usageWindowZero(windows.Daily) || !usageWindowZero(windows.Weekly) {
			return false
		}
	}
	return true
}

func usageWindowZero(value usageWindow) bool {
	return value.TotalUSD == 0 && value.CacheReadTokens == 0 && value.CacheCostUSD == 0 && value.InputTokens == 0 && value.OutputTokens == 0 && value.CallCount == 0
}

func floatEqual(left, right float64) bool {
	if left == right {
		return true
	}
	difference := math.Abs(left - right)
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return difference <= 1e-12*scale
}

func parsePositiveUint32(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, errors.New("runtime account identity is invalid")
	}
	return uint32(parsed), nil
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
