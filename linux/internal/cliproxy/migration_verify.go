package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

type VerifyMigrationPlanOptions struct {
	ReportPath         string
	PlanPath           string
	PortalDatabasePath string
	CLIProxy           config.CLIProxy
	Policy             productconfig.Policy
}

type VerifyMigrationPlanResult struct {
	Users     int `json:"users"`
	Overrides int `json:"overrides"`
}

type migrationUsageSummary struct {
	DailyUSD              float64   `json:"daily_usd"`
	WeeklyUSD             float64   `json:"weekly_usd"`
	DailyLimitUSD         float64   `json:"daily_limit_usd"`
	WeeklyLimitUSD        float64   `json:"weekly_limit_usd"`
	DailyResetAt          time.Time `json:"daily_reset_at,omitempty"`
	WeeklyResetAt         time.Time `json:"weekly_reset_at,omitempty"`
	DailyCacheCostUSD     float64   `json:"daily_cache_cost_usd,omitempty"`
	WeeklyCacheCostUSD    float64   `json:"weekly_cache_cost_usd,omitempty"`
	DailyCacheReadTokens  int64     `json:"daily_cache_read_tokens,omitempty"`
	WeeklyCacheReadTokens int64     `json:"weekly_cache_read_tokens,omitempty"`
	DailyInputTokens      int64     `json:"daily_input_tokens,omitempty"`
	WeeklyInputTokens     int64     `json:"weekly_input_tokens,omitempty"`
	DailyCallCount        int64     `json:"daily_call_count,omitempty"`
	WeeklyCallCount       int64     `json:"weekly_call_count,omitempty"`
}

type migrationAliasUsageEntry struct {
	Alias       string      `json:"alias"`
	Provider    string      `json:"provider,omitempty"`
	TargetModel string      `json:"target_model,omitempty"`
	BillingMode string      `json:"billing_mode,omitempty"`
	PerCallUSD  float64     `json:"per_call_usd,omitempty"`
	InConfig    bool        `json:"in_config"`
	Daily       usageWindow `json:"daily"`
	Weekly      usageWindow `json:"weekly"`
}

// VerifyMigrationPlan performs live management API readback after CLIProxy is
// restarted and before any UserHost consumes the pending one-time keys.
func VerifyMigrationPlan(ctx context.Context, options VerifyMigrationPlanOptions) (VerifyMigrationPlanResult, error) {
	if err := options.CLIProxy.Validate(); err != nil {
		return VerifyMigrationPlanResult{}, fmt.Errorf("CLIProxy contract: %w", err)
	}
	if err := options.Policy.Validate(); err != nil {
		return VerifyMigrationPlanResult{}, fmt.Errorf("CLIProxy policy: %w", err)
	}
	artifacts, err := loadMigrationArtifacts(ctx, options.ReportPath, options.PlanPath, options.PortalDatabasePath)
	if err != nil {
		return VerifyMigrationPlanResult{}, err
	}
	tenants, err := lockMigrationTenants(artifacts.users)
	if err != nil {
		return VerifyMigrationPlanResult{}, err
	}
	defer closeMigrationTenants(tenants)
	client, err := NewManagementClient(ManagementOptions{BaseURL: options.CLIProxy.ManagementURL, KeyFile: options.CLIProxy.ManagementCredentialFile})
	if err != nil {
		return VerifyMigrationPlanResult{}, err
	}
	defer client.Close()
	// Windows migration deliberately completes its key/quota cutover before the
	// replacement host's provider OAuth logins. Keep this gate on the protected
	// core/plugin/policy/catalog contract; Portal and doctor use CheckReadiness
	// and remain fail-closed until both provider credentials are active.
	if err := checkMigrationReadinessWithClient(ctx, options.CLIProxy, options.Policy, client); err != nil {
		return VerifyMigrationPlanResult{}, err
	}
	catalog, err := readCatalog(ctx, client, options.Policy)
	if err != nil {
		return VerifyMigrationPlanResult{}, err
	}
	keys, err := readKeys(ctx, client)
	if err != nil {
		return VerifyMigrationPlanResult{}, err
	}
	byKey := make(map[string]listedKey, len(keys))
	for _, key := range keys {
		if key.ID == "" || byKey[key.ID].ID != "" {
			return VerifyMigrationPlanResult{}, errors.New("CLIProxy migration key readback contains duplicate ids")
		}
		byKey[key.ID] = key
	}
	verificationTime := time.Now().UTC()
	for _, tenant := range tenants {
		if err := rejectAppliedMigrationMarker(tenant.root); err != nil {
			return VerifyMigrationPlanResult{}, err
		}
		pending, err := readMigrationPending(tenant.root, tenant.uid, tenant.gid)
		if err != nil || !pending.exists || pending.recoverable {
			return VerifyMigrationPlanResult{}, errors.New("tenant migration bundle is unavailable for live verification")
		}
		state, err := modelbootstrap.StateFromPolicy(options.Policy, options.CLIProxy.APIBaseURL, tenant.user.TenantID)
		if err != nil || !pending.bundle.State.Equal(state) {
			pending.bundle.Zero()
			return VerifyMigrationPlanResult{}, errors.New("tenant migration bundle policy does not match live verification")
		}
		desired := make([]keyWrite, 0, 2)
		for _, provider := range []struct {
			name, label, id string
			models          []string
		}{{"codex", "ChatGPT-Codex", state.CodexKeyID, state.CodexModels}, {"kimi", "Kimi", state.KimiKeyID, state.KimiModels}} {
			key, desiredErr := desiredKey(tenant.user.Username+" / "+provider.label, provider.id, provider.name, provider.models, options.Policy, catalog)
			if desiredErr != nil {
				pending.bundle.Zero()
				return VerifyMigrationPlanResult{}, desiredErr
			}
			override := artifacts.byTenant[tenant.user.TenantID][0]
			if provider.name == "kimi" {
				override = artifacts.byTenant[tenant.user.TenantID][1]
			}
			key.DailyLimitUSD = json.Number(override.DailyLimitUSD)
			key.WeeklyLimitUSD = json.Number(override.WeeklyLimitUSD)
			desired = append(desired, key)
		}
		if err := verifyKeys(desired, keys); err != nil || byKey[state.CodexKeyID].KeyPreview != migrationKeyPreview(pending.bundle.CodexAPIKey) ||
			byKey[state.KimiKeyID].KeyPreview != migrationKeyPreview(pending.bundle.KimiAPIKey) {
			pending.bundle.Zero()
			return VerifyMigrationPlanResult{}, errors.New("tenant migration key or quota live readback failed")
		}
		if err := verifyPendingKeyAuthentication(ctx, options.CLIProxy.APIBaseURL, tenant.user.TenantID, pending.bundle); err != nil {
			pending.bundle.Zero()
			return VerifyMigrationPlanResult{}, err
		}
		pending.bundle.Zero()
		for _, override := range artifacts.byTenant[tenant.user.TenantID] {
			key := byKey[override.NewKeyID]
			if err := verifyMigrationUsageSummary(key.Usage, override, verificationTime); err != nil {
				return VerifyMigrationPlanResult{}, err
			}
			if err := verifyMigrationAliasUsage(ctx, client, override, verificationTime); err != nil {
				return VerifyMigrationPlanResult{}, err
			}
		}
	}
	return VerifyMigrationPlanResult{Users: len(tenants), Overrides: len(artifacts.plan.Overrides)}, nil
}

func checkMigrationReadinessWithClient(ctx context.Context, endpoint config.CLIProxy, policy productconfig.Policy, client readinessManagementClient) error {
	return checkPolicyReadinessWithClient(ctx, endpoint, policy, client)
}

func verifyMigrationUsageSummary(raw json.RawMessage, override migrationQuotaOverride, now time.Time) error {
	var actual migrationUsageSummary
	if err := decodeStrictJSON(raw, &actual); err != nil {
		return errors.New("CLIProxy migration usage summary readback is invalid")
	}
	daily := effectiveUsageWindow(override.usage.Daily, true, now)
	weekly := effectiveUsageWindow(override.usage.Weekly, false, now)
	dailyLimit, _ := json.Number(override.DailyLimitUSD).Float64()
	weeklyLimit, _ := json.Number(override.WeeklyLimitUSD).Float64()
	if !floatEqual(actual.DailyLimitUSD, dailyLimit) || !floatEqual(actual.WeeklyLimitUSD, weeklyLimit) ||
		!floatEqual(actual.DailyUSD, daily.TotalUSD) || !floatEqual(actual.WeeklyUSD, weekly.TotalUSD) ||
		!floatEqual(actual.DailyCacheCostUSD, daily.CacheCostUSD) || !floatEqual(actual.WeeklyCacheCostUSD, weekly.CacheCostUSD) ||
		actual.DailyCacheReadTokens != daily.CacheReadTokens || actual.WeeklyCacheReadTokens != weekly.CacheReadTokens ||
		actual.DailyInputTokens != daily.InputTokens || actual.WeeklyInputTokens != weekly.InputTokens ||
		actual.DailyCallCount != daily.CallCount || actual.WeeklyCallCount != weekly.CallCount {
		return errors.New("CLIProxy migration quota or usage management readback did not match the archived plan")
	}
	return nil
}

func verifyMigrationAliasUsage(ctx context.Context, client *ManagementClient, override migrationQuotaOverride, now time.Time) error {
	var response struct {
		KeyID   string                     `json:"key_id"`
		KeyName string                     `json:"key_name"`
		Aliases []migrationAliasUsageEntry `json:"aliases"`
	}
	if err := client.keyUsage(ctx, override.NewKeyID, &response); err != nil {
		return err
	}
	if response.KeyID != override.NewKeyID || response.KeyName == "" {
		return errors.New("CLIProxy migration alias usage readback returned the wrong key")
	}
	actual := make(map[string]migrationAliasUsageEntry, len(response.Aliases))
	for _, entry := range response.Aliases {
		if entry.Alias == "" || actual[entry.Alias].Alias != "" {
			return errors.New("CLIProxy migration alias usage readback contains an invalid alias")
		}
		actual[entry.Alias] = entry
	}
	for alias, expected := range override.usage.ByAlias {
		entry, ok := actual[alias]
		if !ok || !usageWindowEqualForLive(entry.Daily, effectiveUsageWindow(expected.Daily, true, now)) ||
			!usageWindowEqualForLive(entry.Weekly, effectiveUsageWindow(expected.Weekly, false, now)) {
			return errors.New("CLIProxy migration per-alias usage readback did not match the archived plan")
		}
		delete(actual, alias)
	}
	for _, entry := range actual {
		if !usageWindowZero(entry.Daily) || !usageWindowZero(entry.Weekly) {
			return errors.New("CLIProxy migration readback contains unexpected non-zero alias usage")
		}
	}
	return nil
}

func effectiveUsageWindow(value usageWindow, daily bool, now time.Time) usageWindow {
	if daily {
		if value.WindowStart.IsZero() || !sameUTCDate(value.WindowStart, now) {
			return usageWindow{}
		}
		return value
	}
	if value.WindowStart.IsZero() || now.Sub(value.WindowStart) >= 7*24*time.Hour {
		return usageWindow{}
	}
	return value
}

func sameUTCDate(left, right time.Time) bool {
	left, right = left.UTC(), right.UTC()
	return left.Year() == right.Year() && left.Month() == right.Month() && left.Day() == right.Day()
}

func usageWindowEqualForLive(actual, expected usageWindow) bool {
	return floatEqual(actual.TotalUSD, expected.TotalUSD) && actual.CacheReadTokens == expected.CacheReadTokens &&
		floatEqual(actual.CacheCostUSD, expected.CacheCostUSD) && actual.InputTokens == expected.InputTokens && actual.OutputTokens == expected.OutputTokens && actual.CallCount == expected.CallCount
}
