package portalusage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

type ManagementRemote struct {
	client *cliproxy.ManagementClient
	now    func() time.Time
}

func NewManagementRemote(options cliproxy.ManagementOptions) (*ManagementRemote, error) {
	client, err := cliproxy.NewManagementClient(options)
	if err != nil {
		return nil, err
	}
	return &ManagementRemote{client: client, now: time.Now}, nil
}

func (c *ManagementRemote) Close() {
	if c != nil && c.client != nil {
		c.client.Close()
	}
}

func (c *ManagementRemote) Query(ctx context.Context, tenantID string, policy productconfig.Policy) (RawSnapshot, error) {
	if err := policy.Validate(); err != nil || policy.ApprovalRequired {
		return RawSnapshot{}, errors.New("approved model policy is required for usage")
	}
	ids := modelbootstrap.KeyIDsForTenant(tenantID)
	if err := ids.ValidateForTenant(tenantID); err != nil {
		return RawSnapshot{}, err
	}
	var response struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.client.JSON(ctx, http.MethodGet, "/keys", nil, &response); err != nil {
		return RawSnapshot{}, err
	}
	expected := map[string]providerPolicy{}
	for _, item := range []struct{ kind, provider, id string }{
		{KindChatGPT, "codex", ids.CodexKeyID},
		{KindKimi, "kimi", ids.KimiKeyID},
	} {
		value, err := expectedProviderPolicy(item.kind, item.provider, policy)
		if err != nil {
			return RawSnapshot{}, err
		}
		expected[item.id] = value
	}
	providers := make(map[string]RawProvider, 2)
	for _, raw := range response.Keys {
		var key listedUsageKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return RawSnapshot{}, errors.New("CLIProxy key usage entry was invalid")
		}
		wanted, belongs := expected[key.ID]
		if !belongs {
			continue
		}
		if _, duplicate := providers[wanted.kind]; duplicate {
			return RawSnapshot{}, errors.New("CLIProxy tenant key usage was duplicated")
		}
		if err := verifyUsageKey(key, wanted); err != nil {
			return RawSnapshot{}, err
		}
		providers[wanted.kind] = RawProvider{Kind: wanted.kind,
			Daily:  RawWindow{LimitUSD: key.Usage.DailyLimitUSD.String(), UsedUSD: key.Usage.DailyUSD.String(), ResetAt: key.Usage.DailyResetAt},
			Weekly: RawWindow{LimitUSD: key.Usage.WeeklyLimitUSD.String(), UsedUSD: key.Usage.WeeklyUSD.String(), ResetAt: key.Usage.WeeklyResetAt}}
	}
	if len(providers) != 2 {
		return RawSnapshot{}, errors.New("CLIProxy tenant key usage summary was missing")
	}
	now := c.now
	if now == nil {
		now = time.Now
	}
	return RawSnapshot{AsOf: now().UTC().Format(time.RFC3339), Providers: []RawProvider{providers[KindChatGPT], providers[KindKimi]}}, nil
}

type listedUsageKey struct {
	ID                  string          `json:"id"`
	Enabled             bool            `json:"enabled"`
	RPM                 int             `json:"rpm"`
	Models              []usageModel    `json:"models"`
	Aliases             []usageAlias    `json:"aliases"`
	DailyLimitUSD       json.Number     `json:"daily_limit_usd"`
	WeeklyLimitUSD      json.Number     `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool            `json:"allow_models_endpoint"`
	Usage               usageAccounting `json:"usage"`
}

type usageAlias struct {
	Alias string `json:"alias"`
}

type usageModel struct {
	Alias                    string      `json:"alias"`
	Provider                 string      `json:"provider"`
	TargetModel              string      `json:"target_model"`
	Group                    string      `json:"group,omitempty"`
	InputPricePerMillion     json.Number `json:"input_price_per_million"`
	OutputPricePerMillion    json.Number `json:"output_price_per_million"`
	CacheReadPricePerMillion json.Number `json:"cache_read_price_per_million,omitempty"`
	PerCallUSD               json.Number `json:"per_call_usd,omitempty"`
}

type usageAccounting struct {
	DailyUSD       json.Number `json:"daily_usd"`
	WeeklyUSD      json.Number `json:"weekly_usd"`
	DailyLimitUSD  json.Number `json:"daily_limit_usd"`
	WeeklyLimitUSD json.Number `json:"weekly_limit_usd"`
	DailyResetAt   string      `json:"daily_reset_at"`
	WeeklyResetAt  string      `json:"weekly_reset_at"`
}

type providerPolicy struct {
	kind, provider, daily, weekly string
	rpm                           int
	models                        map[string]productconfig.Price
}

func expectedProviderPolicy(kind, provider string, policy productconfig.Policy) (providerPolicy, error) {
	result := providerPolicy{kind: kind, provider: provider, models: make(map[string]productconfig.Price)}
	for _, model := range policy.EnabledModels(provider) {
		quota, quotaOK := policy.Quotas[model.ID]
		price, priceOK := policy.Pricing[model.ID]
		if !quotaOK || !priceOK || price.Currency != "USD" {
			return providerPolicy{}, fmt.Errorf("model %s has no USD policy", model.ID)
		}
		if len(result.models) == 0 {
			result.daily, result.weekly, result.rpm = quota.DailyUSD, quota.WeeklyUSD, quota.RequestsPerMinute
		} else if !equalDecimal(result.daily, quota.DailyUSD) || !equalDecimal(result.weekly, quota.WeeklyUSD) || result.rpm != quota.RequestsPerMinute {
			return providerPolicy{}, fmt.Errorf("provider %s models do not share a key quota", provider)
		}
		result.models[strings.ToLower(model.ID)] = price
	}
	if len(result.models) == 0 {
		return providerPolicy{}, fmt.Errorf("provider %s has no enabled models", provider)
	}
	return result, nil
}

func verifyUsageKey(key listedUsageKey, expected providerPolicy) error {
	if !key.Enabled || !key.AllowModelsEndpoint || key.RPM != expected.rpm ||
		!equalDecimal(key.DailyLimitUSD.String(), expected.daily) || !equalDecimal(key.WeeklyLimitUSD.String(), expected.weekly) ||
		!equalDecimal(key.Usage.DailyLimitUSD.String(), expected.daily) || !equalDecimal(key.Usage.WeeklyLimitUSD.String(), expected.weekly) {
		return errors.New("CLIProxy tenant key quota does not match policy")
	}
	aliases := make([]string, 0, len(key.Aliases))
	seenAliases := make(map[string]bool, len(key.Aliases))
	for _, value := range key.Aliases {
		alias := strings.ToLower(strings.TrimSpace(value.Alias))
		if _, ok := expected.models[alias]; !ok || seenAliases[alias] {
			return errors.New("CLIProxy tenant key aliases do not match policy")
		}
		seenAliases[alias] = true
		aliases = append(aliases, alias)
	}
	if len(seenAliases) != len(expected.models) {
		return errors.New("CLIProxy tenant key aliases do not match policy")
	}
	seenModels := make(map[string]bool, len(expected.models))
	seenTargets := make(map[string]bool, len(key.Models))
	for _, model := range key.Models {
		alias := strings.ToLower(strings.TrimSpace(model.Alias))
		price, ok := expected.models[alias]
		target := alias + "\x00" + model.Provider + "\x00" + model.TargetModel + "\x00" + model.Group
		if !ok || model.Provider != expected.provider || strings.TrimSpace(model.TargetModel) == "" || seenTargets[target] ||
			!equalDecimal(model.InputPricePerMillion.String(), price.InputPerMillion) || !equalDecimal(model.OutputPricePerMillion.String(), price.OutputPerMillion) {
			return errors.New("CLIProxy tenant key model authorization does not match policy")
		}
		seenTargets[target] = true
		seenModels[alias] = true
	}
	if len(seenModels) != len(expected.models) {
		return errors.New("CLIProxy tenant key model authorization does not match policy")
	}
	sort.Strings(aliases)
	return nil
}
