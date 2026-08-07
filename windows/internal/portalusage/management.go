package portalusage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"aionuiportal/internal/cliproxy"
	"aionuiportal/internal/modelbootstrap"
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

func RemoteFailureStage(error) string { return "management_query_failed" }

func (c *ManagementRemote) Query(ctx context.Context, ids modelbootstrap.KeyIDs) (RawSnapshot, error) {
	const owner = "single"
	results, err := c.QueryMany(ctx, map[string]modelbootstrap.KeyIDs{owner: ids})
	if err != nil {
		return RawSnapshot{}, err
	}
	result, ok := results[owner]
	if !ok {
		return RawSnapshot{}, errors.New("CLIProxyAPI key usage summary was missing")
	}
	return result, nil
}

func (c *ManagementRemote) QueryMany(ctx context.Context, idsByOwner map[string]modelbootstrap.KeyIDs) (map[string]RawSnapshot, error) {
	if len(idsByOwner) == 0 {
		return map[string]RawSnapshot{}, nil
	}
	var response struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.client.JSON(ctx, "GET", "/keys", nil, &response); err != nil {
		return nil, err
	}
	type expectedKey struct {
		owner string
		kind  string
	}
	expected := make(map[string]expectedKey, len(idsByOwner)*2)
	providers := make(map[string]map[string]RawProvider, len(idsByOwner))
	for owner, ids := range idsByOwner {
		if owner == "" {
			return nil, errors.New("CLIProxyAPI key usage owner was invalid")
		}
		for id, kind := range map[string]string{ids.CodexKeyID: KindChatGPT, ids.KimiKeyID: KindKimi} {
			if id == "" {
				return nil, errors.New("CLIProxyAPI key usage mapping was invalid")
			}
			if _, duplicate := expected[id]; duplicate {
				return nil, errors.New("CLIProxyAPI key usage mapping was duplicated")
			}
			expected[id] = expectedKey{owner: owner, kind: kind}
		}
		providers[owner] = make(map[string]RawProvider, 2)
	}
	for _, raw := range response.Keys {
		var key struct {
			ID      string `json:"id"`
			Aliases []struct {
				Alias string `json:"alias"`
			} `json:"aliases"`
			Models []struct {
				Alias    string `json:"alias"`
				Provider string `json:"provider"`
			} `json:"models"`
			DailyLimitUSD  json.Number `json:"daily_limit_usd"`
			WeeklyLimitUSD json.Number `json:"weekly_limit_usd"`
			Usage          struct {
				DailyUSD       json.Number `json:"daily_usd"`
				WeeklyUSD      json.Number `json:"weekly_usd"`
				DailyLimitUSD  json.Number `json:"daily_limit_usd"`
				WeeklyLimitUSD json.Number `json:"weekly_limit_usd"`
				DailyResetAt   string      `json:"daily_reset_at"`
				WeeklyResetAt  string      `json:"weekly_reset_at"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, errors.New("CLIProxyAPI key usage entry was invalid")
		}
		match, wanted := expected[key.ID]
		if !wanted {
			continue
		}
		ownerProviders := providers[match.owner]
		if _, duplicate := ownerProviders[match.kind]; duplicate || len(key.Aliases) == 0 || len(key.Models) != len(key.Aliases) {
			return nil, errors.New("CLIProxyAPI key usage authorization was missing, duplicated, or inconsistent")
		}
		aliases := make(map[string]bool, len(key.Aliases))
		for _, alias := range key.Aliases {
			name := strings.ToLower(strings.TrimSpace(alias.Alias))
			if name == "" || aliases[name] {
				return nil, errors.New("CLIProxyAPI key usage aliases were invalid")
			}
			aliases[name] = true
		}
		expectedProvider := map[string]string{KindChatGPT: "codex", KindKimi: "kimi"}[match.kind]
		for _, model := range key.Models {
			if !aliases[strings.ToLower(strings.TrimSpace(model.Alias))] || !strings.EqualFold(model.Provider, expectedProvider) {
				return nil, errors.New("CLIProxyAPI key usage model authorization was invalid")
			}
		}
		if key.DailyLimitUSD.String() != key.Usage.DailyLimitUSD.String() || key.WeeklyLimitUSD.String() != key.Usage.WeeklyLimitUSD.String() {
			return nil, errors.New("CLIProxyAPI key usage limits did not match the policy")
		}
		ownerProviders[match.kind] = RawProvider{Kind: match.kind,
			Daily:  RawWindow{LimitUSD: key.Usage.DailyLimitUSD.String(), UsedUSD: key.Usage.DailyUSD.String(), ResetAt: key.Usage.DailyResetAt},
			Weekly: RawWindow{LimitUSD: key.Usage.WeeklyLimitUSD.String(), UsedUSD: key.Usage.WeeklyUSD.String(), ResetAt: key.Usage.WeeklyResetAt}}
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	asOf := now().UTC().Format(time.RFC3339)
	results := make(map[string]RawSnapshot, len(providers))
	for owner, ownerProviders := range providers {
		if len(ownerProviders) != 2 {
			continue
		}
		results[owner] = RawSnapshot{AsOf: asOf, Providers: []RawProvider{ownerProviders[KindChatGPT], ownerProviders[KindKimi]}}
	}
	return results, nil
}
