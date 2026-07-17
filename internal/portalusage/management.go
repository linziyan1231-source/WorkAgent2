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
	var response struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.client.JSON(ctx, "GET", "/keys", nil, &response); err != nil {
		return RawSnapshot{}, err
	}
	expected := map[string]string{ids.CodexKeyID: KindChatGPT, ids.KimiKeyID: KindKimi}
	providers := make(map[string]RawProvider, 2)
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
			return RawSnapshot{}, errors.New("CLIProxyAPI key usage entry was invalid")
		}
		kind, wanted := expected[key.ID]
		if !wanted {
			continue
		}
		if _, duplicate := providers[kind]; duplicate || len(key.Aliases) == 0 || len(key.Models) != len(key.Aliases) {
			return RawSnapshot{}, errors.New("CLIProxyAPI key usage authorization was missing, duplicated, or inconsistent")
		}
		aliases := make(map[string]bool, len(key.Aliases))
		for _, alias := range key.Aliases {
			name := strings.ToLower(strings.TrimSpace(alias.Alias))
			if name == "" || aliases[name] {
				return RawSnapshot{}, errors.New("CLIProxyAPI key usage aliases were invalid")
			}
			aliases[name] = true
		}
		expectedProvider := map[string]string{KindChatGPT: "codex", KindKimi: "kimi"}[kind]
		for _, model := range key.Models {
			if !aliases[strings.ToLower(strings.TrimSpace(model.Alias))] || !strings.EqualFold(model.Provider, expectedProvider) {
				return RawSnapshot{}, errors.New("CLIProxyAPI key usage model authorization was invalid")
			}
		}
		if key.DailyLimitUSD.String() != key.Usage.DailyLimitUSD.String() || key.WeeklyLimitUSD.String() != key.Usage.WeeklyLimitUSD.String() {
			return RawSnapshot{}, errors.New("CLIProxyAPI key usage limits did not match the policy")
		}
		providers[kind] = RawProvider{Kind: kind,
			Daily:  RawWindow{LimitUSD: key.Usage.DailyLimitUSD.String(), UsedUSD: key.Usage.DailyUSD.String(), ResetAt: key.Usage.DailyResetAt},
			Weekly: RawWindow{LimitUSD: key.Usage.WeeklyLimitUSD.String(), UsedUSD: key.Usage.WeeklyUSD.String(), ResetAt: key.Usage.WeeklyResetAt}}
	}
	if len(providers) != 2 {
		return RawSnapshot{}, errors.New("CLIProxyAPI key usage summary was missing")
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	return RawSnapshot{AsOf: now().UTC().Format(time.RFC3339), Providers: []RawProvider{providers[KindChatGPT], providers[KindKimi]}}, nil
}
