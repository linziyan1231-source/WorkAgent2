package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

var (
	plainKeyPattern    = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	policyKeyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
)

type Provisioner struct {
	Config config.CLIProxy
}

type catalogAlias struct {
	Alias                    string          `json:"alias"`
	Targets                  []catalogTarget `json:"targets"`
	Dispatch                 string          `json:"dispatch,omitempty"`
	BillingMode              string          `json:"billing_mode,omitempty"`
	InputPricePerMillion     json.Number     `json:"input_price_per_million"`
	OutputPricePerMillion    json.Number     `json:"output_price_per_million"`
	CacheReadPricePerMillion json.Number     `json:"cache_read_price_per_million,omitempty"`
	PerCallUSD               json.Number     `json:"per_call_usd,omitempty"`
}

type catalogTarget struct {
	Provider    string `json:"provider"`
	TargetModel string `json:"target_model"`
	Group       string `json:"group,omitempty"`
}

type keyModel struct {
	Alias                    string      `json:"alias"`
	Provider                 string      `json:"provider"`
	TargetModel              string      `json:"target_model"`
	Group                    string      `json:"group,omitempty"`
	InputPricePerMillion     json.Number `json:"input_price_per_million"`
	OutputPricePerMillion    json.Number `json:"output_price_per_million"`
	CacheReadPricePerMillion json.Number `json:"cache_read_price_per_million,omitempty"`
	PerCallUSD               json.Number `json:"per_call_usd,omitempty"`
}

type keyWrite struct {
	ID                  string      `json:"id"`
	Name                string      `json:"name"`
	Enabled             bool        `json:"enabled"`
	RPM                 int         `json:"rpm"`
	Models              []keyModel  `json:"models"`
	DailyLimitUSD       json.Number `json:"daily_limit_usd"`
	WeeklyLimitUSD      json.Number `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool        `json:"allow_models_endpoint"`
}

type listedKey struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Enabled             bool              `json:"enabled"`
	KeyPreview          string            `json:"key_preview"`
	RPM                 int               `json:"rpm"`
	Models              []json.RawMessage `json:"models"`
	Aliases             []json.RawMessage `json:"aliases"`
	DailyLimitUSD       json.Number       `json:"daily_limit_usd"`
	WeeklyLimitUSD      json.Number       `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool              `json:"allow_models_endpoint"`
	Usage               json.RawMessage   `json:"usage"`
	CreatedAt           string            `json:"created_at,omitempty"`
	UpdatedAt           string            `json:"updated_at,omitempty"`
}

func (p Provisioner) Provision(ctx context.Context, tenantID, username string, policy productconfig.Policy) (modelbootstrap.Bundle, error) {
	state, err := modelbootstrap.StateFromPolicy(policy, p.Config.APIBaseURL, tenantID)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	if strings.TrimSpace(username) == "" || len(username) > 64 || strings.ContainsAny(username, "\r\n") {
		return modelbootstrap.Bundle{}, errors.New("Portal username is invalid for CLIProxy provisioning")
	}
	client, err := NewManagementClient(ManagementOptions{BaseURL: p.Config.ManagementURL, KeyFile: p.Config.ManagementCredentialFile})
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	defer client.Close()
	catalog, err := readCatalog(ctx, client, policy)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	desired := make([]keyWrite, 0, 2)
	for _, provider := range []struct {
		name, label, id string
		models          []string
	}{{"codex", "ChatGPT-Codex", state.CodexKeyID, state.CodexModels}, {"kimi", "Kimi", state.KimiKeyID, state.KimiModels}} {
		key, err := desiredKey(username+" / "+provider.label, provider.id, provider.name, provider.models, policy, catalog)
		if err != nil {
			return modelbootstrap.Bundle{}, err
		}
		desired = append(desired, key)
	}
	keys, err := readKeys(ctx, client)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	existing := make(map[string]bool, len(keys))
	for _, key := range keys {
		existing[key.ID] = true
	}
	plain := make(map[string]string, 2)
	for _, key := range desired {
		var oneTime struct {
			PlainKey  string          `json:"plain_key"`
			Generated bool            `json:"generated"`
			Key       json.RawMessage `json:"key"`
		}
		if existing[key.ID] {
			if err := client.JSON(ctx, http.MethodPatch, "/keys", key, nil); err != nil {
				return modelbootstrap.Bundle{}, err
			}
			if err := client.JSON(ctx, http.MethodPost, "/keys/rotate", map[string]string{"id": key.ID}, &oneTime); err != nil {
				return modelbootstrap.Bundle{}, err
			}
		} else if err := client.JSON(ctx, http.MethodPost, "/keys", key, &oneTime); err != nil {
			return modelbootstrap.Bundle{}, err
		}
		if !plainKeyPattern.MatchString(oneTime.PlainKey) {
			return modelbootstrap.Bundle{}, errors.New("CLIProxy returned an invalid one-time tenant key")
		}
		plain[key.ID] = oneTime.PlainKey
	}
	verified, err := readKeys(ctx, client)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	if err := verifyKeys(desired, verified); err != nil {
		return modelbootstrap.Bundle{}, err
	}
	bundle := modelbootstrap.Bundle{State: state, CodexAPIKey: plain[state.CodexKeyID], KimiAPIKey: plain[state.KimiKeyID]}
	if err := bundle.ValidateForTenant(tenantID); err != nil {
		bundle.Zero()
		return modelbootstrap.Bundle{}, err
	}
	return bundle, nil
}

type managementJSONClient interface {
	JSON(context.Context, string, string, any, any) error
}

func readCatalog(ctx context.Context, client managementJSONClient, policy productconfig.Policy) (map[string]catalogAlias, error) {
	result, err := readCatalogUnchecked(ctx, client)
	if err != nil {
		return nil, err
	}
	for _, alias := range result {
		if expected, ok := policy.Pricing[alias.Alias]; ok && (!numberEqual(alias.InputPricePerMillion, expected.InputPerMillion) || !numberEqual(alias.OutputPricePerMillion, expected.OutputPerMillion)) {
			return nil, fmt.Errorf("CLIProxy pricing does not match policy for %s", alias.Alias)
		}
	}
	return result, nil
}

func readCatalogUnchecked(ctx context.Context, client managementJSONClient) (map[string]catalogAlias, error) {
	var response struct {
		Aliases []json.RawMessage `json:"aliases"`
	}
	if err := client.JSON(ctx, http.MethodGet, "/aliases", nil, &response); err != nil {
		return nil, err
	}
	result := make(map[string]catalogAlias, len(response.Aliases))
	for _, raw := range response.Aliases {
		var alias catalogAlias
		if err := decodeManagementJSON(raw, &alias); err != nil || alias.Alias == "" || len(alias.Targets) == 0 {
			return nil, errors.New("CLIProxy alias catalog contains an invalid entry")
		}
		key := strings.ToLower(alias.Alias)
		if _, duplicate := result[key]; duplicate {
			return nil, errors.New("CLIProxy alias catalog contains a duplicate")
		}
		result[key] = alias
	}
	return result, nil
}

func desiredKey(name, id, provider string, models []string, policy productconfig.Policy, catalog map[string]catalogAlias) (keyWrite, error) {
	if len(models) == 0 {
		return keyWrite{}, fmt.Errorf("provider %s has no enabled models", provider)
	}
	first, ok := policy.Quotas[models[0]]
	if !ok {
		return keyWrite{}, fmt.Errorf("model %s has no quota", models[0])
	}
	result := keyWrite{ID: id, Name: name, Enabled: true, RPM: first.RequestsPerMinute, DailyLimitUSD: json.Number(first.DailyUSD), WeeklyLimitUSD: json.Number(first.WeeklyUSD), AllowModelsEndpoint: true}
	for _, model := range models {
		quota, ok := policy.Quotas[model]
		if !ok || quota.RequestsPerMinute != first.RequestsPerMinute || quota.DailyUSD != first.DailyUSD || quota.WeeklyUSD != first.WeeklyUSD {
			return keyWrite{}, fmt.Errorf("provider %s models must share one key quota", provider)
		}
		alias, ok := catalog[strings.ToLower(model)]
		if !ok {
			return keyWrite{}, fmt.Errorf("CLIProxy alias %s is missing", model)
		}
		price, ok := policy.Pricing[model]
		if !ok || !numberEqual(alias.InputPricePerMillion, price.InputPerMillion) || !numberEqual(alias.OutputPricePerMillion, price.OutputPerMillion) {
			return keyWrite{}, fmt.Errorf("CLIProxy pricing does not match policy for %s", model)
		}
		for _, target := range alias.Targets {
			result.Models = append(result.Models, keyModel{Alias: alias.Alias, Provider: target.Provider, TargetModel: target.TargetModel, Group: target.Group,
				InputPricePerMillion: alias.InputPricePerMillion, OutputPricePerMillion: alias.OutputPricePerMillion, CacheReadPricePerMillion: alias.CacheReadPricePerMillion, PerCallUSD: alias.PerCallUSD})
		}
	}
	return result, nil
}

func readKeys(ctx context.Context, client managementJSONClient) ([]listedKey, error) {
	var response struct {
		Keys []listedKey `json:"keys"`
	}
	if err := client.JSON(ctx, http.MethodGet, "/keys", nil, &response); err != nil {
		return nil, err
	}
	return response.Keys, nil
}

func verifyKeys(desired []keyWrite, actual []listedKey) error {
	byID := make(map[string]listedKey, len(actual))
	for _, key := range actual {
		if key.ID == "" || byID[key.ID].ID != "" {
			return errors.New("CLIProxy key readback has an invalid or duplicate id")
		}
		byID[key.ID] = key
	}
	for _, expected := range desired {
		value, ok := byID[expected.ID]
		if !ok || value.Name != expected.Name || !value.Enabled || value.RPM != expected.RPM || !numberEqual(value.DailyLimitUSD, expected.DailyLimitUSD.String()) ||
			!numberEqual(value.WeeklyLimitUSD, expected.WeeklyLimitUSD.String()) || !value.AllowModelsEndpoint || len(value.Models) != len(expected.Models) {
			return fmt.Errorf("CLIProxy key verification failed for %s", expected.ID)
		}
		wanted := make([]string, 0, len(expected.Models))
		for _, model := range expected.Models {
			wanted = append(wanted, model.Alias+"\x00"+model.Provider+"\x00"+model.TargetModel+"\x00"+model.Group)
		}
		got := make([]string, 0, len(value.Models))
		for _, raw := range value.Models {
			var model keyModel
			if err := json.Unmarshal(raw, &model); err != nil {
				return errors.New("CLIProxy key model readback is invalid")
			}
			got = append(got, model.Alias+"\x00"+model.Provider+"\x00"+model.TargetModel+"\x00"+model.Group)
		}
		sort.Strings(wanted)
		sort.Strings(got)
		if strings.Join(wanted, "\xff") != strings.Join(got, "\xff") {
			return fmt.Errorf("CLIProxy key model verification failed for %s", expected.ID)
		}
	}
	return nil
}

func numberEqual(value json.Number, expected string) bool {
	left, ok := new(big.Rat).SetString(value.String())
	if !ok {
		return false
	}
	right, ok := new(big.Rat).SetString(expected)
	return ok && left.Cmp(right) == 0
}
