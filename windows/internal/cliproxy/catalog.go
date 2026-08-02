package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const managedKimiK3Alias = "kimi-k3"

type CatalogConvergence struct {
	AliasChanged bool
	KeysChanged  int
	KimiKeys     int
}

type catalogAlias struct {
	Alias                    string          `json:"alias"`
	Targets                  []catalogTarget `json:"targets"`
	Dispatch                 string          `json:"dispatch"`
	BillingMode              string          `json:"billing_mode"`
	InputPricePerMillion     float64         `json:"input_price_per_million"`
	OutputPricePerMillion    float64         `json:"output_price_per_million"`
	CacheReadPricePerMillion float64         `json:"cache_read_price_per_million"`
	PerCallUSD               float64         `json:"per_call_usd"`
}

type catalogTarget struct {
	Provider    string `json:"provider"`
	TargetModel string `json:"target_model"`
	Group       string `json:"group,omitempty"`
}

type catalogKeyAlias struct {
	Alias                    string   `json:"alias"`
	InputPricePerMillion     *float64 `json:"input_price_per_million,omitempty"`
	OutputPricePerMillion    *float64 `json:"output_price_per_million,omitempty"`
	CacheReadPricePerMillion *float64 `json:"cache_read_price_per_million,omitempty"`
	PerCallUSD               *float64 `json:"per_call_usd,omitempty"`
}

type catalogKey struct {
	ID         string            `json:"id"`
	KeyPreview string            `json:"key_preview"`
	Aliases    []json.RawMessage `json:"aliases"`
}

func desiredKimiK3Alias() catalogAlias {
	return catalogAlias{
		Alias:    managedKimiK3Alias,
		Targets:  []catalogTarget{{Provider: "kimi", TargetModel: managedKimiK3Alias}},
		Dispatch: "round-robin", BillingMode: "tokens",
		InputPricePerMillion: 3, OutputPricePerMillion: 15, CacheReadPricePerMillion: 0.3,
	}
}

func ConvergeManagedKimiCatalog(ctx context.Context, options ManagementOptions) (CatalogConvergence, error) {
	client, err := NewManagementClient(options)
	if err != nil {
		return CatalogConvergence{}, err
	}
	return convergeManagedKimiCatalog(ctx, client)
}

func convergeManagedKimiCatalog(ctx context.Context, client *ManagementClient) (CatalogConvergence, error) {
	result := CatalogConvergence{}
	desired := desiredKimiK3Alias()
	aliases, err := readCatalogAliases(ctx, client)
	if err != nil {
		return result, err
	}
	actual, found := aliases[strings.ToLower(managedKimiK3Alias)]
	if !found || !sameCatalogAlias(actual, desired) {
		if err := client.JSON(ctx, http.MethodPost, "/aliases", desired, nil); err != nil {
			return result, fmt.Errorf("converge CLIProxyAPI Kimi K3 alias: %w", err)
		}
		result.AliasChanged = true
	}
	aliases, err = readCatalogAliases(ctx, client)
	if err != nil {
		return result, err
	}
	if actual, ok := aliases[strings.ToLower(managedKimiK3Alias)]; !ok || !sameCatalogAlias(actual, desired) {
		return result, errors.New("CLIProxyAPI Kimi K3 alias readback did not match the managed target and pricing")
	}

	keys, err := readCatalogKeys(ctx, client)
	if err != nil {
		return result, err
	}
	previews := make(map[string]string)
	for _, key := range keys {
		refs, isKimi, changed, err := convergeKimiKeyAliases(key.Aliases)
		if err != nil {
			return result, fmt.Errorf("CLIProxyAPI key %s alias catalog was invalid: %w", key.ID, err)
		}
		if !isKimi {
			continue
		}
		result.KimiKeys++
		previews[key.ID] = key.KeyPreview
		if !changed {
			continue
		}
		if err := client.JSON(ctx, http.MethodPatch, "/keys", map[string]any{"id": key.ID, "aliases": refs}, nil); err != nil {
			return result, fmt.Errorf("add Kimi K3 to CLIProxyAPI key %s: %w", key.ID, err)
		}
		result.KeysChanged++
	}
	if result.KimiKeys == 0 {
		return result, errors.New("CLIProxyAPI policy did not contain any Kimi-managed keys")
	}

	verified, err := readCatalogKeys(ctx, client)
	if err != nil {
		return result, err
	}
	verifiedCount := 0
	for _, key := range verified {
		expectedPreview, managed := previews[key.ID]
		if !managed {
			continue
		}
		_, isKimi, changed, err := convergeKimiKeyAliases(key.Aliases)
		if err != nil || !isKimi || changed || key.KeyPreview != expectedPreview {
			return result, fmt.Errorf("CLIProxyAPI Kimi key readback failed without key rotation for %s", key.ID)
		}
		verifiedCount++
	}
	if verifiedCount != result.KimiKeys {
		return result, errors.New("CLIProxyAPI Kimi key readback count changed during catalog convergence")
	}
	return result, nil
}

func readCatalogAliases(ctx context.Context, client *ManagementClient) (map[string]catalogAlias, error) {
	var response struct {
		Aliases []json.RawMessage `json:"aliases"`
	}
	if err := client.JSON(ctx, http.MethodGet, "/aliases", nil, &response); err != nil {
		return nil, err
	}
	aliases := make(map[string]catalogAlias, len(response.Aliases))
	for _, raw := range response.Aliases {
		var alias catalogAlias
		if err := json.Unmarshal(raw, &alias); err != nil || strings.TrimSpace(alias.Alias) == "" {
			return nil, errors.New("CLIProxyAPI alias catalog contained an invalid entry")
		}
		name := strings.ToLower(strings.TrimSpace(alias.Alias))
		if _, duplicate := aliases[name]; duplicate {
			return nil, errors.New("CLIProxyAPI alias catalog contained a duplicate alias")
		}
		aliases[name] = alias
	}
	return aliases, nil
}

func readCatalogKeys(ctx context.Context, client *ManagementClient) ([]catalogKey, error) {
	var response struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := client.JSON(ctx, http.MethodGet, "/keys", nil, &response); err != nil {
		return nil, err
	}
	keys := make([]catalogKey, 0, len(response.Keys))
	seen := make(map[string]bool, len(response.Keys))
	for _, raw := range response.Keys {
		var key catalogKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, errors.New("CLIProxyAPI key catalog contained an invalid entry")
		}
		if strings.TrimSpace(key.ID) == "" || seen[key.ID] {
			return nil, errors.New("CLIProxyAPI key catalog contained an invalid or duplicate id")
		}
		seen[key.ID] = true
		keys = append(keys, key)
	}
	return keys, nil
}

func convergeKimiKeyAliases(rawRefs []json.RawMessage) ([]json.RawMessage, bool, bool, error) {
	refs := append([]json.RawMessage(nil), rawRefs...)
	isKimi := false
	k3Index := -1
	for index, raw := range refs {
		var ref catalogKeyAlias
		if err := json.Unmarshal(raw, &ref); err != nil || strings.TrimSpace(ref.Alias) == "" {
			return nil, false, false, errors.New("invalid alias reference")
		}
		switch strings.ToLower(strings.TrimSpace(ref.Alias)) {
		case "kimi-for-coding", "kimi-for-coding-highspeed":
			isKimi = true
		case managedKimiK3Alias:
			if k3Index >= 0 {
				return nil, false, false, errors.New("duplicate Kimi K3 alias reference")
			}
			k3Index = index
		}
	}
	if !isKimi {
		return refs, false, false, nil
	}
	desired, _ := json.Marshal(catalogKeyAlias{Alias: managedKimiK3Alias})
	if k3Index < 0 {
		return append(refs, desired), true, true, nil
	}
	var current catalogKeyAlias
	_ = json.Unmarshal(refs[k3Index], &current)
	if current.InputPricePerMillion != nil || current.OutputPricePerMillion != nil || current.CacheReadPricePerMillion != nil || current.PerCallUSD != nil {
		refs[k3Index] = desired
		return refs, true, true, nil
	}
	return refs, true, false, nil
}

func sameCatalogAlias(left, right catalogAlias) bool {
	return strings.EqualFold(strings.TrimSpace(left.Alias), right.Alias) && left.Dispatch == right.Dispatch && left.BillingMode == right.BillingMode &&
		left.InputPricePerMillion == right.InputPricePerMillion && left.OutputPricePerMillion == right.OutputPricePerMillion &&
		left.CacheReadPricePerMillion == right.CacheReadPricePerMillion && left.PerCallUSD == right.PerCallUSD && len(left.Targets) == 1 &&
		strings.EqualFold(left.Targets[0].Provider, right.Targets[0].Provider) && left.Targets[0].TargetModel == right.Targets[0].TargetModel && left.Targets[0].Group == ""
}
