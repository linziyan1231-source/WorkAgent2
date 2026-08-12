package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"aionuiportal/internal/modelbootstrap"
)

var (
	plainKeyPattern   = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	secretTextPattern = regexp.MustCompile(`cpa_[A-Za-z0-9_-]+`)
)

type Client struct {
	ManagementURL     string
	ManagementKeyFile string
}

type ProvisionOptions struct {
	Username          string
	WindowsSID        string
	BaseURL           string
	CodexDefaultModel string
	CodexModels       []string
	KimiModels        []string
	RPM               int
	CodexDailyUSD     float64
	CodexWeeklyUSD    float64
	KimiDailyUSD      float64
	KimiWeeklyUSD     float64
}

type request struct {
	Version int          `json:"version"`
	Keys    []requestKey `json:"keys"`
}

type requestKey struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	RPM                 int      `json:"rpm"`
	Aliases             []string `json:"aliases"`
	DailyLimitUSD       float64  `json:"daily_limit_usd"`
	WeeklyLimitUSD      float64  `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool     `json:"allow_models_endpoint"`
}

type response struct {
	Version int           `json:"version"`
	Keys    []responseKey `json:"keys"`
}

type responseKey struct {
	ID       string `json:"id"`
	PlainKey string `json:"plain_key"`
	Action   string `json:"action"`
}

func (c Client) Provision(ctx context.Context, options ProvisionOptions) (modelbootstrap.Bundle, error) {
	state, err := stateFor(options)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	client, err := NewManagementClient(ManagementOptions{BaseURL: c.ManagementURL, KeyFile: c.ManagementKeyFile})
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	payload := provisionRequest(options, state)
	parsed, err := provisionWithManagementAPI(ctx, client, payload)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	bundle := modelbootstrap.Bundle{State: state, CodexAPIKey: parsed[state.CodexKeyID], KimiAPIKey: parsed[state.KimiKeyID]}
	if err := bundle.Validate(); err != nil {
		return modelbootstrap.Bundle{}, fmt.Errorf("validate CLIProxyAPI provision result: %w", err)
	}
	return bundle, nil
}

type aliasList struct {
	Aliases []json.RawMessage `json:"aliases"`
}

type publicKeyList struct {
	Keys []publicKey `json:"keys"`
}

type publicKey struct {
	ID                        string            `json:"id"`
	Name                      string            `json:"name"`
	Enabled                   bool              `json:"enabled"`
	KeyPreview                string            `json:"key_preview"`
	RPM                       int               `json:"rpm"`
	Models                    []json.RawMessage `json:"models"`
	Aliases                   []any             `json:"aliases"`
	DailyLimitUSD             json.Number       `json:"daily_limit_usd"`
	WeeklyLimitUSD            json.Number       `json:"weekly_limit_usd"`
	AllowModelsEndpoint       bool              `json:"allow_models_endpoint"`
	CollaborationTargetKeyIDs []string          `json:"collaboration_target_key_ids,omitempty"`
	Usage                     any               `json:"usage"`
	CreatedAt                 string            `json:"created_at,omitempty"`
	UpdatedAt                 string            `json:"updated_at,omitempty"`
}

type keyWrite struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Enabled             bool       `json:"enabled"`
	RPM                 int        `json:"rpm"`
	Models              []keyModel `json:"models"`
	DailyLimitUSD       float64    `json:"daily_limit_usd"`
	WeeklyLimitUSD      float64    `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool       `json:"allow_models_endpoint"`
}

type keyModel struct {
	Alias                    string  `json:"alias"`
	Provider                 string  `json:"provider"`
	TargetModel              string  `json:"target_model"`
	Group                    string  `json:"group,omitempty"`
	BillingMode              string  `json:"billing_mode,omitempty"`
	InputPricePerMillion     float64 `json:"input_price_per_million,omitempty"`
	OutputPricePerMillion    float64 `json:"output_price_per_million,omitempty"`
	CacheReadPricePerMillion float64 `json:"cache_read_price_per_million,omitempty"`
	PerCallUSD               float64 `json:"per_call_usd,omitempty"`
}

func provisionWithManagementAPI(ctx context.Context, client *ManagementClient, payload request) (map[string]string, error) {
	var aliases aliasList
	if err := client.JSON(ctx, "GET", "/aliases", nil, &aliases); err != nil {
		return nil, err
	}
	catalog := make(map[string][]keyModel, len(aliases.Aliases))
	for _, raw := range aliases.Aliases {
		var alias struct {
			Alias                    string  `json:"alias"`
			BillingMode              string  `json:"billing_mode,omitempty"`
			InputPricePerMillion     float64 `json:"input_price_per_million,omitempty"`
			OutputPricePerMillion    float64 `json:"output_price_per_million,omitempty"`
			CacheReadPricePerMillion float64 `json:"cache_read_price_per_million,omitempty"`
			PerCallUSD               float64 `json:"per_call_usd,omitempty"`
			Targets                  []struct {
				Provider    string `json:"provider"`
				TargetModel string `json:"target_model"`
				Group       string `json:"group,omitempty"`
			} `json:"targets"`
		}
		if err := json.Unmarshal(raw, &alias); err != nil || strings.TrimSpace(alias.Alias) == "" {
			return nil, errors.New("CLIProxyAPI alias catalog contained an invalid entry")
		}
		catalogKey := strings.ToLower(alias.Alias)
		if _, duplicate := catalog[catalogKey]; duplicate {
			return nil, errors.New("CLIProxyAPI alias catalog contained a duplicate alias")
		}
		for _, target := range alias.Targets {
			catalog[catalogKey] = append(catalog[catalogKey], keyModel{Alias: alias.Alias, Provider: target.Provider, TargetModel: target.TargetModel, Group: target.Group,
				BillingMode: alias.BillingMode, InputPricePerMillion: alias.InputPricePerMillion, OutputPricePerMillion: alias.OutputPricePerMillion,
				CacheReadPricePerMillion: alias.CacheReadPricePerMillion, PerCallUSD: alias.PerCallUSD})
		}
	}
	var listed publicKeyList
	if err := client.JSON(ctx, "GET", "/keys", nil, &listed); err != nil {
		return nil, err
	}
	existing := make(map[string]bool, len(listed.Keys))
	for _, key := range listed.Keys {
		existing[key.ID] = true
	}
	result := response{Version: 1}
	desiredByID := make(map[string]keyWrite, len(payload.Keys))
	for _, requested := range payload.Keys {
		desired := keyWrite{ID: requested.ID, Name: requested.Name, Enabled: requested.Enabled, RPM: requested.RPM, DailyLimitUSD: requested.DailyLimitUSD, WeeklyLimitUSD: requested.WeeklyLimitUSD, AllowModelsEndpoint: requested.AllowModelsEndpoint}
		for _, name := range requested.Aliases {
			models := catalog[strings.ToLower(name)]
			if len(models) == 0 {
				return nil, fmt.Errorf("CLIProxyAPI alias is missing or has no targets: %s", name)
			}
			desired.Models = append(desired.Models, models...)
		}
		desiredByID[desired.ID] = desired
		var oneTime struct {
			PlainKey  string          `json:"plain_key"`
			Key       json.RawMessage `json:"key"`
			Generated bool            `json:"generated"`
		}
		action := "created"
		if existing[desired.ID] {
			if err := client.JSON(ctx, "PATCH", "/keys", desired, &struct {
				Key json.RawMessage `json:"key"`
			}{}); err != nil {
				return nil, err
			}
			if err := client.JSON(ctx, "POST", "/keys/rotate", map[string]string{"id": desired.ID}, &oneTime); err != nil {
				return nil, err
			}
			action = "rotated"
		} else if err := client.JSON(ctx, "POST", "/keys", desired, &oneTime); err != nil {
			return nil, err
		}
		result.Keys = append(result.Keys, responseKey{ID: desired.ID, PlainKey: oneTime.PlainKey, Action: action})
	}
	var verified publicKeyList
	if err := client.JSON(ctx, "GET", "/keys", nil, &verified); err != nil {
		return nil, err
	}
	verifiedByID := make(map[string]publicKey, len(verified.Keys))
	for _, key := range verified.Keys {
		verifiedByID[key.ID] = key
	}
	for id, desired := range desiredByID {
		actual, ok := verifiedByID[id]
		if !ok || actual.Name != desired.Name || actual.Enabled != desired.Enabled || actual.RPM != desired.RPM ||
			actual.AllowModelsEndpoint != desired.AllowModelsEndpoint || actual.DailyLimitUSD.String() != fmt.Sprint(desired.DailyLimitUSD) ||
			actual.WeeklyLimitUSD.String() != fmt.Sprint(desired.WeeklyLimitUSD) || len(actual.Models) != len(desired.Models) {
			return nil, fmt.Errorf("CLIProxyAPI key verification failed for %s", id)
		}
		models := make(map[string]bool, len(actual.Models))
		for _, raw := range actual.Models {
			var model keyModel
			if err := json.Unmarshal(raw, &model); err != nil {
				return nil, fmt.Errorf("CLIProxyAPI key model readback was invalid for %s", id)
			}
			models[strings.ToLower(model.Alias+"\x00"+model.Provider+"\x00"+model.TargetModel+"\x00"+model.Group)] = true
		}
		for _, model := range desired.Models {
			if !models[strings.ToLower(model.Alias+"\x00"+model.Provider+"\x00"+model.TargetModel+"\x00"+model.Group)] {
				return nil, fmt.Errorf("CLIProxyAPI key model verification failed for %s", id)
			}
		}
	}
	keys := make(map[string]string, len(result.Keys))
	for _, key := range result.Keys {
		if !plainKeyPattern.MatchString(key.PlainKey) {
			return nil, errors.New("CLIProxyAPI provision response contained an invalid key result")
		}
		keys[key.ID] = key.PlainKey
	}
	return keys, nil
}

func provisionRequest(options ProvisionOptions, state modelbootstrap.State) request {
	return request{Version: 1, Keys: []requestKey{
		{ID: state.CodexKeyID, Name: options.Username + " / ChatGPT-Codex", Enabled: true, RPM: options.RPM, Aliases: append([]string(nil), state.CodexModels...), DailyLimitUSD: options.CodexDailyUSD, WeeklyLimitUSD: options.CodexWeeklyUSD, AllowModelsEndpoint: true},
		{ID: state.KimiKeyID, Name: options.Username + " / Kimi", Enabled: true, RPM: options.RPM, Aliases: append([]string(nil), state.KimiModels...), DailyLimitUSD: options.KimiDailyUSD, WeeklyLimitUSD: options.KimiWeeklyUSD, AllowModelsEndpoint: true},
	}}
}

func stateFor(options ProvisionOptions) (modelbootstrap.State, error) {
	if strings.TrimSpace(options.Username) == "" || len(options.Username) > 64 || strings.ContainsAny(options.Username, "\r\n") {
		return modelbootstrap.State{}, errors.New("Portal username is invalid for CLIProxyAPI provisioning")
	}
	if options.RPM < 0 || options.RPM > 100000 || options.CodexDailyUSD <= 0 || options.CodexWeeklyUSD != options.CodexDailyUSD*2 || options.KimiDailyUSD <= 0 || options.KimiWeeklyUSD != options.KimiDailyUSD*2 {
		return modelbootstrap.State{}, errors.New("CLIProxyAPI quota policy is invalid")
	}
	ids := modelbootstrap.KeyIDsForSID(options.WindowsSID)
	state := modelbootstrap.State{FormatVersion: modelbootstrap.FormatVersion, BaseURL: options.BaseURL,
		CodexKeyID: ids.CodexKeyID, KimiKeyID: ids.KimiKeyID, CodexDefaultModel: options.CodexDefaultModel,
		CodexModels: append([]string(nil), options.CodexModels...), KimiModels: append([]string(nil), options.KimiModels...)}
	if err := state.Validate(); err != nil {
		return modelbootstrap.State{}, err
	}
	return state, nil
}

func redact(value string) string {
	value = secretTextPattern.ReplaceAllString(value, "<redacted-key>")
	value = strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 32 && r != 127) {
			return r
		}
		return ' '
	}, value)
	if len(value) > 1000 {
		value = value[:1000]
	}
	return strings.TrimSpace(value)
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.buffer.Write(data)
	}
	if original > remaining {
		b.overflow = true
	}
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *cappedBuffer) String() string { return b.buffer.String() }
