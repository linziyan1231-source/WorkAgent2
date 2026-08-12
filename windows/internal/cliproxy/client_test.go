package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testOptions() ProvisionOptions {
	return ProvisionOptions{Username: "test1", WindowsSID: "S-1-5-21-100-200-300-1017", BaseURL: "http://43.134.118.158:8317/v1",
		CodexDefaultModel: "gpt-5.6-luna", CodexModels: []string{"gpt-5.3-codex-spark", "gpt-5.6-luna", "gpt-5.4-mini"}, KimiModels: []string{"kimi-for-coding", "kimi-for-coding-highspeed", "kimi-k3"},
		RPM: 0, CodexDailyUSD: 20, CodexWeeklyUSD: 40, KimiDailyUSD: 5, KimiWeeklyUSD: 10}
}

func TestProvisionRequestEnablesPerKeyModelsEndpoint(t *testing.T) {
	options := testOptions()
	state, err := stateFor(options)
	if err != nil {
		t.Fatal(err)
	}
	payload := provisionRequest(options, state)
	for index, key := range payload.Keys {
		want := [][]string{state.CodexModels, state.KimiModels}[index]
		if !key.AllowModelsEndpoint || !reflect.DeepEqual(key.Aliases, want) {
			t.Fatalf("employee key does not enable its per-key model catalog with exact aliases: %+v", key)
		}
	}
}

func TestStateUsesStableSIDScopedUniqueKeyIDs(t *testing.T) {
	first, err := stateFor(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	secondOptions := testOptions()
	secondOptions.Username = "renamed-user"
	second, err := stateFor(secondOptions)
	if err != nil {
		t.Fatal(err)
	}
	if first.CodexKeyID != second.CodexKeyID || first.KimiKeyID != second.KimiKeyID || first.CodexKeyID == first.KimiKeyID {
		t.Fatalf("key ids are not stable and purpose-specific: first=%+v second=%+v", first, second)
	}
}

func TestRemoteDiagnosticsRedactPlainKeys(t *testing.T) {
	got := redact("failed for cpa_abcdefghijklmnopqrstuvwxyz012345\nnext")
	if strings.Contains(got, "cpa_") || strings.Contains(got, "\n") {
		t.Fatalf("diagnostic was not redacted: %q", got)
	}
}

func TestProvisionUsesLoopbackManagementAPIAndVerifiesReadback(t *testing.T) {
	options := testOptions()
	managementKey := "windows-native-management-key-0123456789abcdef"
	keys := make(map[string]keyWrite)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+managementKey {
			t.Fatalf("management authorization missing")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v0/management/plugins/cpa-key-policy/aliases":
			aliases := make([]map[string]any, 0, len(options.CodexModels)+len(options.KimiModels))
			for _, alias := range append(append([]string(nil), options.CodexModels...), options.KimiModels...) {
				provider := "codex"
				if strings.HasPrefix(alias, "kimi-") {
					provider = "kimi"
				}
				aliases = append(aliases, map[string]any{"alias": alias, "targets": []map[string]string{{"provider": provider, "target_model": alias}},
					"billing_mode": "tokens", "input_price_per_million": 1, "output_price_per_million": 6, "cache_read_price_per_million": 0.1})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"aliases": aliases})
		case "GET /v0/management/plugins/cpa-key-policy/keys":
			listed := make([]map[string]any, 0, len(keys))
			for _, key := range keys {
				listed = append(listed, map[string]any{"id": key.ID, "name": key.Name, "enabled": key.Enabled, "rpm": key.RPM, "models": key.Models, "aliases": []any{},
					"daily_limit_usd": key.DailyLimitUSD, "weekly_limit_usd": key.WeeklyLimitUSD, "allow_models_endpoint": key.AllowModelsEndpoint,
					"collaboration_target_key_ids": []string{"shared-target"}, "usage": map[string]any{}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": listed})
		case "POST /v0/management/plugins/cpa-key-policy/keys":
			var desired keyWrite
			if err := json.NewDecoder(r.Body).Decode(&desired); err != nil {
				t.Fatal(err)
			}
			keys[desired.ID] = desired
			plain := "cpa_abcdefghijklmnopqrstuvwxyz012345"
			if strings.Contains(desired.ID, "kimi") {
				plain = "cpa_zyxwvutsrqponmlkjihgfedcba987654"
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{}, "plain_key": plain, "generated": true})
		default:
			http.Error(w, fmt.Sprintf("unexpected route %s %s", r.Method, r.URL.Path), http.StatusNotFound)
		}
	}))
	defer server.Close()
	keyFile := filepath.Join(t.TempDir(), "management.key")
	if err := os.WriteFile(keyFile, []byte(managementKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := (Client{ManagementURL: server.URL + "/v0/management/plugins/cpa-key-policy", ManagementKeyFile: keyFile}).Provision(context.Background(), options)
	if err != nil || bundle.CodexAPIKey == bundle.KimiAPIKey || len(keys) != 2 {
		t.Fatalf("direct Management API provisioning failed: bundle=%+v keys=%d err=%v", bundle.State, len(keys), err)
	}
	for _, key := range keys {
		for _, model := range key.Models {
			if model.BillingMode != "tokens" || model.InputPricePerMillion != 1 || model.OutputPricePerMillion != 6 || model.CacheReadPricePerMillion != 0.1 {
				t.Fatalf("alias pricing was not preserved in the key model: %+v", model)
			}
		}
	}
}
