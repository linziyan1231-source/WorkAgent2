package cliproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

const provisionTenant = "11111111-1111-4111-8111-111111111111"

func provisionPolicy() productconfig.Policy {
	policy := productconfig.Policy{SchemaVersion: 1, PolicyID: "workagent-models-v1", DefaultAction: "deny", ApprovalRequired: false,
		Aliases: map[string]string{}, Pricing: map[string]productconfig.Price{}, Quotas: map[string]productconfig.Quota{}}
	for _, model := range modelbootstrap.ManagedCodexModels() {
		policy.Models = append(policy.Models, productconfig.Model{ID: model, DisplayName: "Managed " + model, Provider: "codex", Enabled: true, Default: model == modelbootstrap.DefaultCodexModel})
		policy.Pricing[model] = productconfig.Price{InputPerMillion: "1.25", OutputPerMillion: "5", Currency: "USD"}
		policy.Quotas[model] = productconfig.Quota{DailyUSD: "20", WeeklyUSD: "40"}
	}
	for _, model := range modelbootstrap.ManagedKimiModels() {
		policy.Models = append(policy.Models, productconfig.Model{ID: model, DisplayName: "Managed " + model, Provider: "kimi", Enabled: true, Default: model == modelbootstrap.DefaultKimiModel})
		policy.Pricing[model] = productconfig.Price{InputPerMillion: "3", OutputPerMillion: "15", Currency: "USD"}
		policy.Quotas[model] = productconfig.Quota{DailyUSD: "5", WeeklyUSD: "10"}
	}
	return policy
}

func TestProvisionCreatesStablePolicyBoundTenantKeys(t *testing.T) {
	const managementKey = "abcdefghijklmnopqrstuvwxyz_0123456789-ABCDEFG"
	var mu sync.Mutex
	keys := make(map[string]keyWrite)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+managementKey {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		route := strings.TrimPrefix(request.URL.Path, "/v0/management/plugins/cpa-key-policy")
		mu.Lock()
		defer mu.Unlock()
		switch request.Method + " " + route {
		case "GET /aliases":
			aliases := make([]any, 0, len(modelbootstrap.ManagedCodexModels())+len(modelbootstrap.ManagedKimiModels()))
			for _, model := range modelbootstrap.ManagedCodexModels() {
				aliases = append(aliases, map[string]any{"alias": model, "targets": []any{map[string]any{"provider": "codex", "target_model": model + "-upstream"}}, "input_price_per_million": 1.25, "output_price_per_million": 5})
			}
			for _, model := range modelbootstrap.ManagedKimiModels() {
				aliases = append(aliases, map[string]any{"alias": model, "targets": []any{map[string]any{"provider": "kimi", "target_model": model + "-upstream"}}, "input_price_per_million": 3, "output_price_per_million": 15})
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"aliases": aliases})
		case "GET /keys":
			listed := make([]any, 0, len(keys))
			for _, key := range keys {
				listed = append(listed, map[string]any{"id": key.ID, "name": key.Name, "enabled": key.Enabled, "key_preview": "cpa_...", "rpm": key.RPM, "models": key.Models, "aliases": []any{}, "daily_limit_usd": key.DailyLimitUSD, "weekly_limit_usd": key.WeeklyLimitUSD, "allow_models_endpoint": key.AllowModelsEndpoint, "usage": map[string]any{}})
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"keys": listed})
		case "POST /keys", "PATCH /keys":
			var key keyWrite
			if err := json.NewDecoder(request.Body).Decode(&key); err != nil {
				http.Error(writer, "bad request", http.StatusBadRequest)
				return
			}
			keys[key.ID] = key
			_ = json.NewEncoder(writer).Encode(map[string]any{"plain_key": plainForKey(key.ID), "generated": true, "key": map[string]any{}})
		case "POST /keys/rotate":
			var body map[string]string
			_ = json.NewDecoder(request.Body).Decode(&body)
			_ = json.NewEncoder(writer).Encode(map[string]any{"plain_key": plainForKey(body["id"]), "generated": true, "key": map[string]any{}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	keyPath := filepath.Join(t.TempDir(), "management.key")
	if err := os.WriteFile(keyPath, []byte(managementKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	provisioner := Provisioner{Config: config.CLIProxy{APIBaseURL: server.URL + "/v1", ManagementURL: server.URL + "/v0/management/plugins/cpa-key-policy", ManagementCredentialFile: keyPath}}
	bundle, err := provisioner.Provision(context.Background(), provisionTenant, "alice", provisionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Zero()
	ids := modelbootstrap.KeyIDsForTenant(provisionTenant)
	if bundle.CodexKeyID != ids.CodexKeyID || bundle.KimiKeyID != ids.KimiKeyID || bundle.CodexAPIKey == bundle.KimiAPIKey {
		t.Fatalf("unexpected tenant bundle: %+v", bundle.State)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 2 || len(keys[ids.CodexKeyID].Models) != 3 || len(keys[ids.KimiKeyID].Models) != 3 || keys[ids.CodexKeyID].DailyLimitUSD != "20" || keys[ids.KimiKeyID].WeeklyLimitUSD != "10" {
		t.Fatalf("unexpected provisioned policy: %#v", keys)
	}
}

func TestProvisionRejectsCatalogPricingDrift(t *testing.T) {
	policy := provisionPolicy()
	alias := catalogAlias{Alias: modelbootstrap.DefaultCodexModel, Targets: []catalogTarget{{Provider: "codex", TargetModel: "gpt"}}, InputPricePerMillion: "99", OutputPricePerMillion: "5"}
	if _, err := desiredKey("name", "id", "codex", []string{modelbootstrap.DefaultCodexModel}, policy, map[string]catalogAlias{modelbootstrap.DefaultCodexModel: alias}); err == nil {
		t.Fatal("policy/catalog price drift was accepted")
	}
}

func plainForKey(id string) string {
	if strings.HasSuffix(id, "-codex") {
		return "cpa_abcdefghijklmnopqrstuvwxyz012345"
	}
	return "cpa_zyxwvutsrqponmlkjihgfedcba987654"
}
