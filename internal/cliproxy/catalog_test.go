package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestConvergeManagedKimiCatalogIsExactPreservingAndIdempotent(t *testing.T) {
	managementKey := "windows-native-management-key-0123456789abcdef"
	aliases := []catalogAlias{
		{Alias: "kimi-for-coding", Targets: []catalogTarget{{Provider: "kimi", TargetModel: "kimi-k2.7-code"}}, Dispatch: "round-robin", BillingMode: "tokens", InputPricePerMillion: 0.95, OutputPricePerMillion: 4, CacheReadPricePerMillion: 0.19},
		{Alias: managedKimiK3Alias, Targets: []catalogTarget{{Provider: "kimi", TargetModel: managedKimiK3Alias}}, Dispatch: "round-robin", BillingMode: "tokens", InputPricePerMillion: 1, OutputPricePerMillion: 2, CacheReadPricePerMillion: 0.1},
		{Alias: "custom", Targets: []catalogTarget{{Provider: "custom", TargetModel: "custom-model"}}, Dispatch: "priority", BillingMode: "tokens"},
	}
	ref := func(value any) json.RawMessage {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	keys := []catalogKey{
		{ID: "employee-kimi", KeyPreview: "cpa_emp...1234", Aliases: []json.RawMessage{ref(map[string]any{"alias": "kimi-for-coding"}), ref(map[string]any{"alias": "custom", "input_price_per_million": 7})}},
		{ID: "admin-kimi", KeyPreview: "cpa_adm...5678", Aliases: []json.RawMessage{ref(map[string]any{"alias": "kimi-for-coding"}), ref(map[string]any{"alias": managedKimiK3Alias, "input_price_per_million": 99})}},
		{ID: "chatgpt", KeyPreview: "cpa_gpt...9999", Aliases: []json.RawMessage{ref(map[string]any{"alias": "custom"})}},
	}
	posts, patches := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+managementKey {
			t.Fatalf("management authorization missing")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v0/management/plugins/cpa-key-policy/aliases":
			_ = json.NewEncoder(w).Encode(map[string]any{"aliases": aliases})
		case "POST /v0/management/plugins/cpa-key-policy/aliases":
			var desired catalogAlias
			if err := json.NewDecoder(r.Body).Decode(&desired); err != nil {
				t.Fatal(err)
			}
			posts++
			for index := range aliases {
				if aliases[index].Alias == desired.Alias {
					aliases[index] = desired
					_ = json.NewEncoder(w).Encode(map[string]any{"alias": desired})
					return
				}
			}
			aliases = append(aliases, desired)
			_ = json.NewEncoder(w).Encode(map[string]any{"alias": desired})
		case "GET /v0/management/plugins/cpa-key-policy/keys":
			listed := make([]map[string]any, 0, len(keys))
			for _, key := range keys {
				listed = append(listed, map[string]any{"id": key.ID, "key_preview": key.KeyPreview, "aliases": key.Aliases, "name": key.ID, "models": []any{}, "usage": map[string]any{}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": listed})
		case "PATCH /v0/management/plugins/cpa-key-policy/keys":
			var patch struct {
				ID      string            `json:"id"`
				Aliases []json.RawMessage `json:"aliases"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Fatal(err)
			}
			patches++
			for index := range keys {
				if keys[index].ID == patch.ID {
					keys[index].Aliases = patch.Aliases
					_ = json.NewEncoder(w).Encode(map[string]any{"key": keys[index]})
					return
				}
			}
			http.Error(w, "unknown key", http.StatusNotFound)
		default:
			http.Error(w, fmt.Sprintf("unexpected route %s %s", r.Method, r.URL.Path), http.StatusNotFound)
		}
	}))
	defer server.Close()
	keyFile := filepath.Join(t.TempDir(), "management.key")
	if err := os.WriteFile(keyFile, []byte(managementKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := ManagementOptions{BaseURL: server.URL + "/v0/management/plugins/cpa-key-policy", KeyFile: keyFile}
	first, err := ConvergeManagedKimiCatalog(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !first.AliasChanged || first.KeysChanged != 2 || first.KimiKeys != 2 || posts != 1 || patches != 2 {
		t.Fatalf("unexpected first convergence: result=%+v posts=%d patches=%d", first, posts, patches)
	}
	if !sameCatalogAlias(aliases[1], desiredKimiK3Alias()) || aliases[2].Alias != "custom" {
		t.Fatalf("managed alias or custom alias changed incorrectly: %+v", aliases)
	}
	var employeeCustom catalogKeyAlias
	if err := json.Unmarshal(keys[0].Aliases[1], &employeeCustom); err != nil || employeeCustom.Alias != "custom" || employeeCustom.InputPricePerMillion == nil || *employeeCustom.InputPricePerMillion != 7 {
		t.Fatalf("custom key alias was not preserved: %s", keys[0].Aliases[1])
	}
	second, err := ConvergeManagedKimiCatalog(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if second.AliasChanged || second.KeysChanged != 0 || second.KimiKeys != 2 || posts != 1 || patches != 2 {
		t.Fatalf("convergence was not idempotent: result=%+v posts=%d patches=%d", second, posts, patches)
	}
}

func TestConvergeManagedKimiCatalogRequiresManagedKimiKeys(t *testing.T) {
	refs := []json.RawMessage{json.RawMessage(`{"alias":"custom"}`)}
	if _, isKimi, changed, err := convergeKimiKeyAliases(refs); err != nil || isKimi || changed {
		t.Fatalf("non-Kimi key was treated as managed: isKimi=%t changed=%t err=%v", isKimi, changed, err)
	}
}
