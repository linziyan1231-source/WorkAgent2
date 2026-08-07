package userhost

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/modelbootstrap"
)

func TestReadCodexResponseHonorsContextWhileOutputIsBlocked(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	results := scanCodexResponses(ctx, bufio.NewScanner(reader))
	_, err := readCodexResponse(ctx, results, 1)
	if err == nil || !strings.Contains(err.Error(), "exceeded 30 seconds") {
		t.Fatalf("blocked response error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked response ignored context for %v", elapsed)
	}
}

func TestNewUserPendingBootstrapRequiresExactCodexCatalogBeforeCompletion(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"credentials", "config"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := modelbootstrap.Bundle{State: modelbootstrap.State{
		FormatVersion: 1, BaseURL: "http://43.134.118.158:8317/v1",
		CodexKeyID: "new-user-chatgpt", KimiKeyID: "new-user-kimi",
		CodexDefaultModel: "gpt-5.6-luna", CodexModels: modelbootstrap.ManagedCodexModels(), KimiModels: modelbootstrap.ManagedKimiModels(),
	}, CodexAPIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", KimiAPIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654"}
	if err := modelbootstrap.Stage(root, bundle, false); err != nil {
		t.Fatal(err)
	}
	state, managed, err := managedCodexCatalogBootstrapState(root)
	if err != nil || !managed || !sameStringSet(state.CodexModels, modelbootstrap.ManagedCodexModels()) {
		t.Fatalf("pending new-user catalog state: managed=%t state=%+v err=%v", managed, state, err)
	}
	if err := modelbootstrap.Complete(root, bundle.State); err != nil {
		t.Fatal(err)
	}
	state, managed, err = managedCodexCatalogBootstrapState(root)
	if err != nil || !managed || !sameStringSet(state.CodexModels, modelbootstrap.ManagedCodexModels()) {
		t.Fatalf("applied new-user catalog state: managed=%t state=%+v err=%v", managed, state, err)
	}

	otherRoot := t.TempDir()
	for _, name := range []string{"credentials", "config"} {
		if err := os.Mkdir(filepath.Join(otherRoot, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle.State.CodexModels = []string{"gpt-5.6-luna", "gpt-5.4"}
	if err := modelbootstrap.Stage(otherRoot, bundle, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := managedCodexCatalogBootstrapState(otherRoot); err == nil || !strings.Contains(err.Error(), "exact supported catalog") {
		t.Fatalf("non-exact pending new-user catalog error = %v", err)
	}
}

func TestFetchManagedCodexCatalogRequiresExactThreeFullModels(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/v1/models" || r.URL.Query().Get("client_version") != "0.144.4" || r.Header.Get("Authorization") != "Bearer cpa_abcdefghijklmnopqrstuvwxyz012345" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		fixture := realShapedManagedCodexCatalog()
		for _, model := range fixture["models"].([]map[string]any)[:2] {
			levels := model["supported_reasoning_levels"].([]map[string]string)
			model["supported_reasoning_levels"] = append(levels, map[string]string{"effort": "ultra", "description": "Provider-only"})
		}
		_ = json.NewEncoder(w).Encode(fixture)
	}))
	defer server.Close()

	data, err := fetchManagedCodexCatalog(context.Background(), server.URL+"/v1", "0.144.4", []byte("cpa_abcdefghijklmnopqrstuvwxyz012345"))
	if err != nil {
		t.Fatal(err)
	}
	if requestCount != 1 {
		t.Fatalf("catalog request count = %d", requestCount)
	}
	if err := validateManagedCodexCatalog(data); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"effort":"ultra"`) {
		t.Fatalf("normalized catalog still contains ultra: %s", data)
	}
	var catalog managedCodexCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	for _, raw := range catalog.Models {
		var model managedCodexModelMetadata
		if err := json.Unmarshal(raw, &model); err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(model.SupportedReasoningLevels))
		for _, level := range model.SupportedReasoningLevels {
			got = append(got, level.Effort)
		}
		if len(got) != len(managedCodexReasoningEfforts) || !sameStringSet(got, managedCodexReasoningEfforts) || got[len(got)-1] != "max" {
			t.Fatalf("new-user reasoning levels for %s = %v", model.Slug, got)
		}
	}
}

func TestNormalizeManagedCodexCatalogRemovesUltraAndKeepsFiveSupportedLevels(t *testing.T) {
	fixture := realShapedManagedCodexCatalog()
	models := fixture["models"].([]map[string]any)
	for _, model := range models[:2] {
		levels := model["supported_reasoning_levels"].([]map[string]string)
		model["supported_reasoning_levels"] = append(levels, map[string]string{"effort": "ultra", "description": "Provider-only"})
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	normalized, changed, err := normalizeManagedCodexCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("catalog with ultra was not reported as changed")
	}
	if strings.Contains(string(normalized), `"effort":"ultra"`) {
		t.Fatalf("normalized catalog still contains ultra: %s", normalized)
	}
	if err := validateManagedCodexCatalog(normalized); err != nil {
		t.Fatal(err)
	}
	var catalog managedCodexCatalog
	if err := json.Unmarshal(normalized, &catalog); err != nil {
		t.Fatal(err)
	}
	for _, raw := range catalog.Models {
		var model managedCodexModelMetadata
		if err := json.Unmarshal(raw, &model); err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(model.SupportedReasoningLevels))
		for _, level := range model.SupportedReasoningLevels {
			got = append(got, level.Effort)
		}
		if !sameStringSet(got, managedCodexReasoningEfforts) || len(got) != len(managedCodexReasoningEfforts) {
			t.Fatalf("reasoning levels for %s = %v", model.Slug, got)
		}
	}
}

func TestValidateManagedCodexCatalogRejectsExtraOrIncompleteModels(t *testing.T) {
	fixture := realShapedManagedCodexCatalog()
	fixture["models"] = append(fixture["models"].([]map[string]any), realShapedManagedCodexModel("gpt-5.4", 4))
	data, _ := json.Marshal(fixture)
	if err := validateManagedCodexCatalog(data); err == nil || !strings.Contains(err.Error(), "4 models instead of 3") {
		t.Fatalf("extra model error = %v", err)
	}

	fixture = realShapedManagedCodexCatalog()
	delete(fixture["models"].([]map[string]any)[0], "base_instructions")
	data, _ = json.Marshal(fixture)
	if err := validateManagedCodexCatalog(data); err == nil || !strings.Contains(err.Error(), "incomplete runtime metadata") {
		t.Fatalf("incomplete metadata error = %v", err)
	}
}

func TestWriteManagedCodexCatalogSettingPreservesOtherTopLevelAndTableValues(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.toml")
	existing := `model = "gpt-5.6-luna"
model_catalog_json = "C:\\old.json"
approval_policy = "on-request"

[features]
model_catalog_json = "table-value-must-survive"
`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "managed-model-catalog-0.144.4.json")
	catalogData, err := json.Marshal(realShapedManagedCodexCatalog())
	if err != nil {
		t.Fatal(err)
	}
	changed, err := writeManagedCodexCatalogSetting(path, catalogPath, "2.1.0-beta.editfork.19", "0.144.4", catalogData)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first managed catalog configuration was not reported as changed")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	if strings.Count(got, "# Managed Codex model catalog:") != 1 || strings.Count(got, "model_catalog_json =") != 2 || !strings.Contains(got, "release=2.1.0-beta.editfork.19") || !strings.Contains(got, "managed-model-catalog-0.144.4.json") || !strings.Contains(got, `model = "gpt-5.6-luna"`) || !strings.Contains(got, `approval_policy = "on-request"`) || !strings.Contains(got, `model_catalog_json = "table-value-must-survive"`) || strings.Contains(got, "old.json") {
		t.Fatalf("unexpected rewritten Codex config:\n%s", got)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	changed, err = writeManagedCodexCatalogSetting(path, catalogPath, "2.1.0-beta.editfork.19", "0.144.4", catalogData)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("unchanged managed catalog configuration was rewritten")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("unchanged configuration modtime changed from %v to %v", before.ModTime(), after.ModTime())
	}
	changed, err = writeManagedCodexCatalogSetting(path, catalogPath, "2.1.0-beta.editfork.20", "0.144.4", catalogData)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("release change did not require full managed catalog verification")
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got = string(content)
	if strings.Count(got, "# Managed Codex model catalog:") != 1 || !strings.Contains(got, "release=2.1.0-beta.editfork.20") || strings.Contains(got, "release=2.1.0-beta.editfork.19") {
		t.Fatalf("release verification identity was not replaced:\n%s", got)
	}
}

func realShapedManagedCodexCatalog() map[string]any {
	return map[string]any{"models": []map[string]any{
		realShapedManagedCodexModel("gpt-5.6-sol", 1),
		realShapedManagedCodexModel("gpt-5.6-terra", 2),
		realShapedManagedCodexModel("gpt-5.6-luna", 3),
	}}
}

func realShapedManagedCodexModel(slug string, priority int) map[string]any {
	return map[string]any{
		"slug":                              slug,
		"display_name":                      strings.ToUpper(slug),
		"description":                       "Managed GPT-5.6 model",
		"default_reasoning_level":           "medium",
		"supported_reasoning_levels":        []map[string]string{{"effort": "low", "description": "Fast"}, {"effort": "medium", "description": "Balanced"}, {"effort": "high", "description": "Deep"}, {"effort": "xhigh", "description": "Extra deep"}, {"effort": "max", "description": "Maximum"}},
		"shell_type":                        "shell_command",
		"visibility":                        "list",
		"supported_in_api":                  true,
		"priority":                          priority,
		"additional_speed_tiers":            []string{},
		"service_tiers":                     []map[string]string{},
		"default_service_tier":              nil,
		"availability_nux":                  nil,
		"upgrade":                           nil,
		"base_instructions":                 "Official Codex runtime instructions",
		"model_messages":                    nil,
		"include_skills_usage_instructions": false,
		"supports_reasoning_summaries":      true,
		"default_reasoning_summary":         "auto",
		"support_verbosity":                 true,
		"default_verbosity":                 "low",
		"apply_patch_tool_type":             "freeform",
		"web_search_tool_type":              "text_and_image",
		"truncation_policy":                 map[string]any{"mode": "tokens", "limit": 10000},
		"supports_parallel_tool_calls":      true,
		"supports_image_detail_original":    true,
		"context_window":                    372000,
		"max_context_window":                372000,
		"auto_compact_token_limit":          nil,
		"comp_hash":                         "3000",
		"effective_context_window_percent":  95,
		"experimental_supported_tools":      []string{},
		"input_modalities":                  []string{"text", "image"},
		"supports_search_tool":              true,
		"use_responses_lite":                true,
		"auto_review_model_override":        nil,
		"tool_mode":                         "code_mode_only",
		"multi_agent_version":               "v2",
	}
}
