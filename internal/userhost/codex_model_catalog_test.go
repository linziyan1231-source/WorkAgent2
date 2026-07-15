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
		FormatVersion: 1, BaseURL: "http://203.0.113.52:8317/v1",
		CodexKeyID: "new-user-chatgpt", KimiKeyID: "new-user-kimi",
		CodexDefaultModel: "example-reasoning", CodexModels: modelbootstrap.ManagedCodexModels(), KimiModels: modelbootstrap.ManagedKimiModels(),
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
	bundle.State.CodexModels = []string{"example-reasoning", "gpt-5.4"}
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
		_ = json.NewEncoder(w).Encode(realShapedManagedCodexCatalog())
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
	existing := `model = "example-reasoning"
model_catalog_json = "C:\\old.json"
approval_policy = "on-request"

[features]
model_catalog_json = "table-value-must-survive"
`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "managed-model-catalog-0.144.4.json")
	if err := writeManagedCodexCatalogSetting(path, catalogPath); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	if strings.Count(got, "model_catalog_json =") != 2 || !strings.Contains(got, "managed-model-catalog-0.144.4.json") || !strings.Contains(got, `model = "example-reasoning"`) || !strings.Contains(got, `approval_policy = "on-request"`) || !strings.Contains(got, `model_catalog_json = "table-value-must-survive"`) || strings.Contains(got, "old.json") {
		t.Fatalf("unexpected rewritten Codex config:\n%s", got)
	}
}

func realShapedManagedCodexCatalog() map[string]any {
	return map[string]any{"models": []map[string]any{
		realShapedManagedCodexModel("example-balanced", 1),
		realShapedManagedCodexModel("example-fast", 2),
		realShapedManagedCodexModel("example-reasoning", 3),
	}}
}

func realShapedManagedCodexModel(slug string, priority int) map[string]any {
	return map[string]any{
		"slug":                              slug,
		"display_name":                      strings.ToUpper(slug),
		"description":                       "Managed GPT-5.6 model",
		"default_reasoning_level":           "medium",
		"supported_reasoning_levels":        []map[string]string{{"effort": "low", "description": "Fast"}, {"effort": "medium", "description": "Balanced"}, {"effort": "high", "description": "Deep"}, {"effort": "xhigh", "description": "Extra deep"}},
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
