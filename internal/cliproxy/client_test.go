package cliproxy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func testOptions() ProvisionOptions {
	return ProvisionOptions{Username: "test1", WindowsSID: "S-1-5-21-1335169958-1819941586-1322872941-1322", BaseURL: "http://203.0.113.52:8317/v1",
		CodexDefaultModel: "example-reasoning", CodexModels: []string{"gpt-5.3-codex-spark", "example-reasoning", "gpt-5.4-mini"}, KimiModels: []string{"kimi-for-coding", "kimi-k2.5", "kimi-k2.6", "kimi-k2.7", "kimi-k2.7-code", "kimi-k2.7-code-highspeed"},
		RPM: 0, CodexDailyUSD: 20, CodexWeeklyUSD: 40, KimiDailyUSD: 5, KimiWeeklyUSD: 10}
}

func TestProvisionRequestEnablesGlobalModelsEndpoint(t *testing.T) {
	options := testOptions()
	state, err := stateFor(options)
	if err != nil {
		t.Fatal(err)
	}
	payload := provisionRequest(options, state)
	for index, key := range payload.Keys {
		want := [][]string{state.CodexModels, state.KimiModels}[index]
		if !key.AllowModelsEndpoint || !reflect.DeepEqual(key.Aliases, want) {
			t.Fatalf("employee key does not enable the global model catalog with its exact aliases: %+v", key)
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

func TestProvisionResponseRequiresTwoUniqueExpectedOneTimeKeys(t *testing.T) {
	state, err := stateFor(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	valid := response{Version: 1, Keys: []responseKey{
		{ID: state.CodexKeyID, PlainKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", Action: "created"},
		{ID: state.KimiKeyID, PlainKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654", Action: "rotated"},
	}}
	data, _ := json.Marshal(valid)
	parsed, err := parseResponse(data, state)
	if err != nil || len(parsed) != 2 {
		t.Fatalf("valid response rejected: parsed=%v err=%v", parsed, err)
	}
	valid.Keys[1].PlainKey = valid.Keys[0].PlainKey
	data, _ = json.Marshal(valid)
	if _, err := parseResponse(data, state); err == nil {
		t.Fatal("shared employee key was accepted")
	}
}

func TestRemoteDiagnosticsRedactPlainKeys(t *testing.T) {
	got := redact("failed for cpa_abcdefghijklmnopqrstuvwxyz012345\nnext")
	if strings.Contains(got, "cpa_") || strings.Contains(got, "\n") {
		t.Fatalf("diagnostic was not redacted: %q", got)
	}
}
