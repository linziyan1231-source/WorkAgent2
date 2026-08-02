package modelbootstrap

import (
	"reflect"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

const bootstrapTenant = "11111111-1111-4111-8111-111111111111"

func bootstrapPolicy() productconfig.Policy {
	return productconfig.Policy{SchemaVersion: 1, PolicyID: "workagent-models-v1", DefaultAction: "deny", ApprovalRequired: false,
		Models: []productconfig.Model{
			{ID: "gpt-5.6-terra", DisplayName: "Terra", Provider: "codex", Enabled: true},
			{ID: "gpt-5.6-luna", DisplayName: "Luna", Provider: "codex", Enabled: true},
			{ID: "gpt-5.6-sol", DisplayName: "Sol", Provider: "codex", Enabled: true, Default: true},
			{ID: "kimi-for-coding-highspeed", DisplayName: "Kimi HighSpeed", Provider: "kimi", Enabled: true},
			{ID: "kimi-k3", DisplayName: "Kimi K3", Provider: "kimi", Enabled: true, Default: true},
			{ID: "kimi-for-coding", DisplayName: "Kimi Coding", Provider: "kimi", Enabled: true},
		},
		Aliases: map[string]string{}, Pricing: map[string]productconfig.Price{}, Quotas: map[string]productconfig.Quota{}}
}

func TestStateIsPolicyDrivenAndTenantBound(t *testing.T) {
	state, err := StateFromPolicy(bootstrapPolicy(), "http://127.0.0.1:8317/v1", bootstrapTenant)
	if err != nil {
		t.Fatal(err)
	}
	if state.CodexDefaultModel != DefaultCodexModel || state.KimiDefaultModel != DefaultKimiModel || !reflect.DeepEqual(state.CodexModels, ManagedCodexModels()) || !reflect.DeepEqual(state.KimiModels, ManagedKimiModels()) {
		t.Fatalf("unexpected policy state: %+v", state)
	}
	if err := state.ValidateForTenant("22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("another tenant accepted the derived key ids")
	}
}

func TestStateFromPolicyRejectsLegacyCodexDefault(t *testing.T) {
	policy := bootstrapPolicy()
	policy.Models[1].Default = true
	policy.Models[2].Default = false
	if _, err := StateFromPolicy(policy, "http://127.0.0.1:8317/v1", bootstrapTenant); err == nil {
		t.Fatal("legacy Codex default was accepted for a new bootstrap")
	}
}

func TestWithManagedKimiDefaultsChangesOnlyKimiCatalogAndDefault(t *testing.T) {
	state, err := StateFromPolicy(bootstrapPolicy(), "http://127.0.0.1:8317/v1", bootstrapTenant)
	if err != nil {
		t.Fatal(err)
	}
	legacy := state
	legacy.KimiDefaultModel = "kimi-for-coding"
	legacy.KimiModels = []string{"kimi-for-coding", "kimi-for-coding-highspeed"}
	updated, changed, err := legacy.WithManagedKimiDefaults(bootstrapTenant)
	if err != nil || !changed {
		t.Fatalf("update legacy Kimi defaults: changed=%t err=%v", changed, err)
	}
	want := legacy
	want.KimiDefaultModel = DefaultKimiModel
	want.KimiModels = ManagedKimiModels()
	if !reflect.DeepEqual(updated, want) {
		t.Fatalf("Kimi migration changed unrelated state: got=%+v want=%+v", updated, want)
	}
}

func TestWithCodexDefaultModelChangesOnlyDefault(t *testing.T) {
	state, err := StateFromPolicy(bootstrapPolicy(), "http://127.0.0.1:8317/v1", bootstrapTenant)
	if err != nil {
		t.Fatal(err)
	}
	legacy := state
	legacy.CodexDefaultModel = "gpt-5.6-luna"
	updated, changed, err := legacy.WithCodexDefaultModel(bootstrapTenant, DefaultCodexModel)
	if err != nil || !changed {
		t.Fatalf("update legacy default: changed=%t err=%v", changed, err)
	}
	want := legacy
	want.CodexDefaultModel = DefaultCodexModel
	if !reflect.DeepEqual(updated, want) {
		t.Fatalf("migration changed unrelated state: got=%+v want=%+v", updated, want)
	}
}

func TestBundleRejectsSharedOrMalformedKeys(t *testing.T) {
	state, err := StateFromPolicy(bootstrapPolicy(), "http://127.0.0.1:8317/v1", bootstrapTenant)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{State: state, CodexAPIKey: "cpa_AAAAAAAAAAAAAAAAAAAAAAAA", KimiAPIKey: "cpa_BBBBBBBBBBBBBBBBBBBBBBBB"}
	if err := bundle.ValidateForTenant(bootstrapTenant); err != nil {
		t.Fatal(err)
	}
	bundle.KimiAPIKey = bundle.CodexAPIKey
	if err := bundle.ValidateForTenant(bootstrapTenant); err == nil {
		t.Fatal("shared provider keys were accepted")
	}
}
