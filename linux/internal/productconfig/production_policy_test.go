package productconfig

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestProductionPolicyMatchesWindowsManagedCatalog(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	policy, err := LoadPolicy(filepath.Join(filepath.Dir(source), "..", "..", "config", "policy.production.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra", "kimi-for-coding", "kimi-for-coding-highspeed", "kimi-k3"}
	if len(policy.Models) != len(want) {
		t.Fatalf("production model count = %d", len(policy.Models))
	}
	for index, model := range policy.Models {
		if model.ID != want[index] || !model.Enabled {
			t.Fatalf("production model %d = %+v", index, model)
		}
		quota := policy.Quotas[model.ID]
		price := policy.Pricing[model.ID]
		if price.Currency != "USD" || quota.RequestsPerMinute != 0 || quota.DailyRequests != 0 || quota.WeeklyRequests != 0 {
			t.Fatalf("production accounting contract for %s = price=%+v quota=%+v", model.ID, price, quota)
		}
		if model.Provider == "codex" && (quota.DailyUSD != "20" || quota.WeeklyUSD != "40") {
			t.Fatalf("Codex quota for %s = %+v", model.ID, quota)
		}
		if model.Provider == "kimi" && (quota.DailyUSD != "5" || quota.WeeklyUSD != "10") {
			t.Fatalf("Kimi quota for %s = %+v", model.ID, quota)
		}
	}
	if model, ok := policy.DefaultModel("codex"); !ok || model.ID != "gpt-5.6-sol" {
		t.Fatalf("Codex default = %+v, %t", model, ok)
	}
	if model, ok := policy.DefaultModel("kimi"); !ok || model.ID != "kimi-k3" {
		t.Fatalf("Kimi default = %+v, %t", model, ok)
	}
}
