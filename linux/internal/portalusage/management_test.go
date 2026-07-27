package portalusage

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
)

func TestManagementQueryValidatesTenantPolicyAndUsage(t *testing.T) {
	const key = "management-key-abcdefghijklmnopqrstuvwxyz0123456789"
	ids := modelbootstrap.KeyIDsForTenant(usageTenant)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v0/management/plugins/cpa-key-policy/keys" || request.Header.Get("Authorization") != "Bearer "+key {
			http.Error(writer, "rejected", http.StatusForbidden)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"keys":[
{"id":%q,"enabled":true,"rpm":10,"aliases":[{"alias":"gpt-managed"}],"models":[{"alias":"gpt-managed","provider":"codex","target_model":"gpt-upstream","input_price_per_million":1.25,"output_price_per_million":5}],"daily_limit_usd":20,"weekly_limit_usd":40,"allow_models_endpoint":true,"usage":{"daily_usd":1.25,"weekly_usd":3.5,"daily_limit_usd":20,"weekly_limit_usd":40,"daily_reset_at":"2026-07-25T00:00:00Z","weekly_reset_at":"2026-07-27T00:00:00Z"}},
{"id":%q,"enabled":true,"rpm":5,"aliases":[{"alias":"kimi-managed"}],"models":[{"alias":"kimi-managed","provider":"kimi","target_model":"kimi-upstream","input_price_per_million":3,"output_price_per_million":15}],"daily_limit_usd":5,"weekly_limit_usd":10,"allow_models_endpoint":true,"usage":{"daily_usd":0.4,"weekly_usd":1.1,"daily_limit_usd":5,"weekly_limit_usd":10,"daily_reset_at":"2026-07-25T00:00:00Z","weekly_reset_at":"2026-07-27T00:00:00Z"}}]}`, ids.CodexKeyID, ids.KimiKeyID)
	}))
	defer server.Close()
	root := t.TempDir()
	keyFile := filepath.Join(root, "management.key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	remote, err := NewManagementRemote(cliproxy.ManagementOptions{BaseURL: server.URL + "/v0/management/plugins/cpa-key-policy", KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	remote.now = func() time.Time { return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC) }
	got, err := remote.Query(context.Background(), usageTenant, usagePolicy())
	if err != nil || len(got.Providers) != 2 || got.Providers[0].Daily.UsedUSD != "1.25" {
		t.Fatalf("management usage query failed: got=%+v err=%v", got, err)
	}
}

func TestManagementQueryRejectsCrossProviderAuthorization(t *testing.T) {
	policy := usagePolicy()
	expected, err := expectedProviderPolicy(KindChatGPT, "codex", policy)
	if err != nil {
		t.Fatal(err)
	}
	key := listedUsageKey{Enabled: true, RPM: 10, Aliases: []usageAlias{{Alias: "gpt-managed"}}, Models: []usageModel{{Alias: "gpt-managed", Provider: "kimi", TargetModel: "wrong", InputPricePerMillion: "1.25", OutputPricePerMillion: "5"}}, DailyLimitUSD: "20", WeeklyLimitUSD: "40", AllowModelsEndpoint: true,
		Usage: usageAccounting{DailyUSD: "0", WeeklyUSD: "0", DailyLimitUSD: "20", WeeklyLimitUSD: "40", DailyResetAt: "2026-07-25T00:00:00Z", WeeklyResetAt: "2026-07-27T00:00:00Z"}}
	if err := verifyUsageKey(key, expected); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("cross-provider authorization was accepted: %v", err)
	}
}
