package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

const migrationTestTenant = "11111111-1111-4111-8111-111111111111"

func migrationTestReportAndPlan(t *testing.T) (winmigration.Report, migrationQuotaPlan) {
	t.Helper()
	ids := modelbootstrap.KeyIDsForTenant(migrationTestTenant)
	dailyStart := time.Now().UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
	weeklyStart := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	usage := json.RawMessage(fmt.Sprintf(`{"daily":{"total_usd":1.25,"window_start":%q,"input_tokens":10,"call_count":2},"weekly":{"total_usd":2.5,"window_start":%q,"input_tokens":20,"call_count":3},"by_alias":{"gpt-5.6-sol":{"daily":{"total_usd":1.25,"window_start":%q,"input_tokens":10,"call_count":2},"weekly":{"total_usd":2.5,"window_start":%q,"input_tokens":20,"call_count":3}}}}`, dailyStart, weeklyStart, dailyStart, weeklyStart))
	report := winmigration.Report{
		SchemaVersion: winmigration.ReportSchemaVersion, Status: "complete",
		SourceFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OutputFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TenantDataRoot:    "/srv/workagent/users", Portal: winmigration.PortalReport{Users: 1},
		Tenants: []winmigration.TenantReport{{
			Username: "alice", TenantID: migrationTestTenant, RuntimeUser: "workagent_alice",
			DataRoot: "/srv/workagent/users/" + migrationTestTenant,
			QuotaOverrides: []winmigration.QuotaOverrideReport{
				{Provider: "codex", NewKeyID: ids.CodexKeyID, DailyLimitUSD: "20", WeeklyLimitUSD: "40"},
				{Provider: "kimi", NewKeyID: ids.KimiKeyID, DailyLimitUSD: "10", WeeklyLimitUSD: "30"},
			},
		}},
	}
	plan := migrationQuotaPlan{
		SchemaVersion: migrationPlanSchemaVersion, SourceFingerprint: report.SourceFingerprint,
		ApplyAfter: migrationApplyAfter, KeyPolicy: migrationKeyPolicy,
		Overrides: []migrationQuotaOverride{
			{Username: "alice", TenantID: migrationTestTenant, Provider: "codex", NewKeyID: ids.CodexKeyID, DailyLimitUSD: "20", WeeklyLimitUSD: "40", LegacyUsage: usage},
			{Username: "alice", TenantID: migrationTestTenant, Provider: "kimi", NewKeyID: ids.KimiKeyID, DailyLimitUSD: "10", WeeklyLimitUSD: "30", LegacyUsage: json.RawMessage(`{}`)},
		},
	}
	return report, plan
}

func TestValidateMigrationPlanBindsEveryDeterministicKey(t *testing.T) {
	report, plan := migrationTestReportAndPlan(t)
	if err := validateMigrationReportAndPlan(report, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Overrides[0].usage.Daily.CallCount != 2 || plan.Overrides[0].usage.ByAlias["gpt-5.6-sol"].Weekly.InputTokens != 20 {
		t.Fatal("archived usage was not validated and normalized")
	}
	broken := plan
	broken.Overrides = append([]migrationQuotaOverride(nil), plan.Overrides...)
	broken.Overrides[0].NewKeyID = "legacy-tenant-chatgpt"
	if err := validateMigrationReportAndPlan(report, &broken); err == nil {
		t.Fatal("non-deterministic key id was accepted")
	}
}

func TestDecodeUsageRejectsUnknownAndNegativeFields(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"daily":{"total_usd":-1}}`),
		json.RawMessage(`{"daily":{"total_usd":1,"secret":"unexpected"}}`),
		json.RawMessage(`{"by_alias":{"bad alias":{"total_usd":1}}}`),
		json.RawMessage(`{"weekly":{"total_usd":1,"window_start":"2199-01-01T00:00:00Z"}}`),
		json.RawMessage(`{"daily":{"total_usd":1}}`),
		json.RawMessage(`{"by_alias":{"gpt-5.6-sol":{"daily":{"input_tokens":1}}}}`),
	} {
		if _, err := decodeUsageState(raw); err == nil {
			t.Fatalf("invalid usage was accepted: %s", raw)
		}
	}
}

func TestValidateMigrationUSDRequiresPlainFixedDecimal(t *testing.T) {
	for _, valid := range []string{"0.01", "1", "20", "999999.999"} {
		if err := validateMigrationUSD(valid); err != nil {
			t.Fatalf("valid USD %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"0", "1/2", ".5", "1.", "+1", "-1", "1e2", "01", "00.5", "1000000.01"} {
		if err := validateMigrationUSD(invalid); err == nil {
			t.Fatalf("invalid USD %q accepted", invalid)
		}
	}
}

func TestVerifyPendingKeyAuthenticationChecksEachKeyLocally(t *testing.T) {
	ids := modelbootstrap.KeyIDsForTenant(migrationTestTenant)
	codexKey := plainForKey(ids.CodexKeyID)
	kimiKey := plainForKey(ids.KimiKeyID)
	seen := make(chan string, 3)
	drainSeen := func() []string {
		var result []string
		for {
			select {
			case value := <-seen:
				result = append(result, value)
			default:
				return result
			}
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/models" || request.URL.RawQuery != "" || request.ContentLength != 0 {
			seen <- "invalid-request"
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		switch request.Header.Get("Authorization") {
		case "Bearer " + codexKey:
			seen <- "codex"
		case "Bearer " + kimiKey:
			seen <- "kimi"
		default:
			seen <- "rejected"
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"object": "list", "data": []any{}})
	}))
	defer server.Close()
	state, err := modelbootstrap.StateFromPolicy(provisionPolicy(), server.URL+"/v1", migrationTestTenant)
	if err != nil {
		t.Fatal(err)
	}
	bundle := modelbootstrap.Bundle{State: state, CodexAPIKey: codexKey, KimiAPIKey: kimiKey}
	defer bundle.Zero()
	if err := verifyPendingKeyAuthentication(context.Background(), state.BaseURL, migrationTestTenant, bundle); err != nil {
		t.Fatal(err)
	}
	if observed := drainSeen(); len(observed) != 2 || observed[0] != "codex" || observed[1] != "kimi" {
		t.Fatalf("unexpected credential verification sequence: %v", observed)
	}
	bad := bundle
	bad.KimiAPIKey = "cpa_invalidbutwellformedcredential12345"
	defer bad.Zero()
	if err := verifyPendingKeyAuthentication(context.Background(), state.BaseURL, migrationTestTenant, bad); err == nil {
		t.Fatal("an unrecognized pending key authenticated")
	}
	if observed := drainSeen(); len(observed) != 2 || observed[0] != "codex" || observed[1] != "rejected" {
		t.Fatalf("invalid credential verification did not fail closed: %v", observed)
	}
}

func TestPatchMigrationPolicyStateIsNarrowAndIdempotent(t *testing.T) {
	report, plan := migrationTestReportAndPlan(t)
	if err := validateMigrationReportAndPlan(report, &plan); err != nil {
		t.Fatal(err)
	}
	ids := modelbootstrap.KeyIDsForTenant(migrationTestTenant)
	state := []byte(`{
  "version": 1,
  "keys": [
    {"id":"` + ids.CodexKeyID + `","name":"codex","enabled":true,"key_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_preview":"cpa_ABC...VWXYZ","rpm":5,"daily_limit_usd":1,"weekly_limit_usd":2,"models":[],"private_extension":{"keep":true}},
    {"id":"` + ids.KimiKeyID + `","name":"kimi","enabled":true,"key_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","key_preview":"cpa_DEF...QRSTU","rpm":5,"daily_limit_usd":3,"weekly_limit_usd":4,"models":[]},
    {"id":"unrelated","name":"other","enabled":true,"key_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","key_preview":"cpa_GHI...LMNOP","rpm":9,"daily_limit_usd":7,"weekly_limit_usd":8,"models":[]}
  ],
  "usage": {"unrelated":{"daily":{"total_usd":9}}},
  "updated_at": "2026-07-27T00:00:00Z",
  "unknown_top": {"preserve":"exact"}
}`)
	document, err := decodeMutablePolicyState(state)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := patchMigrationPolicyState(document, plan)
	if err != nil || !changed {
		t.Fatalf("first patch changed=%v err=%v", changed, err)
	}
	encoded, err := encodeMutablePolicyState(document)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := decodeMutablePolicyState(encoded)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = patchMigrationPolicyState(readback, plan)
	if err != nil || changed {
		t.Fatalf("idempotent patch changed=%v err=%v", changed, err)
	}
	var hash string
	if err := decodeStrictJSON(readback.keys[0]["key_hash"], &hash); err != nil || hash != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatal("target key hash was modified")
	}
	var extension map[string]bool
	if err := decodeStrictJSON(readback.keys[0]["private_extension"], &extension); err != nil || !extension["keep"] {
		t.Fatal("target key extension was not preserved")
	}
	var unrelatedLimit json.Number
	if err := decodeStrictJSON(readback.keys[2]["daily_limit_usd"], &unrelatedLimit); err != nil || unrelatedLimit.String() != "7" {
		t.Fatal("unrelated key was modified")
	}
	if _, ok := readback.usage["unrelated"]; !ok {
		t.Fatal("unrelated usage was removed")
	}
	converged, err := migrationPolicyStateAfterPlan(state, plan)
	if err != nil || !bytes.Equal(converged, encoded) {
		t.Fatalf("pre-state plus plan did not converge to activated state: %v", err)
	}
	tampered := bytes.Replace(state, []byte(`"preserve":"exact"`), []byte(`"preserve":"tampered"`), 1)
	tamperedConvergence, err := migrationPolicyStateAfterPlan(tampered, plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tamperedConvergence, encoded) {
		t.Fatal("unrelated backup tampering still converged to the activated state")
	}
}

func TestPatchMigrationPolicyStateRejectsConflictingUsage(t *testing.T) {
	report, plan := migrationTestReportAndPlan(t)
	if err := validateMigrationReportAndPlan(report, &plan); err != nil {
		t.Fatal(err)
	}
	ids := modelbootstrap.KeyIDsForTenant(migrationTestTenant)
	state := []byte(`{"version":1,"keys":[` + migrationTestStateKey(ids.CodexKeyID, "a") + `,` + migrationTestStateKey(ids.KimiKeyID, "b") + `],"usage":{"` + ids.CodexKeyID + `":{"daily":{"total_usd":99}}}}`)
	document, err := decodeMutablePolicyState(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := patchMigrationPolicyState(document, plan); err == nil {
		t.Fatal("conflicting non-zero usage was overwritten")
	}
}

func migrationTestStateKey(id, fill string) string {
	return `{"id":"` + id + `","name":"tenant","enabled":true,"key_hash":"sha256:` + repeatTest(fill, 64) + `","key_preview":"cpa_ABC...VWXYZ","daily_limit_usd":1,"weekly_limit_usd":2}`
}

func repeatTest(value string, count int) string {
	result := ""
	for len(result) < count {
		result += value
	}
	return result[:count]
}

type migrationSystemdFixture struct {
	properties map[string]string
	err        error
}

func (fixture migrationSystemdFixture) Properties(context.Context, string, ...string) (map[string]string, error) {
	return fixture.properties, fixture.err
}

func (migrationSystemdFixture) Action(context.Context, ...string) error { return nil }

func TestRequireCLIProxyStoppedFailsClosed(t *testing.T) {
	stopped := migrationSystemdFixture{properties: map[string]string{"ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0"}}
	if err := requireCLIProxyStopped(context.Background(), stopped); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []migrationSystemdFixture{
		{properties: map[string]string{"ActiveState": "active", "SubState": "running", "MainPID": "123", "ControlPID": "0"}},
		{properties: map[string]string{"ActiveState": "inactive", "SubState": "dead", "MainPID": "invalid", "ControlPID": "0"}},
		{err: errors.New("unavailable")},
	} {
		if err := requireCLIProxyStopped(context.Background(), fixture); err == nil {
			t.Fatal("unsafe or unavailable systemd state was accepted")
		}
	}
}

func TestValidatedCLIProxyMigrationLockExcludesConcurrentStart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture requires root")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cliproxy-migration.lock")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 65534); err != nil || os.Chmod(path, 0o640) != nil {
		t.Fatal("prepare group-owned lock")
	}
	first, err := acquireValidatedCLIProxyMigrationLock(path, 65534)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireValidatedCLIProxyMigrationLock(path, 65534); err == nil {
		t.Fatal("concurrent service lock acquisition succeeded")
	}
	first.Close()
	second, err := acquireValidatedCLIProxyMigrationLock(path, 65534)
	if err != nil {
		t.Fatal(err)
	}
	second.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireValidatedCLIProxyMigrationLock(path, 65534); err == nil {
		t.Fatal("symlinked cutover lock was accepted")
	}
}

func TestEffectiveUsageWindowMatchesPluginWindowRules(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	current := usageWindow{TotalUSD: 1, WindowStart: now.Add(-time.Hour), CallCount: 1}
	if got := effectiveUsageWindow(current, true, now); got.TotalUSD != 1 {
		t.Fatal("current daily window was reset")
	}
	old := usageWindow{TotalUSD: 1, WindowStart: now.Add(-8 * 24 * time.Hour), CallCount: 1}
	if got := effectiveUsageWindow(old, false, now); !usageWindowZero(got) {
		t.Fatal("expired weekly window was not reset")
	}
}
