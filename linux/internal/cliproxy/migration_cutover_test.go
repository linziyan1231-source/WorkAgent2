package cliproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
		CaptureID:         "capture-20260728",
		CaptureSpecSHA256: repeatTest("a", 64), CaptureManifestSHA256: repeatTest("b", 64),
		CaptureCompletedAt: time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC),
		SourcePortalSHA256: repeatTest("c", 64), SourcePortalWALSHA256: repeatTest("d", 64),
		SourcePortalSHMSHA256: repeatTest("e", 64), SourceCPAStateSHA256: repeatTest("f", 64),
		SourceExternalManifestSHA256: repeatTest("0", 64),
		OutputFingerprint:            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TenantDataRoot:               "/srv/workagent/users", Portal: winmigration.PortalReport{Users: 1},
		Tenants: []winmigration.TenantReport{{
			Username: "alice", TenantID: migrationTestTenant, RuntimeUser: "workagent_alice",
			DataRoot: "/srv/workagent/users/" + migrationTestTenant, SourceTreeSHA256: repeatTest("1", 64),
			ExternalWorkspaces: []winmigration.ExternalWorkspaceReport{{SourcePathSHA256: repeatTest("2", 64), SourceTreeSHA256: repeatTest("3", 64)}},
			QuotaOverrides: []winmigration.QuotaOverrideReport{
				{Provider: "codex", NewKeyID: ids.CodexKeyID, DailyLimitUSD: "20", WeeklyLimitUSD: "40"},
				{Provider: "kimi", NewKeyID: ids.KimiKeyID, DailyLimitUSD: "10", WeeklyLimitUSD: "30"},
			},
		}},
	}
	report.SourceFingerprint = migrationTestSourceFingerprint(t, report)
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

func migrationTestSourceFingerprint(t *testing.T, report winmigration.Report) string {
	t.Helper()
	payload, err := json.Marshal(struct {
		SchemaVersion                int
		CaptureID                    string
		CaptureSpecSHA256            string
		CaptureManifestSHA256        string
		CaptureCompletedAt           time.Time
		SourcePortalSHA256           string
		SourcePortalWALSHA256        string
		SourcePortalSHMSHA256        string
		SourceCPAStateSHA256         string
		SourceExternalManifestSHA256 string
		TenantDataRoot               string
		Portal                       winmigration.PortalReport
		Tenants                      []winmigration.TenantReport
	}{
		SchemaVersion: report.SchemaVersion, CaptureID: report.CaptureID,
		CaptureSpecSHA256: report.CaptureSpecSHA256, CaptureManifestSHA256: report.CaptureManifestSHA256,
		CaptureCompletedAt: report.CaptureCompletedAt, SourcePortalSHA256: report.SourcePortalSHA256,
		SourcePortalWALSHA256: report.SourcePortalWALSHA256, SourcePortalSHMSHA256: report.SourcePortalSHMSHA256,
		SourceCPAStateSHA256: report.SourceCPAStateSHA256, SourceExternalManifestSHA256: report.SourceExternalManifestSHA256,
		TenantDataRoot: report.TenantDataRoot, Portal: report.Portal, Tenants: report.Tenants,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
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
	detachedReport := report
	detachedReport.CaptureManifestSHA256 = ""
	detachedReport.SourceFingerprint = migrationTestSourceFingerprint(t, detachedReport)
	detachedPlan := plan
	detachedPlan.SourceFingerprint = detachedReport.SourceFingerprint
	if err := validateMigrationReportAndPlan(detachedReport, &detachedPlan); err == nil {
		t.Fatal("CLIProxy cutover accepted a report detached from its frozen capture manifest")
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

func TestValidatedCLIProxyMigrationSharedLockIsReadOnlyAndExcludesApply(t *testing.T) {
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
	first, err := acquireValidatedCLIProxyMigrationLockOperation(path, 65534, unix.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	flags, err := unix.FcntlInt(first.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("shared migration descriptor is not read-only: flags=%#x err=%v", flags, err)
	}
	second, err := acquireValidatedCLIProxyMigrationLockOperation(path, 65534, unix.LOCK_SH)
	if err != nil {
		t.Fatalf("concurrent shared migration verifier was rejected: %v", err)
	}
	if _, err := acquireValidatedCLIProxyMigrationLock(path, 65534); err == nil {
		t.Fatal("offline apply acquired migration EX while live migration readers held SH")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	apply, err := acquireValidatedCLIProxyMigrationLock(path, 65534)
	if err != nil {
		t.Fatalf("offline apply remained blocked after live readers exited: %v", err)
	}
	if err := apply.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidatedCLIProxyMigrationLockRejectsMetadataAndPathReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture requires root")
	}
	for name, mutate := range map[string]func(string) error{
		"mode":     func(path string) error { return os.Chmod(path, 0o660) },
		"owner":    func(path string) error { return os.Chown(path, 0, 65533) },
		"nonempty": func(path string) error { return os.WriteFile(path, []byte("x"), 0o640) },
		"hardlink": func(path string) error { return os.Link(path, path+".link") },
	} {
		t.Run(name, func(t *testing.T) {
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
			if err := mutate(path); err != nil {
				t.Fatal(err)
			}
			if _, err := acquireValidatedCLIProxyMigrationLockOperation(path, 65534, unix.LOCK_SH); err == nil {
				t.Fatal("unsafe migration lock metadata was accepted")
			}
		})
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
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 65534); err != nil || os.Chmod(path, 0o640) != nil {
		t.Fatal("prepare replacement group-owned lock")
	}
	if err := validateCLIProxyMigrationLockFD(fd, path, 65534, true); err == nil || !strings.Contains(err.Error(), "opened inode") {
		t.Fatalf("replaced migration lock pathname was accepted: %v", err)
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
