package userhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/portalusage"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

func TestStorageUsagePrefersConfiguredXFSQuota(t *testing.T) {
	capacity := config.TenantCapacity{ProjectID: 1234, DiskHardLimitBytes: 10 * 1024 * 1024 * 1024}
	measuredAt := time.Date(2026, 7, 26, 8, 0, 0, 0, time.UTC)
	treeCalls := 0
	usage, usedQuota, err := measureStorageUsageWith(context.Background(), "/private/tenant", capacity,
		func(root string, projectID uint32, hardLimit uint64) (hostcheck.ProjectQuotaStatus, error) {
			if root != "/private/tenant" || projectID != capacity.ProjectID || hardLimit != capacity.DiskHardLimitBytes {
				t.Fatalf("quota binding root=%q project=%d limit=%d", root, projectID, hardLimit)
			}
			return hostcheck.ProjectQuotaStatus{ProjectID: projectID, HardLimitBytes: hardLimit, UsedBytes: 4096, Inherit: true}, nil
		},
		func(context.Context, string) (uint64, error) { treeCalls++; return 0, nil },
		func() time.Time { return measuredAt })
	if err != nil || !usedQuota || treeCalls != 0 || usage.LimitBytes != capacity.DiskHardLimitBytes || usage.UsedBytes != 4096 || usage.RemainingBytes != capacity.DiskHardLimitBytes-4096 || usage.MeasuredAt != "2026-07-26T08:00:00Z" {
		t.Fatalf("usage=%+v xfs=%t tree_calls=%d err=%v", usage, usedQuota, treeCalls, err)
	}
}

func TestStorageUsageFallsBackWithoutChangingConfiguredLimit(t *testing.T) {
	capacity := config.TenantCapacity{ProjectID: 1234, DiskHardLimitBytes: 10 * 1024 * 1024 * 1024}
	usage, usedQuota, err := measureStorageUsageWith(context.Background(), "/private/tenant", capacity,
		func(string, uint32, uint64) (hostcheck.ProjectQuotaStatus, error) {
			return hostcheck.ProjectQuotaStatus{}, errors.New("quota unavailable with private path")
		},
		func(context.Context, string) (uint64, error) { return 8192, nil }, time.Now)
	if err != nil || usedQuota || usage.LimitBytes != capacity.DiskHardLimitBytes || usage.UsedBytes != 8192 || usage.RemainingBytes != capacity.DiskHardLimitBytes-8192 {
		t.Fatalf("usage=%+v xfs=%t err=%v", usage, usedQuota, err)
	}
}

func TestStorageUsageStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := measureStorageUsageWith(ctx, t.TempDir(), config.TenantCapacity{},
		func(string, uint32, uint64) (hostcheck.ProjectQuotaStatus, error) { return hostcheck.ProjectQuotaStatus{}, nil },
		func(context.Context, string) (uint64, error) { return 0, nil }, time.Now); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want cancellation", err)
	}
}

func TestStorageUsageControlRouteReturnsTenantBoundMeasurement(t *testing.T) {
	host, root := storageControlFixture(t)
	if err := root.WriteFileAtomic("data/private.bin", make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	request := storageControlRequest(http.MethodGet, "/internal/storage-usage", bytes.NewReader(nil))
	recorder := httptest.NewRecorder()
	host.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("storage status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var usage portalusage.StorageUsage
	if err := json.Unmarshal(recorder.Body.Bytes(), &usage); err != nil {
		t.Fatal(err)
	}
	if usage.LimitBytes != defaultUserStorageLimitBytes || usage.UsedBytes != 4096 || usage.RemainingBytes != defaultUserStorageLimitBytes-4096 {
		t.Fatalf("usage=%+v", usage)
	}
	if _, err := time.Parse(time.RFC3339, usage.MeasuredAt); err != nil {
		t.Fatalf("measured_at=%q: %v", usage.MeasuredAt, err)
	}
}

func TestUsageSnapshotControlRouteAtomicallyWritesValidatedSummary(t *testing.T) {
	host, root := storageControlFixture(t)
	summary := validControlSummary()
	payload, err := portalusage.MarshalSummarySnapshot(summary)
	if err != nil {
		t.Fatal(err)
	}
	request := storageControlRequest(http.MethodPost, "/internal/usage-snapshot", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	host.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("snapshot status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	stored, err := root.ReadFile(usageSnapshotPath, portalusage.MaxSummarySnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := portalusage.ParseSummarySnapshot(stored)
	if err != nil || parsed.Storage == nil || parsed.Storage.UsedBytes != 30 {
		t.Fatalf("stored snapshot=%s err=%v", stored, err)
	}
	info, err := os.Stat(filepath.Join(root.Path(), usageSnapshotPath))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode=%v err=%v", info.Mode(), err)
	}
}

func TestUsageSnapshotControlRouteRejectsInvalidAndOversizePayloads(t *testing.T) {
	host, root := storageControlFixture(t)
	original := []byte(`{"preserved":true}`)
	if err := root.WriteFileAtomic(usageSnapshotPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	valid, err := portalusage.MarshalSummarySnapshot(validControlSummary())
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unknown":true}`)...)
	for name, payload := range map[string][]byte{
		"unknown field": unknown,
		"oversize":      bytes.Repeat([]byte{' '}, portalusage.MaxSummarySnapshotBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			request := storageControlRequest(http.MethodPost, "/internal/usage-snapshot", bytes.NewReader(payload))
			recorder := httptest.NewRecorder()
			host.routes().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_USAGE_SNAPSHOT") {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			stored, err := root.ReadFile(usageSnapshotPath, portalusage.MaxSummarySnapshotBytes)
			if err != nil || !bytes.Equal(stored, original) {
				t.Fatalf("invalid snapshot changed prior file: stored=%s err=%v", stored, err)
			}
		})
	}
}

func storageControlFixture(t *testing.T) (*Host, *projectfs.Root) {
	t.Helper()
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if err := root.EnsureDirectory("data", 0o700); err != nil {
		t.Fatal(err)
	}
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant, DataRoot: rootPath}, dataRoot: root, logger: log.New(io.Discard, "", 0)}
	return host, root
}

func storageControlRequest(method, target string, body *bytes.Reader) *http.Request {
	request := httptest.NewRequest(method, "http://userhost"+target, body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-WorkAgent-Tenant", bootstrapTestTenant)
	request.Header.Set("X-WorkAgent-Control", "portal-v1")
	return request
}

func validControlSummary() portalusage.Summary {
	return portalusage.Summary{AsOf: "2026-07-26T08:00:00Z", Providers: []portalusage.Provider{
		{Kind: portalusage.KindChatGPT, Label: "ChatGPT", Daily: portalusage.Window{LimitUSD: "20.00", UsedUSD: "1.25", RemainingUSD: "18.75", ResetAt: "2026-07-27T00:00:00Z"}, Weekly: portalusage.Window{LimitUSD: "40.00", UsedUSD: "3.50", RemainingUSD: "36.50", ResetAt: "2026-08-03T00:00:00Z"}},
		{Kind: portalusage.KindKimi, Label: "Kimi", Daily: portalusage.Window{LimitUSD: "5.00", UsedUSD: "0.40", RemainingUSD: "4.60", ResetAt: "2026-07-27T00:00:00Z"}, Weekly: portalusage.Window{LimitUSD: "10.00", UsedUSD: "1.10", RemainingUSD: "8.90", ResetAt: "2026-08-03T00:00:00Z"}},
	}, Storage: &portalusage.StorageUsage{LimitBytes: 100, UsedBytes: 30, RemainingBytes: 70, MeasuredAt: "2026-07-26T08:00:00Z"}}
}
