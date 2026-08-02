package portal

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/portalusage"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

type fakeUsageReader struct {
	tenant string
	value  portalusage.Summary
	err    error
}

func (f *fakeUsageReader) Current(_ context.Context, tenantID string) (portalusage.Summary, error) {
	f.tenant = tenantID
	return f.value, f.err
}

func authenticatedPortalRequest(t *testing.T, fixture portalFixture, method, target string) *http.Request {
	t.Helper()
	userValue, err := fixture.store.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CreateSession(context.Background(), token, "test-csrf-token", userValue, "192.0.2.10", "portal-test-agent", fixture.server.now(), fixture.server.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	request := secureRequest(method, target, "")
	request.AddCookie(&http.Cookie{Name: fixture.cfg.Session.CookieName, Value: token})
	return request
}

func TestCurrentUsageIsSessionAndTenantBound(t *testing.T) {
	fixture := newPortalFixture(t)
	usage := &fakeUsageReader{value: validPortalUsageSummary()}
	fixture.server.usage = usage
	fixture.server.readStorageUsage = func(_ context.Context, userValue store.User) (portalusage.StorageUsage, error) {
		if userValue.TenantID != portalTestTenant {
			t.Fatalf("storage lookup tenant=%q", userValue.TenantID)
		}
		return portalusage.StorageUsage{LimitBytes: 100, UsedBytes: 30, RemainingBytes: 70, MeasuredAt: "2026-07-24T12:00:00Z"}, nil
	}
	var snapshotTenant string
	var snapshot []byte
	fixture.server.writeUsageSnapshot = func(_ context.Context, userValue store.User, payload []byte) error {
		snapshotTenant = userValue.TenantID
		snapshot = append([]byte(nil), payload...)
		return nil
	}
	request := authenticatedPortalRequest(t, fixture, http.MethodGet, "https://portal.example.test/api/portal/me/usage")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || usage.tenant != portalTestTenant || !strings.Contains(response.Body.String(), `"kind":"chatgpt"`) || !strings.Contains(response.Body.String(), `"storage":{"limit_bytes":100,"used_bytes":30,"remaining_bytes":70`) {
		t.Fatalf("usage result status=%d tenant=%q body=%s", response.Code, usage.tenant, response.Body.String())
	}
	parsed, err := portalusage.ParseSummarySnapshot(snapshot)
	if err != nil || snapshotTenant != portalTestTenant || parsed.Storage == nil || parsed.Storage.UsedBytes != 30 {
		t.Fatalf("snapshot tenant=%q value=%s parsed=%+v err=%v", snapshotTenant, snapshot, parsed, err)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("usage response was cacheable")
	}
}

func TestCurrentUsageRedactsRemoteErrorsAndRejectsQueries(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.server.usage = &fakeUsageReader{err: errors.New("upstream leaked cpa_secret")}
	request := authenticatedPortalRequest(t, fixture, http.MethodGet, "https://portal.example.test/api/portal/me/usage")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "cpa_secret") {
		t.Fatalf("usage failure leaked details: status=%d body=%s", response.Code, response.Body.String())
	}
	request = authenticatedPortalRequest(t, fixture, http.MethodGet, "https://portal.example.test/api/portal/me/usage?tenant=other")
	response = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("usage query override was accepted: %d", response.Code)
	}
}

func TestCurrentUsageRecordsStorageAndSnapshotFailuresWithoutLeaking(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.server.usage = &fakeUsageReader{value: validPortalUsageSummary()}
	secret := "private-storage-path-cpa_secret"
	fixture.server.readStorageUsage = func(context.Context, store.User) (portalusage.StorageUsage, error) {
		return portalusage.StorageUsage{}, errors.New(secret)
	}
	fixture.server.writeUsageSnapshot = func(context.Context, store.User, []byte) error { return errors.New(secret) }
	var logs bytes.Buffer
	fixture.server.logger = log.New(&logs, "", 0)
	request := authenticatedPortalRequest(t, fixture, http.MethodGet, "https://portal.example.test/api/portal/me/usage")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"storage"`) {
		t.Fatalf("storage failure changed usage response: status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(logs.String(), secret) || !strings.Contains(logs.String(), "stage=storage_unavailable") || !strings.Contains(logs.String(), "stage=snapshot_write_failed") {
		t.Fatalf("unsafe or incomplete failure log: %s", logs.String())
	}
}

func validPortalUsageSummary() portalusage.Summary {
	return portalusage.Summary{AsOf: "2026-07-24T12:00:00Z", Providers: []portalusage.Provider{
		{Kind: portalusage.KindChatGPT, Label: "ChatGPT", Daily: portalusage.Window{LimitUSD: "20.00", UsedUSD: "1.25", RemainingUSD: "18.75", ResetAt: "2026-07-25T00:00:00Z"}, Weekly: portalusage.Window{LimitUSD: "40.00", UsedUSD: "3.50", RemainingUSD: "36.50", ResetAt: "2026-07-27T00:00:00Z"}},
		{Kind: portalusage.KindKimi, Label: "Kimi", Daily: portalusage.Window{LimitUSD: "5.00", UsedUSD: "0.40", RemainingUSD: "4.60", ResetAt: "2026-07-25T00:00:00Z"}, Weekly: portalusage.Window{LimitUSD: "10.00", UsedUSD: "1.10", RemainingUSD: "8.90", ResetAt: "2026-07-27T00:00:00Z"}},
	}}
}

var _ usageReader = (*fakeUsageReader)(nil)
