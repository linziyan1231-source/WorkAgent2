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

	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/portalusage"
)

func TestCurrentUsageUsesOnlyAuthenticatedUsersSIDBoundMapping(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	usage := server.usage.(*fakeUsageService)
	secondSummary := validUsageSummary()
	secondSummary.Providers = append([]portalusage.Provider(nil), secondSummary.Providers...)
	secondSummary.Providers[0].Daily.UsedUSD = "2.75"
	secondSummary.Providers[0].Daily.RemainingUSD = "17.25"
	usage.summaryBySID = map[string]portalusage.Summary{testSID1: validUsageSummary(), testSID2: secondSummary}
	request := authenticatedUsageRequest(token, "/api/portal/me/usage")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"used_usd":"1.25"`) || strings.Contains(response.Body.String(), `"used_usd":"2.75"`) {
		t.Fatalf("first user received another user's quota: %s", response.Body.String())
	}
	secondToken := createPortalSessionFor(t, data, "portal-bob", testSID2, `SERVER\test2`)
	secondResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondResponse, authenticatedUsageRequest(secondToken, "/api/portal/me/usage"))
	if secondResponse.Code != http.StatusOK || !strings.Contains(secondResponse.Body.String(), `"used_usd":"2.75"`) || strings.Contains(secondResponse.Body.String(), `"used_usd":"1.25"`) {
		t.Fatalf("second user received another user's quota: status=%d body=%s", secondResponse.Code, secondResponse.Body.String())
	}

	instances.mu.Lock()
	markerSIDs := append([]string(nil), instances.modelKeyIDSIDs...)
	instances.mu.Unlock()
	usage.mu.Lock()
	calls := append([]usageCall(nil), usage.calls...)
	usage.mu.Unlock()
	wantIDs := modelbootstrap.KeyIDsForSID(testSID1)
	wantSecondIDs := modelbootstrap.KeyIDsForSID(testSID2)
	if len(markerSIDs) != 2 || markerSIDs[0] != testSID1 || markerSIDs[1] != testSID2 || len(calls) != 2 ||
		calls[0].sid != testSID1 || calls[0].ids != wantIDs || calls[1].sid != testSID2 || calls[1].ids != wantSecondIDs {
		t.Fatalf("quota lookup escaped current identity: marker_sids=%v calls=%+v", markerSIDs, calls)
	}
	body := response.Body.String()
	for _, forbidden := range []string{wantIDs.CodexKeyID, wantIDs.KimiKeyID, modelbootstrap.KeyIDsForSID(testSID2).CodexKeyID, "cpa_"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("quota response exposed forbidden identity or key material: %s", body)
		}
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
}

func TestCurrentUsageRejectsAnonymousAndEveryQueryParameter(t *testing.T) {
	server, data, _ := testServer(t)
	unauthenticated := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "https://portal.example.test/api/portal/me/usage", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}
	token := createPortalSession(t, data)
	other := modelbootstrap.KeyIDsForSID(testSID2)
	for _, query := range []string{"username=portal-bob", "sid=" + testSID2, "key_id=" + other.CodexKeyID} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, authenticatedUsageRequest(token, "/api/portal/me/usage?"+query))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query %q status=%d body=%s", query, response.Code, response.Body.String())
		}
	}
	usage := server.usage.(*fakeUsageService)
	usage.mu.Lock()
	defer usage.mu.Unlock()
	if len(usage.calls) != 0 {
		t.Fatalf("rejected query reached quota service: %+v", usage.calls)
	}
}

func TestCurrentUsageFailsExplicitlyWithoutLeakingMappingOrRemoteDiagnostics(t *testing.T) {
	server, data, instances := testServer(t)
	token := createPortalSession(t, data)
	other := modelbootstrap.KeyIDsForSID(testSID2)
	secret := "cpa_abcdefghijklmnopqrstuvwxyz012345"
	var logs bytes.Buffer
	server.logger = log.New(&logs, "", 0)

	instances.modelKeyIDSError = errors.New("broken marker " + other.CodexKeyID + " " + secret + " ManagementKey")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, authenticatedUsageRequest(token, "/api/portal/me/usage"))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "mapping is unavailable") {
		t.Fatalf("mapping failure status=%d body=%s", response.Code, response.Body.String())
	}
	assertNoQuotaSecrets(t, response.Body.String()+logs.String(), secret, other.CodexKeyID, "ManagementKey")

	instances.modelKeyIDSError = nil
	server.usage.(*fakeUsageService).err = errors.New("remote failed " + secret + " " + other.KimiKeyID)
	logs.Reset()
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, authenticatedUsageRequest(token, "/api/portal/me/usage"))
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "temporarily unavailable") {
		t.Fatalf("remote failure status=%d body=%s", response.Code, response.Body.String())
	}
	assertNoQuotaSecrets(t, response.Body.String()+logs.String(), secret, other.KimiKeyID)
}

func TestCurrentUsageReportsRemoteTimeout(t *testing.T) {
	server, data, _ := testServer(t)
	token := createPortalSession(t, data)
	server.usage.(*fakeUsageService).err = context.DeadlineExceeded
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, authenticatedUsageRequest(token, "/api/portal/me/usage"))
	if response.Code != http.StatusGatewayTimeout || !strings.Contains(response.Body.String(), "timed out") {
		t.Fatalf("timeout status=%d body=%s", response.Code, response.Body.String())
	}
}

func authenticatedUsageRequest(token, path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test"+path, nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	return request
}

func assertNoQuotaSecrets(t *testing.T, value string, forbidden ...string) {
	t.Helper()
	for _, item := range forbidden {
		if strings.Contains(value, item) {
			t.Fatalf("quota diagnostics exposed %q: %s", item, value)
		}
	}
}
