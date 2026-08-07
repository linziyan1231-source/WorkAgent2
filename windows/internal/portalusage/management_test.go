package portalusage

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aionuiportal/internal/cliproxy"
	"aionuiportal/internal/modelbootstrap"
)

func TestManagementQueryUsesKeyUsageSummaryAuthority(t *testing.T) {
	ids := modelbootstrap.KeyIDsForSID(testSID1)
	key := "windows-native-management-key-0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/plugins/cpa-key-policy/keys" || r.Header.Get("Authorization") != "Bearer "+key {
			t.Fatalf("unexpected request: %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[
{"id":%q,"aliases":[{"alias":"gpt-5.6-luna"}],"models":[{"alias":"gpt-5.6-luna","provider":"codex","target_model":"gpt-5.6-luna"}],"daily_limit_usd":20,"weekly_limit_usd":40,"usage":{"daily_usd":1.25,"weekly_usd":3.5,"daily_limit_usd":20,"weekly_limit_usd":40,"daily_reset_at":"2026-07-18T00:00:00Z","weekly_reset_at":"2026-07-21T00:00:00Z"}},
{"id":%q,"aliases":[{"alias":"kimi-for-coding"}],"models":[{"alias":"kimi-for-coding","provider":"kimi","target_model":"kimi-k2.7-code"}],"daily_limit_usd":5,"weekly_limit_usd":10,"usage":{"daily_usd":0.4,"weekly_usd":1.1,"daily_limit_usd":5,"weekly_limit_usd":10,"daily_reset_at":"2026-07-18T00:00:00Z","weekly_reset_at":"2026-07-21T00:00:00Z"}}]}`, ids.CodexKeyID, ids.KimiKeyID)
	}))
	defer server.Close()
	root := t.TempDir()
	keyFile := filepath.Join(root, "management.key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	url := server.URL + "/v0/management/plugins/cpa-key-policy"
	remote, err := NewManagementRemote(cliproxy.ManagementOptions{BaseURL: url, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	remote.now = func() time.Time { return time.Date(2026, 7, 17, 5, 0, 0, 0, time.UTC) }
	got, err := remote.Query(context.Background(), ids)
	if err != nil || len(got.Providers) != 2 || got.Providers[0].Daily.UsedUSD != "1.25" || got.Providers[1].Weekly.UsedUSD != "1.1" {
		t.Fatalf("management usage query failed: got=%+v err=%v", got, err)
	}
}

func TestManagementQueryManyLoadsAllRequestedUsersWithOnePolicyRequest(t *testing.T) {
	first := modelbootstrap.KeyIDsForSID(testSID1)
	second := modelbootstrap.KeyIDsForSID(testSID2)
	key := "windows-native-management-key-0123456789abcdef"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[
{"id":%q,"aliases":[{"alias":"gpt-5.6-luna"}],"models":[{"alias":"gpt-5.6-luna","provider":"codex"}],"daily_limit_usd":20,"weekly_limit_usd":40,"usage":{"daily_usd":1,"weekly_usd":2,"daily_limit_usd":20,"weekly_limit_usd":40,"daily_reset_at":"2026-07-18T00:00:00Z","weekly_reset_at":"2026-07-21T00:00:00Z"}},
{"id":%q,"aliases":[{"alias":"kimi-for-coding"}],"models":[{"alias":"kimi-for-coding","provider":"kimi"}],"daily_limit_usd":5,"weekly_limit_usd":10,"usage":{"daily_usd":0.1,"weekly_usd":0.2,"daily_limit_usd":5,"weekly_limit_usd":10,"daily_reset_at":"2026-07-18T00:00:00Z","weekly_reset_at":"2026-07-21T00:00:00Z"}},
{"id":%q,"aliases":[{"alias":"gpt-5.6-luna"}],"models":[{"alias":"gpt-5.6-luna","provider":"codex"}],"daily_limit_usd":20,"weekly_limit_usd":40,"usage":{"daily_usd":3,"weekly_usd":4,"daily_limit_usd":20,"weekly_limit_usd":40,"daily_reset_at":"2026-07-18T00:00:00Z","weekly_reset_at":"2026-07-21T00:00:00Z"}},
{"id":%q,"aliases":[{"alias":"kimi-for-coding"}],"models":[{"alias":"kimi-for-coding","provider":"kimi"}],"daily_limit_usd":5,"weekly_limit_usd":10,"usage":{"daily_usd":0.3,"weekly_usd":0.4,"daily_limit_usd":5,"weekly_limit_usd":10,"daily_reset_at":"2026-07-18T00:00:00Z","weekly_reset_at":"2026-07-21T00:00:00Z"}}]}`,
			first.CodexKeyID, first.KimiKeyID, second.CodexKeyID, second.KimiKeyID)
	}))
	defer server.Close()
	keyFile := filepath.Join(t.TempDir(), "management.key")
	if err := os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	remote, err := NewManagementRemote(cliproxy.ManagementOptions{BaseURL: server.URL + "/v0/management/plugins/cpa-key-policy", KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	got, err := remote.QueryMany(context.Background(), map[string]modelbootstrap.KeyIDs{testSID1: first, testSID2: second})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || len(got) != 2 || got[testSID1].Providers[0].Daily.UsedUSD != "1" || got[testSID2].Providers[0].Daily.UsedUSD != "3" {
		t.Fatalf("batch policy query was not grouped in one request: requests=%d got=%+v", requests, got)
	}
}
