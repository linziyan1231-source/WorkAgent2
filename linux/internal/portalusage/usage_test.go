package portalusage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

const usageTenant = "11111111-1111-4111-8111-111111111111"

type fakeRemote struct {
	mu    sync.Mutex
	calls int
	raw   RawSnapshot
	err   error
}

func (f *fakeRemote) Query(context.Context, string, productconfig.Policy) (RawSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.raw, f.err
}

func usagePolicy() productconfig.Policy {
	return productconfig.Policy{SchemaVersion: 1, PolicyID: "workagent-models-v1", DefaultAction: "deny",
		Models: []productconfig.Model{
			{ID: "gpt-managed", DisplayName: "Managed GPT", Provider: "codex", Enabled: true, Default: true},
			{ID: "kimi-managed", DisplayName: "Managed Kimi", Provider: "kimi", Enabled: true, Default: true},
		},
		Aliases: map[string]string{},
		Pricing: map[string]productconfig.Price{
			"gpt-managed":  {InputPerMillion: "1.25", OutputPerMillion: "5", Currency: "USD"},
			"kimi-managed": {InputPerMillion: "3", OutputPerMillion: "15", Currency: "USD"},
		},
		Quotas: map[string]productconfig.Quota{
			"gpt-managed":  {RequestsPerMinute: 10, DailyUSD: "20", WeeklyUSD: "40"},
			"kimi-managed": {RequestsPerMinute: 5, DailyUSD: "5", WeeklyUSD: "10"},
		}}
}

func validRawUsage() RawSnapshot {
	return RawSnapshot{AsOf: "2026-07-24T12:00:00Z", Providers: []RawProvider{
		{Kind: KindChatGPT, Daily: RawWindow{LimitUSD: "20", UsedUSD: "1.255", ResetAt: "2026-07-25T00:00:00Z"}, Weekly: RawWindow{LimitUSD: "40", UsedUSD: "41", ResetAt: "2026-07-27T00:00:00Z"}},
		{Kind: KindKimi, Daily: RawWindow{LimitUSD: "5", UsedUSD: "0", ResetAt: "2026-07-25T00:00:00Z"}, Weekly: RawWindow{LimitUSD: "10", UsedUSD: "1.1", ResetAt: "2026-07-27T00:00:00Z"}},
	}}
}

func TestServiceNormalizesCachesAndClampsUsage(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	remote := &fakeRemote{raw: validRawUsage()}
	service, err := NewService(remote, usagePolicy(), 15*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Current(context.Background(), usageTenant)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Current(context.Background(), usageTenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Providers) != 2 || first.Providers[0].Daily.UsedUSD != "1.26" || first.Providers[0].Weekly.RemainingUSD != "0.00" || second.Providers[1].Weekly.UsedUSD != "1.10" {
		t.Fatalf("unexpected normalized usage: first=%+v second=%+v", first, second)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.calls != 1 {
		t.Fatalf("cache did not coalesce usage reads: calls=%d", remote.calls)
	}
}

func TestServiceDoesNotCacheRemoteFailures(t *testing.T) {
	remote := &fakeRemote{err: errors.New("unavailable")}
	service, err := NewService(remote, usagePolicy(), time.Second, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := service.Current(context.Background(), usageTenant); err == nil {
			t.Fatal("remote failure was accepted")
		}
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.calls != 2 {
		t.Fatalf("remote failure was cached: calls=%d", remote.calls)
	}
}

func TestNormalizeRejectsAmbiguousOrInvalidUsage(t *testing.T) {
	raw := validRawUsage()
	raw.Providers[1].Kind = KindChatGPT
	if _, err := normalize(raw); err == nil {
		t.Fatal("duplicate provider was accepted")
	}
	raw = validRawUsage()
	raw.Providers[0].Daily.UsedUSD = "NaN"
	if _, err := normalize(raw); err == nil {
		t.Fatal("invalid amount was accepted")
	}
}
