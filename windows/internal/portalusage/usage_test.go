package portalusage

import (
	"context"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/modelbootstrap"
)

const (
	testSID1 = "S-1-5-21-100-200-300-1017"
	testSID2 = "S-1-5-21-100-200-300-1018"
)

type fakeRemote struct {
	calls []modelbootstrap.KeyIDs
	raw   RawSnapshot
	err   error
}

func (f *fakeRemote) Query(_ context.Context, ids modelbootstrap.KeyIDs) (RawSnapshot, error) {
	f.calls = append(f.calls, ids)
	return f.raw, f.err
}

type fakeBatchRemote struct {
	fakeRemote
	batchCalls int
	rawByOwner map[string]RawSnapshot
}

func (f *fakeBatchRemote) QueryMany(_ context.Context, _ map[string]modelbootstrap.KeyIDs) (map[string]RawSnapshot, error) {
	f.batchCalls++
	return f.rawByOwner, f.err
}

func rawUsage() RawSnapshot {
	return RawSnapshot{AsOf: "2026-07-14T05:00:00Z", Providers: []RawProvider{
		{Kind: KindChatGPT, Daily: RawWindow{LimitUSD: "20", UsedUSD: "1.255", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: RawWindow{LimitUSD: "40.00", UsedUSD: "41", ResetAt: "2026-07-21T00:00:00Z"}},
		{Kind: KindKimi, Daily: RawWindow{LimitUSD: "5.00", UsedUSD: "0.4", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: RawWindow{LimitUSD: "10", UsedUSD: "1.1", ResetAt: "2026-07-21T00:00:00Z"}},
	}}
}

func TestCurrentCalculatesFixedPrecisionRemainingWithoutGoingNegative(t *testing.T) {
	remote := &fakeRemote{raw: rawUsage()}
	service, err := NewService(remote, 30*time.Second, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID1))
	if err != nil {
		t.Fatal(err)
	}
	want := []Provider{
		{Kind: KindChatGPT, Label: "ChatGPT", Daily: Window{LimitUSD: "20.00", UsedUSD: "1.26", RemainingUSD: "18.75", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: Window{LimitUSD: "40.00", UsedUSD: "41.00", RemainingUSD: "0.00", ResetAt: "2026-07-21T00:00:00Z"}},
		{Kind: KindKimi, Label: "Kimi", Daily: Window{LimitUSD: "5.00", UsedUSD: "0.40", RemainingUSD: "4.60", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: Window{LimitUSD: "10.00", UsedUSD: "1.10", RemainingUSD: "8.90", ResetAt: "2026-07-21T00:00:00Z"}},
	}
	if got.AsOf != "2026-07-14T05:00:00Z" || len(got.Providers) != len(want) {
		t.Fatalf("unexpected summary: %+v", got)
	}
	for index := range want {
		if got.Providers[index] != want[index] {
			t.Fatalf("provider %d=%+v, want %+v", index, got.Providers[index], want[index])
		}
	}
}

func TestCurrentAcceptsProductionPrecisionAndRoundsDeterministically(t *testing.T) {
	raw := RawSnapshot{AsOf: "2026-07-14T07:00:00Z", Providers: []RawProvider{
		{Kind: KindChatGPT, Daily: RawWindow{LimitUSD: "20", UsedUSD: "0.0759127000000000047", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: RawWindow{LimitUSD: "40", UsedUSD: "0.0780622000000000049", ResetAt: "2026-07-21T00:00:00Z"}},
		{Kind: KindKimi, Daily: RawWindow{LimitUSD: "5", UsedUSD: "0.0162894000000000014", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: RawWindow{LimitUSD: "10", UsedUSD: "0.0188000000000000014", ResetAt: "2026-07-21T00:00:00Z"}},
	}}
	service, err := NewService(&fakeRemote{raw: raw}, 30*time.Second, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID1))
	if err != nil {
		t.Fatal(err)
	}
	want := []Provider{
		{Kind: KindChatGPT, Label: "ChatGPT", Daily: Window{LimitUSD: "20.00", UsedUSD: "0.08", RemainingUSD: "19.92", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: Window{LimitUSD: "40.00", UsedUSD: "0.08", RemainingUSD: "39.92", ResetAt: "2026-07-21T00:00:00Z"}},
		{Kind: KindKimi, Label: "Kimi", Daily: Window{LimitUSD: "5.00", UsedUSD: "0.02", RemainingUSD: "4.98", ResetAt: "2026-07-15T00:00:00Z"}, Weekly: Window{LimitUSD: "10.00", UsedUSD: "0.02", RemainingUSD: "9.98", ResetAt: "2026-07-21T00:00:00Z"}},
	}
	for index := range want {
		if got.Providers[index] != want[index] {
			t.Fatalf("provider %d=%+v, want %+v", index, got.Providers[index], want[index])
		}
	}
}

func TestCacheIsBoundToSIDAndReturnsDefensiveCopies(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	remote := &fakeRemote{raw: rawUsage()}
	service, err := NewService(remote, 30*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID1))
	if err != nil {
		t.Fatal(err)
	}
	first.Providers[0].Label = "mutated"
	second, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID1))
	if err != nil {
		t.Fatal(err)
	}
	if second.Providers[0].Label != "ChatGPT" || len(remote.calls) != 1 {
		t.Fatalf("same-SID cache was not isolated from caller mutation: value=%+v calls=%d", second, len(remote.calls))
	}
	if _, err := service.Current(context.Background(), testSID2, modelbootstrap.KeyIDsForSID(testSID2)); err != nil {
		t.Fatal(err)
	}
	if len(remote.calls) != 2 || remote.calls[0] == remote.calls[1] {
		t.Fatalf("different SIDs shared a cache entry or key mapping: %+v", remote.calls)
	}
	now = now.Add(31 * time.Second)
	if _, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID1)); err != nil {
		t.Fatal(err)
	}
	if len(remote.calls) != 3 {
		t.Fatalf("expired cache did not refresh: calls=%d", len(remote.calls))
	}
}

func TestCurrentManyLoadsUncachedUsersInOneRemoteRequest(t *testing.T) {
	second := rawUsage()
	second.Providers = append([]RawProvider(nil), second.Providers...)
	second.Providers[0].Daily.UsedUSD = "2.50"
	remote := &fakeBatchRemote{rawByOwner: map[string]RawSnapshot{
		strings.ToUpper(testSID1): rawUsage(),
		strings.ToUpper(testSID2): second,
	}}
	service, err := NewService(remote, 30*time.Second, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.CurrentMany(context.Background(), []string{testSID1, testSID2})
	if err != nil {
		t.Fatal(err)
	}
	if remote.batchCalls != 1 || len(remote.calls) != 0 || got[testSID1].Providers[0].Daily.UsedUSD != "1.26" || got[testSID2].Providers[0].Daily.UsedUSD != "2.50" {
		t.Fatalf("users were not loaded by one batch request: batch=%d single=%d got=%+v", remote.batchCalls, len(remote.calls), got)
	}
	if _, err := service.CurrentMany(context.Background(), []string{testSID1, testSID2}); err != nil {
		t.Fatal(err)
	}
	if remote.batchCalls != 1 {
		t.Fatalf("batch cache was not reused: calls=%d", remote.batchCalls)
	}
}

func TestCurrentManyKeepsAvailableUsersWhenOnePolicyMappingIsMissing(t *testing.T) {
	remote := &fakeBatchRemote{rawByOwner: map[string]RawSnapshot{strings.ToUpper(testSID1): rawUsage()}}
	service, err := NewService(remote, 30*time.Second, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.CurrentMany(context.Background(), []string{testSID1, testSID2})
	if err != nil {
		t.Fatal(err)
	}
	if remote.batchCalls != 1 || len(got) != 1 || got[testSID1].Providers[0].Daily.UsedUSD != "1.26" {
		t.Fatalf("missing user policy hid available quota data: calls=%d got=%+v", remote.batchCalls, got)
	}
}

func TestCurrentRejectsAnotherUsersValidIDsBeforeRemoteQuery(t *testing.T) {
	remote := &fakeRemote{raw: rawUsage()}
	service, err := NewService(remote, 30*time.Second, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID2)); err == nil {
		t.Fatal("another user's valid key IDs were accepted")
	}
	if len(remote.calls) != 0 {
		t.Fatalf("invalid mapping reached remote query: %+v", remote.calls)
	}
}

func TestCurrentRejectsMalformedRemoteProviders(t *testing.T) {
	for name, mutate := range map[string]func(*RawSnapshot){
		"unknown kind":   func(raw *RawSnapshot) { raw.Providers[0].Kind = "other" },
		"duplicate kind": func(raw *RawSnapshot) { raw.Providers[1].Kind = KindChatGPT },
		"bad timestamp":  func(raw *RawSnapshot) { raw.AsOf = "not-a-time" },
		"bad decimal":    func(raw *RawSnapshot) { raw.Providers[0].Daily.UsedUSD = "NaN" },
		"zero limit":     func(raw *RawSnapshot) { raw.Providers[0].Daily.LimitUSD = "0" },
		"bad reset time": func(raw *RawSnapshot) { raw.Providers[0].Daily.ResetAt = "not-a-time" },
	} {
		t.Run(name, func(t *testing.T) {
			raw := rawUsage()
			mutate(&raw)
			service, err := NewService(&fakeRemote{raw: raw}, 30*time.Second, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Current(context.Background(), testSID1, modelbootstrap.KeyIDsForSID(testSID1)); err == nil {
				t.Fatal("malformed remote usage was accepted")
			}
		})
	}
}
