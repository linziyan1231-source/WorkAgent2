package portalusage

import (
	"bytes"
	"testing"
)

func validSummarySnapshot() Summary {
	return Summary{AsOf: "2026-07-26T08:00:00Z", Providers: []Provider{
		{Kind: KindChatGPT, Label: "ChatGPT", Daily: Window{LimitUSD: "20.00", UsedUSD: "1.25", RemainingUSD: "18.75", ResetAt: "2026-07-27T00:00:00Z"}, Weekly: Window{LimitUSD: "40.00", UsedUSD: "3.50", RemainingUSD: "36.50", ResetAt: "2026-08-03T00:00:00Z"}, Pro: &CountWindow{Used: 1, Limit: 7, ResetAt: "2026-08-03T00:00:00Z"}},
		{Kind: KindKimi, Label: "Kimi", Daily: Window{LimitUSD: "5.00", UsedUSD: "0.40", RemainingUSD: "4.60", ResetAt: "2026-07-27T00:00:00Z"}, Weekly: Window{LimitUSD: "10.00", UsedUSD: "1.10", RemainingUSD: "8.90", ResetAt: "2026-08-03T00:00:00Z"}},
	}, Storage: &StorageUsage{LimitBytes: 100, UsedBytes: 30, RemainingBytes: 70, MeasuredAt: "2026-07-26T08:00:00Z"}}
}

func TestSummarySnapshotRoundTripIsStrict(t *testing.T) {
	payload, err := MarshalSummarySnapshot(validSummarySnapshot())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSummarySnapshot(payload)
	if err != nil || parsed.Storage == nil || parsed.Storage.RemainingBytes != 70 {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	unknown := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := ParseSummarySnapshot(unknown); err == nil {
		t.Fatal("snapshot with an unknown field was accepted")
	}
	duplicate := append([]byte(`{"as_of":"2026-07-26T07:00:00Z",`), payload[1:]...)
	if _, err := ParseSummarySnapshot(duplicate); err == nil {
		t.Fatal("snapshot with a duplicate field was accepted")
	}
	if _, err := ParseSummarySnapshot(append(payload, []byte(` {}`)...)); err == nil {
		t.Fatal("snapshot with a trailing JSON value was accepted")
	}
}

func TestSummarySnapshotAcceptsNormalizedSubCentUsage(t *testing.T) {
	summary, err := normalize(validRawUsage())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := MarshalSummarySnapshot(summary)
	if err != nil {
		t.Fatalf("normalized usage was not snapshot-safe: %+v: %v", summary, err)
	}
	if _, err := ParseSummarySnapshot(payload); err != nil {
		t.Fatalf("normalized snapshot did not round trip: %v", err)
	}
}

func TestSummarySnapshotRejectsInconsistentValuesAndOversizeInput(t *testing.T) {
	summary := validSummarySnapshot()
	summary.Storage.RemainingBytes++
	if _, err := MarshalSummarySnapshot(summary); err == nil {
		t.Fatal("inconsistent storage remainder was accepted")
	}
	summary = validSummarySnapshot()
	summary.Providers[0].Daily.RemainingUSD = "19.00"
	if _, err := MarshalSummarySnapshot(summary); err == nil {
		t.Fatal("inconsistent monetary remainder was accepted")
	}
	if _, err := ParseSummarySnapshot(bytes.Repeat([]byte{' '}, MaxSummarySnapshotBytes+1)); err == nil {
		t.Fatal("oversize snapshot was accepted")
	}
}
