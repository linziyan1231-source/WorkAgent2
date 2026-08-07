package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChatGPTProReservationEnforcesWeeklyLimitAndReleasesFallback(t *testing.T) {
	data := openTestStore(t)
	user := createTestUser(t, data, "pro-user", "S-1-5-21-100-200-300-1401")
	now := time.Date(2026, 7, 20, 9, 0, 0, 0, time.FixedZone("Asia/Shanghai", 8*60*60))
	if err := data.SetChatGPTProWeeklyLimit(context.Background(), user.ID, 1, now); err != nil {
		t.Fatal(err)
	}
	reservation, err := data.ReserveChatGPTPro(context.Background(), user.ID, testLogicalID('a'), "gpt-5-6-pro", "standard", now)
	if err != nil || reservation.State != ChatGPTProReserved {
		t.Fatalf("first reservation: %+v err=%v", reservation, err)
	}
	blocked, err := data.ReserveChatGPTPro(context.Background(), user.ID, testLogicalID('b'), "gpt-5-6-pro", "standard", now)
	if err != nil || blocked.State != ChatGPTProQuotaExceeded {
		t.Fatalf("concurrent reservation escaped limit: %+v err=%v", blocked, err)
	}
	if err := data.SettleChatGPTPro(context.Background(), user.ID, testLogicalID('a'), ProStatusFallback, 200, true, []string{"gpt-5-3-mini"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	released, err := data.ReserveChatGPTPro(context.Background(), user.ID, testLogicalID('b'), "gpt-5-6-pro", "standard", now.Add(2*time.Minute))
	if err != nil || released.State != ChatGPTProReserved {
		t.Fatalf("fallback did not release the slot: %+v err=%v", released, err)
	}
	events, err := data.PendingChatGPTProEvents(context.Background(), user.ID, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("fallback event: %+v err=%v", events, err)
	}
}

func TestChatGPTProUnknownHoldsSlotAndDuplicateDoesNotCreateAnotherRecord(t *testing.T) {
	data := openTestStore(t)
	user := createTestUser(t, data, "unknown-user", "S-1-5-21-100-200-300-1402")
	now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	logicalID := testLogicalID('c')
	if _, err := data.ReserveChatGPTPro(context.Background(), user.ID, logicalID, "gpt-5-6-pro", "", now); err != nil {
		t.Fatal(err)
	}
	if err := data.SettleChatGPTPro(context.Background(), user.ID, logicalID, ProStatusUnknown, 200, false, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	duplicate, err := data.ReserveChatGPTPro(context.Background(), user.ID, logicalID, "gpt-5-6-pro", "", now.Add(2*time.Minute))
	if err != nil || duplicate.State != ChatGPTProDuplicatePending || duplicate.Quota.Pending != 1 {
		t.Fatalf("unknown duplicate state: %+v err=%v", duplicate, err)
	}
}

func TestChatGPTProUpstreamRejectionCanBeRetried(t *testing.T) {
	data := openTestStore(t)
	user := createTestUser(t, data, "retry-user", "S-1-5-21-100-200-300-1403")
	now := time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC)
	logicalID := testLogicalID('d')
	if _, err := data.ReserveChatGPTPro(context.Background(), user.ID, logicalID, "gpt-5-6-pro", "", now); err != nil {
		t.Fatal(err)
	}
	if err := data.SettleChatGPTPro(context.Background(), user.ID, logicalID, ProStatusUpstreamRejected, 503, false, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	retry, err := data.ReserveChatGPTPro(context.Background(), user.ID, logicalID, "gpt-5-6-pro", "", now.Add(2*time.Minute))
	if err != nil || retry.State != ChatGPTProReserved || retry.Quota.Pending != 1 {
		t.Fatalf("rejected upstream send was not retryable: %+v err=%v", retry, err)
	}
}

func TestChatGPTProWeekUsesShanghaiMondayBoundary(t *testing.T) {
	start, reset := shanghaiWeek(time.Date(2026, 7, 19, 16, 30, 0, 0, time.UTC))
	if start != time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC) || reset != time.Date(2026, 7, 26, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected Shanghai week: start=%s reset=%s", start, reset)
	}
}

func createTestUser(t *testing.T, data *Store, username, sid string) User {
	t.Helper()
	user, err := data.CreateUser(context.Background(), username, "hash", sid, username, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func testLogicalID(character byte) string {
	return strings.Repeat(string(character), 64)
}
