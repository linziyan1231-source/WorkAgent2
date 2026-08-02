package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestChatForwardSignatureIsSingleUseAcrossRequests(t *testing.T) {
	value := openTestStore(t)
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	signature := make([]byte, 32)
	for index := range signature {
		signature[index] = byte(index + 1)
	}
	if err := value.ConsumeChatForwardSignature(context.Background(), signature, now, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := value.ConsumeChatForwardSignature(context.Background(), signature, now, 2*time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed signature returned %v", err)
	}
	if err := value.ConsumeChatForwardSignature(context.Background(), signature, now.Add(2*time.Minute), 2*time.Minute); err != nil {
		t.Fatalf("expired replay marker was not reusable: %v", err)
	}
}

func TestChatGPTProReservationSettlementAndFallbackEvent(t *testing.T) {
	value := openTestStore(t)
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	userValue, err := value.CreateUser(context.Background(), "alice", "hash", testTenantID, "workagent_alice", "/srv/workagent/users/"+testTenantID, false, now)
	if err != nil {
		t.Fatal(err)
	}
	logical := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	reservation, err := value.ReserveChatGPTPro(context.Background(), userValue.ID, 1, logical, "gpt-5-6-pro", "standard", now)
	if err != nil || reservation.State != ChatGPTProReserved || reservation.Quota.Pending != 1 {
		t.Fatalf("reservation=%+v err=%v", reservation, err)
	}
	duplicate, err := value.ReserveChatGPTPro(context.Background(), userValue.ID, 1, logical, "gpt-5-6-pro", "standard", now)
	if err != nil || duplicate.State != ChatGPTProDuplicatePending {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	if err := value.SettleChatGPTPro(context.Background(), userValue.ID, logical, ProStatusFallback, 200, true, []string{"gpt-5-mini"}, now); err != nil {
		t.Fatal(err)
	}
	events, err := value.PendingChatGPTProEvents(context.Background(), userValue.ID, 20)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	quota, err := value.ChatGPTProQuota(context.Background(), userValue.ID, 1, now)
	if err != nil || quota.Confirmed != 0 || quota.Pending != 0 {
		t.Fatalf("fallback was not refunded: quota=%+v err=%v", quota, err)
	}
}
