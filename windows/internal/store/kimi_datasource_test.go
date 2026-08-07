package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestKimiDatasourceGrantEnforcesSourceAndQuota(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	user, err := s.CreateUser(ctx, "kimi-user", "hash", "S-1-5-21-1-1101", `SERVER\kimi-user`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetKimiDatasourceGrant(ctx, user.ID, true, []string{"scholar", "arxiv", "arxiv"}, 2, 3, "employee-token", now); err != nil {
		t.Fatal(err)
	}
	grant, userID, err := s.KimiDatasourceGrantForToken(ctx, "employee-token", now)
	if err != nil || userID != user.ID || len(grant.AllowedSources) != 2 || grant.AllowedSources[0] != "arxiv" {
		t.Fatalf("unexpected grant: grant=%+v user_id=%d err=%v", grant, userID, err)
	}
	if _, _, err := s.ReserveKimiDatasourceCall(ctx, "employee-token", "yuandian_law", now); !errors.Is(err, ErrKimiDatasourceSourceDenied) {
		t.Fatalf("disallowed source error=%v", err)
	}
	for call := 0; call < 2; call++ {
		if _, _, err := s.ReserveKimiDatasourceCall(ctx, "employee-token", "arxiv", now); err != nil {
			t.Fatalf("allowed call %d: %v", call, err)
		}
	}
	if _, _, err := s.ReserveKimiDatasourceCall(ctx, "employee-token", "arxiv", now); !errors.Is(err, ErrKimiDatasourceDailyExceeded) {
		t.Fatalf("daily limit error=%v", err)
	}
	usage, err := s.KimiDatasourceGrantForUser(ctx, user.ID, now)
	if err != nil || usage.DailyUsed != 2 || usage.MonthlyUsed != 2 {
		t.Fatalf("quota usage changed after rejected calls: grant=%+v err=%v", usage, err)
	}
}

func TestKimiDatasourceGrantFailsClosedWhenPortalUserDisabled(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	user, err := s.CreateUser(ctx, "disabled-kimi", "hash", "S-1-5-21-1-1102", `SERVER\disabled-kimi`, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetKimiDatasourceGrant(ctx, user.ID, true, []string{"arxiv"}, 2, 10, "disabled-token", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserEnabled(ctx, user.Username, false, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.KimiDatasourceGrantForToken(ctx, "disabled-token", now); !errors.Is(err, ErrKimiDatasourceDisabled) {
		t.Fatalf("disabled employee token remained valid: %v", err)
	}
}
