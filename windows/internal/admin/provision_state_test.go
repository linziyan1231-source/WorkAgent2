package admin

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProvisionStateNormalCreationPersistsEveryGate(t *testing.T) {
	clock := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	store := provisionStateStore{directory: t.TempDir(), now: func() time.Time { clock = clock.Add(time.Second); return clock }}
	state, err := store.open("worker")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"profile", "acl", "task", "userhost", "core", "model_bootstrap", "login_health"} {
		if err := store.begin(state, step); err != nil {
			t.Fatal(err)
		}
		if err := store.complete(state, step); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.finish(state); err != nil {
		t.Fatal(err)
	}
	reloaded, err := store.open("worker")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Attempt != 1 || reloaded.Status != "complete" || len(reloaded.CompletedSteps) != 7 {
		t.Fatalf("reloaded state = %+v", reloaded)
	}
}

func TestProvisionStateInterruptionRemainsRetryableAtKeyStages(t *testing.T) {
	for _, interrupted := range []string{"profile", "task", "userhost", "model_bootstrap", "login_health"} {
		t.Run(interrupted, func(t *testing.T) {
			store := provisionStateStore{directory: t.TempDir(), now: time.Now}
			state, err := store.open("worker")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.begin(state, interrupted); err != nil {
				t.Fatal(err)
			}
			if err := store.fail(state, interrupted); err != nil {
				t.Fatal(err)
			}
			resumed, err := store.open("worker")
			if err != nil {
				t.Fatal(err)
			}
			if resumed.Attempt != 2 || resumed.Status != "pending" || resumed.FailureStage != "" || resumed.ResumeStep != interrupted {
				t.Fatalf("resumed state = %+v", resumed)
			}
			if err := store.begin(resumed, interrupted); err != nil {
				t.Fatal(err)
			}
			if err := store.complete(resumed, interrupted); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProvisionStateCompletedJournalIsNotClobberedByRetry(t *testing.T) {
	store := provisionStateStore{directory: t.TempDir(), now: time.Now}
	state, err := store.open("worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.begin(state, "login_health"); err != nil {
		t.Fatal(err)
	}
	if err := store.complete(state, "login_health"); err != nil {
		t.Fatal(err)
	}
	if err := store.finish(state); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.open("worker")
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != "complete" || reopened.Attempt != 1 || reopened.FailureStage != "" {
		t.Fatalf("completed journal was mutated: %+v", reopened)
	}
}

func TestProvisionStateGraduationCrashResumesFinalAccountMarker(t *testing.T) {
	store := provisionStateStore{directory: t.TempDir(), now: time.Now}
	state, err := store.open("worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.begin(state, "graduating_account"); err != nil {
		t.Fatal(err)
	}
	// This is the persisted shape if the managed-account comment is written
	// and the process exits after completing the step but before finish().
	if err := store.complete(state, "graduating_account"); err != nil {
		t.Fatal(err)
	}
	resumed, err := store.open("worker")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.ResumeStep != "graduating_account" || resumed.Status != "pending" {
		t.Fatalf("graduation retry lost its final checkpoint: %+v", resumed)
	}
}

func TestProvisionStateRejectsDuplicateWorkForSameUsername(t *testing.T) {
	var locks provisionLocks
	release, err := locks.acquire("Worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locks.acquire("worker"); err == nil {
		t.Fatal("duplicate provisioning was accepted")
	}
	release()
	if releaseAgain, err := locks.acquire("worker"); err != nil {
		t.Fatal(err)
	} else {
		releaseAgain()
	}
}

func TestProvisionStateRejectsCorruptJournal(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "worker.json"), []byte(`{"version":1,"username":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (provisionStateStore{directory: directory, now: time.Now}).open("worker")
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt journal was accepted")
	}
}
