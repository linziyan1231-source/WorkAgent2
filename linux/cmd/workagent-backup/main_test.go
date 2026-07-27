package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type backupResumeTestGuard struct {
	closed  bool
	onClose func()
}

func (guard *backupResumeTestGuard) Close() error {
	guard.closed = true
	if guard.onClose != nil {
		guard.onClose()
	}
	return nil
}

func resumeWithTestControlAuthentication(arguments []string) error {
	return resumeWithDependencies(
		arguments,
		requireExternallyHeldActivationLock,
		func(context.Context) (io.Closer, error) { return &backupResumeTestGuard{}, nil },
		func() error { return nil },
		assertCleanBackupResumeBoundary,
		resumeQuiescedServices,
	)
}

func TestBackupResumeAuthenticatesUnderFixedSnapshotBeforeJournalLoad(t *testing.T) {
	var events []string
	guard := &backupResumeTestGuard{onClose: func() { events = append(events, "fixed-close") }}
	err := resumeWithDependencies(
		nil,
		func() error {
			events = append(events, "activation-authority")
			return nil
		},
		func(context.Context) (io.Closer, error) {
			events = append(events, "catalog-control-snapshot")
			return guard, nil
		},
		func() error {
			if guard.closed {
				t.Fatal("backup executable authentication ran after the fixed snapshot was released")
			}
			events = append(events, "self-authentication")
			return nil
		},
		func() error {
			if guard.closed {
				t.Fatal("backup cleanliness proof ran after the fixed snapshot was released")
			}
			events = append(events, "cleanliness-gates")
			return nil
		},
		func() error {
			if guard.closed {
				t.Fatal("backup quiescence journal load ran after the fixed snapshot was released")
			}
			events = append(events, "journal-load-and-resume")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "activation-authority,catalog-control-snapshot,self-authentication,cleanliness-gates,journal-load-and-resume,fixed-close"
	if got := strings.Join(events, ","); got != want || !guard.closed {
		t.Fatalf("backup resume boundary order=%q guardClosed=%t, want %q and closed", got, guard.closed, want)
	}
}

func TestBackupResumeAuthenticationFailureClosesSnapshotBeforeJournalLoad(t *testing.T) {
	sentinel := errors.New("running backup binary is stale")
	guard := &backupResumeTestGuard{}
	loaded := false
	err := resumeWithDependencies(
		nil,
		func() error { return nil },
		func(context.Context) (io.Closer, error) { return guard, nil },
		func() error { return sentinel },
		func() error { return nil },
		func() error {
			loaded = true
			return nil
		},
	)
	if !errors.Is(err, sentinel) || loaded || !guard.closed {
		t.Fatalf("authentication failure err=%v journalLoaded=%t guardClosed=%t", err, loaded, guard.closed)
	}
}

func TestBackupExternalActivationPathsRejectPendingEdgePublication(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned activation lock fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "activation.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPath := backupActivationLockPath
	originalCoreAssert := assertCoreActivationClean
	originalAssert := assertEdgePublicationClean
	backupActivationLockPath = path
	t.Cleanup(func() {
		backupActivationLockPath = originalPath
		assertCoreActivationClean = originalCoreAssert
		assertEdgePublicationClean = originalAssert
	})
	assertCoreActivationClean = func() error { return nil }
	t.Setenv("WORKAGENT_EXTERNAL_ACTIVATION_LOCK", "1")
	pending := errors.New("pending edge publication fixture")
	tests := []struct {
		name   string
		want   string
		invoke func() error
	}{
		{
			name: "create",
			want: "refuse backup quiescence with a pending edge publication",
			invoke: func() error {
				return create([]string{"--quiesce-systemd"})
			},
		},
		{
			name: "resume",
			want: "refuse service resume with a pending edge publication",
			invoke: func() error {
				return resumeWithTestControlAuthentication(nil)
			},
		},
	}
	unlockedCalls := 0
	assertEdgePublicationClean = func() error {
		unlockedCalls++
		return pending
	}
	for _, test := range tests {
		if err := test.invoke(); err == nil || !strings.Contains(err.Error(), "backup service did not hold the tenant activation lock") {
			t.Fatalf("%s without external activation lock result=%v, want external-lock rejection", test.name, err)
		}
	}
	if unlockedCalls != 0 {
		t.Fatalf("edge-publication admission ran %d times before external activation authority was proved", unlockedCalls)
	}

	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			assertEdgePublicationClean = func() error {
				calls++
				return pending
			}
			err := test.invoke()
			if !errors.Is(err, pending) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("pending edge-publication result=%v, want wrapped fail-closed error containing %q", err, test.want)
			}
			if calls != 1 {
				t.Fatalf("edge-publication admission calls=%d, want 1", calls)
			}
		})
	}
}

func TestBackupQuiescenceRequiresExternallyHeldActivationLock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned activation lock fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "activation.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPath := backupActivationLockPath
	backupActivationLockPath = path
	t.Cleanup(func() { backupActivationLockPath = originalPath })
	t.Setenv("WORKAGENT_EXTERNAL_ACTIVATION_LOCK", "1")
	backupActivationLockPath = filepath.Join(t.TempDir(), "missing.lock")
	if err := requireExternallyHeldActivationLock(); err == nil {
		t.Fatal("missing external activation lock was accepted")
	}
	backupActivationLockPath = path
	if err := requireExternallyHeldActivationLock(); err == nil {
		t.Fatal("unlocked backup quiescence was accepted")
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := requireExternallyHeldActivationLock(); err != nil {
		t.Fatalf("externally held activation lock was rejected: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := requireExternallyHeldActivationLock(); err == nil {
		t.Fatal("unsafe externally held activation inode was accepted")
	}
}

func TestBackupExternalActivationRejectsPendingCoreBeforeEdgeOrQuiesce(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned activation lock fixture requires root")
	}
	path := filepath.Join(t.TempDir(), "activation.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPath := backupActivationLockPath
	originalCore := assertCoreActivationClean
	originalEdge := assertEdgePublicationClean
	t.Cleanup(func() {
		backupActivationLockPath = originalPath
		assertCoreActivationClean = originalCore
		assertEdgePublicationClean = originalEdge
	})
	backupActivationLockPath = path
	t.Setenv("WORKAGENT_EXTERNAL_ACTIVATION_LOCK", "1")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	pending := errors.New("pending core activation fixture")
	edgeCalls := 0
	assertCoreActivationClean = func() error { return pending }
	assertEdgePublicationClean = func() error {
		edgeCalls++
		return nil
	}
	for name, invoke := range map[string]func() error{
		"create": func() error { return create([]string{"--quiesce-systemd"}) },
		"resume": func() error { return resumeWithTestControlAuthentication(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			err := invoke()
			if !errors.Is(err, pending) || !strings.Contains(err.Error(), "pending core activation") {
				t.Fatalf("pending core evidence was not rejected: %v", err)
			}
		})
	}
	if edgeCalls != 0 {
		t.Fatalf("edge admission ran after pending core evidence: calls=%d", edgeCalls)
	}
}

func TestQuiesceJournalAcceptsOnlyCanonicalWorkAgentUnits(t *testing.T) {
	valid := quiesceJournal{SchemaVersion: 1, Units: []string{
		"workagent-portal.service",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.socket",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.service",
		"cliproxyapi.service",
	}}
	if err := validateQuiesceJournal(valid); err != nil {
		t.Fatalf("valid recovery journal rejected: %v", err)
	}
	for _, units := range [][]string{
		{"ssh.service"},
		{"workagent-userhost@../escape.service"},
		{"workagent-portal.service", "workagent-portal.service"},
	} {
		if err := validateQuiesceJournal(quiesceJournal{SchemaVersion: 1, Units: units}); err == nil {
			t.Fatalf("unsafe recovery journal accepted: %v", units)
		}
	}
}

func TestParseQuiesceUnitStateRejectsTransitionsAndResidualProcesses(t *testing.T) {
	activeService := "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nControlPID=0\n"
	activeSocket := "LoadState=loaded\nActiveState=active\nSubState=listening\nMainPID=0\nControlPID=0\n"
	inactive := "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n"
	for unit, payload := range map[string]string{
		"workagent-portal.service":                                       activeService,
		"workagent-userhost@11111111-1111-4111-8111-111111111111.socket": activeSocket,
	} {
		active, err := parseQuiesceUnitState(unit, payload)
		if err != nil || !active {
			t.Fatalf("active %s rejected: active=%v err=%v", unit, active, err)
		}
	}
	if active, err := parseQuiesceUnitState("cliproxyapi.service", inactive); err != nil || active {
		t.Fatalf("inactive unit state rejected: active=%v err=%v", active, err)
	}
	for name, payload := range map[string]string{
		"transition":          "LoadState=loaded\nActiveState=activating\nSubState=start\nMainPID=0\nControlPID=43\n",
		"service without pid": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\nControlPID=0\n",
		"inactive residual":   "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=42\nControlPID=0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseQuiesceUnitState("workagent-portal.service", payload); err == nil {
				t.Fatal("unsafe unit state was accepted")
			}
		})
	}
}
