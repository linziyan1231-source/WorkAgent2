package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
)

type recordingCloser struct {
	name   string
	events *[]string
	err    error
}

func recordingMigrationLifecycleAcquirer(events *[]string) migrationLifecycleAcquirer {
	return migrationLifecycleAcquirer{
		activation: func(context.Context) (io.Closer, error) {
			*events = append(*events, "activation-acquire")
			return recordingCloser{name: "activation", events: events}, nil
		},
		assertNoPendingRecovery: func() error {
			*events = append(*events, "recovery-clean")
			return nil
		},
		assertTenantActivationClean: func() error {
			*events = append(*events, "tenant-clean")
			return nil
		},
		fixed: func(context.Context) (io.Closer, error) {
			*events = append(*events, "fixed-acquire")
			return recordingCloser{name: "fixed", events: events}, nil
		},
		migrationShared: func() (io.Closer, error) {
			*events = append(*events, "migration-acquire")
			return recordingCloser{name: "migration", events: events}, nil
		},
	}
}

func (closer recordingCloser) Close() error {
	*closer.events = append(*closer.events, closer.name+"-close")
	return closer.err
}

func TestMigrationCommandLifecycleHoldsOrderedLocksThroughOperation(t *testing.T) {
	for _, fixture := range []struct {
		name            string
		migrationShared bool
		want            []string
	}{
		{
			name:            "stage and verify",
			migrationShared: true,
			want:            []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "migration-acquire", "operation", "migration-close", "fixed-close", "activation-close"},
		},
		{
			name:            "apply",
			migrationShared: false,
			want:            []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "operation", "fixed-close", "activation-close"},
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			events := []string{}
			acquire := recordingMigrationLifecycleAcquirer(&events)
			if err := withMigrationLifecycleAcquirer(context.Background(), fixture.migrationShared, acquire, func() error {
				events = append(events, "operation")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(events, fixture.want) {
				t.Fatalf("migration lifecycle order drifted: got %#v want %#v", events, fixture.want)
			}
		})
	}
}

func TestMigrationCommandLifecycleCleansUpAndPreservesErrors(t *testing.T) {
	events := []string{}
	acquire := recordingMigrationLifecycleAcquirer(&events)
	acquire.activation = func(context.Context) (io.Closer, error) {
		events = append(events, "activation-acquire")
		return recordingCloser{name: "activation", events: &events, err: errors.New("activation close")}, nil
	}
	acquire.fixed = func(context.Context) (io.Closer, error) {
		events = append(events, "fixed-acquire")
		return recordingCloser{name: "fixed", events: &events, err: errors.New("fixed close")}, nil
	}
	acquire.migrationShared = func() (io.Closer, error) {
		events = append(events, "migration-acquire")
		return recordingCloser{name: "migration", events: &events, err: errors.New("migration close")}, nil
	}
	err := withMigrationLifecycleAcquirer(context.Background(), true, acquire, func() error {
		events = append(events, "operation")
		return errors.New("operation failed")
	})
	for _, fragment := range []string{"operation failed", "migration close", "fixed close", "activation close"} {
		if err == nil || !strings.Contains(err.Error(), fragment) {
			t.Fatalf("migration lifecycle lost %q: %v", fragment, err)
		}
	}

	events = nil
	acquire = recordingMigrationLifecycleAcquirer(&events)
	acquire.fixed = func(context.Context) (io.Closer, error) {
		events = append(events, "fixed-acquire")
		return recordingCloser{name: "fixed", events: &events}, nil
	}
	acquire.migrationShared = func() (io.Closer, error) {
		events = append(events, "migration-acquire")
		return nil, errors.New("migration unavailable")
	}
	err = withMigrationLifecycleAcquirer(context.Background(), true, acquire, func() error {
		t.Fatal("operation ran without the migration lock")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "migration unavailable") || !slices.Equal(events, []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "migration-acquire", "fixed-close", "activation-close"}) {
		t.Fatalf("failed migration acquisition did not close fixed guards: events=%#v err=%v", events, err)
	}
}

func TestMigrationCommandLifecycleRequiresActivationAndCleanJournalsBeforeCatalog(t *testing.T) {
	operationRan := false
	operation := func() error {
		operationRan = true
		return nil
	}

	events := []string{}
	acquire := recordingMigrationLifecycleAcquirer(&events)
	acquire.activation = func(context.Context) (io.Closer, error) {
		events = append(events, "activation-acquire")
		return nil, nil
	}
	if err := withMigrationLifecycleAcquirer(context.Background(), true, acquire, operation); err == nil || operationRan || !slices.Equal(events, []string{"activation-acquire"}) {
		t.Fatalf("missing activation guard did not fail closed: events=%#v ran=%v err=%v", events, operationRan, err)
	}

	events = nil
	acquire = recordingMigrationLifecycleAcquirer(&events)
	recoveryFailure := errors.New("pending recovery")
	acquire.assertNoPendingRecovery = func() error {
		events = append(events, "recovery-clean")
		return recoveryFailure
	}
	if err := withMigrationLifecycleAcquirer(context.Background(), true, acquire, operation); !errors.Is(err, recoveryFailure) || operationRan ||
		!slices.Equal(events, []string{"activation-acquire", "recovery-clean", "activation-close"}) {
		t.Fatalf("pending recovery reached catalog acquisition: events=%#v ran=%v err=%v", events, operationRan, err)
	}

	events = nil
	acquire = recordingMigrationLifecycleAcquirer(&events)
	tenantFailure := errors.New("pending tenant activation")
	acquire.assertTenantActivationClean = func() error {
		events = append(events, "tenant-clean")
		return tenantFailure
	}
	if err := withMigrationLifecycleAcquirer(context.Background(), true, acquire, operation); !errors.Is(err, tenantFailure) || operationRan ||
		!slices.Equal(events, []string{"activation-acquire", "recovery-clean", "tenant-clean", "activation-close"}) {
		t.Fatalf("pending tenant activation reached catalog acquisition: events=%#v ran=%v err=%v", events, operationRan, err)
	}
}

func TestMigrationCommandLifecycleRejectsMissingGuardsAndCanceledContext(t *testing.T) {
	operationRan := false
	operation := func() error {
		operationRan = true
		return nil
	}

	events := []string{}
	acquire := recordingMigrationLifecycleAcquirer(&events)
	acquire.fixed = func(context.Context) (io.Closer, error) {
		events = append(events, "fixed-acquire")
		return nil, nil
	}
	acquire.migrationShared = func() (io.Closer, error) {
		t.Fatal("migration acquisition ran without a fixed guard")
		return nil, nil
	}
	err := withMigrationLifecycleAcquirer(context.Background(), true, acquire, operation)
	if err == nil || !strings.Contains(err.Error(), "no guard") || operationRan || !slices.Equal(events, []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "activation-close"}) {
		t.Fatalf("missing fixed guard was not rejected: events=%#v ran=%v err=%v", events, operationRan, err)
	}
	events = nil
	acquire = recordingMigrationLifecycleAcquirer(&events)
	acquire.fixed = func(context.Context) (io.Closer, error) {
		events = append(events, "fixed-acquire")
		var typedNil *recordingCloser
		return typedNil, nil
	}
	err = withMigrationLifecycleAcquirer(context.Background(), true, acquire, operation)
	if err == nil || !strings.Contains(err.Error(), "no guard") || operationRan || !slices.Equal(events, []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "activation-close"}) {
		t.Fatalf("typed-nil fixed guard was not rejected: events=%#v ran=%v err=%v", events, operationRan, err)
	}

	events = nil
	acquire = recordingMigrationLifecycleAcquirer(&events)
	acquire.fixed = func(context.Context) (io.Closer, error) {
		events = append(events, "fixed-acquire")
		return recordingCloser{name: "fixed", events: &events}, nil
	}
	acquire.migrationShared = func() (io.Closer, error) {
		events = append(events, "migration-acquire")
		return nil, nil
	}
	err = withMigrationLifecycleAcquirer(context.Background(), true, acquire, operation)
	if err == nil || !strings.Contains(err.Error(), "no guard") || operationRan || !slices.Equal(events, []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "migration-acquire", "fixed-close", "activation-close"}) {
		t.Fatalf("missing migration guard was not rejected: events=%#v ran=%v err=%v", events, operationRan, err)
	}

	events = nil
	acquire = recordingMigrationLifecycleAcquirer(&events)
	acquire.migrationShared = func() (io.Closer, error) {
		events = append(events, "migration-acquire")
		return recordingCloser{name: "migration", events: &events}, nil
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err = withMigrationLifecycleAcquirer(canceled, true, acquire, operation)
	if !errors.Is(err, context.Canceled) || operationRan || !slices.Equal(events, []string{"activation-acquire", "recovery-clean", "tenant-clean", "fixed-acquire", "migration-acquire", "migration-close", "fixed-close", "activation-close"}) {
		t.Fatalf("canceled lifecycle ran the operation or leaked guards: events=%#v ran=%v err=%v", events, operationRan, err)
	}
}

func TestEncodeVerifyMigrationPlanResultIncludesDurableReceipt(t *testing.T) {
	expires := time.Date(2026, 7, 27, 3, 4, 5, 600, time.UTC)
	var output bytes.Buffer
	if err := encodeVerifyMigrationPlanResult(&output, cliproxy.VerifyMigrationPlanResult{
		Users: 3, Overrides: 6, ReceiptPath: cliproxy.MigrationLiveVerificationReceiptPath, ReceiptExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Verified             bool      `json:"verified"`
		Users                int       `json:"users"`
		Overrides            int       `json:"overrides"`
		ReceiptPath          string    `json:"receipt_path"`
		ReceiptExpiresAt     time.Time `json:"receipt_expires_at"`
		ContainsPlaintextKey bool      `json:"contains_plaintext_key"`
	}
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Verified || decoded.Users != 3 || decoded.Overrides != 6 ||
		decoded.ReceiptPath != cliproxy.MigrationLiveVerificationReceiptPath || !decoded.ReceiptExpiresAt.Equal(expires) || decoded.ContainsPlaintextKey {
		t.Fatalf("verification output omitted or changed receipt evidence: %#v", decoded)
	}
	for _, invalid := range []cliproxy.VerifyMigrationPlanResult{
		{},
		{Users: 1, Overrides: 1, ReceiptPath: cliproxy.MigrationLiveVerificationReceiptPath, ReceiptExpiresAt: expires},
		{Users: 1, Overrides: 2, ReceiptPath: "/tmp/receipt", ReceiptExpiresAt: expires},
	} {
		if err := encodeVerifyMigrationPlanResult(io.Discard, invalid); err == nil {
			t.Fatalf("incomplete verification result was encoded: %#v", invalid)
		}
	}
}

func TestMigrationRunbookDocumentsInternalLockOrderAndLifetime(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve CLIProxy test source path")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(sourcePath), "..", "..", "docs", "WINDOWS_DATA_MIGRATION.md"))
	if err != nil {
		t.Fatal(err)
	}
	runbook := string(payload)
	for _, required := range []string{
		"A_EX -> C_SH -> control-channel SH -> CLIProxy migration SH",
		"A_EX -> C_SH -> control-channel SH -> CLIProxy migration EX",
		"proves that neither a recovery-activation journal nor a tenant-activation journal is pending",
		"durable receipt/state publication, all readback, and inner-lock release",
		"fixed-root writer's `C_EX -> control-channel EX` order",
		"every activation writer's `A_EX -> C_*` order",
		"/var/lib/workagent/migration/cutover/cliproxy-live-verification.json",
		"requires the unexpired live-verification receipt",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("migration runbook omits lifecycle contract %q", required)
		}
	}
}
