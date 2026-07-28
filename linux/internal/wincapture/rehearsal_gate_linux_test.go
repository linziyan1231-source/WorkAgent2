//go:build linux

package wincapture

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCheckPublishesCanonicalCompleteReceiptOnlyAfterTwoStableCollections(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := newFixtureTransport(t, spec)
	started := time.Unix(1_900_000_000, 0).UTC()
	completed := started.Add(7 * time.Minute)
	nowCalls := 0
	identityCalls := 0
	engine := &captureEngine{
		remote: transport, expectedUID: uint32(os.Geteuid()),
		now: func() time.Time {
			nowCalls++
			if nowCalls == 1 {
				return started
			}
			return completed
		},
		identity: func() (executableIdentity, error) {
			identityCalls++
			return fixtureExecutableIdentity, nil
		},
	}
	options := testCheckOptions(t, parent, specPath, "receipt-rehearsal-0001")
	report, err := engine.check(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if identityCalls != 2 || nowCalls != 2 {
		t.Fatalf("identity/time calls = %d/%d, want 2/2", identityCalls, nowCalls)
	}
	wantRemoteCalls := rehearsalCollectionCount * (2*len(spec.Sources) + 1)
	if transport.callCount() != wantRemoteCalls {
		t.Fatalf("remote calls = %d, want %d", transport.callCount(), wantRemoteCalls)
	}
	info, err := os.Stat(options.ReceiptOutput)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %v, err %v", info, err)
	}
	var receipt rehearsalReceipt
	payload, digest, err := readPrivateCanonicalJSON(options.ReceiptOutput, "rehearsal receipt", maxRehearsalMetadataBytes, uint32(os.Geteuid()), &receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if err := validateRehearsalReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SourceCount != 18 || receipt.SourceCount != len(spec.Sources) || receipt.CollectionCount != 2 ||
		len(receipt.Collections) != 2 || receipt.Collections[0].SHA256 != receipt.Collections[1].SHA256 ||
		receipt.StartedAt != started || receipt.CompletedAt != completed || receipt.Executable != fixtureExecutableIdentity ||
		!receipt.WritersQuiesced || receipt.ConfirmationClass != "REHEARSAL-WRITERS-QUIESCED" {
		t.Fatalf("incomplete rehearsal receipt: %#v", receipt)
	}
	if report.RehearsalReceiptSHA256 != digest || report.CompletedAt != completed || report.Sources != len(spec.Sources) {
		t.Fatalf("report does not bind receipt: %#v", report)
	}
	for _, secret := range append(sourceAndDestinationStrings(spec), spec.OAuthEvidence.SourcePath) {
		if secret != "" && strings.Contains(string(payload), secret) {
			t.Fatalf("receipt exposed private input %q", secret)
		}
	}
}

func TestCheckLocalAdmissionFailuresMakeNoRemoteCallOrReceipt(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*CheckOptions)
	}{
		{name: "missing-quiescence", mutate: func(options *CheckOptions) { options.WritersQuiesced = false }},
		{name: "wrong-confirmation", mutate: func(options *CheckOptions) { options.Confirm = "wrong" }},
		{name: "unsafe-id", mutate: func(options *CheckOptions) { options.RehearsalID = "../unsafe" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := validSpec(t)
			parent := privateTemp(t)
			specPath := writeSpec(t, parent, spec)
			transport := newFixtureTransport(t, spec)
			engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now, identity: fixtureIdentityProvider}
			options := testCheckOptions(t, parent, specPath, "admission-rehearsal-0001")
			test.mutate(&options)
			if _, err := engine.check(context.Background(), options); err == nil {
				t.Fatal("unsafe rehearsal admission was accepted")
			}
			if transport.callCount() != 0 {
				t.Fatal("unsafe rehearsal admission contacted Windows")
			}
			if _, err := os.Lstat(options.ReceiptOutput); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe rehearsal admission published a receipt")
			}
		})
	}
}

func TestCheckReceiptCollisionAndIdentityDriftFailClosed(t *testing.T) {
	t.Run("collision-before-remote", func(t *testing.T) {
		spec := validSpec(t)
		parent := privateTemp(t)
		specPath := writeSpec(t, parent, spec)
		transport := newFixtureTransport(t, spec)
		options := testCheckOptions(t, parent, specPath, "collision-rehearsal-0001")
		if err := os.WriteFile(options.ReceiptOutput, []byte("existing\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now, identity: fixtureIdentityProvider}
		if _, err := engine.check(context.Background(), options); err == nil || transport.callCount() != 0 {
			t.Fatalf("receipt collision did not fail before remote contact: %v / %d", err, transport.callCount())
		}
	})

	t.Run("identity-drift-after-collections", func(t *testing.T) {
		spec := validSpec(t)
		parent := privateTemp(t)
		specPath := writeSpec(t, parent, spec)
		transport := newFixtureTransport(t, spec)
		calls := 0
		engine := &captureEngine{
			remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now,
			identity: func() (executableIdentity, error) {
				calls++
				identity := fixtureExecutableIdentity
				if calls == 2 {
					identity.SHA256 = strings.Repeat("f", 64)
				}
				return identity, nil
			},
		}
		options := testCheckOptions(t, parent, specPath, "identity-rehearsal-0001")
		if _, err := engine.check(context.Background(), options); err == nil || !strings.Contains(err.Error(), "identity drifted") {
			t.Fatalf("identity drift was accepted: %v", err)
		}
		if _, err := os.Lstat(options.ReceiptOutput); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("identity drift published a receipt")
		}
	})
}

type deadlineTransport struct {
	calls atomic.Int64
}

func (transport *deadlineTransport) run(ctx context.Context, _ string, _ []string, _ io.Writer, _ int64) (stderrSummary, error) {
	transport.calls.Add(1)
	<-ctx.Done()
	return stderrSummary{}, ctx.Err()
}

type oauthMutationTransport struct {
	base        remoteTransport
	oauthCalls  int
	mutate      func() error
	mutationErr error
}

func (transport *oauthMutationTransport) run(ctx context.Context, action string, arguments []string, output io.Writer, maximum int64) (stderrSummary, error) {
	summary, err := transport.base.run(ctx, action, arguments, output, maximum)
	if err == nil && action == "oauth" {
		transport.oauthCalls++
		if transport.oauthCalls == rehearsalCollectionCount && transport.mutate != nil {
			transport.mutationErr = transport.mutate()
		}
	}
	return summary, err
}

func TestCheckHasRunLevelTimeoutWithoutConstrainingCaptureModes(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	transport := &deadlineTransport{}
	engine := &captureEngine{
		remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now,
		identity: fixtureIdentityProvider, checkRunTimeout: 20 * time.Millisecond,
	}
	options := testCheckOptions(t, parent, specPath, "timeout-rehearsal-0001")
	started := time.Now()
	_, err := engine.check(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "run-level time limit") || time.Since(started) > 2*time.Second {
		t.Fatalf("rehearsal run-level timeout failed: %v", err)
	}
	if transport.calls.Load() == 0 {
		t.Fatal("timeout fixture was not exercised")
	}
	if _, err := os.Lstat(options.ReceiptOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("timed-out rehearsal published a receipt")
	}
	if engine.rehearsalTimeout() != 20*time.Millisecond || (&captureEngine{}).rehearsalTimeout() != 24*time.Hour {
		t.Fatal("rehearsal timeout contract changed")
	}
}

func TestCheckRejectsReceiptParentNamespaceDriftWithoutPublishing(t *testing.T) {
	spec := validSpec(t)
	container := privateTemp(t)
	specPath := writeSpec(t, container, spec)
	receiptParent := filepath.Join(container, "receipts")
	rotatedParent := filepath.Join(container, "receipts-rotated")
	if err := os.Mkdir(receiptParent, 0o700); err != nil {
		t.Fatal(err)
	}
	transport := &oauthMutationTransport{
		base: newFixtureTransport(t, spec),
		mutate: func() error {
			if err := os.Rename(receiptParent, rotatedParent); err != nil {
				return err
			}
			return os.Mkdir(receiptParent, 0o700)
		},
	}
	engine := &captureEngine{
		remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now, identity: fixtureIdentityProvider,
	}
	options := testCheckOptions(t, receiptParent, specPath, "namespace-drift-rehearsal-0001")
	_, err := engine.check(context.Background(), options)
	if transport.mutationErr != nil {
		t.Fatal(transport.mutationErr)
	}
	if err == nil || !strings.Contains(err.Error(), "output parent path drifted") {
		t.Fatalf("receipt parent namespace drift was accepted: %v", err)
	}
	for _, candidate := range []string{options.ReceiptOutput, filepath.Join(rotatedParent, filepath.Base(options.ReceiptOutput))} {
		if _, statErr := os.Lstat(candidate); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("receipt parent namespace drift published %s", candidate)
		}
	}
}

func TestSealRehearsalGateValidatesThreeReceiptsLocallyAndAllowsCrossRunVariation(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	base := time.Unix(1_900_100_000, 0).UTC()
	paths := make([]string, 0, 3)
	transports := make([]*fixtureTransport, 0, 3)
	for index := 0; index < 3; index++ {
		transport := newFixtureTransport(t, spec)
		if index == 2 {
			transport.inventoryMismatch = true
		}
		transports = append(transports, transport)
		started := base.Add(time.Duration(index*10) * time.Minute)
		completed := started.Add(5 * time.Minute)
		nowCalls := 0
		engine := &captureEngine{
			remote: transport, expectedUID: uint32(os.Geteuid()), identity: fixtureIdentityProvider,
			now: func() time.Time {
				nowCalls++
				if nowCalls == 1 {
					return started
				}
				return completed
			},
		}
		options := testCheckOptions(t, parent, specPath, "seal-rehearsal-000"+string(rune('1'+index)))
		if _, err := engine.check(context.Background(), options); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, options.ReceiptOutput)
	}
	callsBeforeSeal := 0
	for _, transport := range transports {
		callsBeforeSeal += transport.callCount()
	}
	gatePath := filepath.Join(parent, "rehearsal-gate.json")
	report, err := sealRehearsalGate(SealRehearsalGateOptions{SpecPath: specPath, ReceiptPaths: paths, GateOutput: gatePath}, uint32(os.Geteuid()), fixtureIdentityProvider, func() time.Time { return base.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	callsAfterSeal := 0
	for _, transport := range transports {
		callsAfterSeal += transport.callCount()
	}
	if callsAfterSeal != callsBeforeSeal {
		t.Fatal("strictly local rehearsal sealing made a remote call")
	}
	if report.ReceiptCount != 3 || report.SourceCount != 18 || report.CrossRunState != "varied" || !sha256Pattern.MatchString(report.GateSHA256) {
		t.Fatalf("unexpected gate report: %#v", report)
	}
	gate, err := readVerifiedRehearsalGate(gatePath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(gate.payload)
	if gate.digest != report.GateSHA256 || gate.value.CrossRunState != "varied" || len(gate.value.Receipts) != 3 {
		t.Fatalf("gate did not bind three receipts: %#v", gate.value)
	}
	clear(gate.payload)
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	selfContained, err := readVerifiedRehearsalGate(gatePath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("gate depended on external receipt files: %v", err)
	}
	clear(selfContained.payload)
	if _, err := sealRehearsalGate(SealRehearsalGateOptions{SpecPath: specPath, ReceiptPaths: paths, GateOutput: gatePath}, uint32(os.Geteuid()), fixtureIdentityProvider, time.Now); err == nil {
		t.Fatal("gate exact-content retry unexpectedly converged instead of failing closed")
	}
}

func TestSealRejectsGateOutputParentNamespaceDrift(t *testing.T) {
	spec := validSpec(t)
	container := privateTemp(t)
	specPath := writeSpec(t, container, spec)
	receipts := createStableRehearsalReceipts(t, container, specPath, spec)
	gateParent := filepath.Join(container, "gates")
	rotatedParent := filepath.Join(container, "gates-rotated")
	if err := os.Mkdir(gateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	var mutationErr error
	identity := func() (executableIdentity, error) {
		calls++
		if calls == 2 {
			if err := os.Rename(gateParent, rotatedParent); err != nil {
				mutationErr = err
			} else {
				mutationErr = os.Mkdir(gateParent, 0o700)
			}
		}
		return fixtureExecutableIdentity, nil
	}
	gatePath := filepath.Join(gateParent, "three-of-three.gate.json")
	_, err := sealRehearsalGate(SealRehearsalGateOptions{
		SpecPath: specPath, ReceiptPaths: receipts, GateOutput: gatePath,
	}, uint32(os.Geteuid()), identity, func() time.Time { return time.Unix(1_900_200_000, 0).UTC().Add(time.Hour) })
	if mutationErr != nil {
		t.Fatal(mutationErr)
	}
	if err == nil || !strings.Contains(err.Error(), "output parent path drifted") {
		t.Fatalf("gate output parent namespace drift was accepted: %v", err)
	}
	for _, candidate := range []string{gatePath, filepath.Join(rotatedParent, filepath.Base(gatePath))} {
		if _, statErr := os.Lstat(candidate); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("gate parent namespace drift published %s", candidate)
		}
	}
}

func TestSealRejectsNonCanonicalDuplicateAndInvalidReceiptEvidence(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	paths := createStableRehearsalReceipts(t, parent, specPath, spec)

	t.Run("current-executable-mismatch", func(t *testing.T) {
		mismatch := func() (executableIdentity, error) {
			identity := fixtureExecutableIdentity
			identity.SHA256 = strings.Repeat("f", 64)
			return identity, nil
		}
		output := filepath.Join(parent, "identity-mismatch-gate.json")
		if _, err := sealRehearsalGate(SealRehearsalGateOptions{SpecPath: specPath, ReceiptPaths: paths, GateOutput: output}, uint32(os.Geteuid()), mismatch, time.Now); err == nil || !strings.Contains(err.Error(), "current private spec and executable") {
			t.Fatalf("current executable mismatch was accepted: %v", err)
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("identity mismatch published a gate")
		}
	})

	t.Run("current-spec-mismatch", func(t *testing.T) {
		other := spec
		other.Limits.MaxTotalFiles++
		otherPath := writeSpecNamed(t, parent, "other-capture-spec.json", other)
		output := filepath.Join(parent, "spec-mismatch-gate.json")
		if _, err := sealRehearsalGate(SealRehearsalGateOptions{SpecPath: otherPath, ReceiptPaths: paths, GateOutput: output}, uint32(os.Geteuid()), fixtureIdentityProvider, time.Now); err == nil || !strings.Contains(err.Error(), "current private spec and executable") {
			t.Fatalf("current spec mismatch was accepted: %v", err)
		}
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("spec mismatch published a gate")
		}
	})

	t.Run("noncanonical", func(t *testing.T) {
		payload, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(parent, "noncanonical-receipt.json")
		if err := os.WriteFile(bad, append(payload, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		candidate := append([]string(nil), paths...)
		candidate[0] = bad
		if _, err := sealRehearsalGate(SealRehearsalGateOptions{SpecPath: specPath, ReceiptPaths: candidate, GateOutput: filepath.Join(parent, "noncanonical-gate.json")}, uint32(os.Geteuid()), fixtureIdentityProvider, time.Now); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("noncanonical receipt was accepted: %v", err)
		}
	})

	t.Run("duplicate-file-digest", func(t *testing.T) {
		copyPath := filepath.Join(parent, "duplicate-receipt.json")
		payload, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(copyPath, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sealRehearsalGate(SealRehearsalGateOptions{
			SpecPath: specPath, ReceiptPaths: []string{paths[0], copyPath, paths[2]}, GateOutput: filepath.Join(parent, "duplicate-gate.json"),
		}, uint32(os.Geteuid()), fixtureIdentityProvider, time.Now); err == nil || !strings.Contains(err.Error(), "unique") {
			t.Fatalf("duplicate receipt was accepted: %v", err)
		}
	})

	t.Run("recomputed-aggregate", func(t *testing.T) {
		var receipt rehearsalReceipt
		payload, _, err := readPrivateCanonicalJSON(paths[0], "rehearsal receipt", maxRehearsalMetadataBytes, uint32(os.Geteuid()), &receipt)
		if err != nil {
			t.Fatal(err)
		}
		clear(payload)
		for index := range receipt.Collections {
			receipt.Collections[index].Evidence.Aggregate.Bytes++
			record, err := makeRehearsalCollectionRecord(receipt.Collections[index].Evidence)
			if err != nil {
				t.Fatal(err)
			}
			receipt.Collections[index] = record
		}
		bad := filepath.Join(parent, "bad-aggregate-receipt.json")
		writeCanonicalTestJSON(t, bad, receipt)
		candidate := append([]string(nil), paths...)
		candidate[0] = bad
		if _, err := sealRehearsalGate(SealRehearsalGateOptions{SpecPath: specPath, ReceiptPaths: candidate, GateOutput: filepath.Join(parent, "aggregate-gate.json")}, uint32(os.Geteuid()), fixtureIdentityProvider, time.Now); err == nil || !strings.Contains(err.Error(), "evidence") {
			t.Fatalf("invalid aggregate was accepted: %v", err)
		}
	})
}

func TestCaptureRejectsGateBeforeRemoteOrDestinationMutationAndBindsExactGate(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	gatePath := writeTestRehearsalGate(t, specPath)
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: func() time.Time { return time.Unix(1_900_300_000, 0).UTC() }, identity: fixtureIdentityProvider}
	id := "gate-bound-capture-0001"
	destination := filepath.Join(parent, id)

	var changed rehearsalGate
	payload, _, err := readPrivateCanonicalJSON(gatePath, "rehearsal gate", maxRehearsalMetadataBytes, uint32(os.Geteuid()), &changed)
	if err != nil {
		t.Fatal(err)
	}
	clear(payload)
	changed.Executable.SHA256 = strings.Repeat("f", 64)
	badGate := filepath.Join(parent, "wrong-executable-gate.json")
	writeCanonicalTestJSON(t, badGate, changed)
	options := CaptureOptions{SpecPath: specPath, RehearsalGate: badGate, Destination: destination, CaptureID: id, Confirm: finalConfirmationPrefix + id, WindowsFrozen: true}
	if _, err := engine.capture(context.Background(), options); err == nil || transport.callCount() != 0 {
		t.Fatalf("mismatched gate reached remote transport: %v / %d", err, transport.callCount())
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mismatched gate mutated capture destination")
	}
	partials, err := filepath.Glob(filepath.Join(parent, "."+id+".partial-*"))
	if err != nil || len(partials) != 0 {
		t.Fatal("mismatched gate created a partial capture")
	}

	options.RehearsalGate = gatePath
	report, err := engine.capture(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	storedGatePayload, err := os.ReadFile(filepath.Join(destination, "rehearsal-gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	originalGatePayload, err := os.ReadFile(gatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedGatePayload) != string(originalGatePayload) || report.RehearsalGateSHA256 != sha256Bytes(originalGatePayload) {
		t.Fatal("capture did not preserve and bind the exact canonical gate")
	}
	var manifest finalManifest
	if _, err := readStoredCanonicalJSONAtDigestForTest(destination, "capture-manifest.json", &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 2 || manifest.RehearsalGateSHA256 != report.RehearsalGateSHA256 {
		t.Fatalf("manifest v2 omitted gate binding: %#v", manifest)
	}

	alternate := changed
	alternate.Executable = fixtureExecutableIdentity
	alternate.SealedAt = alternate.SealedAt.Add(time.Second)
	alternateGate := filepath.Join(parent, "alternate-gate.json")
	writeCanonicalTestJSON(t, alternateGate, alternate)
	calls := transport.callCount()
	options.RehearsalGate = alternateGate
	if _, err := engine.capture(context.Background(), options); err == nil || !strings.Contains(err.Error(), "different rehearsal gate") || transport.callCount() != calls {
		t.Fatalf("existing capture accepted a different gate: %v / %d", err, transport.callCount())
	}
}

func TestGateValidationRecomputesEmbeddedReceiptsAndCrossRunState(t *testing.T) {
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	gatePath := writeTestRehearsalGate(t, specPath)
	var gate rehearsalGate
	payload, _, err := readPrivateCanonicalJSON(gatePath, "rehearsal gate", maxRehearsalMetadataBytes, uint32(os.Geteuid()), &gate)
	if err != nil {
		t.Fatal(err)
	}
	clear(payload)

	wrongState := gate
	wrongState.CrossRunState = "varied"
	if err := validateRehearsalGate(wrongState); err == nil || !strings.Contains(err.Error(), "cross-run") {
		t.Fatalf("incorrect cross-run fact was accepted: %v", err)
	}

	tampered := gate
	tampered.Receipts = append([]rehearsalReceiptBinding(nil), gate.Receipts...)
	tampered.Receipts[0].Receipt.Collections = append([]rehearsalCollectionRecord(nil), gate.Receipts[0].Receipt.Collections...)
	tampered.Receipts[0].Receipt.Collections[0].Evidence.Aggregate.Bytes++
	receiptPayload, err := marshalPrivateJSON(tampered.Receipts[0].Receipt)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Receipts[0].ReceiptSHA256 = sha256Bytes(receiptPayload)
	if err := validateRehearsalGate(tampered); err == nil {
		t.Fatal("semantically invalid embedded receipt was accepted after digest recomputation")
	}
}

func TestCompletedCaptureAndFinalDeltaRejectStoredGateTamperLocally(t *testing.T) {
	spec, specPath, destination, id := completedCaptureFixture(t)
	gatePath := filepath.Join(destination, "rehearsal-gate.json")
	payload, err := os.ReadFile(gatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gatePath, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCompletedCapture(CompletedCaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id}); err == nil {
		t.Fatal("completed capture accepted noncanonical stored gate")
	}
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	_, err = engine.verifyFinalDelta(context.Background(), FinalDeltaOptions{
		SpecPath: specPath, Destination: destination, CaptureID: id,
		Confirm: finalDeltaConfirmationPrefix + id, WindowsFrozen: true,
	})
	if err == nil || transport.callCount() != 0 {
		t.Fatalf("stored gate tamper reached Windows final delta: %v / %d", err, transport.callCount())
	}
}

func createStableRehearsalReceipts(t *testing.T, parent, specPath string, spec Spec) []string {
	t.Helper()
	base := time.Unix(1_900_200_000, 0).UTC()
	paths := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		started := base.Add(time.Duration(index*10) * time.Minute)
		completed := started.Add(5 * time.Minute)
		calls := 0
		engine := &captureEngine{
			remote: newFixtureTransport(t, spec), expectedUID: uint32(os.Geteuid()), identity: fixtureIdentityProvider,
			now: func() time.Time {
				calls++
				if calls == 1 {
					return started
				}
				return completed
			},
		}
		options := testCheckOptions(t, parent, specPath, "stable-rehearsal-000"+string(rune('1'+index)))
		if _, err := engine.check(context.Background(), options); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, options.ReceiptOutput)
	}
	return paths
}

func writeCanonicalTestJSON(t *testing.T, filename string, value any) {
	t.Helper()
	payload, err := marshalPrivateJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readStoredCanonicalJSONAtDigestForTest(root, relative string, destination any) (string, error) {
	rootFD, _, err := openPrivateRoot(root, uint32(os.Geteuid()))
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)
	return readStoredCanonicalJSONAtDigest(rootFD, relative, maxRehearsalMetadataBytes, uint32(os.Geteuid()), destination)
}

func TestRehearsalReceiptJSONRejectsUnknownAndDuplicateFields(t *testing.T) {
	var target rehearsalReceipt
	for name, payload := range map[string][]byte{
		"unknown":   []byte(`{"schema_version":1,"unknown":true}`),
		"duplicate": []byte(`{"schema_version":1,"schema_version":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			parent := privateTemp(t)
			path := filepath.Join(parent, name+".json")
			if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := readPrivateCanonicalJSON(path, "rehearsal receipt", maxRehearsalMetadataBytes, uint32(os.Geteuid()), &target)
			if err == nil {
				t.Fatal("non-strict receipt JSON was accepted")
			}
		})
	}
}
