//go:build linux

package wincapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFinalDeltaRevalidatesThenMatchesAndReplays(t *testing.T) {
	spec, specPath, destination, id := completedCaptureFixture(t)
	transport := newFixtureTransport(t, spec)
	verifiedAt := time.Unix(1_900_000_000, 0).UTC()
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: func() time.Time { return verifiedAt }}
	options := FinalDeltaOptions{
		SpecPath: specPath, Destination: destination, CaptureID: id,
		Confirm: finalDeltaConfirmationPrefix + id, WindowsFrozen: true,
	}
	report, err := engine.verifyFinalDelta(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := 2 * (2*len(spec.Sources) + 1)
	if transport.callCount() != wantCalls {
		t.Fatalf("final-delta remote calls = %d, want %d", transport.callCount(), wantCalls)
	}
	if transport.tarContacted() {
		t.Fatal("final-delta requested a Windows tar stream")
	}
	if report.SchemaVersion != 1 || report.Status != "complete-frozen-final-delta" || report.CaptureID != id ||
		report.CaptureManifestSHA256 == "" || report.CaptureCompletedAt == nil || !report.CaptureCompletedAt.Equal(time.Unix(1_800_000_000, 0).UTC()) || report.CompletedAt != verifiedAt {
		t.Fatalf("unexpected final-delta report: %#v", report)
	}
	firstJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range append(sourceAndDestinationStrings(spec), spec.OAuthEvidence.SourcePath) {
		if secret != "" && strings.Contains(string(firstJSON), secret) {
			t.Fatalf("redacted final-delta report exposed private input %q", secret)
		}
	}
	for _, required := range []string{"\"schema_version\":1", "\"capture_manifest_sha256\"", "\"capture_completed_at\"", "\"oauth_evidence\""} {
		if !strings.Contains(string(firstJSON), required) {
			t.Fatalf("final-delta report schema omitted %s: %s", required, firstJSON)
		}
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(firstJSON, &schema); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{"schema_version", "status", "capture_id", "spec_sha256", "capture_manifest_sha256", "capture_completed_at", "sources", "summary", "oauth_evidence", "completed_at"}
	if len(schema) != len(wantFields) {
		t.Fatalf("final-delta report field count = %d: %s", len(schema), firstJSON)
	}
	for _, field := range wantFields {
		if _, ok := schema[field]; !ok {
			t.Fatalf("final-delta report omitted %q: %s", field, firstJSON)
		}
	}
	replayed, err := engine.verifyFinalDelta(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(replayed)
	if err != nil || string(secondJSON) != string(firstJSON) {
		t.Fatalf("final-delta replay changed its anonymous binding: %s / %s / %v", firstJSON, secondJSON, err)
	}
	if transport.callCount() != 2*wantCalls {
		t.Fatalf("final-delta replay did not perform a new two-pass read: %d", transport.callCount())
	}
	if transport.tarContacted() {
		t.Fatal("final-delta replay requested a Windows tar stream")
	}
}

func TestFinalDeltaLocalIntegrityFailuresNeverContactWindows(t *testing.T) {
	t.Run("stored-content", func(t *testing.T) {
		spec, specPath, destination, id := completedCaptureFixture(t)
		if err := os.WriteFile(filepath.Join(destination, filepath.FromSlash(spec.Sources[0].Destination)), []byte("tampered"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertFinalDeltaFailsBeforeTransport(t, spec, specPath, destination, id)
	})
	t.Run("strict-manifest-schema", func(t *testing.T) {
		spec, specPath, destination, id := completedCaptureFixture(t)
		manifestPath := filepath.Join(destination, "capture-manifest.json")
		payload, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		payload = append([]byte(strings.TrimSuffix(strings.TrimSpace(string(payload)), "}")), []byte(",\"unexpected\":true}\n")...)
		if err := os.WriteFile(manifestPath, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		assertFinalDeltaFailsBeforeTransport(t, spec, specPath, destination, id)
	})
	t.Run("changed-local-input", func(t *testing.T) {
		spec, specPath, destination, id := completedCaptureFixture(t)
		if err := os.WriteFile(spec.LocalFiles[0].SourcePath, []byte("changed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertFinalDeltaFailsBeforeTransport(t, spec, specPath, destination, id)
	})
	t.Run("unsafe-capture-root", func(t *testing.T) {
		spec, specPath, destination, id := completedCaptureFixture(t)
		if err := os.Chmod(destination, 0o755); err != nil {
			t.Fatal(err)
		}
		assertFinalDeltaFailsBeforeTransport(t, spec, specPath, destination, id)
	})
	t.Run("missing-confirmation", func(t *testing.T) {
		spec, specPath, destination, id := completedCaptureFixture(t)
		transport := newFixtureTransport(t, spec)
		engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
		_, err := engine.verifyFinalDelta(context.Background(), FinalDeltaOptions{SpecPath: specPath, Destination: destination, CaptureID: id, WindowsFrozen: true})
		if err == nil || transport.callCount() != 0 {
			t.Fatalf("missing confirmation reached Windows: %v, calls=%d", err, transport.callCount())
		}
	})
}

func TestFinalDeltaFailsClosedOnStableMismatchAndInterPassDrift(t *testing.T) {
	for _, test := range []struct {
		name                 string
		stableMismatch       bool
		driftAfterCollection bool
		want                 string
	}{
		{name: "stable-mismatch", stableMismatch: true, want: "does not match"},
		{name: "inter-pass-drift", driftAfterCollection: true, want: "not stable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec, specPath, destination, id := completedCaptureFixture(t)
			transport := newFixtureTransport(t, spec)
			transport.inventoryMismatch = test.stableMismatch
			transport.driftAfterCollection = test.driftAfterCollection
			engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
			_, err := engine.verifyFinalDelta(context.Background(), FinalDeltaOptions{
				SpecPath: specPath, Destination: destination, CaptureID: id,
				Confirm: finalDeltaConfirmationPrefix + id, WindowsFrozen: true,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe final delta was accepted: %v", err)
			}
		})
	}
}

func TestFinalDeltaManifestComparisonBindsEveryEvidenceClass(t *testing.T) {
	spec := validSpec(t)
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	inventories, exclusions, oauth, err := engine.collect(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceSources(inventories, exclusions)
	manifest := finalManifest{
		Before: append([]sourceEvidence(nil), evidence...), After: append([]sourceEvidence(nil), evidence...),
		OAuthBefore: oauth, OAuthAfter: oauth,
	}
	if err := compareFinalDeltaToManifest(inventories, exclusions, oauth, manifest); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*finalManifest)
	}{
		{name: "before-source", mutate: func(candidate *finalManifest) { candidate.Before[0].EvidenceSHA256 = strings.Repeat("f", 64) }},
		{name: "after-source", mutate: func(candidate *finalManifest) { candidate.After[0].ArchiveSHA256 = strings.Repeat("f", 64) }},
		{name: "approved-exclusion", mutate: func(candidate *finalManifest) { candidate.Before[0].ExclusionSHA = strings.Repeat("f", 64) }},
		{name: "oauth", mutate: func(candidate *finalManifest) { candidate.OAuthAfter.Bytes++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := manifest
			candidate.Before = append([]sourceEvidence(nil), manifest.Before...)
			candidate.After = append([]sourceEvidence(nil), manifest.After...)
			test.mutate(&candidate)
			if err := compareFinalDeltaToManifest(inventories, exclusions, oauth, candidate); err == nil {
				t.Fatal("manifest evidence mutation was accepted")
			}
		})
	}
}

func TestVerifyCompletedCaptureReturnsExactStableManifestBinding(t *testing.T) {
	_, specPath, destination, id := completedCaptureFixture(t)
	payload, err := os.ReadFile(filepath.Join(destination, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(payload)
	binding, _, manifest, err := verifyCompletedCapture(CompletedCaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if binding.SchemaVersion != 1 || binding.CaptureID != id || binding.SpecSHA256 != manifest.SpecSHA256 ||
		binding.CaptureManifestSHA256 != hex.EncodeToString(wantDigest[:]) || binding.CompletedAt != manifest.CompletedAt || binding.Aggregate != manifest.Aggregate {
		t.Fatalf("completed capture binding is incomplete: %#v", binding)
	}
	replayed, _, _, err := verifyCompletedCapture(CompletedCaptureOptions{SpecPath: specPath, Destination: destination, CaptureID: id}, uint32(os.Geteuid()))
	if err != nil || replayed != binding {
		t.Fatalf("completed capture local replay changed its binding: %#v / %#v / %v", binding, replayed, err)
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{"schema_version", "capture_id", "spec_sha256", "capture_manifest_sha256", "completed_at", "aggregate"}
	if len(schema) != len(wantFields) {
		t.Fatalf("completed capture binding field count = %d: %s", len(schema), encoded)
	}
	for _, field := range wantFields {
		if !strings.Contains(string(encoded), "\""+field+"\"") {
			t.Fatalf("completed capture binding schema omitted %q: %s", field, encoded)
		}
	}
}

func completedCaptureFixture(t *testing.T) (Spec, string, string, string) {
	t.Helper()
	spec := validSpec(t)
	parent := privateTemp(t)
	specPath := writeSpec(t, parent, spec)
	// writeSpec fills this private input into its marshalled copy; load the
	// authoritative spec so subsequent local-input checks use the same path.
	loaded, err := loadSpec(specPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	spec = loaded.value
	id := "frozen-final-delta-0001"
	destination := filepath.Join(parent, id)
	engine := &captureEngine{remote: newFixtureTransport(t, spec), expectedUID: uint32(os.Geteuid()), now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}
	if _, err := engine.capture(context.Background(), CaptureOptions{
		SpecPath: specPath, Destination: destination, CaptureID: id,
		Confirm: finalConfirmationPrefix + id, WindowsFrozen: true,
	}); err != nil {
		t.Fatal(err)
	}
	return spec, specPath, destination, id
}

func assertFinalDeltaFailsBeforeTransport(t *testing.T, spec Spec, specPath, destination, id string) {
	t.Helper()
	transport := newFixtureTransport(t, spec)
	engine := &captureEngine{remote: transport, expectedUID: uint32(os.Geteuid()), now: time.Now}
	_, err := engine.verifyFinalDelta(context.Background(), FinalDeltaOptions{
		SpecPath: specPath, Destination: destination, CaptureID: id,
		Confirm: finalDeltaConfirmationPrefix + id, WindowsFrozen: true,
	})
	if err == nil || transport.callCount() != 0 {
		t.Fatalf("local integrity failure reached Windows: %v, calls=%d", err, transport.callCount())
	}
}

func sourceAndDestinationStrings(spec Spec) []string {
	result := make([]string, 0, len(spec.Sources)*2+len(spec.LocalFiles)*2)
	for _, source := range spec.Sources {
		result = append(result, source.SourcePath, source.Destination)
	}
	for _, input := range spec.LocalFiles {
		result = append(result, input.SourcePath, input.Destination)
	}
	return result
}
