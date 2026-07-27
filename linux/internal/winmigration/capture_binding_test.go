//go:build linux

package winmigration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/wincapture"
)

func TestMigrationVerifiesCompletedCaptureBeforeSnapshotDataRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production capture verification is root-only")
	}
	root := filepath.Join(t.TempDir(), "capture-20260728")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("frozen capture verifier stopped planning")
	called := false
	options := captureBindingOptions(root)
	options.verifyCompletedCapture = func(got wincapture.CompletedCaptureOptions) (wincapture.CompletedCaptureBinding, error) {
		called = true
		if got.SpecPath != options.CaptureSpec || got.Destination != root || got.CaptureID != filepath.Base(root) {
			t.Fatalf("unexpected completed-capture request: %+v", got)
		}
		return wincapture.CompletedCaptureBinding{}, sentinel
	}
	_, err := Migrate(context.Background(), options)
	if !called || !errors.Is(err, sentinel) {
		t.Fatalf("capture verifier did not fail before missing snapshot data was read: called=%v err=%v", called, err)
	}
}

func TestMigrationRequiresExactPrivateRootSnapshotMetadata(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture requires root")
	}
	for name, mutate := range map[string]func(string) error{
		"mode":  func(root string) error { return os.Chmod(root, 0o750) },
		"owner": func(root string) error { return os.Chown(root, 65534, 65534) },
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "capture-20260728")
			if err := os.Mkdir(root, 0o700); err != nil || mutate(root) != nil {
				t.Fatal("prepare unsafe capture root")
			}
			called := false
			options := captureBindingOptions(root)
			options.verifyCompletedCapture = func(wincapture.CompletedCaptureOptions) (wincapture.CompletedCaptureBinding, error) {
				called = true
				return validCaptureBinding(root), nil
			}
			if _, err := Migrate(context.Background(), options); err == nil || !strings.Contains(err.Error(), "exact root:root 0700") || called {
				t.Fatalf("unsafe snapshot root was accepted or read: called=%v err=%v", called, err)
			}
		})
	}
}

func TestMigrationCaptureBindingIsStrict(t *testing.T) {
	root := "/private/workagent/capture-20260728"
	options := captureBindingOptions(root)
	valid := validCaptureBinding(root)
	got, err := verifyMigrationCapture(options, func(request wincapture.CompletedCaptureOptions) (wincapture.CompletedCaptureBinding, error) {
		if request.CaptureID != "capture-20260728" || request.SpecPath != options.CaptureSpec || request.Destination != root {
			t.Fatalf("unexpected verification request: %+v", request)
		}
		return valid, nil
	})
	if err != nil || got != valid {
		t.Fatalf("valid completed capture binding rejected: got=%+v err=%v", got, err)
	}

	invalid := []wincapture.CompletedCaptureBinding{
		{},
		func() wincapture.CompletedCaptureBinding { value := valid; value.SchemaVersion = 2; return value }(),
		func() wincapture.CompletedCaptureBinding {
			value := valid
			value.CaptureID = "capture-20260729"
			return value
		}(),
		func() wincapture.CompletedCaptureBinding {
			value := valid
			value.SpecSHA256 = strings.Repeat("A", 64)
			return value
		}(),
		func() wincapture.CompletedCaptureBinding {
			value := valid
			value.CaptureManifestSHA256 = ""
			return value
		}(),
		func() wincapture.CompletedCaptureBinding {
			value := valid
			value.CompletedAt = value.CompletedAt.In(time.FixedZone("offset", 3600))
			return value
		}(),
	}
	for index, binding := range invalid {
		if _, err := verifyMigrationCapture(options, func(wincapture.CompletedCaptureOptions) (wincapture.CompletedCaptureBinding, error) {
			return binding, nil
		}); err == nil {
			t.Fatalf("invalid completed capture binding %d was accepted: %+v", index, binding)
		}
	}
}

func TestCaptureBindingFieldsAreCanonicalSourceFingerprintInputs(t *testing.T) {
	report := validBoundSourceReport(t)
	base := report.SourceFingerprint
	mutations := []func(*Report){
		func(value *Report) { value.CaptureID = "capture-20260729" },
		func(value *Report) { value.CaptureSpecSHA256 = strings.Repeat("c", 64) },
		func(value *Report) { value.CaptureManifestSHA256 = strings.Repeat("d", 64) },
		func(value *Report) { value.CaptureCompletedAt = value.CaptureCompletedAt.Add(time.Second) },
	}
	for index, mutate := range mutations {
		changed := report
		mutate(&changed)
		fingerprint, err := sourceFingerprint(changed)
		if err != nil || fingerprint == base {
			t.Fatalf("capture binding mutation %d was not fingerprinted: fingerprint=%q err=%v", index, fingerprint, err)
		}
	}
}

func TestReportV3RejectsLegacyOrUnboundSourceEvidence(t *testing.T) {
	report := validBoundSourceReport(t)
	if err := ValidateReportSourceFingerprint(report); err != nil {
		t.Fatalf("valid bound report rejected: %v", err)
	}

	legacy := report
	legacy.SchemaVersion = 2
	legacy.CaptureID = ""
	legacy.CaptureSpecSHA256 = ""
	legacy.CaptureManifestSHA256 = ""
	legacy.CaptureCompletedAt = time.Time{}
	legacy.SourceFingerprint, _ = sourceFingerprint(legacy)
	if err := ValidateReportSourceFingerprint(legacy); err == nil {
		t.Fatal("legacy unbound report was accepted")
	}

	detached := report
	detached.CaptureSpecSHA256 = ""
	detached.SourceFingerprint, _ = sourceFingerprint(detached)
	if err := ValidateReportSourceFingerprint(detached); err == nil {
		t.Fatal("schema-v3 report detached from its capture spec was accepted")
	}

	tampered := report
	tampered.CaptureID = "capture-20260729"
	if err := ValidateReportSourceFingerprint(tampered); err == nil {
		t.Fatal("capture binding changed without recomputing the source fingerprint was accepted")
	}
}

func TestReportV3SerializesExplicitCaptureFieldNames(t *testing.T) {
	report := validBoundSourceReport(t)
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(payload)
	for _, field := range []string{"\"capture_id\"", "\"capture_spec_sha256\"", "\"capture_manifest_sha256\"", "\"capture_completed_at\""} {
		if !strings.Contains(encoded, field) {
			t.Fatalf("report omits explicit capture field %s: %s", field, encoded)
		}
	}
	for _, ambiguous := range []string{"\"spec_sha256\"", "\"manifest_sha256\"", "\"completed_at\""} {
		if strings.Contains(encoded, ambiguous) {
			t.Fatalf("report contains ambiguous field %s: %s", ambiguous, encoded)
		}
	}
}

func captureBindingOptions(root string) Options {
	return Options{
		SnapshotRoot:              root,
		CaptureSpec:               filepath.Join(filepath.Dir(root), "capture-private", "capture-spec.json"),
		StagingDir:                filepath.Join(filepath.Dir(root), "linux-stage"),
		TenantDataRoot:            "/srv/workagent/users",
		ExternalWorkspaceManifest: filepath.Join(root, "external-workspaces.json"),
		DryRun:                    true,
	}
}

func validCaptureBinding(root string) wincapture.CompletedCaptureBinding {
	return wincapture.CompletedCaptureBinding{
		SchemaVersion:         1,
		CaptureID:             filepath.Base(root),
		SpecSHA256:            strings.Repeat("a", 64),
		CaptureManifestSHA256: strings.Repeat("b", 64),
		CompletedAt:           time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC),
	}
}

func validBoundSourceReport(t *testing.T) Report {
	t.Helper()
	report := Report{
		SchemaVersion:                ReportSchemaVersion,
		Status:                       "complete",
		CaptureID:                    "capture-20260728",
		CaptureSpecSHA256:            strings.Repeat("a", 64),
		CaptureManifestSHA256:        strings.Repeat("b", 64),
		CaptureCompletedAt:           time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC),
		SourcePortalSHA256:           strings.Repeat("c", 64),
		SourcePortalWALSHA256:        strings.Repeat("d", 64),
		SourcePortalSHMSHA256:        strings.Repeat("e", 64),
		SourceCPAStateSHA256:         strings.Repeat("f", 64),
		SourceExternalManifestSHA256: strings.Repeat("0", 64),
		TenantDataRoot:               "/srv/workagent/users",
		Tenants: []TenantReport{{
			SourceTreeSHA256: strings.Repeat("1", 64),
			ExternalWorkspaces: []ExternalWorkspaceReport{{
				SourcePathSHA256: strings.Repeat("2", 64), SourceTreeSHA256: strings.Repeat("3", 64),
			}},
		}},
	}
	var err error
	report.SourceFingerprint, err = sourceFingerprint(report)
	if err != nil {
		t.Fatal(err)
	}
	return report
}
