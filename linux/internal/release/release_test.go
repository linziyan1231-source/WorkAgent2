package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRevision = "1111111111111111111111111111111111111111"

func makeRelease(t *testing.T) (string, Manifest) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "release-one")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "runtime"), []byte("runtime"), 0o555); err != nil {
		t.Fatal(err)
	}
	builtAt := time.Unix(1_800_000_000, 0).UTC()
	if err := os.WriteFile(filepath.Join(root, "sbom.spdx.json"), []byte(`{"spdxVersion":"SPDX-2.3","documentNamespace":"https://workagent.example.test/spdx/release-one","packages":[{"name":"workagent-runtime"}]}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "provenance.json"), []byte(`{"schema_version":1,"release_id":"release-one","source_revision":"`+testRevision+`","builder_id":"workagent-builder-v1","build_type":"release","invocation_id":"fixture-1","reproducible":true,"materials":[{"uri":"git+https://example.test/workagent","revision":"`+testRevision+`"}]}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "licenses.json"), []byte(`{"schema_version":1,"approved":true,"reviewed_at":"`+builtAt.Format(time.RFC3339)+`","entries":[{"component":"workagent-runtime","spdx_expression":"LicenseRef-WorkAgent-Approved","copyright":"WorkAgent authorized test fixture"}]}`), 0o444); err != nil {
		t.Fatal(err)
	}
	metadata := Manifest{ReleaseID: "release-one", SourceRevision: testRevision, BuiltAt: builtAt, BrandingVersion: "workagent-v1", PolicyVersion: "deny-all-v1", ComponentScope: ScopeRuntime,
		DataSchemaVersion: 1, MinimumReadableDataSchema: 1, MaximumReadableDataSchema: 1,
		Components: []Component{{Name: "workagent-runtime", Version: "1.0.0", SourceRevision: testRevision}}, SBOMPath: "sbom.spdx.json", ProvenancePath: "provenance.json", LicenseReportPath: "licenses.json"}
	manifest, err := BuildManifest(root, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func TestReleaseEvidenceGenerationIsDeterministicAndFailClosed(t *testing.T) {
	components := []Component{
		{Name: "python", Version: "3.13.13", SourceRevision: strings.Repeat("b", 64)},
		{Name: "aionui", Version: "2.1.0-beta.editfork.21", SourceRevision: strings.Repeat("a", 64)},
	}
	provenance, err := NewProvenance("runtime-20260727", testRevision, "git:workagent2", "builder-one", "workagent-release-v1", "invocation-one", true, components)
	if err != nil {
		t.Fatal(err)
	}
	if provenance.Materials[0].Revision != testRevision || provenance.Materials[1].URI != "component:aionui@2.1.0-beta.editfork.21" || provenance.Materials[2].URI != "component:python@3.13.13" {
		t.Fatalf("provenance materials are not deterministic: %#v", provenance.Materials)
	}
	if _, err := NewProvenance("runtime-20260727", testRevision, "git:workagent2", "builder-one", "workagent-release-v1", "invocation-one", false, components); err == nil {
		t.Fatal("non-reproducible release provenance was accepted")
	}
	template, err := NewLicenseReviewTemplate(components)
	if err != nil {
		t.Fatal(err)
	}
	if template.Approved || !template.ReviewedAt.IsZero() || len(template.Entries) != 2 || template.Entries[0].Component != "aionui" || template.Entries[0].SPDXExpression != "" {
		t.Fatalf("license review template was pre-approved or non-deterministic: %#v", template)
	}
	for _, placeholder := range []string{"", "NOASSERTION", "NONE", "review_required", "TODO", "unresolved", "TODO Apache-2.0", "Copyright unknown owner", "license review required"} {
		if validApprovedLicenseText(placeholder) {
			t.Fatalf("license placeholder %q was accepted", placeholder)
		}
	}
	if !validApprovedLicenseText("Apache-2.0 OR LicenseRef-WorkAgent-Authorized") {
		t.Fatal("reviewed SPDX expression was rejected")
	}
}

func TestVerifyRequiresValidEd25519Signature(t *testing.T) {
	root, _ := makeRelease(t)
	keyRoot := t.TempDir()
	publicPath, privatePath := filepath.Join(keyRoot, "release.pub"), filepath.Join(keyRoot, "release.key")
	if err := GenerateSigningKey(publicPath, privatePath); err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(root, "manifest.sig")
	if err := SignManifest(filepath.Join(root, "manifest.json"), signaturePath, privatePath, false); err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{ExpectedReleaseID: "release-one", RequireSignature: true, PublicKeyPath: publicPath, AllowedScopes: []string{ScopeRuntime}, RequiredComponents: map[string]string{"workagent-runtime": "1.0.0"}}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), options); err != nil {
		t.Fatalf("signed release was rejected: %v", err)
	}
	if err := os.WriteFile(signaturePath, []byte("invalid\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), options); err == nil {
		t.Fatal("invalid release signature was accepted")
	}
}

func TestVerifyReleaseAndDetectTampering(t *testing.T) {
	root, _ := makeRelease(t)
	options := VerifyOptions{ExpectedReleaseID: "release-one", RequiredPaths: []string{"bin/runtime"}}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), options); err != nil {
		t.Fatalf("valid release rejected: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "bin", "runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), options); err == nil {
		t.Fatal("mode tampering was not detected")
	}
}

func TestVerifyRejectsSymlinkAndUnlistedFile(t *testing.T) {
	root, manifest := makeRelease(t)
	extra := filepath.Join(root, "unlisted")
	if err := os.WriteFile(extra, []byte("extra"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{ExpectedReleaseID: manifest.ReleaseID}); err == nil {
		t.Fatal("unlisted release file was accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "bin", "runtime")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sbom.spdx.json", filepath.Join(root, "bin", "runtime")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{}); err == nil {
		t.Fatal("symbolic link was accepted")
	}
}

func TestActivateTracksPreviousRelease(t *testing.T) {
	root := t.TempDir()
	pointerPath := filepath.Join(root, "current.json")
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := Activate(pointerPath, "release-one", now); err != nil {
		t.Fatal(err)
	}
	if err := Activate(pointerPath, "release-two", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	pointer, err := LoadPointer(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	if pointer.Current != "release-two" || pointer.Previous != "release-one" {
		t.Fatalf("unexpected pointer: %+v", pointer)
	}
}

func TestActivateRefusesToOverwriteCorruptPointer(t *testing.T) {
	root := t.TempDir()
	pointerPath := filepath.Join(root, "current.json")
	if err := os.WriteFile(pointerPath, []byte(`{"schema_version":1,"current":"broken"} trailing`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Activate(pointerPath, "release-two", time.Now().UTC()); err == nil {
		t.Fatal("corrupt current pointer was silently overwritten")
	}
	payload, err := os.ReadFile(pointerPath)
	if err != nil || string(payload) != `{"schema_version":1,"current":"broken"} trailing` {
		t.Fatalf("corrupt pointer changed: %q err=%v", payload, err)
	}
}

func TestManifestHashFixture(t *testing.T) {
	payload := []byte("fixture")
	hash := sha256.Sum256(payload)
	if len(hex.EncodeToString(hash[:])) != 64 {
		t.Fatal("invalid SHA-256 encoding")
	}
}

func TestLoadManifestAcceptsCompleteLargeRuntimeEvidence(t *testing.T) {
	files := []File{
		{Path: "sbom.spdx.json", SHA256: strings.Repeat("0", 64), Mode: "0444", UID: 0, GID: 0},
		{Path: "provenance.json", SHA256: strings.Repeat("1", 64), Mode: "0444", UID: 0, GID: 0},
		{Path: "licenses.json", SHA256: strings.Repeat("2", 64), Mode: "0444", UID: 0, GID: 0},
	}
	for index := 0; index < 7_500; index++ {
		files = append(files, File{
			Path:   fmt.Sprintf("bin/managed-resources/package-%04d/long-runtime-evidence-file.js", index),
			SHA256: strings.Repeat("a", 64), Mode: "0444", Size: int64(index), UID: 0, GID: 0,
		})
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion, ReleaseID: "large-runtime", SourceRevision: testRevision,
		TargetOS: "linux", TargetArch: "amd64", BuiltAt: time.Unix(1_800_000_000, 0).UTC(),
		BrandingVersion: "workagent-v1", PolicyVersion: "deny-all-v1", ComponentScope: ScopeRuntime,
		DataSchemaVersion: 1, MinimumReadableDataSchema: 1, MaximumReadableDataSchema: 1,
		Components: []Component{{Name: "aioncore", Version: "v0.1.42-editfork.10", SourceRevision: testRevision}},
		SBOMPath:   "sbom.spdx.json", ProvenancePath: "provenance.json", LicenseReportPath: "licenses.json", Files: files,
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := WriteManifest(path, manifest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 1024*1024 {
		t.Fatalf("large runtime fixture did not cross the legacy 1 MiB boundary: %d", info.Size())
	}
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("complete runtime manifest was rejected: %v", err)
	}
	if len(loaded.Files) != len(files) {
		t.Fatalf("large runtime manifest lost file evidence: got %d want %d", len(loaded.Files), len(files))
	}
}

func TestResolveActiveVerifiesProtectedPointerAndSignature(t *testing.T) {
	releaseRoot, _ := makeRelease(t)
	channel := t.TempDir()
	releasesRoot := filepath.Join(channel, "releases")
	if err := os.Mkdir(releasesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(releasesRoot, "release-one")
	if err := os.Rename(releaseRoot, target); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := filepath.Join(channel, "release.pub"), filepath.Join(channel, "release.key")
	if err := GenerateSigningKey(publicKey, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := SignManifest(filepath.Join(target, "manifest.json"), filepath.Join(target, "manifest.sig"), privateKey, false); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(channel, "current.json")
	if err := ActivateScoped(pointer, "release-one", ScopeRuntime, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	verified, err := ResolveActive(releasesRoot, pointer, publicKey, ResolveOptions{Scope: ScopeRuntime, RequiredPaths: []string{"bin/runtime"}, RequiredComponents: map[string]string{"workagent-runtime": "1.0.0"}})
	if err != nil || verified.Manifest.ReleaseID != "release-one" {
		t.Fatalf("active release did not resolve: %+v err=%v", verified, err)
	}
	if err := os.WriteFile(pointer, []byte(`{"schema_version":1,"scope":"runtime","current":"release-one","activated_at":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveActive(releasesRoot, pointer, publicKey, ResolveOptions{Scope: ScopeRuntime}); err == nil {
		t.Fatal("corrupt release pointer was accepted")
	}
}

func TestRequiredProductionComponentsAreScoped(t *testing.T) {
	runtimeComponents := RequiredComponentsForScope(ScopeRuntime)
	if runtimeComponents["aionui"] != "2.1.0-beta.editfork.21" || runtimeComponents["aioncore"] != "v0.1.42-editfork.10" || runtimeComponents["noble-hashes"] != "2.2.0" || runtimeComponents["codex"] != "0.144.4" || runtimeComponents["kimi-code"] != "0.29.1-fork-steer.1" || runtimeComponents["python"] != "3.13.13" || runtimeComponents["cliproxyapi"] != "" {
		t.Fatalf("runtime scope is not isolated: %#v", runtimeComponents)
	}
	sharedComponents := RequiredComponentsForScope(ScopeShared)
	if sharedComponents["cliproxyapi"] != "7.2.81" || sharedComponents["cliproxyapi-patch"] != "per-key-models.4" || sharedComponents["cpa-key-policy"] != "0.4.5" || sharedComponents["chatforward"] != "zombie-reap-20260725-2329" || sharedComponents["chatforward-extension"] != "0.16.0" || sharedComponents["node"] != "24.15.0" || sharedComponents["ws"] != "8.21.1" || sharedComponents["aionui"] != "" {
		t.Fatalf("shared scope is not isolated: %#v", sharedComponents)
	}
	combined := RequiredComponentsForScope(ScopeCombined)
	if combined["aionui"] == "" || combined["cliproxyapi"] == "" {
		t.Fatalf("combined scope is incomplete: %#v", combined)
	}
}

func TestReleaseDataSchemaCompatibilityIsFailClosed(t *testing.T) {
	reader := Manifest{ReleaseID: "reader", MinimumReadableDataSchema: 2, MaximumReadableDataSchema: 4}
	if err := requireReadableDataSchema(reader, 3); err != nil {
		t.Fatalf("compatible schema rejected: %v", err)
	}
	if err := requireReadableDataSchema(reader, 1); err == nil {
		t.Fatal("too-old data schema was accepted")
	}
	if err := requireReadableDataSchema(reader, 5); err == nil {
		t.Fatal("too-new data schema was accepted")
	}
}

func TestPreflightBindsActivationInputsAndExpires(t *testing.T) {
	root, _ := makeRelease(t)
	evidenceRoot := t.TempDir()
	portalConfig := filepath.Join(evidenceRoot, "portal.json")
	tenantConfig := filepath.Join(evidenceRoot, "tenant.json")
	if err := os.WriteFile(portalConfig, []byte("portal"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tenantConfig, []byte("tenant"), 0o400); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	pointer := filepath.Join(evidenceRoot, "current.json")
	notice := &MaintenanceNotice{ID: ExpectedMaintenanceNoticeID("release-one"), Message: MaintenanceNoticeMessage, PublishedAt: now.Add(-2 * time.Minute), ObservedAt: now}
	report, err := NewPreflightReport("release-one", "release-zero", ScopeRuntime, pointer, filepath.Join(root, "manifest.json"), portalConfig, map[string]string{"tenant-one": tenantConfig}, notice, now)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(evidenceRoot, "preflight.json")
	if err := WritePreflight(reportPath, report); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, filepath.Join(root, "manifest.json"), portalConfig, map[string]string{"tenant-one": tenantConfig}, now.Add(time.Minute), false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tenantConfig, []byte("changed"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, filepath.Join(root, "manifest.json"), portalConfig, map[string]string{"tenant-one": tenantConfig}, now.Add(time.Minute), false); err == nil {
		t.Fatal("tenant configuration changed after preflight without detection")
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, filepath.Join(root, "manifest.json"), portalConfig, map[string]string{"tenant-one": tenantConfig}, now.Add(2*time.Hour), false); err == nil {
		t.Fatal("expired preflight was accepted")
	}
}

func TestPreflightRejectsStaleEarlyOrWrongMaintenanceNotice(t *testing.T) {
	root, _ := makeRelease(t)
	evidenceRoot := t.TempDir()
	portalConfig := filepath.Join(evidenceRoot, "portal.json")
	tenantConfig := filepath.Join(evidenceRoot, "tenant.json")
	if err := os.WriteFile(portalConfig, []byte("portal"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tenantConfig, []byte("tenant"), 0o400); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	pointer := filepath.Join(evidenceRoot, "current.json")
	base := MaintenanceNotice{ID: ExpectedMaintenanceNoticeID("release-one"), Message: MaintenanceNoticeMessage, PublishedAt: now.Add(-time.Minute), ObservedAt: now}
	for name, mutate := range map[string]func(*MaintenanceNotice){
		"published too late": func(value *MaintenanceNotice) { value.PublishedAt = now.Add(-59 * time.Second) },
		"stale":              func(value *MaintenanceNotice) { value.PublishedAt = now.Add(-25 * time.Hour) },
		"wrong id":           func(value *MaintenanceNotice) { value.ID = "old-notice" },
		"wrong message":      func(value *MaintenanceNotice) { value.Message = "upgrade" },
	} {
		t.Run(name, func(t *testing.T) {
			notice := base
			mutate(&notice)
			if _, err := NewPreflightReport("release-one", "release-zero", ScopeRuntime, pointer, filepath.Join(root, "manifest.json"), portalConfig, map[string]string{"tenant-one": tenantConfig}, &notice, now); err == nil {
				t.Fatal("invalid maintenance notice was accepted")
			}
		})
	}
}
