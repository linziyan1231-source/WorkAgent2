package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testRevision = "1111111111111111111111111111111111111111"

func thawReleaseFixture(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else if entry.Type().IsRegular() {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
}

func makeRelease(t *testing.T) (string, Manifest) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "release-one")
	t.Cleanup(func() { thawReleaseFixture(root) })
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "runtime"), []byte("runtime"), 0o555); err != nil {
		t.Fatal(err)
	}
	builtAt := time.Unix(1_800_000_000, 0).UTC()
	if err := os.WriteFile(filepath.Join(root, "provenance.json"), []byte(`{"schema_version":1,"release_id":"release-one","source_revision":"`+testRevision+`","builder_id":"workagent-builder-v1","build_type":"release","invocation_id":"fixture-1","reproducible":true,"materials":[{"uri":"git+https://example.test/workagent","revision":"`+testRevision+`"}]}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin", "runtime"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "provenance.json"), 0o444); err != nil {
		t.Fatal(err)
	}
	metadata := Manifest{ReleaseID: "release-one", SourceRevision: testRevision, BuiltAt: builtAt, BrandingVersion: "workagent-v1", PolicyVersion: "deny-all-v1", ComponentScope: ScopeRuntime,
		DataSchemaVersion: 1, MinimumReadableDataSchema: 1, MaximumReadableDataSchema: 1,
		Components: []Component{{Name: "workagent-runtime", Version: "1.0.0", SourceRevision: testRevision}}}
	manifest, err := BuildManifest(root, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func makeNamedTestRelease(t *testing.T, releasesRoot, releaseID, componentVersion string, dataSchema, minimumReadable, maximumReadable int, extraDataPath string) string {
	t.Helper()
	root, metadata := makeRelease(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	provenancePath := filepath.Join(root, "provenance.json")
	if err := os.Chmod(provenancePath, 0o644); err != nil {
		t.Fatal(err)
	}
	provenance := fmt.Sprintf(`{"schema_version":1,"release_id":%q,"source_revision":%q,"builder_id":"workagent-builder-v1","build_type":"release","invocation_id":"fixture-1","reproducible":true,"materials":[{"uri":"git+https://example.test/workagent","revision":%q}]}`, releaseID, testRevision, testRevision)
	if err := os.WriteFile(provenancePath, []byte(provenance), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(provenancePath, 0o444); err != nil {
		t.Fatal(err)
	}
	if extraDataPath != "" {
		if err := os.WriteFile(filepath.Join(root, extraDataPath), []byte("new consumer data\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, extraDataPath), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	metadata.ReleaseID = releaseID
	metadata.DataSchemaVersion = dataSchema
	metadata.MinimumReadableDataSchema = minimumReadable
	metadata.MaximumReadableDataSchema = maximumReadable
	metadata.Components[0].Version = componentVersion
	manifest, err := BuildManifest(root, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(releasesRoot, releaseID)
	if err := os.Rename(root, target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { thawReleaseFixture(target) })
	return target
}

func makePreflightInputsFixture(t *testing.T, releaseRoot, evidenceRoot, portalConfig, tenantConfig string) PreflightInputs {
	t.Helper()
	paths := map[string]string{
		"backup": filepath.Join(evidenceRoot, "backup.json"),
		"key":    filepath.Join(evidenceRoot, "backup.key"),
		"brand":  filepath.Join(evidenceRoot, "brand.json"),
		"policy": filepath.Join(evidenceRoot, "policy.json"),
	}
	for _, name := range requiredBrandAssetNames {
		paths["asset-"+name] = filepath.Join(evidenceRoot, name+".svg")
	}
	for name, path := range paths {
		if err := os.WriteFile(path, []byte(name+"\n"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	assets := make(map[string]string, len(requiredBrandAssetNames))
	for _, name := range requiredBrandAssetNames {
		assets[name] = paths["asset-"+name]
	}
	return PreflightInputs{
		TargetManifestPath: filepath.Join(releaseRoot, "manifest.json"),
		PortalConfigPath:   portalConfig,
		TenantConfigPaths:  map[string]string{"tenant-one": tenantConfig},
		BackupConfigPath:   paths["backup"], BackupKeyPath: paths["key"],
		BrandID: "workagent", BrandConfigPath: paths["brand"], BrandAssetPaths: assets,
		PolicyID: "workagent-models-v1", PolicyConfigPath: paths["policy"],
	}
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
}

func TestConsumerContractIsCanonicalAndBindsFileRoles(t *testing.T) {
	contract, err := NewConsumerContract(
		[]string{"provenance.json"},
		[]string{"bin/runtime"},
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, paths := range map[string]struct {
		data        []string
		executables []string
	}{
		"empty":        {},
		"dot dot":      {data: []string{".."}},
		"duplicate":    {data: []string{"provenance.json", "provenance.json"}},
		"role overlap": {data: []string{"bin/runtime"}, executables: []string{"bin/runtime"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewConsumerContract(paths.data, paths.executables); err == nil {
				t.Fatal("invalid consumer contract was accepted")
			}
		})
	}

	_, manifest := makeRelease(t)
	if err := ValidateManifestConsumerContract(manifest, contract); err != nil {
		t.Fatalf("valid manifest consumer contract rejected: %v", err)
	}
	wrongDataRole, err := NewConsumerContract([]string{"bin/runtime"}, []string{"provenance.json"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestConsumerContract(manifest, wrongDataRole); err == nil {
		t.Fatal("manifest consumer roles were not enforced")
	}
}

func TestVerifiedPointerMutationRequiresConsumerContract(t *testing.T) {
	root := t.TempDir()
	releasesRoot := filepath.Join(root, "releases")
	pointer := filepath.Join(root, "current.json")
	if _, err := ActivateVerified(releasesRoot, pointer, "release-one", ResolveOptions{Scope: ScopeRuntime}, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "consumer contract") {
		t.Fatalf("activation without a consumer contract was not rejected first: %v", err)
	}
	if _, _, err := RollbackVerified(releasesRoot, pointer, ResolveOptions{Scope: ScopeRuntime}, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "consumer contract") {
		t.Fatalf("rollback without a consumer contract was not rejected first: %v", err)
	}
}

func TestRuntimeConsumerSharedLockBlocksPointerSwitch(t *testing.T) {
	root := t.TempDir()
	pointer := filepath.Join(root, "current.json")
	lockPath := pointer + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(lockPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := ActivateScoped(pointer, "release-one", ScopeRuntime, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "runtime consumer") {
		t.Fatalf("pointer moved while a runtime consumer held the channel: %v", err)
	}
	if _, err := os.Stat(pointer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked activation created a pointer: %v", err)
	}
}

func TestPointerLockRejectsHardLinkedInode(t *testing.T) {
	root := t.TempDir()
	pointer := filepath.Join(root, "current.json")
	lockPath := pointer + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(lockPath, lockPath+".alias"); err != nil {
		t.Fatal(err)
	}
	if err := ActivateScoped(pointer, "release-one", ScopeRuntime, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("hard-linked lifecycle lock was accepted: %v", err)
	}
}

func TestRequiredComponentBaselineRejectsExtraManifestComponents(t *testing.T) {
	root, manifest := makeRelease(t)
	manifest.Components = append(manifest.Components, Component{Name: "unexpected", Version: "1.0.0", SourceRevision: testRevision})
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{
		ExpectedReleaseID: "release-one",
		AllowedScopes:     []string{ScopeRuntime}, RequiredComponents: map[string]string{"workagent-runtime": "1.0.0"},
	}); err == nil || !strings.Contains(err.Error(), "component set") {
		t.Fatalf("extra component was not rejected by the exact baseline: %v", err)
	}
}

func TestVerifyReleaseAndDetectTampering(t *testing.T) {
	root, _ := makeRelease(t)
	options := VerifyOptions{ExpectedReleaseID: "release-one", RequiredExecutablePaths: []string{"bin/runtime"}}
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

func TestSignReadyTreeRejectsUmaskDependentModes(t *testing.T) {
	for name, mutate := range map[string]func(string) error{
		"private root":             func(root string) error { return os.Chmod(root, 0o700) },
		"owner writable directory": func(root string) error { return os.Chmod(filepath.Join(root, "bin"), 0o755) },
		"private metadata":         func(root string) error { return os.Chmod(filepath.Join(root, "provenance.json"), 0o600) },
		"setuid executable":        func(root string) error { return os.Chmod(filepath.Join(root, "bin", "runtime"), 0o555|os.ModeSetuid) },
		"sticky directory":         func(root string) error { return os.Chmod(filepath.Join(root, "bin"), 0o555|os.ModeSticky) },
	} {
		t.Run(name, func(t *testing.T) {
			root, _ := makeRelease(t)
			if err := mutate(root); err != nil {
				t.Fatal(err)
			}
			if err := ValidateSignReadyTree(root, false); err == nil {
				t.Fatal("non-canonical release layout was accepted")
			}
		})
	}
}

func TestReleaseTreeExtendedMetadataPolicy(t *testing.T) {
	if err := validateReleaseXattrNames([]byte("security.selinux\x00")); err != nil {
		t.Fatalf("host-managed SELinux label was rejected: %v", err)
	}
	for _, names := range [][]byte{
		[]byte("security.capability\x00"),
		[]byte("security.ima\x00"),
		[]byte("system.posix_acl_access\x00"),
		[]byte("system.posix_acl_default\x00"),
		[]byte("trusted.fixture\x00"),
		[]byte("user.fixture\x00"),
		[]byte("security.selinux\x00user.fixture\x00"),
		[]byte("missing-terminator"),
		[]byte("security.selinux\x00\x00"),
	} {
		if err := validateReleaseXattrNames(names); err == nil {
			t.Fatalf("prohibited or malformed extended metadata was accepted: %q", names)
		}
	}

	root, _ := makeRelease(t)
	path := filepath.Join(root, "provenance.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	err := unix.Lsetxattr(path, "user.workagent-fixture", []byte("fixture"), 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
		t.Skipf("test filesystem cannot create a user xattr: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSignReadyTree(root, false); err == nil {
		t.Fatal("release tree with an unbound user xattr was accepted")
	}
}

func TestSignReadyTreeRejectsExternalHardlink(t *testing.T) {
	root, _ := makeRelease(t)
	target := filepath.Join(root, "provenance.json")
	outside := filepath.Join(filepath.Dir(root), "outside-hardlink")
	if err := os.Link(target, outside); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSignReadyTree(root, false); err == nil {
		t.Fatal("release tree with an externally mutable hardlink was accepted")
	}
}

func TestRootOnlyFrozenTreeProfile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "migration-tools")
	t.Cleanup(func() { thawReleaseFixture(root) })
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin", "capture")
	metadata := filepath.Join(root, "SHA256SUMS")
	if err := os.WriteFile(executable, []byte("capture"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte("hash"), 0o400); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{root: 0o500, filepath.Join(root, "bin"): 0o500, executable: 0o500, metadata: 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateFrozenTree(root, TreeModeProfileRootOnly, false); err != nil {
		t.Fatalf("canonical root-only artifact was rejected: %v", err)
	}
	if err := ValidateFrozenTree(root, TreeModeProfilePublic, false); err == nil {
		t.Fatal("root-only artifact was accepted as a public release")
	}
	if err := ValidateFrozenTree(root, "unknown", false); err == nil {
		t.Fatal("unknown tree mode profile was accepted")
	}
}

func TestManifestAndRequiredExecutableRejectPrivateExecutableMode(t *testing.T) {
	root, manifest := makeRelease(t)
	for index := range manifest.Files {
		if manifest.Files[index].Path == "bin/runtime" {
			manifest.Files[index].Mode = "0444"
		}
	}
	if err := os.Chmod(filepath.Join(root, "bin", "runtime"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(filepath.Join(root, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{RequiredPaths: []string{"bin/runtime"}}); err != nil {
		t.Fatalf("canonical non-executable required file was rejected: %v", err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{RequiredExecutablePaths: []string{"bin/runtime"}}); err == nil {
		t.Fatal("required executable with mode 0444 was accepted")
	}

	manifest.Files[0].Mode = "0700"
	if err := manifest.Validate(); err == nil {
		t.Fatal("manifest accepted an umask-dependent 0700 file")
	}
}

func TestVerifyRejectsSymlinkAndUnlistedFile(t *testing.T) {
	root, manifest := makeRelease(t)
	extra := filepath.Join(root, "unlisted")
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extra, []byte("extra"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{ExpectedReleaseID: manifest.ReleaseID}); err == nil {
		t.Fatal("unlisted release file was accepted")
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "bin", "runtime")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../provenance.json", filepath.Join(root, "bin", "runtime")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "bin"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o555); err != nil {
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
	if err := ActivateScoped(pointerPath, "release-one", ScopeCombined, now); err != nil {
		t.Fatal(err)
	}
	if err := ActivateScoped(pointerPath, "release-two", ScopeCombined, now.Add(time.Minute)); err != nil {
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
	if err := ActivateScoped(pointerPath, "release-two", ScopeCombined, time.Now().UTC()); err == nil {
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
		{Path: "provenance.json", SHA256: strings.Repeat("1", 64), Mode: "0444", UID: 0, GID: 0},
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
		Files:      files,
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

func TestResolveActiveVerifiesProtectedPointer(t *testing.T) {
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
	pointer := filepath.Join(channel, "current.json")
	if err := ActivateScoped(pointer, "release-one", ScopeRuntime, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	verified, err := ResolveActive(releasesRoot, pointer, ResolveOptions{Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"}, RequiredComponents: map[string]string{"workagent-runtime": "1.0.0"}})
	if err != nil || verified.Manifest.ReleaseID != "release-one" {
		t.Fatalf("active release did not resolve: %+v err=%v", verified, err)
	}
	if err := os.WriteFile(pointer, []byte(`{"schema_version":1,"scope":"runtime","current":"release-one","activated_at":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveActive(releasesRoot, pointer, ResolveOptions{Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"}}); err == nil {
		t.Fatal("corrupt release pointer was accepted")
	}
}

func TestVerifiedActivationAndRollbackSupportHistoricalComponentVersions(t *testing.T) {
	channel := t.TempDir()
	releasesRoot := filepath.Join(channel, "releases")
	if err := os.Mkdir(releasesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	makeNamedTestRelease(t, releasesRoot, "release-old", "1.0.0", 1, 1, 1, "")
	makeNamedTestRelease(t, releasesRoot, "release-new", "2.0.0", 1, 1, 1, "")
	pointer := filepath.Join(channel, "current.json")
	if err := ActivateScoped(pointer, "release-old", ScopeRuntime, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	verified, err := ActivateVerified(releasesRoot, pointer, "release-new", ResolveOptions{
		Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"},
		RequiredComponents:  map[string]string{"workagent-runtime": "2.0.0"},
		RequireCurrentMatch: true, ExpectedCurrentRelease: "release-old",
	}, time.Now().UTC())
	if err != nil || verified.Manifest.ReleaseID != "release-new" {
		t.Fatalf("cross-version activation failed: release=%q err=%v", verified.Manifest.ReleaseID, err)
	}
	next, rolledBack, err := RollbackVerified(releasesRoot, pointer, ResolveOptions{
		Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"},
	}, time.Now().UTC())
	if err != nil || next.Current != "release-old" || rolledBack.Manifest.ReleaseID != "release-old" {
		t.Fatalf("cross-version rollback failed: pointer=%+v release=%q err=%v", next, rolledBack.Manifest.ReleaseID, err)
	}
	active, err := ResolveActive(releasesRoot, pointer, ResolveOptions{
		Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"},
	})
	if err != nil || active.Manifest.Components[0].Version != "1.0.0" {
		t.Fatalf("historical release did not remain resolvable: %+v err=%v", active.Manifest, err)
	}
}

func TestActivationAppliesNewConsumerContractOnlyToTarget(t *testing.T) {
	channel := t.TempDir()
	releasesRoot := filepath.Join(channel, "releases")
	if err := os.Mkdir(releasesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	makeNamedTestRelease(t, releasesRoot, "release-old", "1.0.0", 1, 1, 1, "")
	makeNamedTestRelease(t, releasesRoot, "release-new", "2.0.0", 1, 1, 1, "new-required.txt")
	pointer := filepath.Join(channel, "current.json")
	if err := ActivateScoped(pointer, "release-old", ScopeRuntime, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateVerified(releasesRoot, pointer, "release-new", ResolveOptions{
		Scope: ScopeRuntime, RequiredPaths: []string{"new-required.txt"}, RequiredExecutablePaths: []string{"bin/runtime"},
		RequiredComponents:  map[string]string{"workagent-runtime": "2.0.0"},
		RequireCurrentMatch: true, ExpectedCurrentRelease: "release-old",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("target-only consumer expansion blocked activation from a valid historical release: %v", err)
	}
}

func TestRollbackRejectsHistoricalReleaseThatCannotReadActiveData(t *testing.T) {
	channel := t.TempDir()
	releasesRoot := filepath.Join(channel, "releases")
	if err := os.Mkdir(releasesRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	makeNamedTestRelease(t, releasesRoot, "release-old", "1.0.0", 1, 1, 1, "")
	makeNamedTestRelease(t, releasesRoot, "release-new", "2.0.0", 2, 1, 2, "")
	pointer := filepath.Join(channel, "current.json")
	if err := ActivateScoped(pointer, "release-old", ScopeRuntime, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateVerified(releasesRoot, pointer, "release-new", ResolveOptions{
		Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"},
		RequiredComponents:  map[string]string{"workagent-runtime": "2.0.0"},
		RequireCurrentMatch: true, ExpectedCurrentRelease: "release-old",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("forward-compatible upgrade failed: %v", err)
	}
	if _, _, err := RollbackVerified(releasesRoot, pointer, ResolveOptions{
		Scope: ScopeRuntime, RequiredExecutablePaths: []string{"bin/runtime"},
	}, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "restore is required") {
		t.Fatalf("schema-incompatible historical rollback was accepted: %v", err)
	}
}

func TestRequiredProductionComponentsAreScoped(t *testing.T) {
	runtimeComponents := ProductionRuntimeComponentEvidence()
	if runtimeComponents["aionui"].Version != "2.1.0-beta.editfork.21" || runtimeComponents["aioncore"].Version != "v0.1.42-editfork.10" || runtimeComponents["noble-hashes"].Version != "2.2.0" || runtimeComponents["codex"].Version != "0.144.4" || runtimeComponents["kimi-code"].Version != "0.29.1-fork-steer.1" || runtimeComponents["python"].Version != "3.13.13" || runtimeComponents["cliproxyapi"].Version != "" {
		t.Fatalf("runtime scope is not isolated: %#v", runtimeComponents)
	}
	sharedComponents := ProductionSharedComponentEvidence()
	if sharedComponents["cliproxyapi"].Version != "7.2.81" || sharedComponents["cliproxyapi-patch"].Version != "per-key-models.4" || sharedComponents["cpa-key-policy"].Version != "0.4.5" || sharedComponents["chatforward"].Version != "zombie-reap-20260725-2329" || sharedComponents["chatforward-extension"].Version != "0.16.0" || sharedComponents["node"].Version != "24.15.0" || sharedComponents["ws"].Version != "8.21.1" || sharedComponents["aionui"].Version != "" {
		t.Fatalf("shared scope is not isolated: %#v", sharedComponents)
	}
	combined := RequiredComponentEvidenceForScope(ScopeCombined, "")
	if combined["aionui"].Version == "" || combined["cliproxyapi"].Version == "" {
		t.Fatalf("combined scope is incomplete: %#v", combined)
	}
}

func TestAdmissionBaselineBindsComponentSourceRevisionsAndControlBuild(t *testing.T) {
	var runtimeComponents []Component
	for _, component := range ProductionRuntimeComponentEvidence() {
		runtimeComponents = append(runtimeComponents, component)
	}
	if err := ValidateAdmissionComponentBaseline(ScopeRuntime, testRevision, runtimeComponents); err != nil {
		t.Fatalf("exact runtime component evidence rejected: %v", err)
	}
	runtimeComponents[0].SourceRevision = strings.Repeat("f", 64)
	if err := ValidateAdmissionComponentBaseline(ScopeRuntime, testRevision, runtimeComponents); err == nil || !strings.Contains(err.Error(), "source revision") {
		t.Fatalf("runtime source-revision drift was accepted: %v", err)
	}

	control := []Component{{Name: "workagent-control", Version: "git-111111111111", SourceRevision: testRevision}}
	if err := ValidateAdmissionComponentBaseline(ScopePortal, testRevision, control); err != nil {
		t.Fatalf("exact control-plane build evidence rejected: %v", err)
	}
	control[0].Version = "git-222222222222"
	if err := ValidateAdmissionComponentBaseline(ScopePortal, testRevision, control); err == nil {
		t.Fatal("control component version did not bind the release source revision")
	}
}

func TestStrictAdmissionRequiresExternallyBoundSourceRevision(t *testing.T) {
	root, _ := makeRelease(t)
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{
		RequiredExecutablePaths: []string{"bin/runtime"}, RequireAdmissionBaseline: true,
	}); err == nil || !strings.Contains(err.Error(), "trusted executable") {
		t.Fatalf("strict admission without an external source revision was accepted: %v", err)
	}
	if _, err := Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{
		ExpectedSourceRevision: strings.Repeat("2", 40), RequiredExecutablePaths: []string{"bin/runtime"}, RequireAdmissionBaseline: true,
	}); err == nil || !strings.Contains(err.Error(), "trusted admission executable") {
		t.Fatalf("strict admission accepted a manifest from another source revision: %v", err)
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
	inputs := makePreflightInputsFixture(t, root, evidenceRoot, portalConfig, tenantConfig)
	notice := &MaintenanceNotice{ID: ExpectedMaintenanceNoticeID("release-one"), Message: MaintenanceNoticeMessage, PublishedAt: now.Add(-2 * time.Minute), ObservedAt: now}
	contract, err := NewConsumerContract([]string{"sbom.spdx.json"}, []string{"bin/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := NewPreflightReport("release-one", "release-zero", ScopeRuntime, pointer, inputs, contract, notice, now)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(evidenceRoot, "preflight.json")
	if err := WritePreflight(reportPath, report); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePreflight(reportPath, report); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("immutable preflight report was overwritten: %v", err)
	}
	after, err := os.ReadFile(reportPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed overwrite changed the preflight report: %v", err)
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, inputs, contract, now.Add(time.Minute), false); err != nil {
		t.Fatal(err)
	}
	driftedContract, err := NewConsumerContract([]string{"provenance.json"}, []string{"bin/runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, inputs, driftedContract, now.Add(time.Minute), false); err == nil {
		t.Fatal("activation consumer contract changed after preflight without detection")
	}
	for name, path := range map[string]string{
		"backup config": inputs.BackupConfigPath,
		"backup key":    inputs.BackupKeyPath,
		"brand config":  inputs.BrandConfigPath,
		"brand asset":   inputs.BrandAssetPaths["logo"],
		"policy config": inputs.PolicyConfigPath,
	} {
		t.Run(name+" drift", func(t *testing.T) {
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("changed\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, inputs, contract, now.Add(time.Minute), false); err == nil {
				t.Fatalf("%s changed after preflight without detection", name)
			}
			if err := os.WriteFile(path, original, 0o400); err != nil {
				t.Fatal(err)
			}
		})
	}
	alternateBackup := filepath.Join(evidenceRoot, "alternate-backup.json")
	backupPayload, err := os.ReadFile(inputs.BackupConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alternateBackup, backupPayload, 0o400); err != nil {
		t.Fatal(err)
	}
	driftedInputs := inputs
	driftedInputs.BackupConfigPath = alternateBackup
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, driftedInputs, contract, now.Add(time.Minute), false); err == nil {
		t.Fatal("backup configuration path changed after preflight without detection")
	}
	if err := os.WriteFile(tenantConfig, []byte("changed"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, inputs, contract, now.Add(time.Minute), false); err == nil {
		t.Fatal("tenant configuration changed after preflight without detection")
	}
	if err := os.WriteFile(tenantConfig, []byte("tenant"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPreflight(reportPath, "release-one", "release-zero", ScopeRuntime, pointer, inputs, contract, now.Add(2*time.Hour), false); err == nil {
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
	inputs := makePreflightInputsFixture(t, root, evidenceRoot, portalConfig, tenantConfig)
	contract, err := NewConsumerContract([]string{"sbom.spdx.json"}, []string{"bin/runtime"})
	if err != nil {
		t.Fatal(err)
	}
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
			if _, err := NewPreflightReport("release-one", "release-zero", ScopeRuntime, pointer, inputs, contract, &notice, now); err == nil {
				t.Fatal("invalid maintenance notice was accepted")
			}
		})
	}
}
