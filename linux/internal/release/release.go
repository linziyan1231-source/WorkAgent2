package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/jsonutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

const ManifestSchemaVersion = 4

// A production runtime includes the pinned Python standard library plus the
// AionCore Node/ACP resource trees.  Their per-file evidence remains below the
// 10,000-entry validation limit but does not fit safely in the old 1 MiB JSON
// envelope. Keep the manifest bounded while allowing the complete release to
// be represented without dropping files from verification.
const maxManifestBytes = 8 * 1024 * 1024

const (
	ScopePortal   = "portal"
	ScopeRuntime  = "runtime"
	ScopeShared   = "shared"
	ScopeCombined = "combined"
)

const (
	TreeModeProfilePublic   = "public"
	TreeModeProfileRootOnly = "root-only"
)

func ProductionRuntimeComponentEvidence() map[string]Component {
	return map[string]Component{
		"aioncore":     {Name: "aioncore", Version: "v0.1.42-editfork.15", SourceRevision: "1edfde5edbdc8ed2931ad2c6bd06204149101c91d16b91b6eca19f0bcbedcef2"},
		"aionui":       {Name: "aionui", Version: "2.1.0-beta.editfork.29", SourceRevision: "cea37a6fba78fddcae95564cb1f89d794051163b2481b318e6932cd76023dd52"},
		"codex":        {Name: "codex", Version: "0.144.4", SourceRevision: "9a4a45314e80b53c4761b80067e3a68c2302f9a9026059b5f54f22dec8f34323"},
		"kimi-code":    {Name: "kimi-code", Version: "0.29.1-fork-steer.1", SourceRevision: "d00c6a1eff46bfe4213fe9f0547b51d7d812f2e9acd2e335ef282bb8d78a97af"},
		"noble-hashes": {Name: "noble-hashes", Version: "2.2.0", SourceRevision: "b74fceb0006b617ed388254677b3d3847aeceb7e3f57db0cc9acc54644dabba6"},
		"python":       {Name: "python", Version: "3.13.13", SourceRevision: "2ab91ff401783ccca64f75d10c882e957bdfd60e2bf5a72f8421793729b78a71"},
	}
}

func ProductionSharedComponentEvidence() map[string]Component {
	return map[string]Component{
		"chatforward":           {Name: "chatforward", Version: "zombie-reap-20260725-2329", SourceRevision: "a1b4d643c0cccde0f7d99483963974f0edb2c8107099627273534da7c0c054fe"},
		"chatforward-extension": {Name: "chatforward-extension", Version: "0.16.0", SourceRevision: "a1b4d643c0cccde0f7d99483963974f0edb2c8107099627273534da7c0c054fe"},
		"cliproxyapi":           {Name: "cliproxyapi", Version: "7.2.81", SourceRevision: "ca52365d3d123a1cff34a5020ce16507e3c2ef1032d57f171b9c26d2cd97eb16"},
		"cliproxyapi-patch":     {Name: "cliproxyapi-patch", Version: "per-key-models.4", SourceRevision: "cd8bcc9c683ed394ef4f58c90b3c61e9a5fea0265b9ae91a68259a16e7b43da8"},
		"cpa-key-policy":        {Name: "cpa-key-policy", Version: "0.4.5", SourceRevision: "bc0081c77764312a604add1013d9cb642f628978d967a46ca3f8159c63fa1a8f"},
		"node":                  {Name: "node", Version: "24.15.0", SourceRevision: "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6"},
		"ws":                    {Name: "ws", Version: "8.21.1", SourceRevision: "bb0f7e58ba1f64746672734d36175fe185f226491e336abc0743e2a8f4472ec1"},
	}
}

func RequiredComponentEvidenceForScope(scope, sourceRevision string) map[string]Component {
	switch scope {
	case ScopePortal:
		if !validRevision(sourceRevision) || len(sourceRevision) < 12 {
			return nil
		}
		return map[string]Component{
			"workagent-control": {Name: "workagent-control", Version: "git-" + sourceRevision[:12], SourceRevision: sourceRevision},
		}
	case ScopeRuntime:
		return ProductionRuntimeComponentEvidence()
	case ScopeShared:
		return ProductionSharedComponentEvidence()
	case ScopeCombined:
		components := ProductionRuntimeComponentEvidence()
		for name, component := range ProductionSharedComponentEvidence() {
			components[name] = component
		}
		return components
	default:
		return nil
	}
}

func ValidateAdmissionComponentBaseline(scope, sourceRevision string, components []Component) error {
	required := RequiredComponentEvidenceForScope(scope, sourceRevision)
	if required == nil {
		return errors.New("release admission component scope or source revision is invalid")
	}
	actual := make(map[string]Component, len(components))
	for _, component := range components {
		if _, exists := actual[component.Name]; exists {
			return fmt.Errorf("release component %s is duplicated", component.Name)
		}
		actual[component.Name] = component
	}
	if len(actual) != len(required) {
		return errors.New("release component evidence does not exactly match the admission baseline")
	}
	for name, expected := range required {
		if component, ok := actual[name]; !ok || component != expected {
			return fmt.Errorf("release component %s version or source revision does not match the admission baseline", name)
		}
	}
	return nil
}

func ValidateComponentBaseline(components []Component, required map[string]string) error {
	if required == nil {
		return nil
	}
	actual := make(map[string]string, len(components))
	for _, component := range components {
		if _, exists := actual[component.Name]; exists {
			return fmt.Errorf("release component %s is duplicated", component.Name)
		}
		actual[component.Name] = component.Version
	}
	if len(actual) != len(required) {
		return errors.New("release component set does not exactly match the required baseline")
	}
	for name, version := range required {
		if actual[name] != version {
			return fmt.Errorf("release component %s version does not match the required baseline", name)
		}
	}
	return nil
}

type Manifest struct {
	SchemaVersion             int         `json:"schema_version"`
	ReleaseID                 string      `json:"release_id"`
	SourceRevision            string      `json:"source_revision"`
	TargetOS                  string      `json:"target_os"`
	TargetArch                string      `json:"target_arch"`
	BuiltAt                   time.Time   `json:"built_at"`
	BrandingVersion           string      `json:"branding_version"`
	PolicyVersion             string      `json:"policy_version"`
	ComponentScope            string      `json:"component_scope"`
	DataSchemaVersion         int         `json:"data_schema_version"`
	MinimumReadableDataSchema int         `json:"minimum_readable_data_schema"`
	MaximumReadableDataSchema int         `json:"maximum_readable_data_schema"`
	Components                []Component `json:"components"`
	Files                     []File      `json:"files"`
}

type Component struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	SourceRevision string `json:"source_revision"`
}

type Provenance struct {
	SchemaVersion  int                  `json:"schema_version"`
	ReleaseID      string               `json:"release_id"`
	SourceRevision string               `json:"source_revision"`
	BuilderID      string               `json:"builder_id"`
	BuildType      string               `json:"build_type"`
	InvocationID   string               `json:"invocation_id"`
	Reproducible   bool                 `json:"reproducible"`
	Materials      []ProvenanceMaterial `json:"materials"`
}

type ProvenanceMaterial struct {
	URI      string `json:"uri"`
	Revision string `json:"revision"`
}

// NewProvenance creates deterministic release provenance from the exact
// component list. Reproducibility is an explicit attestation: production
// evidence cannot silently omit or negate it.
func NewProvenance(releaseID, sourceRevision, sourceURI, builderID, buildType, invocationID string, reproducible bool, components []Component) (Provenance, error) {
	value := Provenance{
		SchemaVersion: 1, ReleaseID: releaseID, SourceRevision: sourceRevision,
		BuilderID: builderID, BuildType: buildType, InvocationID: invocationID,
		Reproducible: reproducible,
		Materials:    []ProvenanceMaterial{{URI: sourceURI, Revision: sourceRevision}},
	}
	ordered := append([]Component(nil), components...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	for _, component := range ordered {
		value.Materials = append(value.Materials, ProvenanceMaterial{
			URI:      "component:" + component.Name + "@" + component.Version,
			Revision: component.SourceRevision,
		})
	}
	if err := value.Validate(); err != nil {
		return Provenance{}, err
	}
	return value, nil
}

func (p Provenance) Validate() error {
	if p.SchemaVersion != 1 || !validIdentifier(p.ReleaseID) || !validRevision(p.SourceRevision) ||
		!validEvidenceText(p.BuilderID) || !validEvidenceText(p.BuildType) || !validEvidenceText(p.InvocationID) || !p.Reproducible ||
		len(p.Materials) == 0 || len(p.Materials) > 256 {
		return errors.New("release provenance is invalid or is not reproducible")
	}
	seen := make(map[string]bool, len(p.Materials))
	for _, material := range p.Materials {
		if !validEvidenceText(material.URI) || !validRevision(material.Revision) {
			return errors.New("release provenance contains an invalid material")
		}
		identity := material.URI + "\x00" + material.Revision
		if seen[identity] {
			return errors.New("release provenance contains a duplicate material")
		}
		seen[identity] = true
	}
	return nil
}

func WriteProvenance(path string, value Provenance) error {
	if !cleanAbsolute(path) {
		return errors.New("release provenance path must be clean and absolute")
	}
	if err := value.Validate(); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(payload, '\n'), 0o444)
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Size   int64  `json:"size"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type VerifyOptions struct {
	ExpectedReleaseID        string
	ExpectedSourceRevision   string
	RequiredPaths            []string
	RequiredExecutablePaths  []string
	RequireRootOwner         bool
	AllowedScopes            []string
	RequiredComponents       map[string]string
	RequireAdmissionBaseline bool
}

type Verified struct {
	Path     string
	Manifest Manifest
}

type ResolveOptions struct {
	Scope                    string
	ExpectedSourceRevision   string
	RequiredPaths            []string
	RequiredExecutablePaths  []string
	RequireRootOwner         bool
	RequiredComponents       map[string]string
	RequireAdmissionBaseline bool
	RequireCurrentMatch      bool
	ExpectedCurrentRelease   string
}

type Pointer struct {
	SchemaVersion int       `json:"schema_version"`
	Scope         string    `json:"scope"`
	Current       string    `json:"current"`
	Previous      string    `json:"previous,omitempty"`
	ActivatedAt   time.Time `json:"activated_at"`
}

func LoadComponents(path string, requireRootOwner bool) ([]Component, error) {
	payload, err := readProtectedBoundedFile(path, 1024*1024, requireRootOwner, false)
	if err != nil {
		return nil, fmt.Errorf("read release component list: %w", err)
	}
	var components []Component
	if err := decodeStrictJSON(payload, &components); err != nil {
		return nil, fmt.Errorf("decode release component list: %w", err)
	}
	test := Manifest{
		SchemaVersion: ManifestSchemaVersion, ReleaseID: "validation", SourceRevision: strings.Repeat("0", 40), TargetOS: "linux", TargetArch: "amd64",
		BuiltAt: time.Unix(1, 0).UTC(), BrandingVersion: "validation", PolicyVersion: "validation", ComponentScope: ScopeRuntime,
		DataSchemaVersion: 1, MinimumReadableDataSchema: 1, MaximumReadableDataSchema: 1, Components: components,
		Files: []File{
			{Path: "provenance.json", SHA256: strings.Repeat("0", 64), Mode: "0444", UID: 0, GID: 0},
		},
	}
	if err := test.Validate(); err != nil {
		return nil, fmt.Errorf("validate release component list: %w", err)
	}
	return components, nil
}

func LoadManifest(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return Manifest{}, errors.New("release manifest is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open release manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestBytes))
	decoder.DisallowUnknownFields()
	var value Manifest
	if err := decoder.Decode(&value); err != nil {
		return Manifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("release manifest must contain one JSON value")
	}
	if err := value.Validate(); err != nil {
		return Manifest{}, err
	}
	return value, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("release manifest schema_version must be %d", ManifestSchemaVersion)
	}
	if !validIdentifier(m.ReleaseID) || !validRevision(m.SourceRevision) {
		return errors.New("release identity is invalid")
	}
	if m.TargetOS != "linux" || m.TargetArch != "amd64" {
		return errors.New("release target must be linux/amd64")
	}
	if m.BuiltAt.IsZero() || m.BrandingVersion == "" || m.PolicyVersion == "" {
		return errors.New("release metadata is incomplete")
	}
	if m.ComponentScope != ScopePortal && m.ComponentScope != ScopeRuntime && m.ComponentScope != ScopeShared && m.ComponentScope != ScopeCombined {
		return errors.New("release component scope is invalid")
	}
	if m.DataSchemaVersion < 1 || m.DataSchemaVersion > 1_000_000 || m.MinimumReadableDataSchema < 1 || m.MinimumReadableDataSchema > m.DataSchemaVersion || m.MaximumReadableDataSchema < m.DataSchemaVersion || m.MaximumReadableDataSchema > 1_000_000 {
		return errors.New("release data-schema compatibility range is invalid")
	}
	if len(m.Components) == 0 || len(m.Components) > 64 {
		return errors.New("release component list is empty or too large")
	}
	componentNames := make(map[string]bool, len(m.Components))
	for _, component := range m.Components {
		if !validIdentifier(component.Name) || component.Name != strings.ToLower(component.Name) || !validIdentifier(component.Version) || !validRevision(component.SourceRevision) || componentNames[component.Name] {
			return fmt.Errorf("release component %q is invalid or duplicated", component.Name)
		}
		componentNames[component.Name] = true
	}
	if len(m.Files) == 0 || len(m.Files) > 10000 {
		return errors.New("release file list is empty or too large")
	}
	seen := make(map[string]struct{}, len(m.Files))
	for _, file := range m.Files {
		if err := validRelativePath(file.Path); err != nil {
			return fmt.Errorf("invalid release file path %q: %w", file.Path, err)
		}
		if _, exists := seen[file.Path]; exists {
			return fmt.Errorf("duplicate release file %q", file.Path)
		}
		seen[file.Path] = struct{}{}
		if len(file.SHA256) != sha256.Size*2 {
			return fmt.Errorf("invalid SHA-256 for %q", file.Path)
		}
		if _, err := hex.DecodeString(file.SHA256); err != nil || strings.ToLower(file.SHA256) != file.SHA256 {
			return fmt.Errorf("invalid SHA-256 for %q", file.Path)
		}
		mode, err := parseMode(file.Mode)
		if err != nil || (mode != 0o444 && mode != 0o555) {
			return fmt.Errorf("non-canonical release mode for %q", file.Path)
		}
		if file.Size < 0 || file.UID != 0 || file.GID != 0 {
			return fmt.Errorf("invalid size or ownership for %q", file.Path)
		}
	}
	return nil
}

// ValidateFrozenTree enforces one of the canonical immutable artifact layouts.
// Directory traversal and executable/read access must not depend on the
// builder's umask or on privileged execution.
func ValidateFrozenTree(root, profile string, requireRootOwner bool) error {
	if !cleanAbsolute(root) {
		return errors.New("release root must be a clean absolute path")
	}
	directoryMode, regularMode, executableMode := os.FileMode(0o555), os.FileMode(0o444), os.FileMode(0o555)
	switch profile {
	case TreeModeProfilePublic:
	case TreeModeProfileRootOnly:
		directoryMode, regularMode, executableMode = 0o500, 0o400, 0o500
	default:
		return errors.New("release tree mode profile is invalid")
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return fmt.Errorf("release path has a prohibited special mode: %s", relative)
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("release contains an unsupported entry: %s", relative)
		}
		if err := validateReleaseXattrs(path); err != nil {
			return fmt.Errorf("release path has prohibited extended metadata: %s: %w", relative, err)
		}
		if requireRootOwner {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || stat.Gid != 0 {
				return fmt.Errorf("release path is not owned by root: %s", relative)
			}
		}
		mode := info.Mode().Perm()
		if info.IsDir() {
			if mode != directoryMode {
				return fmt.Errorf("release directory has non-canonical mode: %s", relative)
			}
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return fmt.Errorf("release file is multiply linked: %s", relative)
		}
		if mode != regularMode && mode != executableMode {
			return fmt.Errorf("release file has non-canonical mode: %s", relative)
		}
		return nil
	})
}

// ValidateSignReadyTree is the public, non-secret payload profile accepted by
// the production manifest and service verifier.
func ValidateSignReadyTree(root string, requireRootOwner bool) error {
	return ValidateFrozenTree(root, TreeModeProfilePublic, requireRootOwner)
}

func validateReleaseXattrs(path string) error {
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil
		}
		return err
	}
	if size == 0 {
		return nil
	}
	if size < 0 || size > 64*1024 {
		return errors.New("extended-attribute name list is too large")
	}
	names := make([]byte, size)
	count, err := unix.Llistxattr(path, names)
	if err != nil {
		return err
	}
	if count <= 0 || count > len(names) {
		return errors.New("extended-attribute name list changed during inspection")
	}
	return validateReleaseXattrNames(names[:count])
}

func validateReleaseXattrNames(names []byte) error {
	if len(names) == 0 {
		return nil
	}
	if names[len(names)-1] != 0 {
		return errors.New("extended-attribute name list is malformed")
	}
	for _, name := range bytes.Split(names[:len(names)-1], []byte{0}) {
		if len(name) == 0 {
			return errors.New("extended-attribute name list is malformed")
		}
		if string(name) != "security.selinux" {
			return errors.New("extended attribute is not permitted")
		}
	}
	return nil
}

func Verify(root, manifestPath string, options VerifyOptions) (Verified, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Clean(manifestPath) != manifestPath || manifestPath != filepath.Join(root, "manifest.json") {
		return Verified{}, errors.New("release and manifest paths are not canonical")
	}
	if len(options.RequiredPaths)+len(options.RequiredExecutablePaths) != 0 {
		contract, err := NewConsumerContract(options.RequiredPaths, options.RequiredExecutablePaths)
		if err != nil {
			return Verified{}, err
		}
		options.RequiredPaths = contract.RequiredPaths
		options.RequiredExecutablePaths = contract.RequiredExecutablePaths
	}
	if err := ValidateSignReadyTree(root, options.RequireRootOwner); err != nil {
		return Verified{}, err
	}
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return Verified{}, err
	}
	if options.ExpectedReleaseID != "" && manifest.ReleaseID != options.ExpectedReleaseID {
		return Verified{}, errors.New("release ID does not match tenant configuration")
	}
	if manifest.TargetOS != runtime.GOOS || manifest.TargetArch != runtime.GOARCH {
		return Verified{}, errors.New("release target does not match this host")
	}
	if len(options.AllowedScopes) != 0 {
		allowed := false
		for _, scope := range options.AllowedScopes {
			allowed = allowed || manifest.ComponentScope == scope
		}
		if !allowed {
			return Verified{}, errors.New("release component scope is not permitted for this consumer")
		}
	}
	if err := ValidateComponentBaseline(manifest.Components, options.RequiredComponents); err != nil {
		return Verified{}, err
	}
	if options.RequireAdmissionBaseline {
		if len(options.ExpectedSourceRevision) != 40 || !validRevision(options.ExpectedSourceRevision) {
			return Verified{}, errors.New("release admission requires the trusted executable's clean 40-hex source revision")
		}
		if manifest.SourceRevision != options.ExpectedSourceRevision {
			return Verified{}, errors.New("release source revision does not match the trusted admission executable")
		}
		if err := ValidateAdmissionComponentBaseline(manifest.ComponentScope, options.ExpectedSourceRevision, manifest.Components); err != nil {
			return Verified{}, err
		}
	}
	secureRoot, err := projectfs.OpenRoot(root)
	if err != nil {
		return Verified{}, err
	}
	defer secureRoot.Close()
	listed := make(map[string]struct{}, len(manifest.Files))
	listedModes := make(map[string]os.FileMode, len(manifest.Files))
	for _, expected := range manifest.Files {
		file, err := secureRoot.Open(filepath.FromSlash(expected.Path), unix.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return Verified{}, fmt.Errorf("verify release file %q: %w", expected.Path, err)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			file.Close()
			return Verified{}, fmt.Errorf("release file %q is not regular", expected.Path)
		}
		stat, statOK := info.Sys().(*syscall.Stat_t)
		if !statOK || stat.Uid != expected.UID || stat.Gid != expected.GID {
			file.Close()
			return Verified{}, fmt.Errorf("release file ownership mismatch for %q", expected.Path)
		}
		if options.RequireRootOwner {
			if stat.Uid != 0 || stat.Gid != 0 {
				file.Close()
				return Verified{}, fmt.Errorf("release file %q is not owned by root", expected.Path)
			}
		}
		mode, _ := parseMode(expected.Mode)
		if info.Mode().Perm() != mode || info.Size() != expected.Size {
			file.Close()
			return Verified{}, fmt.Errorf("release file metadata mismatch for %q", expected.Path)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			file.Close()
			return Verified{}, fmt.Errorf("hash release file %q: %w", expected.Path, err)
		}
		file.Close()
		if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return Verified{}, fmt.Errorf("release file hash mismatch for %q", expected.Path)
		}
		nativePath := filepath.FromSlash(expected.Path)
		listed[nativePath] = struct{}{}
		listedModes[nativePath] = mode
	}
	for _, required := range options.RequiredPaths {
		if err := validRelativePath(required); err != nil {
			return Verified{}, fmt.Errorf("required release file %q is invalid: %w", required, err)
		}
		if _, ok := listed[filepath.FromSlash(required)]; !ok {
			return Verified{}, fmt.Errorf("required release file %q is not in the manifest", required)
		}
		if listedModes[filepath.FromSlash(required)] != 0o444 {
			return Verified{}, fmt.Errorf("required release data file %q is not canonically non-executable", required)
		}
	}
	for _, required := range options.RequiredExecutablePaths {
		if _, ok := listed[filepath.FromSlash(required)]; !ok {
			return Verified{}, fmt.Errorf("required release executable %q is not in the manifest", required)
		}
		if listedModes[filepath.FromSlash(required)] != 0o555 {
			return Verified{}, fmt.Errorf("required release executable %q is not canonically executable", required)
		}
	}
	if err := rejectUnlisted(root, listed, options.RequireRootOwner); err != nil {
		return Verified{}, err
	}
	return Verified{Path: root, Manifest: manifest}, nil
}

// ResolveActive resolves an immutable release through its protected channel
// pointer and verifies the complete release contents against its SHA-256
// manifest before the caller is allowed to execute anything from it.
func ResolveActive(releasesRoot, pointerPath string, options ResolveOptions) (Verified, error) {
	if !cleanAbsolute(releasesRoot) || !cleanAbsolute(pointerPath) || pointerPath != filepath.Join(filepath.Dir(releasesRoot), "current.json") {
		return Verified{}, errors.New("release channel paths are not canonical")
	}
	if options.Scope != ScopePortal && options.Scope != ScopeRuntime && options.Scope != ScopeShared && options.Scope != ScopeCombined {
		return Verified{}, errors.New("release channel scope is invalid")
	}
	contract, err := NewConsumerContract(options.RequiredPaths, options.RequiredExecutablePaths)
	if err != nil {
		return Verified{}, fmt.Errorf("release resolver consumer contract: %w", err)
	}
	options.RequiredPaths = contract.RequiredPaths
	options.RequiredExecutablePaths = contract.RequiredExecutablePaths
	pointer, err := LoadProtectedPointer(pointerPath, options.RequireRootOwner)
	if err != nil {
		return Verified{}, fmt.Errorf("load active release pointer: %w", err)
	}
	if pointer.Scope != options.Scope {
		return Verified{}, errors.New("active release pointer scope does not match its consumer")
	}
	releaseRoot := filepath.Join(releasesRoot, pointer.Current)
	return Verify(releaseRoot, filepath.Join(releaseRoot, "manifest.json"), VerifyOptions{
		ExpectedReleaseID:        pointer.Current,
		ExpectedSourceRevision:   options.ExpectedSourceRevision,
		RequiredPaths:            options.RequiredPaths,
		RequiredExecutablePaths:  options.RequiredExecutablePaths,
		RequireRootOwner:         options.RequireRootOwner,
		AllowedScopes:            []string{options.Scope},
		RequiredComponents:       options.RequiredComponents,
		RequireAdmissionBaseline: options.RequireAdmissionBaseline,
	})
}

func decodeStrictJSON(payload []byte, destination any) error {
	err := jsonutil.DecodeStrict(payload, destination, false)
	if errors.Is(err, jsonutil.ErrTrailingData) {
		return errors.New("JSON document contains trailing data")
	}
	return err
}

func rejectUnlisted(root string, listed map[string]struct{}, requireRootOwner bool) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("release contains a symbolic link: %s", relative)
		}
		if requireRootOwner {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || stat.Gid != 0 {
				return fmt.Errorf("release path is not owned by root: %s", relative)
			}
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0o555 {
				return fmt.Errorf("release directory has non-canonical mode: %s", relative)
			}
			return nil
		}
		if relative == "manifest.json" {
			return nil
		}
		if _, ok := listed[relative]; !ok {
			return fmt.Errorf("release contains unlisted file: %s", relative)
		}
		return nil
	})
}

func BuildManifest(root string, metadata Manifest) (Manifest, error) {
	metadata.SchemaVersion = ManifestSchemaVersion
	metadata.TargetOS = "linux"
	metadata.TargetArch = "amd64"
	metadata.Files = nil
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "manifest.json" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("release contains unsupported entry: %s", relative)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("release file ownership is unavailable: %s", relative)
		}
		metadata.Files = append(metadata.Files, File{Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(hash.Sum(nil)), Mode: fmt.Sprintf("%04o", info.Mode().Perm()), Size: info.Size(), UID: stat.Uid, GID: stat.Gid})
		return nil
	}); err != nil {
		return Manifest{}, err
	}
	sort.Slice(metadata.Files, func(i, j int) bool { return metadata.Files[i].Path < metadata.Files[j].Path })
	if err := metadata.Validate(); err != nil {
		return Manifest{}, err
	}
	return metadata, nil
}

func WriteManifest(path string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return atomicWrite(path, payload, 0o444)
}

func readProtectedBoundedFile(path string, maximum int64, requireRootOwner, requirePrivate bool) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("protected file path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm()&0o022 != 0 || (requirePrivate && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("protected file is missing or unsafe")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, errors.New("protected file is not root-owned")
		}
	}
	payload, err := os.ReadFile(path)
	if err != nil || int64(len(payload)) > maximum {
		return nil, errors.New("protected file could not be read")
	}
	return payload, nil
}

func ActivateScoped(pointerPath, nextRelease, scope string, now time.Time) error {
	return withPointerLock(pointerPath, false, func() error {
		return activateScopedUnlocked(pointerPath, nextRelease, scope, now)
	})
}

func activateScopedUnlocked(pointerPath, nextRelease, scope string, now time.Time) error {
	if !validIdentifier(nextRelease) || !filepath.IsAbs(pointerPath) || filepath.Clean(pointerPath) != pointerPath {
		return errors.New("invalid activation target")
	}
	if scope != ScopePortal && scope != ScopeRuntime && scope != ScopeShared && scope != ScopeCombined {
		return errors.New("invalid activation component scope")
	}
	current, err := LoadPointer(pointerPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("refuse to replace invalid current release pointer: %w", err)
	}
	if current.Current != "" && current.Scope != scope {
		return errors.New("release pointer component scope cannot be changed")
	}
	pointer := Pointer{SchemaVersion: 1, Scope: scope, Current: nextRelease, ActivatedAt: now.UTC()}
	if current.Current != "" && current.Current != nextRelease {
		pointer.Previous = current.Current
	} else {
		pointer.Previous = current.Previous
	}
	payload, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(pointerPath, append(payload, '\n'), 0o444)
}

func Rollback(pointerPath string, now time.Time) (Pointer, error) {
	var result Pointer
	err := withPointerLock(pointerPath, false, func() error {
		var err error
		result, err = rollbackUnlocked(pointerPath, now)
		return err
	})
	return result, err
}

func rollbackUnlocked(pointerPath string, now time.Time) (Pointer, error) {
	current, err := LoadPointer(pointerPath)
	if err != nil {
		return Pointer{}, err
	}
	if current.Previous == "" || current.Previous == current.Current {
		return Pointer{}, errors.New("release pointer has no distinct previous release")
	}
	next := Pointer{SchemaVersion: 1, Scope: current.Scope, Current: current.Previous, Previous: current.Current, ActivatedAt: now.UTC()}
	payload, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return Pointer{}, err
	}
	if err := atomicWrite(pointerPath, append(payload, '\n'), 0o444); err != nil {
		return Pointer{}, err
	}
	return next, nil
}

func ActivateVerified(releasesRoot, pointerPath, nextRelease string, options ResolveOptions, now time.Time) (Verified, error) {
	contract, err := NewConsumerContract(options.RequiredPaths, options.RequiredExecutablePaths)
	if err != nil {
		return Verified{}, fmt.Errorf("activation consumer contract: %w", err)
	}
	options.RequiredPaths = contract.RequiredPaths
	options.RequiredExecutablePaths = contract.RequiredExecutablePaths
	var verified Verified
	err = withPointerLock(pointerPath, options.RequireRootOwner, func() error {
		if !cleanAbsolute(releasesRoot) || pointerPath != filepath.Join(filepath.Dir(releasesRoot), "current.json") || !validIdentifier(nextRelease) {
			return errors.New("release channel paths are not canonical")
		}
		if options.RequireCurrentMatch {
			current, err := LoadPointer(pointerPath)
			if errors.Is(err, os.ErrNotExist) && options.ExpectedCurrentRelease == "" {
				// An explicitly requested first activation has no prior pointer.
			} else if err != nil {
				return fmt.Errorf("load current release for compare-and-swap activation: %w", err)
			} else if current.Current != options.ExpectedCurrentRelease || current.Scope != options.Scope {
				return errors.New("active release changed after preflight")
			}
		}
		releaseRoot := filepath.Join(releasesRoot, nextRelease)
		var err error
		verified, err = Verify(releaseRoot, filepath.Join(releaseRoot, "manifest.json"), VerifyOptions{
			ExpectedReleaseID: nextRelease, ExpectedSourceRevision: options.ExpectedSourceRevision, RequiredPaths: options.RequiredPaths, RequiredExecutablePaths: options.RequiredExecutablePaths, RequireRootOwner: options.RequireRootOwner,
			AllowedScopes: []string{options.Scope}, RequiredComponents: options.RequiredComponents, RequireAdmissionBaseline: options.RequireAdmissionBaseline,
		})
		if err != nil {
			return err
		}
		if options.ExpectedCurrentRelease != "" {
			currentRoot := filepath.Join(releasesRoot, options.ExpectedCurrentRelease)
			current, currentErr := Verify(currentRoot, filepath.Join(currentRoot, "manifest.json"), VerifyOptions{
				ExpectedReleaseID: options.ExpectedCurrentRelease, RequireRootOwner: options.RequireRootOwner,
				AllowedScopes: []string{options.Scope},
			})
			if currentErr != nil {
				return fmt.Errorf("verify active release before activation: %w", currentErr)
			}
			if err := requireReadableDataSchema(verified.Manifest, current.Manifest.DataSchemaVersion); err != nil {
				return fmt.Errorf("target release cannot safely upgrade active data: %w", err)
			}
		}
		return activateScopedUnlocked(pointerPath, nextRelease, options.Scope, now)
	})
	return verified, err
}

func RollbackVerified(releasesRoot, pointerPath string, options ResolveOptions, now time.Time) (Pointer, Verified, error) {
	contract, err := NewConsumerContract(options.RequiredPaths, options.RequiredExecutablePaths)
	if err != nil {
		return Pointer{}, Verified{}, fmt.Errorf("rollback consumer contract: %w", err)
	}
	options.RequiredPaths = contract.RequiredPaths
	options.RequiredExecutablePaths = contract.RequiredExecutablePaths
	var next Pointer
	var verified Verified
	err = withPointerLock(pointerPath, options.RequireRootOwner, func() error {
		if !cleanAbsolute(releasesRoot) || pointerPath != filepath.Join(filepath.Dir(releasesRoot), "current.json") {
			return errors.New("release channel paths are not canonical")
		}
		current, err := LoadProtectedPointer(pointerPath, options.RequireRootOwner)
		if err != nil {
			return err
		}
		if current.Scope != options.Scope || current.Previous == "" || current.Previous == current.Current {
			return errors.New("release pointer has no distinct previous release in the requested scope")
		}
		root := filepath.Join(releasesRoot, current.Previous)
		verified, err = Verify(root, filepath.Join(root, "manifest.json"), VerifyOptions{
			ExpectedReleaseID: current.Previous, RequiredPaths: options.RequiredPaths, RequiredExecutablePaths: options.RequiredExecutablePaths, RequireRootOwner: options.RequireRootOwner,
			AllowedScopes: []string{options.Scope},
		})
		if err != nil {
			return err
		}
		currentRoot := filepath.Join(releasesRoot, current.Current)
		active, activeErr := Verify(currentRoot, filepath.Join(currentRoot, "manifest.json"), VerifyOptions{
			ExpectedReleaseID: current.Current, RequireRootOwner: options.RequireRootOwner,
			AllowedScopes: []string{options.Scope},
		})
		if activeErr != nil {
			return fmt.Errorf("verify active release before rollback: %w", activeErr)
		}
		if err := requireReadableDataSchema(verified.Manifest, active.Manifest.DataSchemaVersion); err != nil {
			return fmt.Errorf("previous release cannot safely read data written by the active release; restore is required: %w", err)
		}
		next, err = rollbackUnlocked(pointerPath, now)
		return err
	})
	return next, verified, err
}

func requireReadableDataSchema(reader Manifest, storedVersion int) error {
	if storedVersion < reader.MinimumReadableDataSchema || storedVersion > reader.MaximumReadableDataSchema {
		return fmt.Errorf("data schema %d is outside release %s readable range %d..%d", storedVersion, reader.ReleaseID, reader.MinimumReadableDataSchema, reader.MaximumReadableDataSchema)
	}
	return nil
}

func withPointerLock(pointerPath string, requireRootOwner bool, operation func() error) error {
	if !cleanAbsolute(pointerPath) || operation == nil {
		return errors.New("invalid release pointer lock request")
	}
	parent := filepath.Dir(pointerPath)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("release pointer parent is missing or unsafe")
	}
	if requireRootOwner {
		parentStat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || parentStat.Uid != 0 || parentStat.Gid != 0 {
			return errors.New("release pointer parent is not root-owned")
		}
	}
	lockPath := pointerPath + ".lock"
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if !requireRootOwner {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(lockPath, flags, 0o600)
	if err != nil {
		return fmt.Errorf("open release pointer lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer lock.Close()
	lockInfo, err := lock.Stat()
	lockPathInfo, pathErr := os.Lstat(lockPath)
	if err != nil || pathErr != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 || lockInfo.Size() != 0 || lockPathInfo.Mode()&os.ModeSymlink != 0 || !lockPathInfo.Mode().IsRegular() {
		return errors.New("release pointer lock is unsafe")
	}
	openedStat, openedOK := lockInfo.Sys().(*syscall.Stat_t)
	pathStat, pathOK := lockPathInfo.Sys().(*syscall.Stat_t)
	if !openedOK || !pathOK || openedStat.Nlink != 1 || pathStat.Nlink != 1 || openedStat.Dev != pathStat.Dev || openedStat.Ino != pathStat.Ino {
		return errors.New("release pointer lock is unsafe")
	}
	if requireRootOwner && (openedStat.Uid != 0 || openedStat.Gid != 0) {
		return errors.New("release pointer lock is not root-owned")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return errors.New("release pointer is in use by a runtime consumer")
		}
		return fmt.Errorf("lock release pointer: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return operation()
}

func LoadPointer(path string) (Pointer, error) {
	return loadPointer(path, false)
}

func LoadProtectedPointer(path string, requireRootOwner bool) (Pointer, error) {
	if !cleanAbsolute(path) {
		return Pointer{}, errors.New("release pointer path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Pointer{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 || info.Mode().Perm()&0o022 != 0 {
		return Pointer{}, errors.New("release pointer is missing or unsafe")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return Pointer{}, errors.New("release pointer is not owned by root")
		}
	}
	return loadPointer(path, true)
}

func loadPointer(path string, noFollow bool) (Pointer, error) {
	var file *os.File
	var err error
	if noFollow {
		file, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	} else {
		file, err = os.Open(path)
	}
	if err != nil {
		return Pointer{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	var value Pointer
	if err := decoder.Decode(&value); err != nil {
		return Pointer{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Pointer{}, errors.New("release pointer must contain one JSON value")
	}
	if value.SchemaVersion != 1 || (value.Scope != ScopePortal && value.Scope != ScopeRuntime && value.Scope != ScopeShared && value.Scope != ScopeCombined) || !validIdentifier(value.Current) || (value.Previous != "" && !validIdentifier(value.Previous)) || value.ActivatedAt.IsZero() {
		return Pointer{}, errors.New("invalid release pointer")
	}
	return value, nil
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func atomicWrite(path string, payload []byte, mode os.FileMode) error {
	return atomicWriteMode(path, payload, mode, false)
}

func atomicWriteExclusive(path string, payload []byte, mode os.FileMode) error {
	return atomicWriteMode(path, payload, mode, true)
}

func atomicWriteMode(path string, payload []byte, mode os.FileMode, noReplace bool) error {
	err := fsutil.WriteFileAtomic(path, payload, fsutil.AtomicWriteOptions{
		Mode: mode, NoReplace: noReplace, TempPattern: ".workagent-*", CheckParent: true,
	})
	if errors.Is(err, fsutil.ErrUnsafeParent) {
		return errors.New("atomic write parent is not a real directory")
	}
	if errors.Is(err, fsutil.ErrTargetExists) {
		return errors.New("atomic write target already exists")
	}
	return err
}

func parseMode(value string) (os.FileMode, error) {
	if len(value) != 4 || value[0] != '0' {
		return 0, errors.New("file mode must use four octal digits")
	}
	parsed, err := strconv.ParseUint(value, 8, 12)
	return os.FileMode(parsed), err
}

func validIdentifier(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidateReleaseID(value string) error {
	if !validIdentifier(value) {
		return errors.New("release ID is invalid")
	}
	return nil
}

func validRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validEvidenceText(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 1024 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(filepath.FromSlash(value)) != filepath.FromSlash(value) || value == "." || value == ".." || strings.Contains(value, "\\") || strings.HasPrefix(value, "../") {
		return errors.New("path must be clean and relative")
	}
	return nil
}
