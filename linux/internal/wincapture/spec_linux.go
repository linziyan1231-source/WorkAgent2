//go:build linux

package wincapture

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
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const maxSpecBytes = 1024 * 1024

var (
	safeIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	sha256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	captureIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{7,79}$`)
)

type loadedSpec struct {
	value  Spec
	digest string
}

func loadSpec(filename string, expectedUID uint32) (loadedSpec, error) {
	if err := validateAbsoluteFilePath(filename, "capture spec"); err != nil {
		return loadedSpec{}, err
	}
	parent := filepath.Dir(filename)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || resolvedParent != parent {
		return loadedSpec{}, errors.New("capture spec parent path must not contain symbolic links")
	}
	parentFD, _, err := openPrivateRoot(parent, expectedUID)
	if err != nil {
		return loadedSpec{}, errors.New("capture spec parent must be a real private 0700 directory")
	}
	defer unix.Close(parentFD)
	leaf := filepath.Base(filename)
	if !safePrivateLeaf(leaf) {
		return loadedSpec{}, errors.New("capture spec filename is unsafe")
	}
	fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return loadedSpec{}, errors.New("open capture spec")
	}
	file := os.NewFile(uintptr(fd), "private-capture-spec")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != expectedUID || before.Gid != expectedUID || before.Nlink != 1 {
		return loadedSpec{}, errors.New("capture spec must be a real private 0600 regular file with one link")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxSpecBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maxSpecBytes {
		return loadedSpec{}, errors.New("capture spec is empty, unreadable, or too large")
	}
	defer clear(payload)
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !stableFileStat(before, after) || after.Size != int64(len(payload)) {
		return loadedSpec{}, errors.New("capture spec changed while it was read")
	}
	var spec Spec
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return loadedSpec{}, errors.New("capture spec is not strict JSON")
	}
	if err := validateSpec(spec); err != nil {
		return loadedSpec{}, err
	}
	digest := sha256.Sum256(payload)
	return loadedSpec{value: spec, digest: hex.EncodeToString(digest[:])}, nil
}

func validateSpec(spec Spec) error {
	if spec.SchemaVersion != SpecSchemaVersion {
		return errors.New("capture spec schema version is unsupported")
	}
	if spec.ExpectedTenantCount != 8 {
		return errors.New("capture spec must bind exactly eight tenant trees")
	}
	if spec.ExpectedExternalWorkspaceCount < 1 || spec.ExpectedExternalWorkspaceCount > 128 {
		return errors.New("capture spec external-workspace count is invalid")
	}
	limits := spec.Limits
	if limits.MaxSources < 5 || limits.MaxSources > 2048 || len(spec.Sources) > limits.MaxSources ||
		limits.MaxTotalFiles < 1 || limits.MaxTotalBytes < 1 || limits.MaxCaptureBytes < limits.MaxTotalBytes ||
		limits.MaxCaptureBytes > 2<<40 || limits.MinFreeBytes < 0 || limits.MinFreeBytes > 1<<40 {
		return errors.New("capture spec aggregate limits are invalid")
	}
	if len(spec.Sources) == 0 || len(spec.Sources) > 2048 {
		return errors.New("capture spec source count is invalid")
	}
	roles := make(map[string]int)
	ids := make(map[string]bool)
	destinations := []string{"journal-start.json", "evidence-before.json", "evidence-after.json", "capture-manifest.json", "failure.json"}
	sourcePaths := make([]string, 0, len(spec.Sources))
	var declaredFiles, declaredBytes int64
	for index := range spec.Sources {
		source := &spec.Sources[index]
		if err := validateSource(source); err != nil {
			return fmt.Errorf("capture source %d: %w", index+1, err)
		}
		if ids[source.ID] {
			return errors.New("capture source IDs must be unique")
		}
		ids[source.ID] = true
		roles[source.Role]++
		destinations = append(destinations, source.Destination)
		sourcePaths = append(sourcePaths, source.SourcePath)
		if source.MaxFiles > limits.MaxTotalFiles-declaredFiles || source.MaxBytes > limits.MaxTotalBytes-declaredBytes {
			return errors.New("capture source limits exceed aggregate limits")
		}
		declaredFiles += source.MaxFiles
		declaredBytes += source.MaxBytes
	}
	if roles[RolePortalDatabase] != 1 || roles[RolePortalWAL] != 1 || roles[RolePortalSHM] != 1 || roles[RolePortalConfig] != 1 ||
		roles[RoleNotification] != 1 || roles[RoleChatForward] != 1 || roles[RolePolicyState] != 1 ||
		roles[RoleCLIProxyConfig] != 1 || roles[RoleCLIProxyAdmin] != 1 || roles[RoleTenantTree] != spec.ExpectedTenantCount ||
		roles[RoleExternal] != spec.ExpectedExternalWorkspaceCount {
		return errors.New("capture spec does not bind the complete Portal, ChatForward, notification, CLIProxy, tenant, and external migration state")
	}
	for _, role := range []string{RolePortalDatabase, RolePortalWAL, RolePortalSHM, RolePortalConfig, RoleNotification, RoleChatForward, RolePolicyState, RoleCLIProxyConfig, RoleCLIProxyAdmin} {
		for _, source := range spec.Sources {
			if source.Role == role && source.Kind != SourceFile {
				return fmt.Errorf("role %s must bind one regular file", role)
			}
		}
	}
	if err := validateOAuthEvidence(spec.OAuthEvidence); err != nil {
		return err
	}
	for first := range sourcePaths {
		for second := first + 1; second < len(sourcePaths); second++ {
			if absoluteRootsOverlap(sourcePaths[first], sourcePaths[second]) {
				return errors.New("capture source paths must not overlap")
			}
		}
		if absoluteRootsOverlap(sourcePaths[first], spec.OAuthEvidence.SourcePath) {
			return errors.New("OAuth evidence directory must not overlap a copied source")
		}
	}
	if len(spec.LocalFiles) == 0 || len(spec.LocalFiles) > 16 {
		return errors.New("capture spec local-input count is invalid")
	}
	var localMaximumBytes int64
	for index := range spec.LocalFiles {
		local := &spec.LocalFiles[index]
		if err := validateAbsoluteFilePath(local.SourcePath, "local input"); err != nil || !safeRelative(local.Destination) ||
			!sha256Pattern.MatchString(local.SHA256) || local.MaxBytes < 1 || local.MaxBytes > 64*1024*1024 {
			return fmt.Errorf("local input %d is invalid", index+1)
		}
		destinations = append(destinations, local.Destination)
		if local.MaxBytes > (1<<40)-localMaximumBytes {
			return errors.New("capture local-input limits overflow")
		}
		localMaximumBytes += local.MaxBytes
	}
	manifestInputs := 0
	for _, local := range spec.LocalFiles {
		if local.Destination == "external-workspaces.json" {
			manifestInputs++
		}
	}
	if manifestInputs != 1 {
		return errors.New("capture spec must bind one private external-workspaces.json local input")
	}
	metadataAllowance := int64(16 * 1024 * 1024)
	if declaredFiles > ((1<<62)-metadataAllowance)/4096 {
		return errors.New("capture entry limits overflow disk estimate")
	}
	estimatedCaptureBytes := metadataAllowance + declaredFiles*4096
	if declaredBytes > (1<<62)-estimatedCaptureBytes || localMaximumBytes > (1<<62)-(estimatedCaptureBytes+declaredBytes) {
		return errors.New("capture byte limits overflow disk estimate")
	}
	estimatedCaptureBytes += declaredBytes + localMaximumBytes
	if estimatedCaptureBytes > limits.MaxCaptureBytes {
		return errors.New("capture source, local-input, and filesystem-overhead limits exceed max_capture_bytes")
	}
	for first := range destinations {
		for second := first + 1; second < len(destinations); second++ {
			if relativeRootsOverlap(destinations[first], destinations[second]) {
				return errors.New("capture destinations must not overlap")
			}
		}
	}
	return nil
}

func validateSource(source *Source) error {
	if !safeIDPattern.MatchString(source.ID) {
		return errors.New("source ID is invalid")
	}
	switch source.Role {
	case RolePortalDatabase, RolePortalWAL, RolePortalSHM, RolePortalConfig, RoleNotification, RoleChatForward, RoleTenantTree, RolePolicyState, RoleCLIProxyConfig, RoleCLIProxyAdmin, RoleExternal, RoleSupplemental:
	default:
		return errors.New("source role is invalid")
	}
	if err := validateRemotePath(source.SourcePath); err != nil {
		return err
	}
	if !safeRelative(source.Destination) {
		return errors.New("source destination is unsafe")
	}
	if source.Kind != SourceFile && source.Kind != SourceDirectory {
		return errors.New("source kind is invalid")
	}
	if (source.Role == RoleTenantTree || source.Role == RoleExternal) && source.Kind != SourceDirectory {
		return errors.New("tenant and external sources must be directories")
	}
	if source.MaxFiles < 1 || source.MaxFiles > 20_000_000 || source.MaxBytes < 0 || source.MaxBytes > 1<<40 ||
		source.MaxTarBytes < 1024 || source.MaxTarBytes > 2<<40 || source.MaxTarBytes < source.MaxBytes {
		return errors.New("source size limits are invalid")
	}
	if source.Kind == SourceFile && (source.MaxFiles != 1 || len(source.Exclusions) != 0) {
		return errors.New("regular-file sources must bind one file and have no exclusions")
	}
	switch source.Role {
	case RolePortalDatabase:
		if source.Destination != "global/portal.windows.db" {
			return errors.New("Portal database destination is not the migration contract path")
		}
	case RolePortalWAL:
		if source.Destination != "global/portal.windows.db-wal" {
			return errors.New("Portal WAL destination is not the migration contract path")
		}
	case RolePortalSHM:
		if source.Destination != "global/portal.windows.db-shm" {
			return errors.New("Portal SHM destination is not the migration contract path")
		}
	case RolePortalConfig:
		if source.Destination != "global/portal.json" {
			return errors.New("Portal configuration destination is not the migration contract path")
		}
	case RoleNotification:
		if source.Destination != "global/notification.json" {
			return errors.New("notification-state destination is not the migration contract path")
		}
	case RoleChatForward:
		if source.Destination != "global/chatforward.key" {
			return errors.New("ChatForward-state destination is not the migration contract path")
		}
	case RolePolicyState:
		if source.Destination != "cliproxy/cpa-key-policy-state.json" {
			return errors.New("CLIProxy policy destination is not the migration contract path")
		}
	case RoleCLIProxyConfig:
		if source.Destination != "cliproxy/config.yaml" {
			return errors.New("CLIProxy configuration destination is not the migration contract path")
		}
	case RoleCLIProxyAdmin:
		if source.Destination != "cliproxy/.management-key" {
			return errors.New("CLIProxy management-state destination is not the migration contract path")
		}
	case RoleTenantTree:
		if !strings.HasPrefix(source.Destination, "tenants/raw/") || !strings.HasSuffix(source.Destination, "/AionUiPortal") {
			return errors.New("tenant destination is not below the private migration raw-tree contract")
		}
		if _, err := capturedBuiltinSkillsPrefix(*source); err != nil {
			return err
		}
	case RoleExternal:
		if !strings.HasPrefix(source.Destination, "external-workspaces/") {
			return errors.New("external workspace destination is not below its migration contract root")
		}
	}
	seen := make(map[string]bool)
	for _, exclusion := range source.Exclusions {
		if !safeRelative(exclusion.Path) || seen[exclusion.Path] {
			return errors.New("source exclusion is unsafe or duplicated")
		}
		seen[exclusion.Path] = true
		if err := validateExclusion(exclusion); err != nil {
			return err
		}
	}
	sort.Slice(source.Exclusions, func(i, j int) bool { return source.Exclusions[i].Path < source.Exclusions[j].Path })
	for first := range source.Exclusions {
		for second := first + 1; second < len(source.Exclusions); second++ {
			if relativeRootsOverlap(source.Exclusions[first].Path, source.Exclusions[second].Path) {
				return errors.New("source exclusions must not overlap")
			}
		}
	}
	return nil
}

func validateExclusion(exclusion Exclusion) error {
	leaf := path.Base(exclusion.Path)
	valid := false
	switch exclusion.Type {
	case ExcludeNodeModules:
		valid = leaf == "node_modules"
	case ExcludePythonVenv:
		valid = leaf == ".venv" || leaf == "venv"
	case ExcludePythonBytecode:
		valid = leaf == "__pycache__"
	case ExcludePytestCache:
		valid = leaf == ".pytest_cache"
	case ExcludeMypyCache:
		valid = leaf == ".mypy_cache"
	case ExcludeRuffCache:
		valid = leaf == ".ruff_cache"
	case ExcludeDownloadCache:
		valid = leaf == ".cache"
	case ExcludeNPMCache:
		valid = leaf == ".npm"
	case ExcludePNPMStore:
		valid = leaf == ".pnpm-store"
	case ExcludeExternalBackendEnv:
		valid = exclusion.Path == "backend/.venv"
	default:
		return errors.New("source exclusion type is not approved")
	}
	if !valid {
		return errors.New("source exclusion path does not match its approved type")
	}
	return nil
}

func validateOAuthEvidence(evidence OAuthEvidence) error {
	if err := validateRemotePath(evidence.SourcePath); err != nil {
		return errors.New("OAuth evidence path is invalid")
	}
	if evidence.MaxFiles < 1 || evidence.MaxFiles > 1_000_000 || evidence.MaxBytes < 0 || evidence.MaxBytes > 64<<30 {
		return errors.New("OAuth evidence limits are invalid")
	}
	return nil
}

func validateRemotePath(value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "/" ||
		strings.ContainsAny(value, "\x00\r\n") || !utf8.ValidString(value) || len(value) > 4096 {
		return errors.New("remote source path must be a clean absolute Git Bash path")
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("remote source path contains an unsafe component")
		}
	}
	return nil
}

func validateAbsoluteFilePath(value, label string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s path must be clean and absolute", label)
	}
	return nil
}

func safeRelative(value string) bool {
	return value != "" && value != "." && fs.ValidPath(value) && !strings.ContainsAny(value, "\\\x00\r\n")
}

// safeCapturedRelative is for names read from a NUL-delimited remote
// inventory or tar stream. Windows forbids NUL and backslash in these Git Bash
// paths, but a newline is a legal filename byte and must not become a record
// delimiter or silently lose user data.
func safeCapturedRelative(value string) bool {
	return value != "" && value != "." && fs.ValidPath(value) && !strings.ContainsAny(value, "\\\x00")
}

func relativeRootsOverlap(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func absoluteRootsOverlap(first, second string) bool {
	first = strings.ToLower(first)
	second = strings.ToLower(second)
	return relativeRootsOverlap(strings.TrimPrefix(first, "/"), strings.TrimPrefix(second, "/"))
}

func validCaptureID(value string) bool { return captureIDPattern.MatchString(value) }
