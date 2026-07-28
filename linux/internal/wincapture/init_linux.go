//go:build linux

package wincapture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type InitSpecOptions struct {
	LegacySnapshot   string
	MigrationReport  string
	TransportProfile string
	Output           string
}

type InitSpecReport struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	SpecSHA256    string `json:"spec_sha256"`
	Sources       int    `json:"sources"`
	Exclusions    int    `json:"exclusions"`
}

type legacyPortalConfig struct {
	DatabasePath     string
	UserProfilesRoot string
}

type legacyReportSeed struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Tenants       []struct {
		WindowsSID      string `json:"windows_sid"`
		SourceDirectory string `json:"source_directory"`
	} `json:"tenants"`
}

type externalSeed struct {
	SchemaVersion int `json:"schema_version"`
	Workspaces    []struct {
		WindowsPath    string   `json:"windows_path"`
		SourceRelative string   `json:"source_relative"`
		ExcludedPaths  []string `json:"excluded_paths"`
	} `json:"workspaces"`
}

type portalIdentitySeed struct {
	SID      string
	Username string
}

// InitializeSpec creates a private operator spec from the already-protected
// legacy snapshot and its completed migration report. It never contacts or
// writes Windows. The resulting paths still have to pass --check three times
// before the operator may establish a cutover freeze.
func InitializeSpec(ctx context.Context, options InitSpecOptions) (InitSpecReport, error) {
	if os.Geteuid() != 0 {
		return InitSpecReport{}, errors.New("private capture-spec initialization requires root")
	}
	for _, item := range []struct{ value, label string }{{options.LegacySnapshot, "legacy snapshot"}, {options.MigrationReport, "migration report"}, {options.TransportProfile, "SSH transport profile"}, {options.Output, "spec output"}} {
		if err := validateAbsoluteFilePath(item.value, item.label); err != nil {
			return InitSpecReport{}, err
		}
	}
	transport, err := loadSSHTransportProfile(options.TransportProfile, 0)
	if err != nil {
		return InitSpecReport{}, err
	}
	rootFD, _, err := openPrivateRoot(options.LegacySnapshot, 0)
	if err != nil {
		return InitSpecReport{}, errors.New("legacy snapshot must be a real root-owned 0700 directory")
	}
	defer unix.Close(rootFD)
	portalPayload, err := readPrivateLegacyFile(rootFD, "global/portal.json", 8*1024*1024)
	if err != nil {
		return InitSpecReport{}, err
	}
	defer clear(portalPayload)
	portalConfig, err := parseLegacyPortalConfig(portalPayload)
	if err != nil {
		return InitSpecReport{}, err
	}
	reportPayload, err := readPrivateAbsoluteFile(options.MigrationReport, 16*1024*1024, 0)
	if err != nil {
		return InitSpecReport{}, errors.New("read private completed migration report")
	}
	defer clear(reportPayload)
	var report legacyReportSeed
	if err := decodePrivateJSON(reportPayload, &report); err != nil || report.SchemaVersion != 1 || report.Status != "complete" || len(report.Tenants) != 8 {
		return InitSpecReport{}, errors.New("private migration report is not a completed eight-tenant schema-v1 report")
	}
	externalPayload, err := readPrivateLegacyFile(rootFD, "external-workspaces.json", 8*1024*1024)
	if err != nil {
		return InitSpecReport{}, err
	}
	defer clear(externalPayload)
	var external externalSeed
	if err := decodePrivateJSON(externalPayload, &external); err != nil || external.SchemaVersion != 1 || len(external.Workspaces) == 0 {
		return InitSpecReport{}, errors.New("private external-workspace manifest is invalid")
	}
	if _, err := secureLegacyFileInfo(rootFD, "global/portal.windows.db"); err != nil {
		return InitSpecReport{}, err
	}
	identities, err := readLegacyPortalIdentities(ctx, filepath.Join(options.LegacySnapshot, "global", "portal.windows.db"))
	if err != nil {
		return InitSpecReport{}, err
	}
	authDir, err := parseLegacyAuthDirectory(rootFD)
	if err != nil {
		return InitSpecReport{}, err
	}
	portalDatabase, err := windowsPathToGitBash(portalConfig.DatabasePath)
	if err != nil {
		return InitSpecReport{}, errors.New("legacy Portal database path is invalid")
	}
	portalRoot := path.Dir(portalDatabase)
	authPath, err := windowsPathToGitBash(authDir)
	if err != nil {
		return InitSpecReport{}, errors.New("legacy CLIProxy auth directory is invalid")
	}
	cliproxyRoot := path.Dir(authPath)
	spec := Spec{SchemaVersion: SpecSchemaVersion, SSHTransport: transport, ExpectedTenantCount: 8, ExpectedExternalWorkspaceCount: len(external.Workspaces)}
	addFile := func(id, role, source, destination string, minimum int64) error {
		relative := destination
		info, err := secureLegacyFileInfo(rootFD, relative)
		if err != nil {
			return err
		}
		maximum := info.Size*8 + 64*1024*1024
		if maximum < minimum {
			maximum = minimum
		}
		spec.Sources = append(spec.Sources, Source{ID: id, Role: role, SourcePath: source, Destination: destination, Kind: SourceFile, MaxFiles: 1, MaxBytes: maximum, MaxTarBytes: maximum + 1024*1024})
		return nil
	}
	for _, binding := range []struct {
		id, role, source, destination string
		minimum                       int64
	}{
		{"portal-db", RolePortalDatabase, portalDatabase, "global/portal.windows.db", 4 << 30},
		{"portal-wal", RolePortalWAL, portalDatabase + "-wal", "global/portal.windows.db-wal", 4 << 30},
		{"portal-shm", RolePortalSHM, portalDatabase + "-shm", "global/portal.windows.db-shm", 1 << 30},
		{"portal-config", RolePortalConfig, path.Join(portalRoot, "portal.json"), "global/portal.json", 64 << 20},
		{"notification-state", RoleNotification, path.Join(portalRoot, "notification.json"), "global/notification.json", 64 << 20},
		{"chatforward-state", RoleChatForward, path.Join(portalRoot, "chatforward.key"), "global/chatforward.key", 64 << 20},
		{"policy-state", RolePolicyState, path.Join(cliproxyRoot, "cpa-key-policy-state.json"), "cliproxy/cpa-key-policy-state.json", 64 << 20},
		{"cliproxy-config", RoleCLIProxyConfig, path.Join(cliproxyRoot, "config.yaml"), "cliproxy/config.yaml", 64 << 20},
		{"cliproxy-admin", RoleCLIProxyAdmin, path.Join(cliproxyRoot, ".management-key"), "cliproxy/.management-key", 64 << 20},
	} {
		if err := addFile(binding.id, binding.role, binding.source, binding.destination, binding.minimum); err != nil {
			return InitSpecReport{}, err
		}
	}
	identityBySID := make(map[string]string, len(identities))
	for _, identity := range identities {
		identityBySID[identity.SID] = identity.Username
	}
	sort.Slice(report.Tenants, func(i, j int) bool { return report.Tenants[i].SourceDirectory < report.Tenants[j].SourceDirectory })
	for index, tenant := range report.Tenants {
		username, ok := identityBySID[tenant.WindowsSID]
		if !ok || !safePrivateLeaf(tenant.SourceDirectory) {
			return InitSpecReport{}, errors.New("private migration identity mapping is incomplete")
		}
		leaf := windowsAccountLeafForCapture(username)
		if !safePrivateLeaf(leaf) {
			return InitSpecReport{}, errors.New("private Windows account leaf is invalid")
		}
		windowsRoot := strings.TrimRight(portalConfig.UserProfilesRoot, "\\/") + `\` + leaf + `\AionUiPortal`
		remoteRoot, err := windowsPathToGitBash(windowsRoot)
		if err != nil {
			return InitSpecReport{}, errors.New("private tenant source path is invalid")
		}
		destination := path.Join("tenants/raw", tenant.SourceDirectory, "AionUiPortal")
		localRoot := filepath.Join(options.LegacySnapshot, filepath.FromSlash(destination))
		source, err := makeDirectorySource(fmt.Sprintf("tenant-%02d", index+1), RoleTenantTree, remoteRoot, destination, localRoot, nil)
		if err != nil {
			return InitSpecReport{}, err
		}
		spec.Sources = append(spec.Sources, source)
	}
	for index, workspace := range external.Workspaces {
		if !safeRelative(workspace.SourceRelative) || !strings.HasPrefix(workspace.SourceRelative, "external-workspaces/") {
			return InitSpecReport{}, errors.New("private external-workspace source mapping is unsafe")
		}
		remoteRoot, err := windowsPathToGitBash(workspace.WindowsPath)
		if err != nil {
			return InitSpecReport{}, errors.New("private external-workspace Windows path is invalid")
		}
		localRoot := filepath.Join(options.LegacySnapshot, filepath.FromSlash(workspace.SourceRelative))
		source, err := makeDirectorySource(fmt.Sprintf("external-%02d", index+1), RoleExternal, remoteRoot, workspace.SourceRelative, localRoot, workspace.ExcludedPaths)
		if err != nil {
			return InitSpecReport{}, err
		}
		spec.Sources = append(spec.Sources, source)
	}
	manifestDigest := sha256.Sum256(externalPayload)
	manifestCopy := options.Output + ".external-workspaces.json"
	spec.LocalFiles = []LocalFile{{SourcePath: manifestCopy, Destination: "external-workspaces.json", SHA256: hex.EncodeToString(manifestDigest[:]), MaxBytes: 8 * 1024 * 1024}}
	spec.OAuthEvidence = OAuthEvidence{SourcePath: authPath, MaxFiles: 10_000, MaxBytes: 16 << 30}
	var maximumFiles, maximumBytes, exclusionCount int64
	for _, source := range spec.Sources {
		maximumFiles += source.MaxFiles
		maximumBytes += source.MaxBytes
		exclusionCount += int64(len(source.Exclusions))
	}
	maxCapture := maximumBytes + maximumFiles*4096 + 8*1024*1024 + 16*1024*1024
	spec.Limits = AggregateLimits{MaxSources: len(spec.Sources) + 16, MaxTotalFiles: maximumFiles, MaxTotalBytes: maximumBytes, MaxCaptureBytes: maxCapture, MinFreeBytes: 16 << 30}
	if err := validateSpec(spec); err != nil {
		return InitSpecReport{}, err
	}
	payload, err := marshalPrivateJSON(spec)
	if err != nil {
		return InitSpecReport{}, err
	}
	defer clear(payload)
	digest := sha256.Sum256(payload)
	endingTransport, err := loadSSHTransportProfile(options.TransportProfile, 0)
	if err != nil || endingTransport != transport {
		return InitSpecReport{}, errors.New("private SSH transport profile drifted during capture-spec initialization")
	}
	if err := writePrivateSpecNoReplace(manifestCopy, externalPayload, 0); err != nil {
		return InitSpecReport{}, errors.New("publish root-owned private external-workspace companion")
	}
	if err := writePrivateSpecNoReplace(options.Output, payload, 0); err != nil {
		return InitSpecReport{}, err
	}
	return InitSpecReport{SchemaVersion: 1, Status: "private-spec-created-rehearsal-required", SpecSHA256: hex.EncodeToString(digest[:]), Sources: len(spec.Sources), Exclusions: int(exclusionCount)}, nil
}

func parseLegacyPortalConfig(payload []byte) (legacyPortalConfig, error) {
	var raw map[string]json.RawMessage
	if err := decodeStrictJSON(payload, &raw); err != nil {
		return legacyPortalConfig{}, errors.New("private legacy Portal configuration is invalid")
	}
	var result legacyPortalConfig
	for key, destination := range map[string]*string{"database_path": &result.DatabasePath, "user_profiles_root": &result.UserProfilesRoot} {
		if err := json.Unmarshal(raw[key], destination); err != nil || strings.TrimSpace(*destination) == "" {
			return legacyPortalConfig{}, fmt.Errorf("private legacy Portal configuration is missing %s", key)
		}
	}
	return result, nil
}

func readLegacyPortalIdentities(ctx context.Context, databasePath string) ([]portalIdentitySeed, error) {
	dsn := "file:" + filepath.ToSlash(databasePath) + "?mode=ro&immutable=1&_pragma=query_only(1)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.New("open private legacy Portal identity database")
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	rows, err := database.QueryContext(ctx, `SELECT windows_sid,windows_username FROM portal_users ORDER BY id`)
	if err != nil {
		return nil, errors.New("read private legacy Portal identities")
	}
	defer rows.Close()
	var result []portalIdentitySeed
	for rows.Next() {
		var identity portalIdentitySeed
		if err := rows.Scan(&identity.SID, &identity.Username); err != nil || identity.SID == "" || identity.Username == "" {
			return nil, errors.New("private legacy Portal identity is invalid")
		}
		result = append(result, identity)
	}
	if err := rows.Err(); err != nil || len(result) != 8 {
		return nil, errors.New("private legacy Portal identity count is invalid")
	}
	return result, nil
}

func parseLegacyAuthDirectory(rootFD int) (string, error) {
	payload, err := readPrivateLegacyFile(rootFD, "cliproxy/config.yaml", 8*1024*1024)
	if err != nil {
		return "", err
	}
	defer clear(payload)
	var found string
	for _, line := range strings.Split(string(payload), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "auth-dir:") {
			continue
		}
		if found != "" {
			return "", errors.New("legacy CLIProxy configuration has duplicate auth-dir entries")
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "auth-dir:"))
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return "", errors.New("legacy CLIProxy auth-dir quoting is invalid")
			}
			value = decoded
		} else if strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`) && len(value) >= 2 {
			value = strings.ReplaceAll(value[1:len(value)-1], `''`, `'`)
		} else if marker := strings.Index(value, " #"); marker >= 0 {
			value = strings.TrimSpace(value[:marker])
		}
		found = value
	}
	if found == "" {
		return "", errors.New("legacy CLIProxy auth-dir is missing")
	}
	return found, nil
}

func windowsPathToGitBash(value string) (string, error) {
	normalized := strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	if strings.HasPrefix(normalized, "//?/") {
		normalized = normalized[4:]
	}
	if len(normalized) < 4 || normalized[1] != ':' || normalized[2] != '/' || !((normalized[0] >= 'A' && normalized[0] <= 'Z') || (normalized[0] >= 'a' && normalized[0] <= 'z')) || path.Clean(normalized) != normalized || strings.HasSuffix(normalized, "/") {
		return "", errors.New("Windows path is not canonical")
	}
	drive := strings.ToLower(normalized[:1])
	result := "/" + drive + "/" + normalized[3:]
	if err := validateRemotePath(result); err != nil {
		return "", err
	}
	return result, nil
}

func windowsAccountLeafForCapture(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.LastIndexAny(value, `\/`); index >= 0 {
		value = value[index+1:]
	}
	return value
}

func safePrivateLeaf(value string) bool {
	return value != "" && value != "." && value != ".." && fs.ValidPath(value) && !strings.ContainsAny(value, "/\\\x00\r\n")
}

func makeDirectorySource(id, role, remoteRoot, destination, localRoot string, manifestExclusions []string) (Source, error) {
	files, directories, bytesTotal, discovered, err := inventoryLegacyDirectory(localRoot)
	if err != nil {
		return Source{}, err
	}
	byPath := make(map[string]Exclusion)
	for _, exclusion := range discovered {
		byPath[exclusion.Path] = exclusion
	}
	for _, relative := range manifestExclusions {
		exclusion, err := classifyExclusion(relative, localRoot)
		if err != nil {
			return Source{}, err
		}
		byPath[relative] = exclusion
	}
	exclusions := make([]Exclusion, 0, len(byPath))
	for _, exclusion := range byPath {
		exclusions = append(exclusions, exclusion)
	}
	sort.Slice(exclusions, func(i, j int) bool { return exclusions[i].Path < exclusions[j].Path })
	entryMaximum := (files+directories)*8 + 10_000
	if entryMaximum < 100_000 {
		entryMaximum = 100_000
	}
	byteMaximum := bytesTotal*8 + 1024*1024*1024
	if byteMaximum < 8<<30 {
		byteMaximum = 8 << 30
	}
	tarMaximum := byteMaximum + entryMaximum*4096 + 16*1024*1024
	return Source{ID: id, Role: role, SourcePath: remoteRoot, Destination: destination, Kind: SourceDirectory, MaxFiles: entryMaximum, MaxBytes: byteMaximum, MaxTarBytes: tarMaximum, Exclusions: exclusions}, nil
}

func inventoryLegacyDirectory(root string) (files, directories, bytesTotal int64, exclusions []Exclusion, returnedErr error) {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, 0, 0, nil, errors.New("private legacy source directory is unsafe")
	}
	err = filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk private legacy source directory")
		}
		if filename == root {
			directories++
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			directories++
			if exclusion, ok := discoverExclusion(relative, filename); ok {
				exclusions = append(exclusions, exclusion)
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("private legacy source contains a special file")
		}
		files++
		bytesTotal += info.Size()
		return nil
	})
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return files, directories, bytesTotal, exclusions, nil
}

func discoverExclusion(relative, filename string) (Exclusion, bool) {
	leaf := path.Base(relative)
	var kind string
	switch leaf {
	case "node_modules":
		kind = ExcludeNodeModules
	case "__pycache__":
		kind = ExcludePythonBytecode
	case ".pytest_cache":
		kind = ExcludePytestCache
	case ".mypy_cache":
		kind = ExcludeMypyCache
	case ".ruff_cache":
		kind = ExcludeRuffCache
	case ".cache":
		kind = ExcludeDownloadCache
	case ".npm":
		kind = ExcludeNPMCache
	case ".pnpm-store":
		kind = ExcludePNPMStore
	case ".venv", "venv":
		if !positiveLegacyVenv(filename) {
			return Exclusion{}, false
		}
		if relative == "backend/.venv" {
			kind = ExcludeExternalBackendEnv
		} else {
			kind = ExcludePythonVenv
		}
	default:
		return Exclusion{}, false
	}
	return Exclusion{Path: relative, Type: kind}, true
}

func classifyExclusion(relative, localRoot string) (Exclusion, error) {
	if !safeRelative(relative) {
		return Exclusion{}, errors.New("private external exclusion path is unsafe")
	}
	exclusion, ok := discoverExclusion(relative, filepath.Join(localRoot, filepath.FromSlash(relative)))
	if !ok {
		if relative == "backend/.venv" {
			return Exclusion{Path: relative, Type: ExcludeExternalBackendEnv}, nil
		}
		return Exclusion{}, errors.New("private external exclusion is not an approved reconstructable path")
	}
	return exclusion, nil
}

func positiveLegacyVenv(directory string) bool {
	marker, markerErr := os.Lstat(filepath.Join(directory, "pyvenv.cfg"))
	if markerErr != nil || !marker.Mode().IsRegular() || marker.Mode()&os.ModeSymlink != 0 {
		return false
	}
	for _, leaf := range []string{"Scripts", "bin"} {
		info, err := os.Lstat(filepath.Join(directory, leaf))
		if err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return true
		}
	}
	return false
}

func secureLegacyFileInfo(rootFD int, relative string) (unix.Stat_t, error) {
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return unix.Stat_t{}, errors.New("private legacy required file is missing")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || os.FileMode(stat.Mode).Perm() != 0o600 {
		return unix.Stat_t{}, errors.New("private legacy required file is unsafe")
	}
	return stat, nil
}

func readPrivateLegacyFile(rootFD int, relative string, maximum int64) ([]byte, error) {
	expected, err := secureLegacyFileInfo(rootFD, relative)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return nil, errors.New("open private legacy file")
	}
	file := os.NewFile(uintptr(fd), "private-legacy-file")
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !stableFileStat(expected, before) {
		file.Close()
		return nil, errors.New("private legacy file changed while it was opened")
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	var after unix.Stat_t
	statErr := unix.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(payload) == 0 || int64(len(payload)) > maximum || int64(len(payload)) != before.Size || !stableFileStat(before, after) {
		clear(payload)
		return nil, errors.New("private legacy file is unreadable or too large")
	}
	return payload, nil
}

func readPrivateAbsoluteFile(filename string, maximum int64, expectedUID uint32) ([]byte, error) {
	if err := validateAbsoluteFilePath(filename, "private input file"); err != nil {
		return nil, err
	}
	parentFD, _, err := openPrivateRoot(filepath.Dir(filename), expectedUID)
	if err != nil {
		return nil, errors.New("private input file parent is unsafe")
	}
	defer unix.Close(parentFD)
	leaf := filepath.Base(filename)
	if !safePrivateLeaf(leaf) {
		return nil, errors.New("private input filename is unsafe")
	}
	fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: localResolveFlags})
	if err != nil {
		return nil, errors.New("open private input file")
	}
	file := os.NewFile(uintptr(fd), "private-input-file")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != expectedUID || before.Gid != expectedUID || before.Nlink != 1 || before.Size < 1 || before.Size > maximum {
		return nil, errors.New("private input file is unsafe")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		clear(payload)
		return nil, errors.New("private input file is unreadable or too large")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || int64(len(payload)) != before.Size || !stableFileStat(before, after) {
		clear(payload)
		return nil, errors.New("private input file changed while it was read")
	}
	return payload, nil
}

func decodeStrictJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON has trailing data")
	}
	return nil
}

func decodePrivateJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON has trailing data")
	}
	return nil
}

func writePrivateSpecNoReplace(target string, payload []byte, expectedUID uint32) error {
	if err := validateAbsoluteFilePath(target, "private spec output"); err != nil || len(payload) == 0 || len(payload) > maxSpecBytes*8 {
		return errors.New("private spec output path or payload is invalid")
	}
	parent := filepath.Dir(target)
	leaf := filepath.Base(target)
	if !safePrivateLeaf(leaf) {
		return errors.New("private spec output filename is unsafe")
	}
	parentFD, _, err := openPrivateRoot(parent, expectedUID)
	if err != nil {
		return errors.New("private spec output parent must be a real 0700 directory")
	}
	defer unix.Close(parentFD)
	exists, err := privatePayloadMatchesAt(parentFD, leaf, payload, expectedUID)
	if err != nil {
		return err
	}
	if exists {
		if err := unix.Fsync(parentFD); err != nil {
			return errors.New("sync converged private spec parent")
		}
		return nil
	}
	temporaryLeaf, temporaryFD, err := createPrivatePartialAt(parentFD)
	if err != nil {
		return errors.New("create private spec partial")
	}
	temporary := os.NewFile(uintptr(temporaryFD), "private-spec-partial")
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(parentFD, temporaryLeaf, 0)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if written, err := temporary.Write(payload); err != nil || written != len(payload) {
		temporary.Close()
		return errors.New("write private spec partial")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync private spec partial")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close private spec partial")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("sync private spec parent")
	}
	if err := unix.Renameat2(parentFD, temporaryLeaf, parentFD, leaf, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			exists, verifyErr := privatePayloadMatchesAt(parentFD, leaf, payload, expectedUID)
			if verifyErr != nil {
				return verifyErr
			}
			if exists {
				if err := unix.Unlinkat(parentFD, temporaryLeaf, 0); err != nil {
					return errors.New("remove colliding private spec partial")
				}
				published = true
				if err := unix.Fsync(parentFD); err != nil {
					return errors.New("sync private spec parent after convergent collision")
				}
				return nil
			}
		}
		return errors.New("publish private spec without replacement")
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("sync published private spec parent")
	}
	return nil
}

func createPrivatePartialAt(parentFD int) (string, int, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var random [16]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return "", -1, err
		}
		leaf := ".capture-spec.partial-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{
			Flags:   uint64(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Mode:    0o600,
			Resolve: localResolveFlags,
		})
		if err == nil {
			return leaf, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, err
		}
	}
	return "", -1, errors.New("private partial name collision limit exceeded")
}

func privatePayloadMatchesAt(parentFD int, leaf string, payload []byte, expectedUID uint32) (bool, error) {
	fd, err := unix.Openat2(parentFD, leaf, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: localResolveFlags,
	})
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("private spec output already exists but is unsafe")
	}
	file := os.NewFile(uintptr(fd), "existing-private-spec")
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(before.Mode).Perm() != 0o600 ||
		before.Uid != expectedUID || before.Gid != expectedUID || before.Nlink != 1 || before.Size != int64(len(payload)) {
		return false, errors.New("private spec output already exists but is unsafe or different")
	}
	existing, err := io.ReadAll(io.LimitReader(file, int64(len(payload))+1))
	if err != nil {
		clear(existing)
		return false, errors.New("read existing private spec output")
	}
	defer clear(existing)
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !stableFileStat(before, after) {
		return false, errors.New("private spec output changed while it was verified")
	}
	if !bytes.Equal(existing, payload) {
		return false, errors.New("private spec output already exists with different content")
	}
	return true, nil
}
