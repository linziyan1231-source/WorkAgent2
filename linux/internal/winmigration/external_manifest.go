package winmigration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type externalWorkspaceManifest struct {
	SchemaVersion int                              `json:"schema_version"`
	Workspaces    []externalWorkspaceManifestEntry `json:"workspaces"`
}

type externalWorkspaceManifestEntry struct {
	TenantWindowsSID    string                         `json:"tenant_windows_sid"`
	WindowsPath         string                         `json:"windows_path"`
	SourceRelative      string                         `json:"source_relative"`
	DestinationRelative string                         `json:"destination_relative"`
	ExcludedPaths       []string                       `json:"excluded_paths"`
	SourceSummary       ExternalWorkspaceSourceSummary `json:"source_summary"`
}

func loadExternalWorkspaceManifest(snapshotFD int, options Options) (map[string][]externalWorkspaceManifestEntry, string, error) {
	result := make(map[string][]externalWorkspaceManifestEntry)
	if options.ExternalWorkspaceManifest == "" {
		return result, "", nil
	}
	relative, err := snapshotRelativePath(options.SnapshotRoot, options.ExternalWorkspaceManifest)
	if err != nil {
		return nil, "", err
	}
	payload, err := readSecurePrivateFile(snapshotFD, relative, 1024*1024)
	if err != nil {
		return nil, "", fmt.Errorf("read external workspace manifest: %w", err)
	}
	defer clear(payload)
	var manifest externalWorkspaceManifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, "", errors.New("external workspace manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || manifest.SchemaVersion != 1 || len(manifest.Workspaces) == 0 {
		return nil, "", errors.New("external workspace manifest must contain a non-empty schema v1 workspace list")
	}
	seenSources := make(map[string]int)
	seenWindowsRoots := make(map[string]int)
	seenDestinations := make(map[string]int)
	for index := range manifest.Workspaces {
		entry := &manifest.Workspaces[index]
		if strings.TrimSpace(entry.TenantWindowsSID) != entry.TenantWindowsSID || !windowsSIDPattern.MatchString(entry.TenantWindowsSID) {
			return nil, "", fmt.Errorf("external workspace manifest entry %d has an invalid canonical tenant SID", index+1)
		}
		normalizedWindowsPath, err := normalizeWindowsAbsoluteRoot(entry.WindowsPath)
		if err != nil {
			return nil, "", fmt.Errorf("external workspace manifest entry %d has an invalid Windows root", index+1)
		}
		entry.WindowsPath = normalizedWindowsPath
		if !fs.ValidPath(entry.SourceRelative) || !strings.HasPrefix(entry.SourceRelative, "external-workspaces/") {
			return nil, "", fmt.Errorf("external workspace manifest entry %d has an unsafe capture path", index+1)
		}
		if !fs.ValidPath(entry.DestinationRelative) || !strings.HasPrefix(entry.DestinationRelative, "workspace/") {
			return nil, "", fmt.Errorf("external workspace manifest entry %d must target a path below workspace/", index+1)
		}
		if err := validateExternalSourceSummary(entry.SourceSummary); err != nil {
			return nil, "", fmt.Errorf("external workspace manifest entry %d source summary: %w", index+1, err)
		}
		excluded := make(map[string]bool, len(entry.ExcludedPaths))
		for _, excludedPath := range entry.ExcludedPaths {
			if !fs.ValidPath(excludedPath) || excluded[excludedPath] {
				return nil, "", fmt.Errorf("external workspace manifest entry %d has an invalid or duplicate exclusion", index+1)
			}
			excluded[excludedPath] = true
		}
		sort.Strings(entry.ExcludedPaths)
		foldedWindows := strings.ToLower(entry.WindowsPath)
		foldedSource := strings.ToLower(entry.SourceRelative)
		foldedDestination := strings.ToLower(entry.TenantWindowsSID + "\x00" + entry.DestinationRelative)
		for previousRoot, previousIndex := range seenWindowsRoots {
			if windowsRootsOverlap(previousRoot, foldedWindows) {
				return nil, "", fmt.Errorf("external workspace manifest entries %d and %d have overlapping Windows roots", previousIndex, index+1)
			}
		}
		for previousSource, previousIndex := range seenSources {
			if pathRootsOverlap(previousSource, foldedSource) {
				return nil, "", fmt.Errorf("external workspace manifest entries %d and %d have overlapping capture paths", previousIndex, index+1)
			}
		}
		if previous := seenDestinations[foldedDestination]; previous != 0 {
			return nil, "", fmt.Errorf("external workspace manifest entries %d and %d reuse a destination", previous, index+1)
		}
		seenWindowsRoots[foldedWindows] = index + 1
		seenSources[foldedSource] = index + 1
		seenDestinations[foldedDestination] = index + 1
		result[entry.TenantWindowsSID] = append(result[entry.TenantWindowsSID], *entry)
	}
	for sid := range result {
		sort.Slice(result[sid], func(i, j int) bool {
			return result[sid][i].WindowsPath < result[sid][j].WindowsPath
		})
	}
	digest := sha256.Sum256(payload)
	return result, hex.EncodeToString(digest[:]), nil
}

func snapshotRelativePath(snapshotRoot, target string) (string, error) {
	relative, err := filepath.Rel(snapshotRoot, target)
	if err != nil {
		return "", errors.New("resolve snapshot-relative path")
	}
	relative = filepath.ToSlash(relative)
	if !fs.ValidPath(relative) {
		return "", errors.New("snapshot-relative path is unsafe")
	}
	return relative, nil
}

func normalizeWindowsAbsoluteRoot(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", errors.New("empty or padded Windows path")
	}
	normalized := strings.ReplaceAll(value, `\`, "/")
	if strings.HasPrefix(normalized, "//?/") {
		normalized = normalized[4:]
	}
	if !isWindowsAbsolutePath(normalized) || strings.HasPrefix(normalized, "//") || len(normalized) < 4 {
		return "", errors.New("Windows workspace root must be an absolute drive path below the drive root")
	}
	if path.Clean(normalized) != normalized || strings.HasSuffix(normalized, "/") {
		return "", errors.New("Windows workspace root must be canonical")
	}
	for _, component := range strings.Split(normalized[3:], "/") {
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, '\x00') {
			return "", errors.New("Windows workspace root contains an unsafe component")
		}
	}
	return strings.ToUpper(normalized[:1]) + normalized[1:], nil
}

func validateExternalSourceSummary(summary ExternalWorkspaceSourceSummary) error {
	if summary.Files < 0 || summary.Directories < 1 || summary.Bytes < 0 || summary.Symlinks < 0 || summary.SpecialFiles < 0 || summary.LargestFileBytes < 0 || summary.GitTrackedFiles < 0 || summary.GitIgnoredFiles < 0 || summary.GitStatusEntries < 0 {
		return errors.New("counts must be non-negative and include at least the source root directory")
	}
	if summary.Symlinks != 0 || summary.SpecialFiles != 0 {
		return errors.New("only an audited source with no links or special files can be admitted")
	}
	if strings.ContainsAny(summary.GitBranch, "\r\n\x00") {
		return errors.New("Git branch is malformed")
	}
	return nil
}

func windowsRootsOverlap(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func sourcePathDigest(normalizedWindowsPath string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(normalizedWindowsPath)))
	return hex.EncodeToString(digest[:])
}

func planExternalWorkspaces(ctx context.Context, snapshotFD int, tenant *plannedTenant, manifestEntries []externalWorkspaceManifestEntry) error {
	for _, manifestEntry := range manifestEntries {
		if err := validateExternalDestination(*tenant, manifestEntry.DestinationRelative); err != nil {
			return err
		}
		inventory, err := inventoryTree(ctx, snapshotFD, manifestEntry.SourceRelative)
		if err != nil {
			return fmt.Errorf("inventory external workspace capture: %w", err)
		}
		if inventory.symlinks != 0 {
			return errors.New("external workspace capture contains a symbolic link")
		}
		if len(inventory.skipped) != 0 {
			return errors.New("external workspace capture contains a tenant-only transient path")
		}
		for _, excludedPath := range manifestEntry.ExcludedPaths {
			if inventoryContainsPath(inventory.entries, excludedPath) {
				return errors.New("external workspace capture contains a path declared as excluded")
			}
		}
		if err := validateCapturedSummary(inventory, manifestEntry.SourceSummary); err != nil {
			return err
		}
		planned := plannedExternalWorkspace{
			windowsPath:         manifestEntry.WindowsPath,
			sourceRelative:      manifestEntry.SourceRelative,
			destinationRelative: manifestEntry.DestinationRelative,
			entries:             inventory.entries,
			report: ExternalWorkspaceReport{
				SourcePathSHA256:    sourcePathDigest(manifestEntry.WindowsPath),
				DestinationRelative: manifestEntry.DestinationRelative,
				Files:               inventory.files,
				Directories:         inventory.directories,
				Bytes:               inventory.bytes,
				SourceTreeSHA256:    inventory.hash,
				ExcludedPaths:       append([]string(nil), manifestEntry.ExcludedPaths...),
				SourceSummary:       manifestEntry.SourceSummary,
			},
		}
		tenant.externalWorkspaces = append(tenant.externalWorkspaces, planned)
		tenant.report.ExternalWorkspaces = append(tenant.report.ExternalWorkspaces, planned.report)
	}
	return nil
}

func validateCapturedSummary(inventory treeInventory, summary ExternalWorkspaceSourceSummary) error {
	if inventory.files > summary.Files || inventory.directories+1 > summary.Directories || inventory.bytes > summary.Bytes {
		return errors.New("external workspace capture exceeds its audited source summary")
	}
	var largest int64
	for _, entry := range inventory.entries {
		if entry.Kind == 'f' && entry.Size > largest {
			largest = entry.Size
		}
	}
	if largest > summary.LargestFileBytes || (summary.Files > 0 && summary.LargestFileBytes == 0) {
		return errors.New("external workspace capture conflicts with its audited largest-file summary")
	}
	return nil
}

func inventoryContainsPath(entries []treeEntry, target string) bool {
	for _, entry := range entries {
		if entry.Path == target || strings.HasPrefix(entry.Path, target+"/") {
			return true
		}
	}
	return false
}

func validateExternalDestination(tenant plannedTenant, destination string) error {
	for _, workspace := range tenant.externalWorkspaces {
		if pathRootsOverlap(workspace.destinationRelative, destination) {
			return errors.New("external workspace destinations overlap")
		}
	}
	for _, entry := range tenant.entries {
		output, err := outputRelative(entry.Path)
		if err != nil {
			return err
		}
		if output == destination || strings.HasPrefix(output, destination+"/") {
			return errors.New("external workspace destination collides with tenant snapshot content")
		}
		if strings.HasPrefix(destination, output+"/") && entry.Kind != 'd' {
			return errors.New("external workspace destination has a non-directory tenant ancestor")
		}
	}
	return nil
}

func pathRootsOverlap(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func pathIdentityForTenant(tenant plannedTenant) pathIdentity {
	identity := pathIdentity{WindowsLeaf: tenant.windowsLeaf, LinuxRoot: tenant.report.DataRoot}
	for _, workspace := range tenant.externalWorkspaces {
		identity.External = append(identity.External, externalPathMapping{
			WindowsRoot: workspace.windowsPath,
			LinuxRoot:   filepath.Join(tenant.report.DataRoot, filepath.FromSlash(workspace.destinationRelative)),
		})
	}
	return identity
}
