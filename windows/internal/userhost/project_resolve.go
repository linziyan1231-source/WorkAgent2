package userhost

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aionuiportal/internal/ipc"
	"aionuiportal/internal/projectfs"
)

func resolveProjectState(workspaceRoot, projectID string) (ipc.ProjectResolveResult, string, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return ipc.ProjectResolveResult{}, "INVALID_PROJECT_ID", errors.New("project id is required")
	}
	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		return ipc.ProjectResolveResult{}, "PROJECT_RESOLVE_FAILED", err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		candidate := filepath.Join(workspaceRoot, entry.Name())
		info, err := os.Lstat(candidate)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		marker, err := projectfs.ReadMarker(candidate)
		if err == nil && marker.ProjectID == projectID {
			return ipc.ProjectResolveResult{Path: candidate}, "", nil
		}
	}
	return ipc.ProjectResolveResult{}, "PROJECT_NOT_FOUND", errors.New("project id was not found")
}

func listProjectStates(workspaceRoot string) (ipc.ProjectListResult, string, error) {
	if err := requireNormalDirectory(workspaceRoot); err != nil {
		return ipc.ProjectListResult{}, "PROJECT_LIST_FAILED", err
	}
	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		return ipc.ProjectListResult{}, "PROJECT_LIST_FAILED", err
	}
	projects := make([]ipc.ProjectListItem, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".shared-migrating-") {
			continue
		}
		candidate := filepath.Join(workspaceRoot, entry.Name())
		info, err := os.Lstat(candidate)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || windowsReparse(info) {
			continue
		}
		marker, err := projectfs.ReadMarker(candidate)
		if err != nil {
			continue
		}
		projects = append(projects, ipc.ProjectListItem{ProjectID: marker.ProjectID, Name: entry.Name()})
	}
	sort.Slice(projects, func(i, j int) bool { return strings.ToLower(projects[i].Name) < strings.ToLower(projects[j].Name) })
	return ipc.ProjectListResult{Projects: projects}, "", nil
}
