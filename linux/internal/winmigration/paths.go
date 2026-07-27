package winmigration

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

type pathIdentity struct {
	WindowsLeaf string
	LinuxRoot   string
	External    []externalPathMapping
}

type externalPathMapping struct {
	WindowsRoot string
	LinuxRoot   string
}

var errExternalWindowsPath = errors.New("stored Windows path is outside the owning tenant root")

func rewriteWindowsTenantPath(value string, identity pathIdentity) (string, bool, error) {
	if value == "" {
		return value, false, nil
	}
	if filepath.IsAbs(value) && pathWithin(identity.LinuxRoot, value) {
		return filepath.Clean(value), filepath.Clean(value) != value, nil
	}
	normalized := strings.ReplaceAll(value, `\`, "/")
	if strings.HasPrefix(normalized, "//?/") {
		normalized = normalized[4:]
	}
	prefix := "C:/Users/" + identity.WindowsLeaf + "/AionUiPortal"
	if len(normalized) >= len(prefix) && strings.EqualFold(normalized[:len(prefix)], prefix) && (len(normalized) == len(prefix) || normalized[len(prefix)] == '/') {
		tail := strings.TrimPrefix(normalized[len(prefix):], "/")
		components := []string{}
		if tail != "" {
			if !fs.ValidPath(tail) {
				return "", false, errors.New("Windows tenant path contains an unsafe component")
			}
			components = strings.Split(tail, "/")
			for _, component := range components {
				if component == "" || component == "." || component == ".." {
					return "", false, errors.New("Windows tenant path contains an unsafe component")
				}
			}
		}
		if len(components) > 0 && strings.EqualFold(components[0], "profile") {
			components[0] = "home"
		}
		rewritten := identity.LinuxRoot
		for _, component := range components {
			rewritten = filepath.Join(rewritten, component)
		}
		if !pathWithin(identity.LinuxRoot, rewritten) {
			return "", false, errors.New("rewritten tenant path escapes the Linux tenant root")
		}
		return rewritten, rewritten != value, nil
	}
	for _, mapping := range identity.External {
		if len(normalized) < len(mapping.WindowsRoot) || !strings.EqualFold(normalized[:len(mapping.WindowsRoot)], mapping.WindowsRoot) || (len(normalized) != len(mapping.WindowsRoot) && normalized[len(mapping.WindowsRoot)] != '/') {
			continue
		}
		tail := strings.TrimPrefix(normalized[len(mapping.WindowsRoot):], "/")
		if tail != "" && !fs.ValidPath(tail) {
			return "", false, errors.New("external Windows path contains an unsafe component")
		}
		rewritten := mapping.LinuxRoot
		if tail != "" {
			rewritten = filepath.Join(rewritten, filepath.FromSlash(tail))
		}
		if !pathWithin(identity.LinuxRoot, rewritten) || !pathWithin(mapping.LinuxRoot, rewritten) {
			return "", false, errors.New("rewritten external workspace path escapes its Linux destination")
		}
		return rewritten, rewritten != value, nil
	}
	if isWindowsAbsolutePath(normalized) {
		return "", false, errExternalWindowsPath
	}
	return value, false, nil
}

func isWindowsAbsolutePath(normalized string) bool {
	return (len(normalized) >= 3 && ((normalized[0] >= 'A' && normalized[0] <= 'Z') || (normalized[0] >= 'a' && normalized[0] <= 'z')) && normalized[1] == ':' && normalized[2] == '/') || strings.HasPrefix(normalized, "//")
}

func outputRelative(sourceRelative string) (string, error) {
	if sourceRelative == "profile" {
		return "home", nil
	}
	if strings.HasPrefix(sourceRelative, "profile/") {
		return "home/" + strings.TrimPrefix(sourceRelative, "profile/"), nil
	}
	if !fs.ValidPath(sourceRelative) {
		return "", errors.New("invalid tenant-relative path")
	}
	return sourceRelative, nil
}

func validatePlannedSymlinks(tenant plannedTenant) error {
	outputs := make(map[string]treeEntry, len(tenant.entries))
	for _, entry := range tenant.entries {
		output, err := outputRelative(entry.Path)
		if err != nil {
			return err
		}
		if _, duplicate := outputs[output]; duplicate {
			return fmt.Errorf("source paths collide at Linux path %q", output)
		}
		outputs[output] = entry
	}
	for _, entry := range tenant.entries {
		if entry.Kind != 'l' {
			continue
		}
		output, err := outputRelative(entry.Path)
		if err != nil {
			return err
		}
		rewritten, targetOutput, err := rewriteBuiltinLink(output, entry.LinkTarget, tenant.windowsLeaf)
		if err != nil {
			return err
		}
		if _, exists := outputs[targetOutput]; !exists {
			return fmt.Errorf("builtin-skills link %q points to a missing staged target", output)
		}
		resolved := path.Clean(path.Join(path.Dir(output), rewritten))
		if resolved != targetOutput || resolved == ".." || strings.HasPrefix(resolved, "../") {
			return fmt.Errorf("rewritten link %q would escape the tenant root", output)
		}
	}
	return nil
}

func rewriteBuiltinLink(linkOutput, target, windowsLeaf string) (rewritten string, targetOutput string, err error) {
	normalized := strings.ReplaceAll(target, `\`, "/")
	if strings.HasPrefix(normalized, "//?/") {
		normalized = normalized[4:]
	}
	var prefix string
	if strings.HasPrefix(strings.ToLower(normalized), "/c/users/") {
		prefix = "/c/Users/" + windowsLeaf + "/AionUiPortal/data/builtin-skills/"
	} else {
		prefix = "C:/Users/" + windowsLeaf + "/AionUiPortal/data/builtin-skills/"
	}
	if len(normalized) < len(prefix) || !strings.EqualFold(normalized[:len(prefix)], prefix) {
		return "", "", errors.New("symbolic link is not an approved same-tenant builtin-skills link")
	}
	suffix := normalized[len(prefix):]
	if suffix == "" || !fs.ValidPath(suffix) {
		return "", "", errors.New("builtin-skills symbolic link has an unsafe target")
	}
	targetOutput = path.Join("data/builtin-skills", suffix)
	parent := path.Dir(linkOutput)
	relative, err := filepath.Rel(filepath.FromSlash(parent), filepath.FromSlash(targetOutput))
	if err != nil {
		return "", "", err
	}
	rewritten = filepath.ToSlash(relative)
	return rewritten, targetOutput, nil
}
