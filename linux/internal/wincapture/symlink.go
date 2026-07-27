//go:build linux

package wincapture

import (
	"errors"
	"path"
	"strings"
)

// validateCapturedSymlink admits only the legacy same-tenant builtin-skills
// links already understood and rewritten by the offline Windows migrator.
// External, Portal, CLIProxy, and arbitrary tenant links remain rejected.
func validateCapturedSymlink(source Source, relative, target string) error {
	if source.Role != RoleTenantTree || relative == "." || !safeCapturedRelative(relative) ||
		target == "" || len(target) > 32*1024 || strings.ContainsRune(target, '\x00') {
		return errors.New("symbolic link is outside the approved tenant builtin-skills contract")
	}
	normalized := strings.ReplaceAll(target, `\`, "/")
	if strings.HasPrefix(normalized, "//?/") {
		normalized = normalized[4:]
	}
	if len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/' {
		normalized = "/" + strings.ToLower(normalized[:1]) + normalized[2:]
	}
	prefix, err := capturedBuiltinSkillsPrefix(source)
	if err != nil {
		return err
	}
	if len(normalized) <= len(prefix) || !strings.EqualFold(normalized[:len(prefix)], prefix) {
		return errors.New("symbolic link target is not in the same tenant builtin-skills tree")
	}
	suffix := normalized[len(prefix):]
	if !safeCapturedRelative(suffix) || path.Clean(suffix) != suffix {
		return errors.New("symbolic link target suffix is unsafe")
	}
	return nil
}

func capturedSymlinkTargetRelative(source Source, target string) (string, error) {
	if err := validateCapturedSymlink(source, "data/builtin-skills/link", target); err != nil {
		return "", err
	}
	normalized := strings.ReplaceAll(target, `\`, "/")
	if strings.HasPrefix(normalized, "//?/") {
		normalized = normalized[4:]
	}
	if len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/' {
		normalized = "/" + strings.ToLower(normalized[:1]) + normalized[2:]
	}
	prefix, err := capturedBuiltinSkillsPrefix(source)
	if err != nil {
		return "", err
	}
	return path.Join("data/builtin-skills", normalized[len(prefix):]), nil
}

func capturedBuiltinSkillsPrefix(source Source) (string, error) {
	components := strings.Split(strings.TrimPrefix(source.SourcePath, "/"), "/")
	if len(components) != 4 || !strings.EqualFold(components[0], "c") || !strings.EqualFold(components[1], "Users") ||
		!strings.EqualFold(components[3], "AionUiPortal") || components[2] == "" {
		return "", errors.New("tenant source root is outside the offline migrator's Windows path contract")
	}
	return "/c/Users/" + components[2] + "/AionUiPortal/data/builtin-skills/", nil
}
