package userhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	cliLanguageMarkerName          = "cli-language-defaults-v2.applied"
	cliLanguageMarkerContent       = "codex=developer_instructions\nkimi=unmanaged\n"
	legacyCLILanguageMarkerName    = "cli-language-defaults-v1.applied"
	legacyCLILanguageMarkerContent = "codex=developer_instructions\nkimi=managed-default-agent\n"
	legacyKimiLanguageAgentPath    = ".kimi/aion-default-agent.yaml"
	cliChineseLanguageInstruction  = "无论用户输入使用何种语言，默认使用简体中文回复；代码、命令、文件路径、标识符以及用户明确要求的其他语言保持原样。"
	kimiLanguageAgentContent       = `version: 1
agent:
  extend: default
  system_prompt_args:
    ROLE_ADDITIONAL: >-
      无论用户输入使用何种语言，默认使用简体中文回复；代码、命令、文件路径、标识符以及用户明确要求的其他语言保持原样。
`
)

func applyInitialCLILanguageDefaults(dirs privateDirs) (bool, error) {
	markerPath := filepath.Join(dirs.Config, cliLanguageMarkerName)
	applied, err := cliLanguageDefaultsAlreadyApplied(markerPath)
	if err != nil {
		return false, err
	}
	legacyMarkerPath := filepath.Join(dirs.Config, legacyCLILanguageMarkerName)
	legacyApplied, err := markerHasContent(legacyMarkerPath, legacyCLILanguageMarkerContent)
	if err != nil {
		return false, err
	}
	legacyAgentPath := filepath.Join(dirs.Profile, filepath.FromSlash(legacyKimiLanguageAgentPath))
	if err := removeExactLegacyFile(legacyAgentPath, kimiLanguageAgentContent, "managed Kimi language agent"); err != nil {
		return false, err
	}
	if !applied && !legacyApplied {
		if err := writeInitialCodexLanguageDefault(filepath.Join(dirs.Config, "codex", "config.toml")); err != nil {
			return false, fmt.Errorf("initialize Codex response language: %w", err)
		}
	}
	if !applied {
		if err := writePrivateFileAtomic(markerPath, []byte(cliLanguageMarkerContent)); err != nil {
			return false, fmt.Errorf("write CLI language defaults marker: %w", err)
		}
	}
	if err := removeExactLegacyFile(legacyMarkerPath, legacyCLILanguageMarkerContent, "legacy CLI language defaults marker"); err != nil {
		return false, err
	}
	return !applied, nil
}

func removeExactLegacyFile(path, expected, label string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64*1024 {
		return fmt.Errorf("%s must be a bounded regular non-symlink file", label)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	if string(content) != expected {
		return fmt.Errorf("%s has unexpected content; refusing to delete it", label)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove %s: %w", label, err)
	}
	return nil
}

func cliLanguageDefaultsAlreadyApplied(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect CLI language defaults marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("CLI language defaults marker must be a regular non-symlink file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read CLI language defaults marker: %w", err)
	}
	if string(content) != cliLanguageMarkerContent {
		return false, errors.New("CLI language defaults marker has unexpected content")
	}
	return true, nil
}
