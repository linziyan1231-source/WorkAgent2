package userhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"aionuiportal/internal/agentcli"
)

const (
	cliLanguageMarkerName         = "cli-language-defaults-v1.applied"
	cliLanguageMarkerContent      = "codex=developer_instructions\nkimi=managed-default-agent\n"
	cliChineseLanguageInstruction = "无论用户输入使用何种语言，默认使用简体中文回复；代码、命令、文件路径、标识符以及用户明确要求的其他语言保持原样。"
	kimiLanguageAgentContent      = `version: 1
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
	if err != nil || applied {
		return false, err
	}
	if err := writeInitialCodexLanguageDefault(filepath.Join(dirs.Config, "codex", "config.toml")); err != nil {
		return false, fmt.Errorf("initialize Codex response language: %w", err)
	}
	kimiDirectory := filepath.Join(dirs.Profile, ".kimi")
	if err := os.Mkdir(kimiDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return false, fmt.Errorf("create private Kimi configuration directory: %w", err)
	}
	info, err := os.Lstat(kimiDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("private Kimi configuration path must be a regular non-symlink directory")
	}
	agentPath := filepath.Join(dirs.Profile, filepath.FromSlash(agentcli.KimiManagedAgentRelativePath))
	if err := writeKimiLanguageAgentOnce(agentPath); err != nil {
		return false, err
	}
	if err := writePrivateFileAtomic(markerPath, []byte(cliLanguageMarkerContent)); err != nil {
		return false, fmt.Errorf("write CLI language defaults marker: %w", err)
	}
	return true, nil
}

func writeKimiLanguageAgentOnce(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64*1024 {
			return errors.New("existing managed Kimi language agent must be a bounded regular non-symlink file")
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(content) != kimiLanguageAgentContent {
			return errors.New("existing managed Kimi language agent has unexpected content; refusing to overwrite it")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writePrivateFileAtomic(path, []byte(kimiLanguageAgentContent)); err != nil {
		return fmt.Errorf("write managed Kimi language agent: %w", err)
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
