package userhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"aionuiportal/internal/agentcli"
	"golang.org/x/sys/windows"
)

const maxKimiConfig = 1024 * 1024

func (h *Host) initializeKimiCodeConfig(ctx context.Context, env []string) (bool, error) {
	root := agentcli.RootFromAionReleases(h.cfg.ReleasesRoot)
	verified, err := agentcli.VerifyCurrent(root)
	if err != nil {
		return false, fmt.Errorf("verify shared agent CLI release before Kimi Code configuration migration: %w", err)
	}
	if _, ok := verified.Manifest.Files[agentcli.KimiCodeRelativePath]; !ok {
		return false, nil
	}
	target := filepath.Join(h.dirs.Profile, filepath.FromSlash(kimiCodeConfigRelativePath))
	legacy := filepath.Join(h.dirs.Profile, filepath.FromSlash(legacyKimiConfigRelativePath))
	return migrateKimiConfigFile(legacy, target, func(candidate string) error {
		return h.validateKimiCodeConfig(ctx, env, verified, candidate)
	})
}

func migrateKimiConfigFile(source, target string, validate func(string) error) (bool, error) {
	if _, err := boundedRegularFile(target, maxKimiConfig); err == nil {
		if err := validate(target); err != nil {
			return false, err
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect Kimi Code configuration: %w", err)
	}

	info, err := boundedRegularFile(source, maxKimiConfig)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect legacy Kimi configuration: %w", err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return false, fmt.Errorf("read legacy Kimi configuration: %w", err)
	}
	defer zero(data)
	if int64(len(data)) != info.Size() {
		return false, errors.New("legacy Kimi configuration changed while it was being copied")
	}
	if err := ensureNormalKimiDirectory(filepath.Dir(target)); err != nil {
		return false, err
	}
	candidate := target + ".migrating-from-kimi-cli"
	if _, err := os.Lstat(candidate); err == nil {
		return false, errors.New("stale Kimi Code configuration migration candidate exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect Kimi Code configuration migration candidate: %w", err)
	}
	if err := writePrivateFileAtomic(candidate, data); err != nil {
		return false, fmt.Errorf("stage Kimi Code configuration migration: %w", err)
	}
	removeCandidate := true
	defer func() {
		if removeCandidate {
			_ = os.Remove(candidate)
		}
	}()
	if err := validate(candidate); err != nil {
		return false, err
	}
	if err := os.Rename(candidate, target); err != nil {
		return false, fmt.Errorf("activate migrated Kimi Code configuration: %w", err)
	}
	removeCandidate = false
	persisted, err := os.ReadFile(target)
	if err != nil {
		return false, fmt.Errorf("verify migrated Kimi Code configuration: %w", err)
	}
	defer zero(persisted)
	if !bytes.Equal(data, persisted) {
		return false, errors.New("migrated Kimi Code configuration differs from the legacy source")
	}
	return true, nil
}

func boundedRegularFile(path string, maxSize int64) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxSize {
		return nil, errors.New("configuration must be a bounded regular non-symlink file")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("configuration must not be a reparse point")
	}
	return info, nil
}

func (h *Host) validateKimiCodeConfig(ctx context.Context, env []string, verified agentcli.Verified, configPath string) error {
	if _, ok := verified.Manifest.Files[agentcli.KimiCodeRelativePath]; !ok {
		return nil
	}
	validateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	executable := filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiCodeRelativePath))
	cmd := exec.CommandContext(validateCtx, executable, "doctor", "config", configPath)
	cmd.Dir = h.dirs.Workspace
	cmd.Env = env
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := h.sandbox.Apply(cmd); err != nil {
		return fmt.Errorf("sandbox Kimi Code configuration validation: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Kimi Code configuration validation: %w", err)
	}
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	if err := cmd.Wait(); err != nil {
		if errors.Is(validateCtx.Err(), context.DeadlineExceeded) {
			return errors.New("Kimi Code configuration validation exceeded 30 seconds")
		}
		return errors.New("Kimi Code rejected the configuration")
	}
	return nil
}
