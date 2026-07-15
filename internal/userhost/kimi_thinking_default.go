package userhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"aionuiportal/internal/agentcli"
	"golang.org/x/sys/windows"
)

const (
	kimiThinkingMarkerName    = "kimi-model-defaults-v2.applied"
	kimiThinkingMarkerContent = "default_thinking=true\nmodels=kimi-for-coding,kimi-for-coding-highspeed\n"
)

const kimiThinkingDefaultScript = `
import os
import stat
import sys
import tempfile
from pathlib import Path

import tomlkit
from kimi_cli.config import load_config

MODEL_KEY = "kimi-code/kimi-for-coding"
HIGHSPEED_MODEL_KEY = "kimi-code/kimi-for-coding-highspeed"
PROVIDER_KEY = "managed:kimi-code"
MAX_CONFIG_BYTES = 1024 * 1024

config_path = Path(sys.argv[1])
info = config_path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
    raise RuntimeError("existing Kimi config is not a bounded regular file")

document = tomlkit.parse(config_path.read_text(encoding="utf-8"))
current = load_config(config_path)
model = current.models.get(MODEL_KEY)
if current.default_model != MODEL_KEY or model is None or model.capabilities is None or "thinking" not in model.capabilities:
    raise RuntimeError("managed Kimi model does not support thinking")

models = document.get("models")
if not isinstance(models, dict):
    raise RuntimeError("managed Kimi model catalog is missing")
highspeed = models.get(HIGHSPEED_MODEL_KEY)
if not isinstance(highspeed, dict):
    highspeed = tomlkit.table()
highspeed["provider"] = PROVIDER_KEY
highspeed["model"] = "kimi-for-coding-highspeed"
highspeed["max_context_size"] = 262144
capabilities = highspeed.get("capabilities")
if not isinstance(capabilities, list):
    capabilities = ["video_in", "image_in", "thinking"]
elif "thinking" not in capabilities:
    capabilities.append("thinking")
highspeed["capabilities"] = capabilities
if "display_name" not in highspeed:
    highspeed["display_name"] = "Kimi for Coding HighSpeed"
models[HIGHSPEED_MODEL_KEY] = highspeed
document["default_thinking"] = True
fd, temporary_name = tempfile.mkstemp(prefix=".config.toml.tmp-", dir=config_path.parent)
temporary_path = Path(temporary_name)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(tomlkit.dumps(document))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary_path, 0o600)
    candidate = load_config(temporary_path)
    candidate_model = candidate.models.get(MODEL_KEY)
    candidate_highspeed = candidate.models.get(HIGHSPEED_MODEL_KEY)
    if candidate.default_model != MODEL_KEY or candidate.default_thinking is not True or candidate_model is None or candidate_model.capabilities is None or "thinking" not in candidate_model.capabilities or candidate_highspeed is None or candidate_highspeed.provider != PROVIDER_KEY or candidate_highspeed.model != "kimi-for-coding-highspeed" or candidate_highspeed.capabilities is None or "thinking" not in candidate_highspeed.capabilities:
        raise RuntimeError("Kimi thinking default verification failed")
    os.replace(temporary_path, config_path)
finally:
    if temporary_path.exists():
        temporary_path.unlink()

if load_config(config_path).default_thinking is not True:
    raise RuntimeError("persisted Kimi thinking default verification failed")
`

func (h *Host) applyKimiThinkingDefault(ctx context.Context, env []string) (bool, error) {
	markerPath := filepath.Join(h.dirs.Config, kimiThinkingMarkerName)
	applied, err := markerHasContent(markerPath, kimiThinkingMarkerContent)
	if err != nil || applied {
		return false, err
	}
	root := agentcli.RootFromAionReleases(h.cfg.ReleasesRoot)
	verified, err := agentcli.VerifyCurrent(root)
	if err != nil {
		return false, fmt.Errorf("verify shared agent CLI release before Kimi thinking initialization: %w", err)
	}
	applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	python := filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiRelativePath))
	configPath := filepath.Join(h.dirs.Profile, filepath.FromSlash(kimiConfigRelativePath))
	cmd := exec.CommandContext(applyCtx, python, "-B", "-c", kimiThinkingDefaultScript, configPath)
	cmd.Dir = h.dirs.Workspace
	cmd.Env = append(append([]string(nil), env...), "PYTHONDONTWRITEBYTECODE=1", "PYTHONUTF8=1")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := h.sandbox.Apply(cmd); err != nil {
		return false, fmt.Errorf("sandbox Kimi thinking initialization: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start Kimi thinking initialization: %w", err)
	}
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return false, err
	}
	if err := cmd.Wait(); err != nil {
		if errors.Is(applyCtx.Err(), context.DeadlineExceeded) {
			return false, errors.New("Kimi thinking initialization exceeded 30 seconds")
		}
		return false, errors.New("Kimi thinking initialization failed")
	}
	if _, err := agentcli.VerifyCurrent(root); err != nil {
		return false, fmt.Errorf("verify shared agent CLI release after Kimi thinking initialization: %w", err)
	}
	if err := writePrivateFileAtomic(markerPath, []byte(kimiThinkingMarkerContent)); err != nil {
		return false, fmt.Errorf("write Kimi thinking default marker: %w", err)
	}
	return true, nil
}
