package kimi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const maxCredentialBytes = 1 << 20

type ConfigureFunc func(context.Context, string, string, string, string) (string, error)

type SeedOptions struct {
	SourceOAuthPath  string
	SourceConfigPath string
	TargetProfile    string
	PythonPath       string
	BeforeWrite      func() error
	Configure        ConfigureFunc
}

type Result struct {
	SHA256 string
	Output string
}

func HasCredential(path string) (bool, error) {
	_, err := readCredential(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func CredentialSHA256(path string) (string, error) {
	credential, err := readCredential(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(credential)
	return hex.EncodeToString(hash[:]), nil
}

func ValidateSource(ctx context.Context, sourceOAuthPath, sourceConfigPath, pythonPath string, configure ConfigureFunc) error {
	if _, err := readCredential(sourceOAuthPath); err != nil {
		return err
	}
	if err := requireRegularPath(sourceConfigPath, false); err != nil {
		return fmt.Errorf("inspect Kimi source config: %w", err)
	}
	if configure == nil {
		configure = runConfigure
	}
	if _, err := configure(ctx, pythonPath, sourceConfigPath, "-", "validate"); err != nil {
		return fmt.Errorf("validate Kimi source provider metadata: %w", err)
	}
	return nil
}

func Seed(ctx context.Context, options SeedOptions) (Result, error) {
	credential, err := readCredential(options.SourceOAuthPath)
	if err != nil {
		return Result{}, err
	}
	if err := requireRegularPath(options.SourceConfigPath, false); err != nil {
		return Result{}, fmt.Errorf("inspect Kimi source config: %w", err)
	}
	configure := options.Configure
	if configure == nil {
		configure = runConfigure
	}
	if _, err := configure(ctx, options.PythonPath, options.SourceConfigPath, "-", "validate"); err != nil {
		return Result{}, fmt.Errorf("validate Kimi source provider metadata: %w", err)
	}
	if err := requireRegularPath(options.TargetProfile, true); err != nil {
		return Result{}, fmt.Errorf("inspect private UserHost profile: %w", err)
	}
	if options.BeforeWrite != nil {
		if err := options.BeforeWrite(); err != nil {
			return Result{}, fmt.Errorf("stop target UserHost before Kimi OAuth seeding: %w", err)
		}
	}

	kimiDirectory := filepath.Join(options.TargetProfile, ".kimi")
	credentialsDirectory := filepath.Join(kimiDirectory, "credentials")
	for _, path := range []string{kimiDirectory, credentialsDirectory} {
		if err := ensureNormalDirectory(path); err != nil {
			return Result{}, err
		}
	}
	destination := filepath.Join(credentialsDirectory, "kimi-code.json")
	if err := requireRegularPath(destination, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect Kimi OAuth destination: %w", err)
	}
	targetConfig := filepath.Join(kimiDirectory, "config.toml")
	if err := requireRegularPath(targetConfig, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect Kimi target config: %w", err)
	}
	if err := atomicWrite(destination, credential); err != nil {
		return Result{}, fmt.Errorf("copy Kimi OAuth credential: %w", err)
	}
	written, err := os.ReadFile(destination)
	if err != nil {
		return Result{}, fmt.Errorf("verify copied Kimi OAuth credential: %w", err)
	}
	sourceHash := sha256.Sum256(credential)
	destinationHash := sha256.Sum256(written)
	if sourceHash != destinationHash {
		return Result{}, errors.New("copied Kimi OAuth credential hash does not match the source")
	}
	output, err := configure(ctx, options.PythonPath, options.SourceConfigPath, targetConfig, "configure")
	if err != nil {
		return Result{}, fmt.Errorf("Kimi OAuth was copied but its provider/model config could not be initialized: %w", err)
	}
	return Result{SHA256: hex.EncodeToString(sourceHash[:]), Output: strings.TrimSpace(output)}, nil
}

func readCredential(path string) ([]byte, error) {
	if err := requireRegularPath(path, false); err != nil {
		return nil, fmt.Errorf("inspect Kimi OAuth source: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Kimi OAuth source: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Kimi OAuth source: %w", err)
	}
	if len(data) > maxCredentialBytes {
		return nil, errors.New("Kimi OAuth source exceeds 1 MiB")
	}
	var credential struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&credential); err != nil {
		return nil, fmt.Errorf("decode Kimi OAuth source: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, fmt.Errorf("decode Kimi OAuth source: %w", err)
	}
	if strings.TrimSpace(credential.AccessToken) == "" || strings.TrimSpace(credential.RefreshToken) == "" || strings.TrimSpace(credential.TokenType) == "" {
		return nil, errors.New("Kimi OAuth source requires non-empty access_token, refresh_token, and token_type")
	}
	return data, nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func ensureNormalDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create Kimi private directory %s: %w", path, err)
	}
	if err := requireRegularPath(path, true); err != nil {
		return fmt.Errorf("Kimi private directory is unsafe: %w", err)
	}
	return nil
}

func requireRegularPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 || info.IsDir() != directory {
		return fmt.Errorf("path is not a normal %s: %s", map[bool]string{true: "directory", false: "file"}[directory], path)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("path is a reparse point: %s", path)
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".kimi-code.json.tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

type limitedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (w *limitedOutput) Write(data []byte) (int, error) {
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		_, _ = w.buffer.Write(data[:remaining])
	}
	return len(data), nil
}

func runConfigure(ctx context.Context, pythonPath, sourceConfigPath, targetConfigPath, mode string) (string, error) {
	command := configureCommand(ctx, pythonPath, sourceConfigPath, targetConfigPath, mode)
	command.Stdin = strings.NewReader(configureScript)
	output := &limitedOutput{limit: 64 << 10}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(output.buffer.String())
		if message == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, message)
	}
	return output.buffer.String(), nil
}

func configureCommand(ctx context.Context, pythonPath, sourceConfigPath, targetConfigPath, mode string) *exec.Cmd {
	command := exec.CommandContext(ctx, pythonPath, "-B", "-", sourceConfigPath, targetConfigPath, mode)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	return command
}

const configureScript = `
import os
import sys
import tempfile
from pathlib import Path

from kimi_cli.auth import KIMI_CODE_PLATFORM_ID
from kimi_cli.auth.oauth import KIMI_CODE_OAUTH_KEY
from kimi_cli.auth.platforms import get_platform_by_id, managed_provider_key
from kimi_cli.config import load_config, save_config

source_path = Path(sys.argv[1])
target_path = Path(sys.argv[2]) if sys.argv[2] != "-" else None
mode = sys.argv[3]
source = load_config(source_path)
platform = get_platform_by_id(KIMI_CODE_PLATFORM_ID)
if platform is None:
    raise RuntimeError("Kimi Code platform is unavailable")
provider_key = managed_provider_key(KIMI_CODE_PLATFORM_ID)
provider = source.providers.get(provider_key)
models = {key: value for key, value in source.models.items() if value.provider == provider_key}
if (
    provider is None
    or provider.type != "kimi"
    or str(provider.base_url).rstrip("/") != str(platform.base_url).rstrip("/")
    or provider.api_key.get_secret_value() != ""
    or provider.oauth is None
    or provider.oauth.storage != "file"
    or provider.oauth.key != KIMI_CODE_OAUTH_KEY
    or source.default_model not in models
):
    raise RuntimeError("source config does not contain the expected non-secret Kimi Code OAuth provider and default model")
if mode == "validate":
    print(f"Validated Kimi provider metadata with {len(models)} model(s).")
    raise SystemExit(0)
if mode != "configure" or target_path is None:
    raise RuntimeError("invalid Kimi config bootstrap mode")
target = load_config(target_path)
target.providers[provider_key] = provider.model_copy(deep=True)
for key, model in list(target.models.items()):
    if model.provider == provider_key:
        del target.models[key]
for key, model in models.items():
    target.models[key] = model.model_copy(deep=True)
target.default_model = source.default_model
target.default_thinking = source.default_thinking
fd, temporary_name = tempfile.mkstemp(prefix=".config.toml.tmp-", dir=target_path.parent)
os.close(fd)
temporary_path = Path(temporary_name)
try:
    temporary_path.unlink()
    save_config(target, temporary_path)
    os.replace(temporary_path, target_path)
finally:
    if temporary_path.exists():
        temporary_path.unlink()
verified = load_config(target_path)
if verified.default_model not in verified.models or provider_key not in verified.providers:
    raise RuntimeError("Kimi target config verification failed")
print(f"Configured Kimi OAuth provider with {len(models)} model(s).")
`
