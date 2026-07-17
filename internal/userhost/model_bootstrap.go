package userhost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/modelbootstrap"
	"golang.org/x/sys/windows"
)

const maxCodexConfig = 1024 * 1024

const (
	legacyKimiConfigRelativePath = ".kimi/config.toml"
	kimiCodeConfigRelativePath   = ".kimi-code/config.toml"
	kimiDefaultModelKey          = "kimi-code/kimi-for-coding"
)

var managedCodexAssignment = regexp.MustCompile(`^\s*(?:["']?(openai_base_url|model_reasoning_effort|model|cli_auth_credentials_store)["']?)\s*=`)
var managedAPIKey = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)

type pendingModelBootstrap struct {
	bundle       *modelbootstrap.Bundle
	rebase       *modelbootstrap.Rebase
	codexKeyHash [sha256.Size]byte
	kimiKeyHash  [sha256.Size]byte
}

type cappedOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (c *cappedOutput) Write(data []byte) (int, error) {
	original := len(data)
	remaining := c.limit - c.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = c.Buffer.Write(data)
	}
	if original > remaining {
		c.overflow = true
	}
	return original, nil
}

type aionProvider struct {
	ID       string   `json:"id"`
	Platform string   `json:"platform"`
	Name     string   `json:"name"`
	BaseURL  string   `json:"base_url"`
	APIKey   string   `json:"api_key"`
	Models   []string `json:"models"`
	Enabled  bool     `json:"enabled"`
}

func (h *Host) preparePendingModelBootstrap(ctx context.Context, env []string) (*pendingModelBootstrap, error) {
	bundle, found, err := modelbootstrap.LoadPending(h.cfg.DataRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect API model bootstrap: %w", err)
	}
	rebase, rebasing, err := modelbootstrap.LoadPendingRebase(h.cfg.DataRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect API model bootstrap rebase: %w", err)
	}
	if found && rebasing {
		return nil, errors.New("API model bootstrap and rebase are both pending")
	}
	if !found && !rebasing {
		return nil, nil
	}
	if rebasing {
		codexHome := filepath.Join(h.dirs.Config, "codex")
		codexKey, err := readCodexAPIKey(filepath.Join(codexHome, "auth.json"))
		if err != nil {
			return nil, fmt.Errorf("read existing Codex API-key login for rebase: %w", err)
		}
		defer zero(codexKey)
		if err := writeInitialCodexConfig(filepath.Join(codexHome, "config.toml"), rebase.Target.BaseURL, rebase.Target.CodexDefaultModel); err != nil {
			return nil, fmt.Errorf("rebase Codex configuration: %w", err)
		}
		if err := verifyCodexAPIKey(filepath.Join(codexHome, "auth.json"), string(codexKey)); err != nil {
			return nil, fmt.Errorf("verify preserved Codex API-key login: %w", err)
		}
		kimiHash, err := h.configureKimiAPIKey(ctx, env, rebase.Target.BaseURL, "")
		if err != nil {
			return nil, err
		}
		pending := &pendingModelBootstrap{rebase: &rebase, codexKeyHash: sha256.Sum256(codexKey)}
		decoded, err := hex.DecodeString(kimiHash)
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("Kimi API-key rebase returned an invalid verification hash")
		}
		copy(pending.kimiKeyHash[:], decoded)
		return pending, nil
	}
	codexHome := filepath.Join(h.dirs.Config, "codex")
	if err := writeInitialCodexConfig(filepath.Join(codexHome, "config.toml"), bundle.BaseURL, bundle.CodexDefaultModel); err != nil {
		return nil, fmt.Errorf("initialize Codex configuration: %w", err)
	}
	if err := h.loginCodexAPIKey(ctx, env, bundle.CodexAPIKey); err != nil {
		return nil, err
	}
	if err := verifyCodexAPIKey(filepath.Join(codexHome, "auth.json"), bundle.CodexAPIKey); err != nil {
		return nil, fmt.Errorf("verify Codex API-key login: %w", err)
	}
	if _, err := h.configureKimiAPIKey(ctx, env, bundle.BaseURL, bundle.KimiAPIKey); err != nil {
		return nil, err
	}
	return &pendingModelBootstrap{bundle: &bundle}, nil
}

func (h *Host) configureKimiAPIKey(ctx context.Context, env []string, baseURL, apiKey string) (string, error) {
	root := agentcli.RootFromAionReleases(h.cfg.ReleasesRoot)
	verified, err := agentcli.VerifyCurrent(root)
	if err != nil {
		return "", fmt.Errorf("verify shared agent CLI release before Kimi API-key configuration: %w", err)
	}
	kimiDirectory := filepath.Dir(kimiConfigPath(h.dirs.Profile, verified.Manifest))
	if err := ensureNormalKimiDirectory(kimiDirectory); err != nil {
		return "", err
	}
	input := map[string]string{"base_url": baseURL}
	if apiKey != "" {
		input["api_key"] = apiKey
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return "", errors.New("encode Kimi API-key configuration input")
	}
	defer zero(payload)

	configureCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	python := filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiRelativePath))
	configPath := kimiConfigPath(h.dirs.Profile, verified.Manifest)
	cmd := exec.CommandContext(configureCtx, python, "-B", "-c", kimiAPIKeyConfigureScript, configPath)
	cmd.Dir = h.dirs.Workspace
	cmd.Env = append(append([]string(nil), env...), "PYTHONDONTWRITEBYTECODE=1", "PYTHONUTF8=1")
	cmd.Stdin = bytes.NewReader(payload)
	stdout := &cappedOutput{limit: 128}
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := h.sandbox.Apply(cmd); err != nil {
		return "", fmt.Errorf("sandbox Kimi API-key configuration: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start Kimi API-key configuration: %w", err)
	}
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return "", err
	}
	if err := cmd.Wait(); err != nil {
		if errors.Is(configureCtx.Err(), context.DeadlineExceeded) {
			return "", errors.New("Kimi API-key configuration exceeded 30 seconds")
		}
		return "", errors.New("Kimi API-key configuration failed")
	}
	if _, err := agentcli.VerifyCurrent(root); err != nil {
		return "", fmt.Errorf("verify shared agent CLI release after Kimi API-key configuration: %w", err)
	}
	if err := h.validateKimiCodeConfig(ctx, env, verified, configPath); err != nil {
		return "", err
	}
	hash := strings.TrimSpace(stdout.String())
	if stdout.overflow || len(hash) != sha256.Size*2 {
		return "", errors.New("Kimi API-key configuration verification hash was invalid")
	}
	return hash, nil
}

func kimiConfigPath(profile string, manifest agentcli.Manifest) string {
	relative := legacyKimiConfigRelativePath
	if _, ok := manifest.Files[agentcli.KimiCodeRelativePath]; ok {
		relative = kimiCodeConfigRelativePath
	}
	return filepath.Join(profile, filepath.FromSlash(relative))
}

func ensureNormalKimiDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create private Kimi configuration directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private Kimi configuration path must be a regular non-symlink directory")
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("private Kimi configuration path must not be a reparse point")
	}
	return nil
}

const kimiAPIKeyConfigureScript = `
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import tomlkit
from kimi_cli.config import load_config

PROVIDER_KEY = "managed:kimi-code"
MODEL_KEY = "kimi-code/kimi-for-coding"
MODEL_NAME = "kimi-for-coding"
HIGHSPEED_MODEL_KEY = "kimi-code/kimi-for-coding-highspeed"
HIGHSPEED_MODEL_NAME = "kimi-for-coding-highspeed"
OAUTH_KEY = "oauth/kimi-code"
MAX_CONFIG_BYTES = 1024 * 1024

config_path = Path(sys.argv[1])
payload = json.load(sys.stdin)
api_key = payload.pop("api_key", None)
base_url = payload.pop("base_url")
if payload or (api_key is not None and (not isinstance(api_key, str) or not api_key.startswith("cpa_"))) or not isinstance(base_url, str):
    raise RuntimeError("invalid Kimi API-key configuration input")

if config_path.exists():
    info = config_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError("existing Kimi config is not a bounded regular file")
    document = tomlkit.parse(config_path.read_text(encoding="utf-8"))
else:
    document = tomlkit.document()

credentials = config_path.parent / "credentials"
oauth_paths = [credentials / "kimi-code.json", credentials / "kimi-code.lock"]
if credentials.exists():
    info = credentials.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError("Kimi OAuth credential directory is not a regular directory")
for path in oauth_paths:
    try:
        info = path.lstat()
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError("Kimi OAuth credential path is not a regular file")

providers = document.get("providers")
if not isinstance(providers, dict):
    providers = tomlkit.table()
    document["providers"] = providers
existing_provider = providers.get(PROVIDER_KEY)
if api_key is None:
    api_key = existing_provider.get("api_key") if isinstance(existing_provider, dict) else None
    if not isinstance(api_key, str) or not api_key.startswith("cpa_"):
        raise RuntimeError("existing managed Kimi API key is missing")
provider = tomlkit.table()
provider["type"] = "kimi"
provider["base_url"] = base_url
provider["api_key"] = api_key
providers[PROVIDER_KEY] = provider

models = document.get("models")
if not isinstance(models, dict):
    models = tomlkit.table()
    document["models"] = models
def upsert_model(key, name, display_name):
    model = models.get(key)
    if not isinstance(model, dict):
        model = tomlkit.table()
    model["provider"] = PROVIDER_KEY
    model["model"] = name
    model["max_context_size"] = 262144
    capabilities = model.get("capabilities")
    if not isinstance(capabilities, list):
        capabilities = ["video_in", "image_in", "thinking"]
    elif "thinking" not in capabilities:
        capabilities.append("thinking")
    model["capabilities"] = capabilities
    if "display_name" not in model:
        model["display_name"] = display_name
    models[key] = model

upsert_model(MODEL_KEY, MODEL_NAME, "Kimi for Coding")
upsert_model(HIGHSPEED_MODEL_KEY, HIGHSPEED_MODEL_NAME, "Kimi for Coding HighSpeed")
document["default_model"] = MODEL_KEY
document["default_thinking"] = True
document["default_yolo"] = True

def remove_kimi_oauth(section):
    if not isinstance(section, dict):
        return
    for value in section.values():
        if not isinstance(value, dict):
            continue
        oauth = value.get("oauth")
        if isinstance(oauth, dict) and oauth.get("key") == OAUTH_KEY:
            del value["oauth"]

remove_kimi_oauth(document.get("providers"))
remove_kimi_oauth(document.get("services"))

fd, temporary_name = tempfile.mkstemp(prefix=".config.toml.tmp-", dir=config_path.parent)
temporary_path = Path(temporary_name)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(tomlkit.dumps(document))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary_path, 0o600)
    candidate = load_config(temporary_path)
    candidate_provider = candidate.providers.get(PROVIDER_KEY)
    candidate_model = candidate.models.get(MODEL_KEY)
    candidate_highspeed_model = candidate.models.get(HIGHSPEED_MODEL_KEY)
    if (
        candidate.default_model != MODEL_KEY
        or candidate.default_thinking is not True
        or candidate.default_yolo is not True
        or candidate_provider is None
        or candidate_provider.type != "kimi"
        or candidate_provider.base_url != base_url
        or candidate_provider.api_key.get_secret_value() != api_key
        or candidate_provider.oauth is not None
        or candidate_model is None
        or candidate_model.provider != PROVIDER_KEY
        or candidate_model.model != MODEL_NAME
        or candidate_model.capabilities is None
        or "thinking" not in candidate_model.capabilities
        or candidate_highspeed_model is None
        or candidate_highspeed_model.provider != PROVIDER_KEY
        or candidate_highspeed_model.model != HIGHSPEED_MODEL_NAME
        or candidate_highspeed_model.capabilities is None
        or "thinking" not in candidate_highspeed_model.capabilities
    ):
        raise RuntimeError("Kimi API-key configuration verification failed")
    for service in (candidate.services.moonshot_search, candidate.services.moonshot_fetch):
        if service is not None and service.oauth is not None and service.oauth.key == OAUTH_KEY:
            raise RuntimeError("Kimi OAuth service reference remains")
    os.replace(temporary_path, config_path)
finally:
    if temporary_path.exists():
        temporary_path.unlink()

for path in oauth_paths:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
for path in oauth_paths:
    if path.exists():
        raise RuntimeError("Kimi OAuth credential removal failed")

verified = load_config(config_path)
verified_provider = verified.providers.get(PROVIDER_KEY)
if verified.default_thinking is not True or verified.default_yolo is not True or verified_provider is None or verified_provider.oauth is not None or verified_provider.api_key.get_secret_value() != api_key:
    raise RuntimeError("persisted Kimi API-key configuration verification failed")
print(hashlib.sha256(api_key.encode("utf-8")).hexdigest())
`

func (h *Host) loginCodexAPIKey(ctx context.Context, env []string, apiKey string) error {
	loginCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	executable := filepath.Join(agentcli.BinFromAionReleases(h.cfg.ReleasesRoot), "codex.exe")
	cmd := exec.CommandContext(loginCtx, executable, "login", "--with-api-key")
	cmd.Dir = h.dirs.Workspace
	cmd.Env = env
	cmd.Stdin = strings.NewReader(apiKey + "\n")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	if err := h.sandbox.Apply(cmd); err != nil {
		return fmt.Errorf("sandbox Codex API-key login: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Codex API-key login: %w", err)
	}
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	if err := cmd.Wait(); err != nil {
		if errors.Is(loginCtx.Err(), context.DeadlineExceeded) {
			return errors.New("Codex API-key login exceeded 30 seconds")
		}
		return errors.New("Codex API-key login failed")
	}
	return nil
}

func writeInitialCodexConfig(path, baseURL, model string) error {
	managed := []string{
		"# Initial CLIProxyAPI settings managed by AionUiPortal.",
		"openai_base_url = " + strconv.Quote(baseURL),
		"model = " + strconv.Quote(model),
		`model_reasoning_effort = "xhigh"`,
		`cli_auth_credentials_store = "file"`,
		"",
	}
	return rewriteCodexConfig(path, managedCodexAssignment, managed)
}

func rewriteCodexConfig(path string, assignment *regexp.Regexp, managed []string) error {
	var existing string
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxCodexConfig {
			return errors.New("existing Codex config must be a bounded regular non-symlink file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		existing = string(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	var preserved []string
	scanner := bufio.NewScanner(strings.NewReader(existing))
	scanner.Buffer(make([]byte, 4096), maxCodexConfig)
	inTable := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTable = true
		}
		if !inTable {
			if match := assignment.FindStringSubmatch(line); len(match) == 2 {
				right := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
				if strings.HasPrefix(right, `"""`) || strings.HasPrefix(right, `'''`) {
					return fmt.Errorf("managed Codex key %s uses a multiline value", match[1])
				}
				continue
			}
		}
		preserved = append(preserved, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for len(preserved) > 0 && strings.TrimSpace(preserved[0]) == "" {
		preserved = preserved[1:]
	}
	content := strings.Join(append(managed, preserved...), "\n")
	content = strings.TrimRight(content, "\n") + "\n"
	return writePrivateFileAtomic(path, []byte(content))
}

func writePrivateFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private configuration parent must be a regular directory")
	}
	temporary, err := os.CreateTemp(directory, ".private-config.tmp-*")
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

func verifyCodexAPIKey(path, expected string) error {
	apiKey, err := readCodexAPIKey(path)
	if err != nil {
		return err
	}
	defer zero(apiKey)
	if string(apiKey) != expected {
		return errors.New("Codex auth.json did not contain the expected API-key login")
	}
	return nil
}

func readCodexAPIKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64*1024 {
		return nil, errors.New("Codex auth.json must be a bounded regular non-symlink file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer zero(data)
	var auth struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&auth); err != nil {
		return nil, errors.New("Codex auth.json is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || auth.AuthMode != "apikey" || !managedAPIKey.MatchString(auth.APIKey) {
		return nil, errors.New("Codex auth.json did not contain a managed API-key login")
	}
	return []byte(auth.APIKey), nil
}

func (h *Host) applyPendingModelBootstrap(ctx context.Context, pending *pendingModelBootstrap) error {
	if pending == nil {
		return nil
	}
	if pending.rebase != nil {
		return h.applyPendingModelRebase(ctx, pending)
	}
	bundle := pending.bundle
	if bundle == nil {
		return errors.New("pending model bootstrap has no operation")
	}
	defer func() { bundle.CodexAPIKey, bundle.KimiAPIKey = "", "" }()
	desired := []aionProvider{
		{ID: modelbootstrap.CodexProviderID, Platform: "custom", Name: modelbootstrap.CodexProviderName, BaseURL: bundle.BaseURL, APIKey: bundle.CodexAPIKey, Models: append([]string(nil), bundle.CodexModels...), Enabled: true},
		{ID: modelbootstrap.KimiProviderID, Platform: "custom", Name: modelbootstrap.KimiProviderName, BaseURL: bundle.BaseURL, APIKey: bundle.KimiAPIKey, Models: append([]string(nil), bundle.KimiModels...), Enabled: true},
	}
	if err := h.client.upsertManagedProviders(ctx, desired); err != nil {
		return fmt.Errorf("initialize Aion model providers: %w", err)
	}
	if err := modelbootstrap.Complete(h.cfg.DataRoot, bundle.State); err != nil {
		return err
	}
	h.log.Printf("Initialized Codex API-key login and Aion providers codex_key_id=%s kimi_key_id=%s", bundle.CodexKeyID, bundle.KimiKeyID)
	return nil
}

func (h *Host) applyPendingModelRebase(ctx context.Context, pending *pendingModelBootstrap) error {
	rebase := pending.rebase
	if rebase == nil {
		return errors.New("pending model rebase is missing")
	}
	current, err := h.client.listProviders(ctx)
	if err != nil {
		return fmt.Errorf("list Aion model providers for rebase: %w", err)
	}
	byID := make(map[string]aionProvider, len(current))
	for _, provider := range current {
		if _, duplicate := byID[provider.ID]; duplicate {
			return fmt.Errorf("Aion provider id is duplicated: %s", provider.ID)
		}
		byID[provider.ID] = provider
	}
	codex, hasCodex := byID[modelbootstrap.CodexProviderID]
	kimi, hasKimi := byID[modelbootstrap.KimiProviderID]
	if !hasCodex || !hasKimi {
		return errors.New("managed Aion providers are incomplete during Base URL rebase")
	}
	for _, provider := range []aionProvider{codex, kimi} {
		if provider.BaseURL != rebase.Previous.BaseURL && provider.BaseURL != rebase.Target.BaseURL {
			return fmt.Errorf("managed Aion provider %s has an unexpected Base URL", provider.ID)
		}
		if !managedAPIKey.MatchString(provider.APIKey) {
			return fmt.Errorf("managed Aion provider %s has an invalid API key", provider.ID)
		}
	}
	if sha256.Sum256([]byte(codex.APIKey)) != pending.codexKeyHash || sha256.Sum256([]byte(kimi.APIKey)) != pending.kimiKeyHash {
		return errors.New("managed Aion provider keys do not match the preserved CLI keys")
	}
	codex.BaseURL, kimi.BaseURL = rebase.Target.BaseURL, rebase.Target.BaseURL
	codex.Name, kimi.Name = modelbootstrap.CodexProviderName, modelbootstrap.KimiProviderName
	codex.Models, kimi.Models = append([]string(nil), rebase.Target.CodexModels...), append([]string(nil), rebase.Target.KimiModels...)
	if err := h.client.upsertManagedProviders(ctx, []aionProvider{codex, kimi}); err != nil {
		return fmt.Errorf("rebase Aion model providers: %w", err)
	}
	if err := modelbootstrap.CompleteRebase(h.cfg.DataRoot, rebase.Target); err != nil {
		return err
	}
	h.log.Printf("Rebased CLIProxyAPI Base URL without rotating keys codex_key_id=%s kimi_key_id=%s", rebase.Target.CodexKeyID, rebase.Target.KimiKeyID)
	return nil
}

func (h *Host) enforceManagedProviderPolicy(ctx context.Context) error {
	current, err := h.client.listProviders(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]aionProvider, len(current))
	for _, provider := range current {
		if _, duplicate := byID[provider.ID]; duplicate {
			return fmt.Errorf("Aion provider id is duplicated: %s", provider.ID)
		}
		byID[provider.ID] = provider
	}
	codex, hasCodex := byID[modelbootstrap.CodexProviderID]
	kimi, hasKimi := byID[modelbootstrap.KimiProviderID]
	if !hasCodex && !hasKimi {
		return nil
	}
	if !hasCodex || !hasKimi {
		return errors.New("managed Aion providers are incomplete")
	}
	codex.Name = modelbootstrap.CodexProviderName
	codex.Models = modelbootstrap.ManagedCodexModels()
	kimi.Name = modelbootstrap.KimiProviderName
	kimi.Models = modelbootstrap.ManagedKimiModels()
	if err := h.client.upsertManagedProviders(ctx, []aionProvider{codex, kimi}); err != nil {
		return fmt.Errorf("enforce managed Aion provider policy: %w", err)
	}
	return nil
}

func (a *aionClient) upsertManagedProviders(ctx context.Context, desired []aionProvider) error {
	current, err := a.listProviders(ctx)
	if err != nil {
		return err
	}
	existing := make(map[string]aionProvider, len(current))
	for _, provider := range current {
		if _, duplicate := existing[provider.ID]; duplicate {
			return fmt.Errorf("Aion provider id is duplicated: %s", provider.ID)
		}
		existing[provider.ID] = provider
	}
	for _, provider := range desired {
		method, path := http.MethodPost, "/api/providers"
		if _, found := existing[provider.ID]; found {
			method, path = http.MethodPut, "/api/providers/"+url.PathEscape(provider.ID)
		}
		if err := a.sendJSON(ctx, method, path, provider, nil); err != nil {
			return err
		}
	}
	verified, err := a.listProviders(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string][]aionProvider, len(verified))
	for _, provider := range verified {
		byID[provider.ID] = append(byID[provider.ID], provider)
	}
	for _, expected := range desired {
		matches := byID[expected.ID]
		if len(matches) != 1 || !sameProvider(matches[0], expected) {
			return fmt.Errorf("Aion provider verification failed for %s", expected.ID)
		}
	}
	return nil
}

func (a *aionClient) listProviders(ctx context.Context) ([]aionProvider, error) {
	var response struct {
		Success bool           `json:"success"`
		Data    []aionProvider `json:"data"`
	}
	if err := a.getJSON(ctx, "/api/providers", &response); err != nil {
		return nil, err
	}
	if !response.Success || response.Data == nil {
		return nil, errors.New("Aion provider list response was unsuccessful or incomplete")
	}
	return response.Data, nil
}

func sameProvider(actual, expected aionProvider) bool {
	if actual.ID != expected.ID || actual.Platform != expected.Platform || actual.Name != expected.Name || actual.BaseURL != expected.BaseURL || actual.APIKey != expected.APIKey || actual.Enabled != expected.Enabled {
		return false
	}
	actualModels, expectedModels := append([]string(nil), actual.Models...), append([]string(nil), expected.Models...)
	sort.Strings(actualModels)
	sort.Strings(expectedModels)
	return strings.Join(actualModels, "\x00") == strings.Join(expectedModels, "\x00")
}
