package userhost

import (
	"bufio"
	"bytes"
	"context"
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

var managedCodexAssignment = regexp.MustCompile(`^\s*(?:["']?(openai_base_url|model|cli_auth_credentials_store)["']?)\s*=`)

type pendingModelBootstrap struct {
	bundle modelbootstrap.Bundle
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
	if !found {
		return nil, nil
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
	return &pendingModelBootstrap{bundle: bundle}, nil
}

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
			if match := managedCodexAssignment.FindStringSubmatch(line); len(match) == 2 {
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
	managed := []string{
		"# Initial CLIProxyAPI settings managed by AionUiPortal.",
		"openai_base_url = " + strconv.Quote(baseURL),
		"model = " + strconv.Quote(model),
		`cli_auth_credentials_store = "file"`,
		"",
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
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64*1024 {
		return errors.New("Codex auth.json must be a bounded regular non-symlink file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defer zero(data)
	var auth struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&auth); err != nil {
		return errors.New("Codex auth.json is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || auth.AuthMode != "apikey" || auth.APIKey != expected {
		return errors.New("Codex auth.json did not contain the expected API-key login")
	}
	return nil
}

func (h *Host) applyPendingModelBootstrap(ctx context.Context, pending *pendingModelBootstrap) error {
	if pending == nil {
		return nil
	}
	bundle := &pending.bundle
	defer func() {
		bundle.CodexAPIKey = ""
		bundle.KimiAPIKey = ""
	}()
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
