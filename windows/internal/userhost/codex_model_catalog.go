package userhost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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

const (
	maxManagedCodexCatalog             = 1024 * 1024
	managedCodexVerifierCleanupTimeout = 3 * time.Second
)

var (
	managedCodexCatalogVersion   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	managedCodexCatalogSetting   = regexp.MustCompile(`^\s*(?:(?:["']?(model_catalog_json)["']?)\s*=|# Managed Codex model catalog:)`)
	managedCodexAPIKeyPattern    = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	managedCodexReasoningEfforts = []string{"low", "medium", "high", "xhigh", "max"}
)

type managedCodexCatalog struct {
	Models []json.RawMessage `json:"models"`
}

type managedCodexModelMetadata struct {
	Slug                     string                       `json:"slug"`
	DisplayName              string                       `json:"display_name"`
	BaseInstructions         string                       `json:"base_instructions"`
	Visibility               string                       `json:"visibility"`
	SupportedInAPI           bool                         `json:"supported_in_api"`
	Priority                 int                          `json:"priority"`
	ContextWindow            int64                        `json:"context_window"`
	MaxContextWindow         int64                        `json:"max_context_window"`
	SupportedReasoningLevels []managedCodexReasoningLevel `json:"supported_reasoning_levels"`
}

type managedCodexReasoningLevel struct {
	Effort      string `json:"effort"`
	Description string `json:"description"`
}

type codexResponseEnvelope struct {
	ID     int `json:"id"`
	Result struct {
		Data []struct {
			Model string `json:"model"`
		} `json:"data"`
	} `json:"result"`
	Error json.RawMessage `json:"error"`
}

type codexScanResult struct {
	line []byte
	err  error
}

func (h *Host) applyManagedCodexModelCatalog(ctx context.Context, env []string, codexVersion string) (bool, error) {
	state, managed, err := managedCodexCatalogBootstrapState(h.cfg.DataRoot)
	if err != nil {
		return false, err
	}
	if !managed {
		return false, nil
	}
	if !managedCodexCatalogVersion.MatchString(codexVersion) {
		return false, fmt.Errorf("unsupported Codex catalog version %q", codexVersion)
	}

	codexHome := filepath.Join(h.dirs.Config, "codex")
	catalogPath := filepath.Join(codexHome, "managed-model-catalog-"+codexVersion+".json")
	applied := false
	var catalogData []byte
	info, statErr := os.Lstat(catalogPath)
	switch {
	case statErr == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxManagedCodexCatalog {
			return false, errors.New("managed Codex model catalog must be a bounded regular non-symlink file")
		}
		data, readErr := os.ReadFile(catalogPath)
		if readErr != nil {
			return false, readErr
		}
		normalized, changed, normalizeErr := normalizeManagedCodexCatalog(data)
		if normalizeErr != nil {
			return false, fmt.Errorf("normalize existing managed Codex model catalog: %w", normalizeErr)
		}
		if changed {
			if writeErr := writePrivateFileAtomic(catalogPath, normalized); writeErr != nil {
				return false, fmt.Errorf("rewrite managed Codex model catalog: %w", writeErr)
			}
			applied = true
		}
		catalogData = normalized
	case errors.Is(statErr, os.ErrNotExist):
		apiKey, keyErr := loadCodexAPIKey(filepath.Join(codexHome, "auth.json"))
		if keyErr != nil {
			return false, fmt.Errorf("load managed Codex API-key login: %w", keyErr)
		}
		defer zero(apiKey)
		data, fetchErr := fetchManagedCodexCatalog(ctx, state.BaseURL, codexVersion, apiKey)
		if fetchErr != nil {
			return false, fetchErr
		}
		if writeErr := writePrivateFileAtomic(catalogPath, data); writeErr != nil {
			return false, fmt.Errorf("write managed Codex model catalog: %w", writeErr)
		}
		catalogData = data
		applied = true
	case statErr != nil:
		return false, fmt.Errorf("inspect managed Codex model catalog: %w", statErr)
	}

	configChanged, err := writeManagedCodexCatalogSetting(filepath.Join(codexHome, "config.toml"), catalogPath, h.release.Manifest.Version, codexVersion, catalogData)
	if err != nil {
		return false, fmt.Errorf("configure managed Codex model catalog: %w", err)
	}
	if applied || configChanged {
		if err := h.verifyManagedCodexModelList(ctx, env); err != nil {
			return false, err
		}
	}
	verification := "fast"
	if applied || configChanged {
		verification = "full"
	}
	h.log.Printf("Managed Codex model catalog checked verification=%s config_changed=%t catalog_fetched=%t", verification, configChanged, applied)
	return applied, nil
}

func managedCodexCatalogBootstrapState(dataRoot string) (modelbootstrap.State, bool, error) {
	status, err := modelbootstrap.Inspect(dataRoot)
	if err != nil {
		return modelbootstrap.State{}, false, fmt.Errorf("inspect managed Codex model state: %w", err)
	}
	if !status.Applied && !status.Pending {
		return modelbootstrap.State{}, false, nil
	}
	if !sameStringSet(status.State.CodexModels, modelbootstrap.ManagedCodexModels()) {
		return modelbootstrap.State{}, false, errors.New("managed Codex model state does not contain the exact supported catalog")
	}
	return status.State, true, nil
}

func fetchManagedCodexCatalog(ctx context.Context, baseURL, codexVersion string, apiKey []byte) ([]byte, error) {
	endpoint, err := url.Parse(baseURL)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("managed Codex catalog base URL is invalid")
	}
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/models"
	query := endpoint.Query()
	query.Set("client_version", codexVersion)
	endpoint.RawQuery = query.Encode()

	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("create managed Codex catalog request")
	}
	request.Header.Set("Authorization", "Bearer "+string(apiKey))
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Timeout:   30 * time.Second,
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch managed Codex model catalog: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch managed Codex model catalog returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxManagedCodexCatalog+1))
	if err != nil {
		return nil, errors.New("read managed Codex model catalog")
	}
	if len(data) > maxManagedCodexCatalog {
		return nil, errors.New("managed Codex model catalog exceeded its size limit")
	}
	normalized, _, err := normalizeManagedCodexCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("normalize fetched managed Codex model catalog: %w", err)
	}
	return normalized, nil
}

// normalizeManagedCodexCatalog removes provider-only reasoning levels before
// the catalog reaches Codex. GPT-5.6 is intentionally limited to the five
// product-supported levels, so an upstream `ultra` entry cannot leak into the
// picker. Unknown model metadata is preserved byte-for-byte unless filtering
// is required.
func normalizeManagedCodexCatalog(data []byte) ([]byte, bool, error) {
	if len(data) == 0 || len(data) > maxManagedCodexCatalog {
		return nil, false, errors.New("managed Codex model catalog has an invalid size")
	}
	var catalog managedCodexCatalog
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return nil, false, errors.New("managed Codex model catalog is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, false, errors.New("managed Codex model catalog has a trailing JSON value")
	}

	changed := false
	for index, raw := range catalog.Models {
		var model map[string]json.RawMessage
		if err := json.Unmarshal(raw, &model); err != nil {
			return nil, false, errors.New("managed Codex model metadata is invalid")
		}
		var levels []managedCodexReasoningLevel
		if err := json.Unmarshal(model["supported_reasoning_levels"], &levels); err != nil {
			return nil, false, errors.New("managed Codex reasoning metadata is invalid")
		}
		filtered := levels[:0]
		for _, level := range levels {
			if containsString(managedCodexReasoningEfforts, level.Effort) {
				filtered = append(filtered, level)
			} else {
				changed = true
			}
		}
		if len(filtered) != len(levels) {
			encodedLevels, err := json.Marshal(filtered)
			if err != nil {
				return nil, false, errors.New("encode managed Codex reasoning metadata")
			}
			model["supported_reasoning_levels"] = encodedLevels
			encodedModel, err := json.Marshal(model)
			if err != nil {
				return nil, false, errors.New("encode managed Codex model metadata")
			}
			catalog.Models[index] = encodedModel
		}
	}

	if !changed {
		if err := validateManagedCodexCatalog(data); err != nil {
			return nil, false, err
		}
		return append(bytes.TrimSpace(data), '\n'), false, nil
	}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		return nil, false, errors.New("encode managed Codex model catalog")
	}
	encoded = append(encoded, '\n')
	if err := validateManagedCodexCatalog(encoded); err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

func validateManagedCodexCatalog(data []byte) error {
	if len(data) == 0 || len(data) > maxManagedCodexCatalog {
		return errors.New("managed Codex model catalog has an invalid size")
	}
	var catalog managedCodexCatalog
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return errors.New("managed Codex model catalog is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("managed Codex model catalog has a trailing JSON value")
	}
	want := modelbootstrap.ManagedCodexModels()
	if len(catalog.Models) != len(want) {
		return fmt.Errorf("managed Codex model catalog has %d models instead of %d", len(catalog.Models), len(want))
	}
	seen := make([]string, 0, len(catalog.Models))
	for _, raw := range catalog.Models {
		var model managedCodexModelMetadata
		if err := json.Unmarshal(raw, &model); err != nil {
			return errors.New("managed Codex model metadata is invalid")
		}
		if model.Slug == "" || model.DisplayName == "" || model.BaseInstructions == "" || model.Visibility != "list" || !model.SupportedInAPI || model.Priority <= 0 || model.ContextWindow <= 0 || model.MaxContextWindow < model.ContextWindow || len(model.SupportedReasoningLevels) == 0 {
			return fmt.Errorf("managed Codex model %q has incomplete runtime metadata", model.Slug)
		}
		for _, effort := range model.SupportedReasoningLevels {
			if effort.Effort == "" || effort.Description == "" {
				return fmt.Errorf("managed Codex model %q has incomplete reasoning metadata", model.Slug)
			}
		}
		reasoningEfforts := make([]string, 0, len(model.SupportedReasoningLevels))
		for _, effort := range model.SupportedReasoningLevels {
			reasoningEfforts = append(reasoningEfforts, effort.Effort)
		}
		if len(reasoningEfforts) != len(managedCodexReasoningEfforts) || !sameStringSet(reasoningEfforts, managedCodexReasoningEfforts) {
			return fmt.Errorf("managed Codex model %q does not contain the exact supported reasoning levels", model.Slug)
		}
		seen = append(seen, model.Slug)
	}
	if !sameStringSet(seen, want) {
		return errors.New("managed Codex model catalog does not contain the exact supported models")
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func writeManagedCodexCatalogSetting(configPath, catalogPath, releaseVersion, codexVersion string, catalogData []byte) (bool, error) {
	if releaseVersion == "" || strings.ContainsAny(releaseVersion, "\r\n") || !managedCodexCatalogVersion.MatchString(codexVersion) {
		return false, errors.New("managed Codex catalog verification identity is invalid")
	}
	digest := sha256.Sum256(catalogData)
	managed := []string{
		fmt.Sprintf("# Managed Codex model catalog: release=%s codex=%s sha256=%x", releaseVersion, codexVersion, digest),
		"model_catalog_json = " + strconv.Quote(catalogPath),
		"",
	}
	return rewriteCodexConfigIfChanged(configPath, managedCodexCatalogSetting, managed)
}

func loadCodexAPIKey(path string) ([]byte, error) {
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
	if err := decoder.Decode(&struct{}{}); err != io.EOF || auth.AuthMode != "apikey" || !managedCodexAPIKeyPattern.MatchString(auth.APIKey) {
		return nil, errors.New("Codex auth.json did not contain a managed API-key login")
	}
	return []byte(auth.APIKey), nil
}

func (h *Host) verifyManagedCodexModelList(ctx context.Context, env []string) error {
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	executable := filepath.Join(agentcli.BinFromAionReleases(h.cfg.ReleasesRoot), "codex.exe")
	cmd := exec.CommandContext(verifyCtx, executable, "app-server", "--listen", "stdio://")
	cmd.WaitDelay = managedCodexVerifierCleanupTimeout
	cmd.Dir = h.dirs.Workspace
	cmd.Env = env
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := h.sandbox.Apply(cmd); err != nil {
		return fmt.Errorf("sandbox Codex model catalog verification: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Codex model catalog verification: %w", err)
	}
	defer func() {
		_ = stdin.Close()
		cancel()
		if err := cmd.Wait(); errors.Is(err, exec.ErrWaitDelay) {
			h.log.Printf("Codex model catalog verifier cleanup exceeded %s; inherited pipes were closed", managedCodexVerifierCleanupTimeout)
		}
	}()
	if err := h.sandbox.VerifyProcess(uint32(cmd.Process.Pid), h.cfg.WindowsSID); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), maxManagedCodexCatalog)
	results := scanCodexResponses(verifyCtx, scanner)
	readResponse := func(requestID int) (codexResponseEnvelope, error) {
		return readCodexResponse(verifyCtx, results, requestID)
	}
	send := func(request string) error {
		if _, err := io.WriteString(stdin, request+"\n"); err != nil {
			return errors.New("write Codex model catalog verification request")
		}
		return nil
	}

	if err := send(`{"id":1,"method":"initialize","params":{"clientInfo":{"name":"aionui-portal","title":"AionUi Portal","version":"1.0.0"}}}`); err != nil {
		return err
	}
	initialized, err := readResponse(1)
	if err != nil {
		return err
	}
	if len(initialized.Error) != 0 && string(initialized.Error) != "null" {
		return errors.New("Codex app-server rejected model catalog verification initialization")
	}
	if err := send(`{"method":"initialized","params":{}}`); err != nil {
		return err
	}
	if err := send(`{"id":2,"method":"model/list","params":{"limit":100}}`); err != nil {
		return err
	}
	envelope, err := readResponse(2)
	if err != nil {
		return err
	}
	if len(envelope.Error) != 0 && string(envelope.Error) != "null" {
		return errors.New("Codex model/list rejected the managed catalog")
	}
	models := make([]string, 0, len(envelope.Result.Data))
	for _, item := range envelope.Result.Data {
		models = append(models, item.Model)
	}
	if !sameStringSet(models, modelbootstrap.ManagedCodexModels()) {
		return fmt.Errorf("Codex model/list returned %v instead of the exact managed catalog", models)
	}
	return nil
}

func scanCodexResponses(ctx context.Context, scanner *bufio.Scanner) <-chan codexScanResult {
	results := make(chan codexScanResult)
	go func() {
		defer close(results)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case results <- codexScanResult{line: line}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case results <- codexScanResult{err: scanner.Err()}:
		case <-ctx.Done():
		}
	}()
	return results
}

func readCodexResponse(ctx context.Context, results <-chan codexScanResult, requestID int) (codexResponseEnvelope, error) {
	for lines := 0; lines < 100; lines++ {
		select {
		case <-ctx.Done():
			return codexResponseEnvelope{}, errors.New("Codex model catalog verification exceeded 30 seconds")
		case result, open := <-results:
			if !open {
				return codexResponseEnvelope{}, fmt.Errorf("Codex model catalog verification returned no response for request %d", requestID)
			}
			if result.err != nil {
				return codexResponseEnvelope{}, fmt.Errorf("read Codex model catalog verification: %w", result.err)
			}
			if result.line == nil {
				return codexResponseEnvelope{}, fmt.Errorf("Codex model catalog verification returned no response for request %d", requestID)
			}
			var envelope codexResponseEnvelope
			if json.Unmarshal(result.line, &envelope) == nil && envelope.ID == requestID {
				return envelope, nil
			}
		}
	}
	return codexResponseEnvelope{}, fmt.Errorf("Codex model catalog verification returned no response for request %d", requestID)
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}
