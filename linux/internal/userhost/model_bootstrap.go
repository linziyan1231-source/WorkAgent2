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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/httpjson"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
)

const (
	modelBootstrapMarkerPath  = "config/model-bootstrap-v1.applied.json"
	modelBootstrapPendingPath = "credentials/model-bootstrap-v1.pending.json"
	codexConfigPath           = "config/codex/config.toml"
	codexAuthPath             = "config/codex/auth.json"
	kimiConfigPath            = "home/.kimi-code/config.toml"
	maxModelConfigBytes       = 1024 * 1024
	managedKimiProvider       = "managed:kimi-code"
	kimiTopBlockStart         = "# BEGIN WORKAGENT2 MANAGED KIMI DEFAULTS"
	kimiTopBlockEnd           = "# END WORKAGENT2 MANAGED KIMI DEFAULTS"
	kimiTableBlockStart       = "# BEGIN WORKAGENT2 MANAGED KIMI CATALOG"
	kimiTableBlockEnd         = "# END WORKAGENT2 MANAGED KIMI CATALOG"
	legacyKimiTopBlockStart   = "# BEGIN WorkAgent2 MANAGED KIMI DEFAULTS"
	legacyKimiTopBlockEnd     = "# END WorkAgent2 MANAGED KIMI DEFAULTS"
	legacyKimiTableBlockStart = "# BEGIN WorkAgent2 MANAGED KIMI CATALOG"
	legacyKimiTableBlockEnd   = "# END WorkAgent2 MANAGED KIMI CATALOG"
)

var managedCodexAssignment = regexp.MustCompile(`^\s*(?:["']?(openai_base_url|model_reasoning_effort|model|cli_auth_credentials_store)["']?)\s*=`)

type modelBootstrapStatusResponse struct {
	Applied bool                 `json:"applied"`
	Pending bool                 `json:"pending"`
	State   modelbootstrap.State `json:"state"`
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

func (h *Host) modelBootstrapStatus(writer http.ResponseWriter, request *http.Request) {
	state, markerErr := h.readAppliedModelState()
	pending, pendingErr := h.readPendingModelBundle()
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		http.Error(writer, "model configuration state is invalid", http.StatusInternalServerError)
		return
	}
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		http.Error(writer, "model configuration state is invalid", http.StatusInternalServerError)
		return
	}
	response := modelBootstrapStatusResponse{Applied: markerErr == nil, Pending: pendingErr == nil, State: state}
	if pendingErr == nil {
		response.State = pending.State
		pending.Zero()
	}
	writeJSON(writer, http.StatusOK, response)
}

func (h *Host) modelBootstrapApply(writer http.ResponseWriter, request *http.Request) {
	if mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); mediaType != "application/json" {
		http.Error(writer, "JSON content type required", http.StatusUnsupportedMediaType)
		return
	}
	var bundle modelbootstrap.Bundle
	if err := httpjson.Decode(request, &bundle, 256*1024); err != nil || bundle.ValidateManagedForTenant(h.cfg.TenantID) != nil {
		bundle.Zero()
		http.Error(writer, "invalid model configuration", http.StatusBadRequest)
		return
	}
	defer bundle.Zero()

	// A single writer keeps key rotation, client files, backend providers and the
	// key-free applied marker in one observable order.
	h.bootstrapMu.Lock()
	defer h.bootstrapMu.Unlock()
	payload, err := encodeStrictJSON(bundle)
	if err != nil {
		http.Error(writer, "model configuration unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.dataRoot.WriteFileAtomic(modelBootstrapPendingPath, payload, 0o600); err != nil {
		clear(payload)
		h.logger.Printf("stage model bootstrap: %v", err)
		http.Error(writer, "model configuration unavailable", http.StatusInternalServerError)
		return
	}
	clear(payload)
	operation := &bootstrapOperation{bundle: bundle, done: make(chan error, 1)}
	select {
	case h.bootstrap <- operation:
	case <-request.Context().Done():
		return
	}
	select {
	case err := <-operation.done:
		if err != nil {
			h.logger.Printf("apply model bootstrap policy=%s: %v", operation.bundle.PolicyID, err)
			http.Error(writer, "model configuration could not be applied", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, modelBootstrapStatusResponse{Applied: true, State: operation.bundle.State})
	case <-request.Context().Done():
		return
	}
}

func (h *Host) loadStartupModelBundle() (modelbootstrap.Bundle, bool, error) {
	pending, pendingErr := h.readPendingModelBundle()
	state, markerErr := h.readAppliedModelState()
	if pendingErr == nil {
		if markerErr == nil && !pending.State.Equal(state) {
			pending.Zero()
			return modelbootstrap.Bundle{}, false, errors.New("pending and applied model policies conflict")
		}
		if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
			pending.Zero()
			return modelbootstrap.Bundle{}, false, markerErr
		}
		return pending, true, nil
	}
	if !errors.Is(pendingErr, os.ErrNotExist) {
		return modelbootstrap.Bundle{}, false, pendingErr
	}
	if markerErr == nil {
		bundle, err := h.loadAppliedModelBundle(state)
		return bundle, err == nil, err
	}
	if errors.Is(markerErr, os.ErrNotExist) {
		return modelbootstrap.Bundle{}, false, nil
	}
	return modelbootstrap.Bundle{}, false, markerErr
}

func (h *Host) readAppliedModelState() (modelbootstrap.State, error) {
	var state modelbootstrap.State
	if err := h.readPrivateJSON(modelBootstrapMarkerPath, 256*1024, &state); err != nil {
		return modelbootstrap.State{}, err
	}
	if err := state.ValidateForTenant(h.cfg.TenantID); err != nil {
		return modelbootstrap.State{}, err
	}
	return state, nil
}

func (h *Host) readPendingModelBundle() (modelbootstrap.Bundle, error) {
	var bundle modelbootstrap.Bundle
	if err := h.readPrivateJSON(modelBootstrapPendingPath, 256*1024, &bundle); err != nil {
		return modelbootstrap.Bundle{}, err
	}
	if err := bundle.ValidateManagedForTenant(h.cfg.TenantID); err != nil {
		bundle.Zero()
		return modelbootstrap.Bundle{}, err
	}
	return bundle, nil
}

func (h *Host) readPrivateJSON(relative string, maximum int64, destination any) error {
	payload, err := h.dataRoot.ReadFile(relative, maximum)
	if err != nil {
		return err
	}
	defer clear(payload)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("private JSON file contains trailing data")
	}
	return nil
}

func (h *Host) loadAppliedModelBundle(state modelbootstrap.State) (modelbootstrap.Bundle, error) {
	var auth struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
	}
	if err := h.readPrivateJSON(codexAuthPath, 64*1024, &auth); err != nil {
		return modelbootstrap.Bundle{}, fmt.Errorf("read Codex API-key login: %w", err)
	}
	kimi, err := h.readManagedKimiKey()
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	bundle := modelbootstrap.Bundle{State: state, CodexAPIKey: auth.APIKey, KimiAPIKey: kimi}
	if auth.AuthMode != "apikey" || bundle.ValidateForTenant(h.cfg.TenantID) != nil {
		bundle.Zero()
		return modelbootstrap.Bundle{}, errors.New("applied CLI model credentials do not match the marker")
	}
	return bundle, nil
}

func (h *Host) readManagedKimiKey() (string, error) {
	payload, err := h.dataRoot.ReadFile(kimiConfigPath, maxModelConfigBytes)
	if err != nil {
		return "", fmt.Errorf("read Kimi model configuration: %w", err)
	}
	defer clear(payload)
	lines := strings.Split(string(payload), "\n")
	inManaged := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == `[providers."`+managedKimiProvider+`"]` {
			inManaged = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inManaged = false
		}
		if inManaged && strings.HasPrefix(trimmed, "api_key") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) != 2 {
				break
			}
			value, err := strconv.Unquote(strings.TrimSpace(parts[1]))
			if err == nil {
				return value, nil
			}
		}
	}
	return "", errors.New("managed Kimi API key is missing")
}

func (h *Host) writeCLIModelConfiguration(bundle modelbootstrap.Bundle) error {
	if err := bundle.ValidateManagedForTenant(h.cfg.TenantID); err != nil {
		return err
	}
	if err := h.writeCodexConfig(bundle); err != nil {
		return err
	}
	authPayload, err := encodeStrictJSON(map[string]string{"auth_mode": "apikey", "OPENAI_API_KEY": bundle.CodexAPIKey})
	if err != nil {
		return err
	}
	if err := h.dataRoot.WriteFileAtomic(codexAuthPath, authPayload, 0o600); err != nil {
		clear(authPayload)
		return fmt.Errorf("write Codex API-key login: %w", err)
	}
	clear(authPayload)
	if err := h.writeKimiConfig(bundle); err != nil {
		return err
	}
	return nil
}

func (h *Host) writeCodexConfig(bundle modelbootstrap.Bundle) error {
	existing, err := h.readOptional(codexConfigPath, maxModelConfigBytes)
	if err != nil {
		return err
	}
	defer clear(existing)
	preserved, err := removeTopLevelAssignments(string(existing), managedCodexAssignment)
	if err != nil {
		return fmt.Errorf("rewrite Codex configuration: %w", err)
	}
	managed := []string{
		"# Initial CLIProxyAPI settings managed by WorkAgent2.",
		"openai_base_url = " + strconv.Quote(bundle.BaseURL),
		"model = " + strconv.Quote(bundle.CodexDefaultModel),
		"model_reasoning_effort = " + strconv.Quote(modelbootstrap.DefaultCodexReasoningEffort),
		`cli_auth_credentials_store = "file"`,
		"",
	}
	content := strings.Join(managed, "\n") + strings.TrimLeft(preserved, "\n")
	content = strings.TrimRight(content, "\n") + "\n"
	if err := h.dataRoot.WriteFileAtomic(codexConfigPath, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write Codex configuration: %w", err)
	}
	return nil
}

func removeTopLevelAssignments(existing string, assignment *regexp.Regexp) (string, error) {
	var preserved []string
	scanner := bufio.NewScanner(strings.NewReader(existing))
	scanner.Buffer(make([]byte, 4096), maxModelConfigBytes)
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
					return "", fmt.Errorf("managed key %s uses a multiline value", match[1])
				}
				continue
			}
		}
		preserved = append(preserved, line)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.Join(preserved, "\n"), nil
}

func (h *Host) writeKimiConfig(bundle modelbootstrap.Bundle) error {
	if err := bundle.ValidateManagedForTenant(h.cfg.TenantID); err != nil {
		return err
	}
	existing, err := h.readOptional(kimiConfigPath, maxModelConfigBytes)
	if err != nil {
		return err
	}
	defer clear(existing)
	preserved, err := removeMarkedBlock(string(existing), kimiTopBlockStart, kimiTopBlockEnd)
	if err != nil {
		return err
	}
	preserved, err = removeMarkedBlock(preserved, kimiTableBlockStart, kimiTableBlockEnd)
	if err != nil {
		return err
	}
	preserved, err = removeMarkedBlock(preserved, legacyKimiTopBlockStart, legacyKimiTopBlockEnd)
	if err != nil {
		return err
	}
	preserved, err = removeMarkedBlock(preserved, legacyKimiTableBlockStart, legacyKimiTableBlockEnd)
	if err != nil {
		return err
	}
	kimiDefaults := regexp.MustCompile(`^\s*(?:["']?(default_model|default_thinking|default_yolo)["']?)\s*=`)
	preserved, err = removeTopLevelAssignments(preserved, kimiDefaults)
	if err != nil {
		return fmt.Errorf("rewrite Kimi configuration: %w", err)
	}
	preserved, hasThinkingTable, err := reconcileKimiThinkingTable(preserved)
	if err != nil {
		return fmt.Errorf("rewrite Kimi thinking configuration: %w", err)
	}
	for _, line := range strings.Split(preserved, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == `[providers."`+managedKimiProvider+`"]` || strings.HasPrefix(trimmed, `[models."workagent-managed/`) || strings.HasPrefix(trimmed, `[models."workagent-managed/`) {
			return errors.New("unmanaged Kimi configuration collides with the WorkAgent2 managed catalog")
		}
	}
	var output strings.Builder
	output.WriteString(kimiTopBlockStart + "\n")
	output.WriteString("default_model = " + strconv.Quote("workagent-managed/"+modelbootstrap.DefaultKimiModel) + "\n")
	output.WriteString("default_thinking = true\n")
	output.WriteString("default_yolo = true\n")
	output.WriteString(kimiTopBlockEnd + "\n\n")
	if strings.TrimSpace(preserved) != "" {
		output.WriteString(strings.TrimSpace(preserved))
		output.WriteString("\n\n")
	}
	output.WriteString(kimiTableBlockStart + "\n")
	if !hasThinkingTable {
		output.WriteString("[thinking]\n")
		output.WriteString("enabled = true\n\n")
	}
	output.WriteString(`[providers."` + managedKimiProvider + `"]` + "\n")
	output.WriteString(`type = "kimi"` + "\n")
	output.WriteString("base_url = " + strconv.Quote(bundle.BaseURL) + "\n")
	output.WriteString("api_key = " + strconv.Quote(bundle.KimiAPIKey) + "\n\n")
	for _, model := range modelbootstrap.ManagedKimiModels() {
		output.WriteString(`[models."workagent-managed/` + model + `"]` + "\n")
		output.WriteString("provider = " + strconv.Quote(managedKimiProvider) + "\n")
		output.WriteString("model = " + strconv.Quote(model) + "\n")
		output.WriteString(`support_efforts = ["low", "high", "max"]` + "\n")
		switch model {
		case "kimi-k3":
			output.WriteString("max_context_size = 1048576\n")
			output.WriteString(`capabilities = ["thinking"]` + "\n")
			output.WriteString(`default_effort = "low"` + "\n")
			output.WriteString(`display_name = "Kimi K3"` + "\n\n")
		case "kimi-for-coding":
			output.WriteString("max_context_size = 262144\n")
			output.WriteString(`capabilities = ["video_in", "image_in", "thinking"]` + "\n")
			output.WriteString(`default_effort = "high"` + "\n")
			output.WriteString(`display_name = "Kimi K2.7 Code"` + "\n\n")
		case "kimi-for-coding-highspeed":
			output.WriteString("max_context_size = 262144\n")
			output.WriteString(`capabilities = ["video_in", "image_in", "thinking"]` + "\n")
			output.WriteString(`default_effort = "high"` + "\n")
			output.WriteString(`display_name = "Kimi K2.7 Code HighSpeed"` + "\n\n")
		default:
			return fmt.Errorf("unsupported managed Kimi model %q", model)
		}
	}
	output.WriteString(kimiTableBlockEnd + "\n")
	data := []byte(output.String())
	defer clear(data)
	if err := h.dataRoot.WriteFileAtomic(kimiConfigPath, data, 0o600); err != nil {
		return fmt.Errorf("write Kimi configuration: %w", err)
	}
	return nil
}

func reconcileKimiThinkingTable(existing string) (string, bool, error) {
	lines := strings.Split(existing, "\n")
	result := make([]string, 0, len(lines)+1)
	inThinking := false
	found := false
	assignment := regexp.MustCompile(`^\s*(?:["']?enabled["']?)\s*=`)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inThinking = trimmed == "[thinking]"
			if inThinking {
				if found {
					return "", false, errors.New("Kimi thinking table is duplicated")
				}
				found = true
				result = append(result, line, "enabled = true")
				continue
			}
		}
		if inThinking && assignment.MatchString(line) {
			right := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			if strings.HasPrefix(right, `"""`) || strings.HasPrefix(right, `'''`) {
				return "", false, errors.New("Kimi thinking enabled uses a multiline value")
			}
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n"), found, nil
}

func removeMarkedBlock(existing, start, end string) (string, error) {
	lines := strings.Split(existing, "\n")
	result := make([]string, 0, len(lines))
	inside := false
	foundStart := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case start:
			if inside || foundStart {
				return "", errors.New("managed Kimi block is duplicated or nested")
			}
			inside, foundStart = true, true
		case end:
			if !inside {
				return "", errors.New("managed Kimi block terminator is unmatched")
			}
			inside = false
		default:
			if !inside {
				result = append(result, line)
			}
		}
	}
	if inside {
		return "", errors.New("managed Kimi block is incomplete")
	}
	return strings.Join(result, "\n"), nil
}

func (h *Host) readOptional(relative string, maximum int64) ([]byte, error) {
	payload, err := h.dataRoot.ReadFile(relative, maximum)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (h *Host) completeModelBootstrap(ctx context.Context, bundle modelbootstrap.Bundle) error {
	if err := h.upsertManagedProviders(ctx, bundle); err != nil {
		return fmt.Errorf("initialize backend model providers: %w", err)
	}
	payload, err := encodeStrictJSON(bundle.State)
	if err != nil {
		return err
	}
	if err := h.dataRoot.WriteFileAtomic(modelBootstrapMarkerPath, payload, 0o600); err != nil {
		clear(payload)
		return fmt.Errorf("write applied model marker: %w", err)
	}
	clear(payload)
	if err := h.dataRoot.RemoveFile(modelBootstrapPendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("consume pending model credentials: %w", err)
	}
	return nil
}

func (h *Host) applyLiveModelBootstrap(ctx context.Context, bundle modelbootstrap.Bundle) error {
	h.setReady(false)
	if err := h.writeCLIModelConfiguration(bundle); err != nil {
		return err
	}
	if err := h.completeModelBootstrap(ctx, bundle); err != nil {
		return err
	}
	h.setReady(true)
	return nil
}

func (h *Host) finishBootstrap(operation *bootstrapOperation, err error) {
	if operation == nil {
		return
	}
	operation.done <- err
	operation.bundle.Zero()
}

func (h *Host) upsertManagedProviders(ctx context.Context, bundle modelbootstrap.Bundle) error {
	desired := []aionProvider{
		{ID: modelbootstrap.CodexProviderID, Platform: "custom", Name: modelbootstrap.CodexProviderName, BaseURL: bundle.BaseURL, APIKey: bundle.CodexAPIKey, Models: append([]string(nil), bundle.CodexModels...), Enabled: true},
		{ID: modelbootstrap.KimiProviderID, Platform: "custom", Name: modelbootstrap.KimiProviderName, BaseURL: bundle.BaseURL, APIKey: bundle.KimiAPIKey, Models: append([]string(nil), bundle.KimiModels...), Enabled: true},
	}
	var response struct {
		Success bool           `json:"success"`
		Data    []aionProvider `json:"data"`
	}
	if err := h.backendJSON(ctx, http.MethodGet, "/api/providers", nil, &response); err != nil {
		return err
	}
	if !response.Success || response.Data == nil {
		return errors.New("backend provider list was unsuccessful")
	}
	existing := make(map[string]aionProvider, len(response.Data))
	for _, provider := range response.Data {
		if _, duplicate := existing[provider.ID]; duplicate {
			return fmt.Errorf("backend provider id %s is duplicated", provider.ID)
		}
		existing[provider.ID] = provider
	}
	for _, provider := range desired {
		method, requestPath := http.MethodPost, "/api/providers"
		if _, found := existing[provider.ID]; found {
			method, requestPath = http.MethodPut, "/api/providers/"+url.PathEscape(provider.ID)
		}
		if err := h.backendJSON(ctx, method, requestPath, provider, nil); err != nil {
			return err
		}
	}
	response = struct {
		Success bool           `json:"success"`
		Data    []aionProvider `json:"data"`
	}{}
	if err := h.backendJSON(ctx, http.MethodGet, "/api/providers", nil, &response); err != nil {
		return err
	}
	byID := make(map[string][]aionProvider, len(response.Data))
	for _, provider := range response.Data {
		byID[provider.ID] = append(byID[provider.ID], provider)
	}
	for _, expected := range desired {
		matches := byID[expected.ID]
		if len(matches) != 1 || !sameAionProvider(matches[0], expected) {
			return fmt.Errorf("backend provider verification failed for %s", expected.ID)
		}
	}
	return nil
}

func (h *Host) backendJSON(ctx context.Context, method, requestPath string, source, destination any) error {
	h.mu.RLock()
	backendURL := h.backendURL
	transport := h.transport
	auth := h.auth
	h.mu.RUnlock()
	if backendURL == nil || transport == nil || !strings.HasPrefix(requestPath, "/") {
		return errors.New("backend management endpoint is unavailable")
	}
	var body io.Reader
	var encoded []byte
	if source != nil {
		var err error
		encoded, err = json.Marshal(source)
		if err != nil {
			return err
		}
		defer clear(encoded)
		body = bytes.NewReader(encoded)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, backendURL.String()+requestPath, body)
	if err != nil {
		return err
	}
	setWorkAgentRuntimeHeader(request, h.runtimeToken)
	if source != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", backendURL.String())
		if auth.CSRFToken != "" {
			request.Header.Set("X-CSRF-Token", auth.CSRFToken)
		}
	}
	if auth.CookieHeader != "" {
		request.Header.Set("Cookie", auth.CookieHeader)
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("backend management request failed")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxModelConfigBytes+1))
	if err != nil || len(payload) > maxModelConfigBytes {
		clear(payload)
		return errors.New("backend management response exceeded its limit")
	}
	defer clear(payload)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("backend management returned HTTP %d", response.StatusCode)
	}
	if destination == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("backend management response was invalid")
	}
	return nil
}

func sameAionProvider(actual, expected aionProvider) bool {
	if actual.ID != expected.ID || actual.Platform != expected.Platform || actual.Name != expected.Name || actual.BaseURL != expected.BaseURL || actual.APIKey != expected.APIKey || actual.Enabled != expected.Enabled {
		return false
	}
	left, right := append([]string(nil), actual.Models...), append([]string(nil), expected.Models...)
	sort.Strings(left)
	sort.Strings(right)
	return slices.Equal(left, right)
}

func encodeStrictJSON(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}
