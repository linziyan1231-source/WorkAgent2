package userhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"aionuiportal/internal/ipc"
)

var sharedCredentialIDPattern = regexp.MustCompile(`^shared-[a-f0-9]{32}$`)

type sharedAgentCredential struct {
	PlainKey string
	BaseURL  string
}

func (h *Host) installSharedAgentCredential(request ipc.SharedAgentCredentialRequest) error {
	id, key, baseURL := strings.TrimSpace(request.CredentialID), strings.TrimSpace(request.PlainKey), strings.TrimSpace(request.BaseURL)
	parsed, err := url.Parse(baseURL)
	if !sharedCredentialIDPattern.MatchString(id) || err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Path != "/v1" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`).MatchString(key) {
		return errors.New("shared Agent credential is invalid")
	}
	h.sharedCredentialMu.Lock()
	h.sharedCredentials[id] = sharedAgentCredential{PlainKey: key, BaseURL: baseURL}
	h.sharedCredentialMu.Unlock()
	return nil
}

func (h *Host) hasSharedAgentCredential(id string) bool {
	h.sharedCredentialMu.RLock()
	_, ok := h.sharedCredentials[strings.TrimSpace(id)]
	h.sharedCredentialMu.RUnlock()
	return ok
}

func (h *Host) sharedAgentCredential(id string) (sharedAgentCredential, bool) {
	h.sharedCredentialMu.RLock()
	credential, ok := h.sharedCredentials[strings.TrimSpace(id)]
	h.sharedCredentialMu.RUnlock()
	return credential, ok
}

func (h *Host) runSharedAgent(ctx context.Context, request ipc.SharedAgentRequest) (ipc.SharedAgentResult, string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) || !sharedCredentialIDPattern.MatchString(strings.TrimSpace(request.CredentialID)) {
		return ipc.SharedAgentResult{}, "INVALID_SHARED_AGENT", errors.New("shared agent request is invalid")
	}
	request.Name, request.AssistantID, request.ModelID = strings.TrimSpace(request.Name), strings.TrimSpace(request.AssistantID), strings.TrimSpace(request.ModelID)
	request.ThinkingEffort = strings.TrimSpace(request.ThinkingEffort)
	if request.Name == "" || len(request.Name) > 128 || request.AssistantID == "" || len(request.AssistantID) > 256 || request.ModelID == "" || len(request.ModelID) > 256 || request.ThinkingEffort == "" || len(request.ThinkingEffort) > 32 || (request.AssistantBackend != "codex" && request.AssistantBackend != "kimi") || request.Context == "" || len(request.Context) > 512*1024 || len(request.RecoveryContext) > 768*1024 {
		return ipc.SharedAgentResult{}, "INVALID_SHARED_AGENT", errors.New("shared agent fields are invalid")
	}
	projectRoot := filepath.Join(filepath.Clean(h.cfg.DataRootBase), "shared", h.cfg.WindowsSID, request.ProjectID)
	if err := requireNormalDirectory(projectRoot); err != nil {
		return ipc.SharedAgentResult{}, "SHARED_PROJECT_NOT_FOUND", err
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".aionui-shared-runtime"), []byte("managed shared runtime\n"), 0600); err != nil {
		return ipc.SharedAgentResult{}, "SHARED_PROJECT_INVALID", err
	}
	runtimeID := strings.TrimSpace(request.RuntimeConversationID)
	recovered := false
	if runtimeID == "" {
		var err error
		runtimeID, err = h.createSharedRuntimeConversation(ctx, request, projectRoot)
		if err != nil {
			return ipc.SharedAgentResult{}, "SHARED_AGENT_CREATE_FAILED", err
		}
	}
	if err := h.configureSharedRuntimeCredential(ctx, runtimeID, request.AssistantBackend, request.CredentialID); err != nil {
		return ipc.SharedAgentResult{}, "SHARED_AGENT_CREDENTIAL_FAILED", err
	}
	previousAssistantID, _, err := h.lastSharedAssistantText(ctx, runtimeID, "")
	if err != nil {
		return ipc.SharedAgentResult{}, "SHARED_AGENT_WAIT_FAILED", err
	}
	turnID, err := h.sendSharedRuntimeMessage(ctx, runtimeID, request.Context)
	if err != nil && request.RuntimeConversationID != "" {
		recovered = true
		runtimeID, err = h.createSharedRuntimeConversation(ctx, request, projectRoot)
		if err == nil {
			err = h.configureSharedRuntimeCredential(ctx, runtimeID, request.AssistantBackend, request.CredentialID)
		}
		if err == nil {
			previousAssistantID = ""
			contextBody := request.RecoveryContext
			if strings.TrimSpace(contextBody) == "" {
				contextBody = request.Context
			}
			turnID, err = h.sendSharedRuntimeMessage(ctx, runtimeID, contextBody)
		}
	}
	if err != nil {
		return ipc.SharedAgentResult{}, "SHARED_AGENT_SEND_FAILED", err
	}
	body, err := h.waitSharedRuntimeResult(ctx, runtimeID, turnID, previousAssistantID)
	if err != nil {
		return ipc.SharedAgentResult{}, "SHARED_AGENT_WAIT_FAILED", err
	}
	return ipc.SharedAgentResult{RuntimeConversationID: runtimeID, TurnID: turnID, AssistantBody: body, Recovered: recovered}, "", nil
}

func (h *Host) configureSharedRuntimeCredential(ctx context.Context, runtimeID, backend, credentialID string) error {
	credential, ok := h.sharedAgentCredential(credentialID)
	if !ok {
		return errors.New("shared Agent credential is not installed in this UserHost instance")
	}
	path := "/api/internal/conversations/" + url.PathEscape(runtimeID) + "/runtime-env"
	body := map[string]string{"backend": backend, "base_url": credential.BaseURL, "api_key": credential.PlainKey}
	return h.client.sendJSONWithHeader(ctx, http.MethodPost, path, body, nil, "x-aionui-portal-runtime-control", h.runtimeControlSecret)
}

func (h *Host) stopSharedAgent(ctx context.Context, request ipc.SharedAgentStopRequest) (string, error) {
	if !h.validOAuthInstance(request.InstanceID) || !validSharedProjectID(request.ProjectID) {
		return "INVALID_SHARED_AGENT", errors.New("shared agent stop request is invalid")
	}
	projectRoot := filepath.Join(filepath.Clean(h.cfg.DataRootBase), "shared", h.cfg.WindowsSID, request.ProjectID)
	if err := requireNormalDirectory(projectRoot); err != nil {
		return "SHARED_PROJECT_NOT_FOUND", err
	}
	ids, err := projectConversationIDs(ctx, filepath.Join(h.dirs.Data, "aionui-backend.db"), projectRoot)
	if err != nil {
		return "SHARED_AGENT_STOP_FAILED", err
	}
	active, err := h.activeProjectConversations(ctx, ids)
	if err != nil {
		return "SHARED_AGENT_STOP_FAILED", err
	}
	if err := h.stopProjectConversations(ctx, active); err != nil {
		return "SHARED_AGENT_STOP_FAILED", err
	}
	return "", nil
}

func (h *Host) createSharedRuntimeConversation(ctx context.Context, request ipc.SharedAgentRequest, projectRoot string) (string, error) {
	payload := map[string]any{
		"type": "acp",
		"name": request.Name,
		"assistant": map[string]any{
			"id":                     request.AssistantID,
			"conversation_overrides": map[string]any{"model": request.ModelID},
		},
		"extra": map[string]any{
			"workspace":               projectRoot,
			"custom_workspace":        true,
			"is_project_workspace":    true,
			"shared_project_id":       request.ProjectID,
			"internal_shared_runtime": true,
			"thought_level":           request.ThinkingEffort,
		},
	}
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := h.client.sendJSON(ctx, http.MethodPost, "/api/conversations", payload, &response); err != nil {
		return "", err
	}
	if !response.Success || strings.TrimSpace(response.Data.ID) == "" {
		return "", errors.New("AionCore returned no shared runtime conversation")
	}
	return response.Data.ID, nil
}

func (h *Host) sendSharedRuntimeMessage(ctx context.Context, runtimeID, content string) (string, error) {
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			TurnID string `json:"turn_id"`
		} `json:"data"`
	}
	path := "/api/conversations/" + url.PathEscape(runtimeID) + "/messages"
	if err := h.client.sendJSON(ctx, http.MethodPost, path, map[string]any{"content": content, "files": []string{}}, &response); err != nil {
		return "", err
	}
	if !response.Success || response.Data.TurnID == "" {
		return "", errors.New("AionCore returned no shared turn id")
	}
	return response.Data.TurnID, nil
}

func (h *Host) waitSharedRuntimeResult(ctx context.Context, runtimeID, turnID, previousAssistantID string) (string, error) {
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	observedActive := false
	idleWithoutText := 0
	for {
		body, err := h.sharedAssistantTextsAfter(ctx, runtimeID, previousAssistantID)
		if err != nil {
			return "", err
		}
		active, err := h.sharedRuntimeTurnActive(ctx, runtimeID, turnID)
		if err != nil {
			return "", err
		}
		if active {
			observedActive = true
			idleWithoutText = 0
		} else if strings.TrimSpace(body) != "" {
			return body, nil
		} else if observedActive {
			idleWithoutText++
			if idleWithoutText >= 3 {
				return "", errors.New("shared Agent turn completed without an assistant response")
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func (h *Host) sharedRuntimeTurnActive(ctx context.Context, runtimeID, turnID string) (bool, error) {
	var response struct {
		Success *bool `json:"success"`
		Data    *struct {
			ID      *string         `json:"id"`
			Runtime *projectRuntime `json:"runtime"`
		} `json:"data"`
	}
	path := "/api/conversations/" + url.PathEscape(runtimeID)
	if err := h.client.getJSON(ctx, path, &response); err != nil || response.Success == nil || !*response.Success || response.Data == nil || response.Data.ID == nil || *response.Data.ID != runtimeID {
		return false, fmt.Errorf("shared Agent conversation %s runtime is unavailable", runtimeID)
	}
	runtime := response.Data.Runtime
	if runtime == nil {
		return false, nil
	}
	if runtime.State == nil || runtime.IsProcessing == nil || runtime.PendingConfirmations == nil || *runtime.PendingConfirmations < 0 {
		return false, errors.New("shared Agent runtime is incomplete")
	}
	if *runtime.State == "idle" && !*runtime.IsProcessing && *runtime.PendingConfirmations == 0 {
		return false, nil
	}
	if runtime.TurnID == nil || strings.TrimSpace(*runtime.TurnID) != turnID {
		return false, errors.New("shared Agent runtime is processing an unexpected turn")
	}
	return true, nil
}

func (h *Host) sharedAssistantTextsAfter(ctx context.Context, runtimeID, excludedID string) (string, error) {
	items, err := h.sharedAssistantTextItems(ctx, runtimeID)
	if err != nil {
		return "", err
	}
	start := excludedID == ""
	parts := make([]string, 0)
	for _, item := range items {
		if !start {
			if item.ID == excludedID {
				start = true
			}
			continue
		}
		if text := strings.TrimSpace(item.Body); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n\n"), nil
}

type sharedAssistantTextItem struct {
	ID   string
	Body string
}

func (h *Host) sharedAssistantTextItems(ctx context.Context, runtimeID string) ([]sharedAssistantTextItem, error) {
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			Items []struct {
				ID       string          `json:"id"`
				Type     string          `json:"type"`
				Position string          `json:"position"`
				Status   string          `json:"status"`
				Content  json.RawMessage `json:"content"`
			} `json:"items"`
		} `json:"data"`
	}
	path := "/api/conversations/" + url.PathEscape(runtimeID) + "/messages?limit=200"
	if err := h.client.getJSON(ctx, path, &response); err != nil {
		return nil, err
	}
	items := make([]sharedAssistantTextItem, 0)
	for _, item := range response.Data.Items {
		if item.Type != "text" || item.Position == "right" || item.Status != "finish" {
			continue
		}
		var content struct {
			Content string `json:"content"`
		}
		if json.Unmarshal(item.Content, &content) == nil && strings.TrimSpace(content.Content) != "" {
			items = append(items, sharedAssistantTextItem{ID: item.ID, Body: content.Content})
		}
	}
	return items, nil
}

func (h *Host) lastSharedAssistantText(ctx context.Context, runtimeID, excludedID string) (string, string, error) {
	items, err := h.sharedAssistantTextItems(ctx, runtimeID)
	if err != nil {
		return "", "", err
	}
	if len(items) == 0 {
		return "", "", nil
	}
	latestID, latest := items[len(items)-1].ID, items[len(items)-1].Body
	if latestID == excludedID {
		return latestID, "", nil
	}
	return latestID, latest, nil
}
