package userhost

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type activeProjectConversation struct {
	id     string
	turnID string
}

type projectRuntime struct {
	State                *string `json:"state"`
	IsProcessing         *bool   `json:"is_processing"`
	PendingConfirmations *int    `json:"pending_confirmations"`
	TurnID               *string `json:"turn_id"`
}

func projectConversationIDs(ctx context.Context, dbPath, workspace string) ([]string, error) {
	db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(dbPath, `\`, "/")+"?mode=ro&_pragma=busy_timeout(3000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT id,extra FROM conversations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil || extra == nil {
			return nil, fmt.Errorf("conversation %s has invalid extra JSON", id)
		}
		path, pathOK := extra["workspace"].(string)
		custom, customOK := extra["custom_workspace"].(bool)
		if pathOK && customOK && custom && samePath(path, workspace) {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func (h *Host) activeProjectConversations(ctx context.Context, ids []string) ([]activeProjectConversation, error) {
	active := make([]activeProjectConversation, 0, len(ids))
	for _, id := range ids {
		var response struct {
			Success *bool `json:"success"`
			Data    *struct {
				ID      *string         `json:"id"`
				Runtime *projectRuntime `json:"runtime"`
			} `json:"data"`
		}
		path := "/api/conversations/" + url.PathEscape(id)
		if err := h.client.getJSON(ctx, path, &response); err != nil || response.Success == nil || !*response.Success || response.Data == nil || response.Data.ID == nil || *response.Data.ID != id {
			return nil, fmt.Errorf("conversation %s runtime is unavailable", id)
		}
		runtime := response.Data.Runtime
		if runtime == nil {
			continue
		}
		if runtime.State == nil || runtime.IsProcessing == nil || runtime.PendingConfirmations == nil || runtime.TurnID == nil || *runtime.PendingConfirmations < 0 {
			return nil, fmt.Errorf("conversation %s runtime is incomplete", id)
		}
		switch *runtime.State {
		case "idle":
			if !*runtime.IsProcessing && *runtime.PendingConfirmations == 0 {
				continue
			}
		case "starting", "running", "cancelling", "waiting_confirmation":
		default:
			return nil, fmt.Errorf("conversation %s runtime state is unknown", id)
		}
		if strings.TrimSpace(*runtime.TurnID) == "" {
			return nil, fmt.Errorf("conversation %s is active without a turn id", id)
		}
		active = append(active, activeProjectConversation{id: id, turnID: *runtime.TurnID})
	}
	return active, nil
}

func (h *Host) stopProjectConversations(ctx context.Context, active []activeProjectConversation) error {
	for _, conversation := range active {
		path := "/api/conversations/" + url.PathEscape(conversation.id) + "/cancel"
		if err := h.client.sendJSON(ctx, http.MethodPost, path, map[string]string{"turn_id": conversation.turnID}, nil); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	ids := make([]string, 0, len(active))
	for _, conversation := range active {
		ids = append(ids, conversation.id)
	}
	for {
		remaining, err := h.activeProjectConversations(ctx, ids)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("project tasks did not stop within 5 seconds")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
