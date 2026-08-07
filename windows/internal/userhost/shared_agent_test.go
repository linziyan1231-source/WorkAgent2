package userhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWaitSharedRuntimeResultWaitsForNewFinishedAssistantMessage(t *testing.T) {
	messageRequests := 0
	runtimeRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/conversations/runtime" {
			runtimeRequests++
			processing := runtimeRequests == 1
			state := "idle"
			var turnID any
			if processing {
				state, turnID = "running", "turn"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"id": "runtime", "runtime": map[string]any{"state": state, "is_processing": processing, "pending_confirmations": 0, "turn_id": turnID}}})
			return
		}
		messageRequests++
		items := []map[string]any{
			{"id": "old", "type": "text", "position": "left", "status": "finish", "content": map[string]string{"content": "old reply"}},
		}
		if messageRequests > 1 {
			items = append(items,
				map[string]any{"id": "in-progress", "type": "text", "position": "left", "status": "pending", "content": map[string]string{"content": "partial"}},
				map[string]any{"id": "new-1", "type": "text", "position": "left", "status": "finish", "content": map[string]string{"content": "first reply"}},
				map[string]any{"id": "new-2", "type": "text", "position": "left", "status": "finish", "content": map[string]string{"content": "final reply"}},
			)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"items": items}})
	}))
	defer server.Close()

	host := &Host{client: clientForServer(t, server)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body, err := host.waitSharedRuntimeResult(ctx, "runtime", "turn", "old")
	if err != nil {
		t.Fatal(err)
	}
	if body != "first reply\n\nfinal reply" || messageRequests != 2 || runtimeRequests != 2 {
		t.Fatalf("body=%q message_requests=%d runtime_requests=%d", body, messageRequests, runtimeRequests)
	}
}
