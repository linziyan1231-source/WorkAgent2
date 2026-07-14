package userhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestProjectActivityIgnoresIdleRuntimeAndStopsOnlyActiveConversation(t *testing.T) {
	var mu sync.Mutex
	active := true
	cancelled := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/conversations/"):]
		if r.Method == http.MethodPost {
			mu.Lock()
			active = false
			cancelled = append(cancelled, id[:len(id)-len("/cancel")])
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"success": true})
			return
		}
		mu.Lock()
		isActive := active && id == "active"
		mu.Unlock()
		state, turnID := "idle", ""
		if isActive {
			state, turnID = "running", "turn-1"
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
			"id": id, "runtime": map[string]any{"state": state, "is_processing": isActive, "pending_confirmations": 0, "turn_id": turnID},
		}})
	}))
	defer server.Close()
	host := Host{client: clientForServer(t, server)}

	items, err := host.activeProjectConversations(context.Background(), []string{"idle", "active"})
	if err != nil || len(items) != 1 || items[0].id != "active" {
		t.Fatalf("project activity mismatch: items=%+v err=%v", items, err)
	}
	if err := host.stopProjectConversations(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cancelled) != 1 || cancelled[0] != "active" {
		t.Fatalf("wrong conversations cancelled: %v", cancelled)
	}
}
