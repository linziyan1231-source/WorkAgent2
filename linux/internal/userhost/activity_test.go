package userhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestAionUIActivityUsesConversationsAgentsAndCron(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/conversations/active-count", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"count": 0}})
	})
	mux.HandleFunc("GET /api/extensions/agent-activity", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{
			"generatedAt": 1, "totalConversations": 1, "runningConversations": 1,
			"agents": []any{map[string]any{"id": "a", "backend": "codex", "agentName": "Codex", "state": "executing", "runtimeStatus": "running", "conversations": 1, "activeConversations": 1, "lastActiveAt": 1, "recentEvents": []any{map[string]any{"conversationId": "c", "at": 1, "kind": "tool", "text": "running"}}}},
		}})
	})
	mux.HandleFunc("GET /api/cron/jobs", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": []any{map[string]any{"enabled": true}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	base, _ := url.Parse(server.URL)
	host := &Host{cfg: configForActivity("aionui", ""), backendURL: base, transport: server.Client().Transport.(*http.Transport)}
	result, err := host.probeActivity(context.Background())
	if err != nil || !result.Known || !result.Active || result.AgentTasks != 1 || result.ScheduledJobs != 1 {
		t.Fatalf("unexpected activity result: %+v err=%v", result, err)
	}
}

func TestAionUIUnknownActivityFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/conversations/active-count" {
			writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"count": 0}})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"unexpected": true}})
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	host := &Host{cfg: configForActivity("aionui", ""), backendURL: base, transport: server.Client().Transport.(*http.Transport)}
	if _, err := host.probeActivity(context.Background()); err == nil {
		t.Fatal("unknown authoritative activity was accepted")
	}
}

func TestAdditionalRuntimeProcessPreventsIdleClassification(t *testing.T) {
	if hasAdditionalRuntimeProcess([]int{99, 100, 101}, 99, 100, 101) {
		t.Fatal("the verified AionUi and AionCore baseline was classified as extra work")
	}
	if !hasAdditionalRuntimeProcess([]int{99, 100, 101, 102}, 99, 100, 101) {
		t.Fatal("an additional runtime process was not classified as active work")
	}
}

func configForActivity(mode, path string) config.Tenant {
	return config.Tenant{Backend: config.Backend{ActivityProbe: mode, ActivityPath: path}}
}
