package userhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type ActivityStatus struct {
	Known         bool `json:"known"`
	Active        bool `json:"active"`
	Conversations int  `json:"conversations"`
	AgentTasks    int  `json:"agent_tasks"`
	ScheduledJobs int  `json:"scheduled_jobs"`
}

type agentActivityEvent struct {
	ConversationID *string `json:"conversationId"`
	At             *int64  `json:"at"`
	Kind           *string `json:"kind"`
	Text           *string `json:"text"`
}

type agentActivityItem struct {
	ID                  *string               `json:"id"`
	Backend             *string               `json:"backend"`
	AgentName           *string               `json:"agentName"`
	State               *string               `json:"state"`
	RuntimeStatus       *string               `json:"runtimeStatus"`
	Conversations       *int                  `json:"conversations"`
	ActiveConversations *int                  `json:"activeConversations"`
	LastActiveAt        *int64                `json:"lastActiveAt"`
	LastStatus          *string               `json:"lastStatus,omitempty"`
	CurrentTask         *string               `json:"currentTask,omitempty"`
	RecentEvents        *[]agentActivityEvent `json:"recentEvents"`
}

type agentActivitySnapshot struct {
	GeneratedAt          *int64               `json:"generatedAt"`
	TotalConversations   *int                 `json:"totalConversations"`
	RunningConversations *int                 `json:"runningConversations"`
	Agents               *[]agentActivityItem `json:"agents"`
}

func (h *Host) probeActivity(ctx context.Context) (ActivityStatus, error) {
	switch h.cfg.Backend.ActivityProbe {
	case "aggregate":
		return h.probeAggregateActivity(ctx)
	case "aionui":
		return h.probeAionUIActivity(ctx)
	default:
		return ActivityStatus{}, errors.New("activity probe mode is unsupported")
	}
}

func (h *Host) probeAggregateActivity(ctx context.Context) (ActivityStatus, error) {
	h.mu.RLock()
	backendURL := h.backendURL
	transport := h.transport
	h.mu.RUnlock()
	if backendURL == nil || transport == nil {
		return ActivityStatus{}, errors.New("backend activity endpoint is unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, backendURL.String()+h.cfg.Backend.ActivityPath, nil)
	if err != nil {
		return ActivityStatus{}, err
	}
	setWorkAgentRuntimeHeader(request, h.runtimeToken)
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return ActivityStatus{}, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(payload) > 64*1024 || response.StatusCode != http.StatusOK {
		return ActivityStatus{}, errors.New("backend activity response is unavailable")
	}
	var result ActivityStatus
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ActivityStatus{}, errors.New("backend activity response is invalid")
	}
	if err := validateActivityCounts(result); err != nil {
		return ActivityStatus{}, err
	}
	result.Known = true
	return result, nil
}

func (h *Host) probeAionUIActivity(ctx context.Context) (ActivityStatus, error) {
	result := ActivityStatus{Known: true}
	processActive, err := h.hasAdditionalRuntimeProcesses()
	if err != nil {
		return ActivityStatus{}, err
	}
	var conversations struct {
		Success *bool `json:"success"`
		Data    *struct {
			Count *int `json:"count"`
		} `json:"data"`
	}
	if err := h.backendJSON(ctx, http.MethodGet, "/api/conversations/active-count", nil, &conversations); err != nil || conversations.Success == nil || !*conversations.Success || conversations.Data == nil || conversations.Data.Count == nil || *conversations.Data.Count < 0 {
		return ActivityStatus{}, errors.New("active conversation count is unavailable or invalid")
	}
	result.Conversations = *conversations.Data.Count

	var agents struct {
		Success *bool            `json:"success"`
		Data    *json.RawMessage `json:"data"`
	}
	if err := h.backendJSON(ctx, http.MethodGet, "/api/extensions/agent-activity", nil, &agents); err != nil || agents.Success == nil || !*agents.Success || agents.Data == nil {
		return ActivityStatus{}, errors.New("Agent activity is unavailable")
	}
	agentTasks, err := inspectAgentActivity(*agents.Data)
	if err != nil {
		return ActivityStatus{}, err
	}
	result.AgentTasks = agentTasks

	var cron struct {
		Success *bool            `json:"success"`
		Data    *json.RawMessage `json:"data"`
	}
	if err := h.backendJSON(ctx, http.MethodGet, "/api/cron/jobs", nil, &cron); err != nil || cron.Success == nil || !*cron.Success || cron.Data == nil {
		return ActivityStatus{}, errors.New("Cron activity is unavailable")
	}
	result.ScheduledJobs, err = inspectCronActivity(*cron.Data)
	if err != nil {
		return ActivityStatus{}, err
	}
	result.Active = processActive || result.Conversations > 0 || result.AgentTasks > 0 || result.ScheduledJobs > 0
	return result, nil
}

func (h *Host) hasAdditionalRuntimeProcesses() (bool, error) {
	h.mu.RLock()
	backend := h.backend
	corePID := h.aionCorePID
	h.mu.RUnlock()
	if backend == nil || backend.Process == nil {
		return false, nil
	}
	pids, err := cgroupProcessIDs(os.Getpid())
	if err != nil {
		return false, fmt.Errorf("inspect runtime process activity: %w", err)
	}
	return hasAdditionalRuntimeProcess(pids, os.Getpid(), backend.Process.Pid, corePID), nil
}

func hasAdditionalRuntimeProcess(pids []int, hostPID, backendPID, corePID int) bool {
	for _, pid := range pids {
		if pid != hostPID && pid != backendPID && pid != corePID {
			return true
		}
	}
	return false
}

func inspectAgentActivity(data json.RawMessage) (int, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("{}")) {
		return 0, nil
	}
	var snapshot agentActivitySnapshot
	if err := json.Unmarshal(trimmed, &snapshot); err != nil || snapshot.GeneratedAt == nil || snapshot.TotalConversations == nil || snapshot.RunningConversations == nil || snapshot.Agents == nil || *snapshot.GeneratedAt < 0 || *snapshot.TotalConversations < 0 || *snapshot.RunningConversations < 0 {
		return 0, errors.New("Agent activity returned an unknown structure")
	}
	active := *snapshot.RunningConversations
	for _, agent := range *snapshot.Agents {
		if agent.ID == nil || agent.Backend == nil || agent.AgentName == nil || agent.State == nil || agent.RuntimeStatus == nil || agent.Conversations == nil || agent.ActiveConversations == nil || agent.LastActiveAt == nil || agent.RecentEvents == nil || *agent.Conversations < 0 || *agent.ActiveConversations < 0 || *agent.LastActiveAt < 0 {
			return 0, errors.New("Agent activity item is incomplete")
		}
		for _, event := range *agent.RecentEvents {
			if event.ConversationID == nil || event.At == nil || event.Kind == nil || event.Text == nil || *event.At < 0 || (*event.Kind != "status" && *event.Kind != "tool" && *event.Kind != "message") {
				return 0, errors.New("Agent activity event is invalid")
			}
		}
		itemActive := *agent.ActiveConversations
		if agent.CurrentTask != nil && strings.TrimSpace(*agent.CurrentTask) != "" && itemActive == 0 {
			itemActive = 1
		}
		switch *agent.State {
		case "writing", "researching", "executing", "syncing":
			if itemActive == 0 {
				itemActive = 1
			}
		case "idle", "error":
		default:
			return 0, errors.New("Agent activity state is unknown")
		}
		switch *agent.RuntimeStatus {
		case "pending", "running":
			if itemActive == 0 {
				itemActive = 1
			}
		case "finished":
		case "unknown":
			return 0, errors.New("Agent runtime status is unknown")
		default:
			return 0, errors.New("Agent runtime status is unsupported")
		}
		if itemActive > active {
			active = itemActive
		}
	}
	return active, nil
}

func inspectCronActivity(data json.RawMessage) (int, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return 0, errors.New("Cron jobs returned an unknown structure")
	}
	var jobs []map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &jobs); err != nil || jobs == nil {
		return 0, errors.New("Cron jobs returned an unknown structure")
	}
	enabledCount := 0
	for _, job := range jobs {
		raw, ok := job["enabled"]
		if !ok {
			return 0, errors.New("Cron job is missing its enabled state")
		}
		var enabled bool
		if err := json.Unmarshal(raw, &enabled); err != nil {
			return 0, errors.New("Cron job enabled state is invalid")
		}
		if enabled {
			enabledCount++
		}
	}
	return enabledCount, nil
}

func validateActivityCounts(result ActivityStatus) error {
	if result.Conversations < 0 || result.AgentTasks < 0 || result.ScheduledJobs < 0 {
		return errors.New("backend activity counts are invalid")
	}
	counted := result.Conversations > 0 || result.AgentTasks > 0 || result.ScheduledJobs > 0
	if counted != result.Active {
		return errors.New("backend activity response is inconsistent")
	}
	return nil
}
