package userhost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"aionuiportal/internal/ipc"
)

type activityProbeResult struct {
	known  bool
	active bool
	reason string
}

func (h *Host) probeActivity(ctx context.Context) ipc.Activity {
	now := time.Now().Unix()
	result := func(probe activityProbeResult) ipc.Activity {
		return ipc.Activity{Known: probe.known, Active: probe.active, Reason: probe.reason, CheckedAtUnix: now}
	}
	if h.client == nil || h.job == nil {
		return result(unknownActivity("internal client or Job Object is unavailable"))
	}
	stats, err := h.job.Stats()
	if err != nil {
		return result(unknownActivity("Job Object accounting failed"))
	}
	if stats.ProcessCount > 3 {
		return result(activeActivity(fmt.Sprintf("Job Object contains %d processes", stats.ProcessCount)))
	}
	var activeCount struct {
		Success *bool `json:"success"`
		Data    *struct {
			Count *int `json:"count"`
		} `json:"data"`
	}
	if err := h.client.getJSON(ctx, "/api/conversations/active-count", &activeCount); err != nil || activeCount.Success == nil || !*activeCount.Success || activeCount.Data == nil || activeCount.Data.Count == nil || *activeCount.Data.Count < 0 {
		return result(unknownActivity("active conversation count is unavailable or unknown"))
	}
	if *activeCount.Data.Count > 0 {
		return result(activeActivity("AionUi reports active conversations"))
	}

	for _, endpoint := range []struct {
		path    string
		inspect func(json.RawMessage) activityProbeResult
	}{
		{path: "/api/extensions/agent-activity", inspect: inspectAgentActivity},
		{path: "/api/cron/jobs", inspect: inspectCronJobs},
	} {
		var response struct {
			Success *bool            `json:"success"`
			Data    *json.RawMessage `json:"data"`
		}
		if err := h.client.getJSON(ctx, endpoint.path, &response); err != nil || response.Success == nil || !*response.Success || response.Data == nil {
			return result(unknownActivity(endpoint.path + " is unavailable or unknown"))
		}
		probe := endpoint.inspect(*response.Data)
		if !probe.known || probe.active {
			probe.reason = endpoint.path + ": " + probe.reason
			return result(probe)
		}
	}
	return result(idleActivity("all authoritative activity probes are idle"))
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

func inspectAgentActivity(data json.RawMessage) activityProbeResult {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("{}")) {
		return idleActivity("AionUi reports no extension agent activity")
	}
	var snapshot agentActivitySnapshot
	if err := decodeStrictJSON(trimmed, &snapshot); err != nil || snapshot.GeneratedAt == nil || snapshot.TotalConversations == nil || snapshot.RunningConversations == nil || snapshot.Agents == nil {
		return unknownActivity("agent activity returned an unknown structure")
	}
	if *snapshot.GeneratedAt < 0 || *snapshot.TotalConversations < 0 || *snapshot.RunningConversations < 0 {
		return unknownActivity("agent activity returned an invalid counter")
	}
	if *snapshot.RunningConversations > 0 {
		return activeActivity("runningConversations is non-zero")
	}
	for _, agent := range *snapshot.Agents {
		if agent.ID == nil || agent.Backend == nil || agent.AgentName == nil || agent.State == nil || agent.RuntimeStatus == nil || agent.Conversations == nil || agent.ActiveConversations == nil || agent.LastActiveAt == nil || agent.RecentEvents == nil {
			return unknownActivity("agent activity item is missing a required field")
		}
		if *agent.Conversations < 0 || *agent.ActiveConversations < 0 || *agent.LastActiveAt < 0 {
			return unknownActivity("agent activity item contains an invalid counter")
		}
		for _, event := range *agent.RecentEvents {
			if event.ConversationID == nil || event.At == nil || event.Kind == nil || event.Text == nil || *event.At < 0 {
				return unknownActivity("agent activity event is malformed")
			}
			switch *event.Kind {
			case "status", "tool", "message":
			default:
				return unknownActivity("agent activity event has an unknown kind")
			}
		}
		if *agent.ActiveConversations > 0 {
			return activeActivity("activeConversations is non-zero")
		}
		if agent.CurrentTask != nil && strings.TrimSpace(*agent.CurrentTask) != "" {
			return activeActivity("agent reports a current task")
		}
		switch *agent.State {
		case "writing", "researching", "executing", "syncing":
			return activeActivity("agent state is " + *agent.State)
		case "idle", "error":
		default:
			return unknownActivity("agent has an unknown state")
		}
		switch *agent.RuntimeStatus {
		case "pending", "running":
			return activeActivity("agent runtime status is " + *agent.RuntimeStatus)
		case "finished":
		case "unknown":
			return unknownActivity("agent runtime status is unknown")
		default:
			return unknownActivity("agent has an unsupported runtime status")
		}
	}
	return idleActivity("all extension agents are idle")
}

func inspectCronJobs(data json.RawMessage) activityProbeResult {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return unknownActivity("cron jobs returned an unknown structure")
	}
	var jobs []json.RawMessage
	if err := json.Unmarshal(trimmed, &jobs); err != nil || jobs == nil {
		return unknownActivity("cron jobs returned an unknown structure")
	}
	for _, raw := range jobs {
		var job map[string]json.RawMessage
		if err := json.Unmarshal(raw, &job); err != nil || job == nil {
			return unknownActivity("cron job entry is not an object")
		}
		rawEnabled, ok := job["enabled"]
		if !ok {
			return unknownActivity("cron job entry is missing enabled")
		}
		var enabled bool
		if err := json.Unmarshal(rawEnabled, &enabled); err != nil {
			return unknownActivity("cron job enabled value is invalid")
		}
		if enabled {
			return activeActivity("an enabled cron job is waiting or running")
		}
	}
	return idleActivity("no enabled cron jobs")
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func unknownActivity(reason string) activityProbeResult {
	return activityProbeResult{known: false, active: true, reason: reason}
}

func activeActivity(reason string) activityProbeResult {
	return activityProbeResult{known: true, active: true, reason: reason}
}

func idleActivity(reason string) activityProbeResult {
	return activityProbeResult{known: true, active: false, reason: reason}
}
