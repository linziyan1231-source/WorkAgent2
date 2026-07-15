package userhost

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/config"
	"aionuiportal/internal/release"
)

func TestInspectAgentActivityAcceptsCapturedEmptyResponse(t *testing.T) {
	probe := inspectAgentActivity(json.RawMessage(`{}`))
	if !probe.known || probe.active {
		t.Fatalf("captured empty v0.1.42 response was not idle: %+v", probe)
	}
}

func TestInspectAgentActivityUsesRealSnapshotFields(t *testing.T) {
	idle := json.RawMessage(`{
		"generatedAt":1783937561785,
		"totalConversations":1,
		"runningConversations":0,
		"agents":[{
			"id":"agent-1","backend":"codex","agentName":"Codex CLI",
			"state":"idle","runtimeStatus":"finished","conversations":1,
			"activeConversations":0,"lastActiveAt":1783937561785,
			"recentEvents":[{"conversationId":"conversation-1","at":1783937561785,"kind":"status","text":"finished"}]
		}]
	}`)
	if probe := inspectAgentActivity(idle); !probe.known || probe.active {
		t.Fatalf("real-shaped finished agent was not idle: %+v", probe)
	}

	active := json.RawMessage(`{
		"generatedAt":1783937561785,"totalConversations":1,"runningConversations":0,
		"agents":[{"id":"agent-1","backend":"codex","agentName":"Codex CLI",
		"state":"executing","runtimeStatus":"running","conversations":1,
		"activeConversations":0,"lastActiveAt":1783937561785,"recentEvents":[]}]
	}`)
	if probe := inspectAgentActivity(active); !probe.known || !probe.active {
		t.Fatalf("executing agent was not active: %+v", probe)
	}
}

func TestInspectAgentActivityFailsSafeOnUnknownStateOrShape(t *testing.T) {
	for name, input := range map[string]string{
		"unknown state": `{"generatedAt":1,"totalConversations":1,"runningConversations":0,"agents":[{"id":"a","backend":"codex","agentName":"Codex","state":"paused","runtimeStatus":"finished","conversations":1,"activeConversations":0,"lastActiveAt":1,"recentEvents":[]}]}`,
		"unknown key":   `{"generatedAt":1,"totalConversations":0,"runningConversations":0,"agents":[],"newActivityField":true}`,
		"missing field": `{"generatedAt":1,"totalConversations":0,"agents":[]}`,
		"null":          `null`,
	} {
		t.Run(name, func(t *testing.T) {
			probe := inspectAgentActivity(json.RawMessage(input))
			if probe.known || !probe.active {
				t.Fatalf("unknown activity was not fail-safe active: %+v", probe)
			}
		})
	}
}

func TestInspectCronJobsTreatsEnabledJobsAsPendingWork(t *testing.T) {
	for name, input := range map[string]string{
		"captured empty": `[]`,
		"disabled":       `[{"id":"job-1","enabled":false,"state":{"run_count":0}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			probe := inspectCronJobs(json.RawMessage(input))
			if !probe.known || probe.active {
				t.Fatalf("idle cron response was not idle: %+v", probe)
			}
		})
	}
	probe := inspectCronJobs(json.RawMessage(`[{"id":"job-1","enabled":true,"state":{"run_count":0}}]`))
	if !probe.known || !probe.active {
		t.Fatalf("enabled cron job was not treated as pending work: %+v", probe)
	}
}

func TestInspectCronJobsFailsSafeOnUnknownShape(t *testing.T) {
	for name, input := range map[string]string{
		"missing enabled": `[{"id":"job-1"}]`,
		"invalid enabled": `[{"enabled":"yes"}]`,
		"object":          `{}`,
		"null":            `null`,
	} {
		t.Run(name, func(t *testing.T) {
			probe := inspectCronJobs(json.RawMessage(input))
			if probe.known || !probe.active {
				t.Fatalf("unknown cron response was not fail-safe active: %+v", probe)
			}
		})
	}
}

func TestSensitiveEnvironmentNamesAreRemoved(t *testing.T) {
	for _, name := range []string{"OPENAI_API_KEY", "ACCESS_TOKEN", "DB_PASSWORD", "CLIENT_SECRET", "PRIVATE_KEY_FILE"} {
		if !isSensitiveEnvironmentName(name) {
			t.Fatalf("%s was not classified as sensitive", name)
		}
	}
	if isSensitiveEnvironmentName("PATH") {
		t.Fatal("PATH was classified as sensitive")
	}
}

func TestEnvironmentPrependsSharedAgentCLIsAndKeepsPrivateCodexHome(t *testing.T) {
	root := t.TempDir()
	host := Host{cfg: config.UserHost{ReleasesRoot: filepath.Join(root, "AionUiWebShared", "releases")}, release: release.Verified{Path: filepath.Join(root, "release")}, dirs: privateDirs{
		Profile: filepath.Join(root, "profile"), AppData: filepath.Join(root, "profile", "AppData", "Roaming"),
		LocalAppData: filepath.Join(root, "profile", "AppData", "Local"), Temp: filepath.Join(root, "temp"), Data: filepath.Join(root, "data"),
		Logs: filepath.Join(root, "logs"), Cache: filepath.Join(root, "cache"), Workspace: filepath.Join(root, "workspace"), Config: filepath.Join(root, "config"),
	}}
	environment := host.environment()
	values := make(map[string]string)
	for _, entry := range environment {
		if index := strings.IndexByte(entry, '='); index >= 0 {
			values[strings.ToUpper(entry[:index])] = entry[index+1:]
		}
	}
	wantBin := agentcli.BinFromAionReleases(host.cfg.ReleasesRoot)
	if segments := filepath.SplitList(values["PATH"]); len(segments) == 0 || !strings.EqualFold(filepath.Clean(segments[0]), filepath.Clean(wantBin)) {
		t.Fatalf("shared agent CLI bin is not first in PATH: %q", values["PATH"])
	}
	if values["CODEX_HOME"] != filepath.Join(host.dirs.Config, "codex") {
		t.Fatalf("CODEX_HOME is not private: %q", values["CODEX_HOME"])
	}
	if values["AIONUI_BUILTIN_ASSISTANTS_PATH"] != filepath.Join(host.release.Path, "workagent-builtin-assistants") {
		t.Fatalf("builtin assistant override is not release-bound: %q", values["AIONUI_BUILTIN_ASSISTANTS_PATH"])
	}
}
