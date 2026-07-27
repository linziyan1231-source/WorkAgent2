package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

type readinessClientFixture struct {
	runtimeConfig []byte
	headers       http.Header
	plugins       pluginListResponse
	pluginConfig  map[string]json.RawMessage
	authFiles     []byte
	authFilesErr  error
	status        keyPolicyStatus
	keys          any
	aliases       any
	aliasWrites   int
}

func (f *readinessClientFixture) coreRaw(_ context.Context, route string, _ int64) ([]byte, http.Header, error) {
	switch route {
	case "/v0/management/config.yaml":
		return append([]byte(nil), f.runtimeConfig...), f.headers.Clone(), nil
	case "/v0/management/auth-files":
		if f.authFilesErr != nil {
			return nil, nil, f.authFilesErr
		}
		return append([]byte(nil), f.authFiles...), nil, nil
	default:
		return nil, nil, errors.New("unexpected core raw route")
	}
}

func (f *readinessClientFixture) coreJSON(_ context.Context, method, route string, output any) (http.Header, error) {
	if method != http.MethodGet {
		return nil, errors.New("unexpected core method")
	}
	var value any
	switch route {
	case "/v0/management/plugins":
		value = f.plugins
	case "/v0/management/plugins/cpa-key-policy/config":
		value = f.pluginConfig
	default:
		return nil, errors.New("unexpected core JSON route")
	}
	return nil, assignJSON(value, output)
}

func (f *readinessClientFixture) JSON(_ context.Context, method, route string, _ any, output any) error {
	if method == http.MethodPost && route == "/aliases" {
		f.aliasWrites++
		return nil
	}
	if method != http.MethodGet {
		return errors.New("unexpected plugin method")
	}
	var value any
	switch route {
	case "/status":
		value = f.status
	case "/keys":
		value = f.keys
	case "/aliases":
		value = f.aliases
	default:
		return errors.New("unexpected plugin JSON route")
	}
	return assignJSON(value, output)
}

func assignJSON(value, output any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return decodeManagementJSON(payload, output)
}

func readinessEndpoint() config.CLIProxy {
	allowRemote := false
	return config.CLIProxy{
		APIBaseURL: config.CLIProxyAPIBaseURL, ManagementURL: config.CLIProxyManagementURL,
		ManagementCredentialFile: config.CLIProxyManagementKeyFile,
		CoreVersion:              config.CLIProxyCoreVersion, CorePatch: config.CLIProxyCorePatch,
		PluginID: config.CLIProxyPluginID, PluginVersion: config.CLIProxyPluginVersion,
		AuthDirectory: config.CLIProxyAuthDirectory, PluginDirectory: config.CLIProxyPluginDirectory,
		PolicyStateFile: config.CLIProxyPolicyStateFile, AllowRemote: &allowRemote,
	}
}

func readinessPolicy() productconfig.Policy {
	return productconfig.Policy{
		SchemaVersion: 1, PolicyID: "workagent-managed-v1", DefaultAction: "deny",
		Models:  []productconfig.Model{{ID: "gpt-5.6-sol", DisplayName: "GPT 5.6 Sol", Provider: "codex", Enabled: true, Default: true}},
		Aliases: map[string]string{},
		Pricing: map[string]productconfig.Price{"gpt-5.6-sol": {InputPerMillion: "5", OutputPerMillion: "30", Currency: "USD"}},
		Quotas:  map[string]productconfig.Quota{"gpt-5.6-sol": {RequestsPerMinute: 10, DailyUSD: "10", WeeklyUSD: "20"}},
	}
}

func validReadinessClient() *readinessClientFixture {
	return &readinessClientFixture{
		runtimeConfig: []byte("host: \"127.0.0.1\"\nport: 8317\nremote-management:\n  allow-remote: false\n  secret-key: \"redacted-hash\"\n  disable-control-panel: true\n  disable-auto-update-panel: true\nauth-dir: \"/var/lib/cliproxyapi/auth\"\nlogs-max-total-size-mb: 256\nerror-logs-max-files: 10\n"),
		headers: http.Header{
			"X-Cpa-Version":        []string{"7.2.81"},
			"X-Cpa-Commit":         []string{"per-key-models.4"},
			"X-Cpa-Support-Plugin": []string{"1"},
			"X-Cpa-Build-Date":     []string{"2026-07-17T07:24:41Z"},
		},
		plugins: pluginListResponse{PluginsEnabled: true, PluginsDir: config.CLIProxyPluginDirectory, Plugins: []pluginListEntry{{
			ID: config.CLIProxyPluginID, Configured: true, Registered: true, Enabled: true, EffectiveEnabled: true,
			Metadata: &pluginMetadataInfo{Name: config.CLIProxyPluginID, Version: config.CLIProxyPluginVersion},
		}}},
		pluginConfig: map[string]json.RawMessage{
			"enabled": json.RawMessage("true"), "priority": json.RawMessage("10"),
			"state_file": json.RawMessage(`"/var/lib/cliproxyapi/policy/cpa-key-policy-state.json"`),
		},
		authFiles: validProviderAuthFiles("codex", "kimi"),
		status:    keyPolicyStatus{Enabled: true, StateFile: config.CLIProxyPolicyStateFile, KeyCount: 0, RPMUsage: map[string]json.RawMessage{}, Usage: map[string]json.RawMessage{}},
		keys:      map[string]any{"keys": []any{}},
		aliases:   map[string]any{"aliases": managedAliases()},
	}
}

func validProviderAuthFiles(providers ...string) []byte {
	files := make([]any, 0, len(providers))
	for _, provider := range providers {
		name := provider + "-production.json"
		recent := make([]any, 0, providerRecentRequestSlots)
		for index := 0; index < providerRecentRequestSlots; index++ {
			recent = append(recent, map[string]any{
				"time": "00:00-00:05", "success": index, "failed": 0,
			})
		}
		files = append(files, map[string]any{
			"id": provider + "-id", "auth_index": provider + "-index", "name": name,
			"type": provider, "provider": provider, "label": "production",
			"status": "active", "status_message": "", "disabled": false,
			"unavailable": false, "runtime_only": false, "source": "file", "size": 512,
			"path":    config.CLIProxyAuthDirectory + "/" + name,
			"success": 0, "failed": 0, "recent_requests": recent,
		})
	}
	payload, err := json.Marshal(map[string]any{"files": files})
	if err != nil {
		panic(err)
	}
	return payload
}

func TestCLIProxyReadinessChecksAuthenticatedRuntimeContract(t *testing.T) {
	if err := checkReadinessWithClient(context.Background(), readinessEndpoint(), readinessPolicy(), validReadinessClient()); err != nil {
		t.Fatalf("valid runtime contract was rejected: %v", err)
	}
}

func TestMigrationVerificationAllowsPreOAuthWhileFullReadinessRejectsIt(t *testing.T) {
	fixture := validReadinessClient()
	fixture.authFiles = validProviderAuthFiles()
	if err := checkMigrationReadinessWithClient(context.Background(), readinessEndpoint(), readinessPolicy(), fixture); err != nil {
		t.Fatalf("pre-OAuth migration verification readiness was rejected: %v", err)
	}
	if err := checkReadinessWithClient(context.Background(), readinessEndpoint(), readinessPolicy(), fixture); err == nil {
		t.Fatal("doctor/Portal full readiness accepted an empty provider OAuth inventory")
	}
}

func TestCLIProxyReadinessRejectsNonUSDDownstreamAccounting(t *testing.T) {
	policy := readinessPolicy()
	price := policy.Pricing["gpt-5.6-sol"]
	price.Currency = "CNY"
	policy.Pricing["gpt-5.6-sol"] = price
	if err := checkReadinessWithClient(context.Background(), readinessEndpoint(), policy, validReadinessClient()); err == nil {
		t.Fatal("CNY policy was accepted by the USD-denominated CLIProxy ledger")
	}
}

func TestCLIProxyReadinessRejectsHealthOnlyAndRuntimeDrift(t *testing.T) {
	tests := map[string]func(*readinessClientFixture){
		"no management build identity": func(f *readinessClientFixture) { f.headers = http.Header{} },
		"remote management enabled": func(f *readinessClientFixture) {
			f.runtimeConfig = []byte(strings.ReplaceAll(string(f.runtimeConfig), "allow-remote: false", "allow-remote: true"))
		},
		"management panel enabled": func(f *readinessClientFixture) {
			f.runtimeConfig = []byte(strings.ReplaceAll(string(f.runtimeConfig), "disable-control-panel: true", "disable-control-panel: false"))
		},
		"management panel updater enabled": func(f *readinessClientFixture) {
			f.runtimeConfig = []byte(strings.ReplaceAll(string(f.runtimeConfig), "disable-auto-update-panel: true", "disable-auto-update-panel: false"))
		},
		"unbounded total logs": func(f *readinessClientFixture) {
			f.runtimeConfig = []byte(strings.ReplaceAll(string(f.runtimeConfig), "logs-max-total-size-mb: 256", "logs-max-total-size-mb: 0"))
		},
		"wrong error log cap": func(f *readinessClientFixture) {
			f.runtimeConfig = []byte(strings.ReplaceAll(string(f.runtimeConfig), "error-logs-max-files: 10", "error-logs-max-files: 11"))
		},
		"ambiguous YAML numeric cap": func(f *readinessClientFixture) {
			f.runtimeConfig = []byte(strings.ReplaceAll(string(f.runtimeConfig), "logs-max-total-size-mb: 256", "logs-max-total-size-mb: 0256"))
		},
		"wrong plugin version":          func(f *readinessClientFixture) { f.plugins.Plugins[0].Metadata.Version = "0.4.4" },
		"wrong policy state":            func(f *readinessClientFixture) { f.status.StateFile = "/tmp/policy.json" },
		"missing managed alias catalog": func(f *readinessClientFixture) { f.aliases = map[string]any{"aliases": []any{}} },
		"auth status request failed":    func(f *readinessClientFixture) { f.authFilesErr = errors.New("HTTP 503") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := validReadinessClient()
			mutate(fixture)
			if err := checkReadinessWithClient(context.Background(), readinessEndpoint(), readinessPolicy(), fixture); err == nil {
				t.Fatal("drifted CLIProxy runtime was accepted")
			}
		})
	}
}

func TestCLIProxyReadinessRejectsMissingOrUnusableProviderOAuth(t *testing.T) {
	tests := map[string][]byte{
		"empty":             validProviderAuthFiles(),
		"missing Kimi":      validProviderAuthFiles("codex"),
		"missing Codex":     validProviderAuthFiles("kimi"),
		"disabled Codex":    bytes.Replace(validProviderAuthFiles("codex", "kimi"), []byte(`"disabled":false`), []byte(`"disabled":true`), 1),
		"unavailable Codex": bytes.Replace(validProviderAuthFiles("codex", "kimi"), []byte(`"unavailable":false`), []byte(`"unavailable":true`), 1),
		"error Codex":       bytes.Replace(validProviderAuthFiles("codex", "kimi"), []byte(`"status":"active"`), []byte(`"status":"error"`), 1),
		"temporary Codex":   bytes.Replace(validProviderAuthFiles("codex", "kimi"), []byte(`"runtime_only":false`), []byte(`"runtime_only":true`), 1),
		"memory Codex":      bytes.Replace(validProviderAuthFiles("codex", "kimi"), []byte(`"source":"file"`), []byte(`"source":"memory"`), 1),
	}
	for name, authFiles := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := validReadinessClient()
			fixture.authFiles = authFiles
			if err := checkReadinessWithClient(context.Background(), readinessEndpoint(), readinessPolicy(), fixture); err == nil {
				t.Fatal("CLIProxy readiness accepted missing or unusable provider OAuth")
			}
		})
	}
}

func TestProviderOAuthStatusParserRejectsAmbiguousOrMalformedResponses(t *testing.T) {
	valid := validProviderAuthFiles("codex", "kimi")
	tests := map[string][]byte{
		"unknown root field":  bytes.Replace(valid, []byte(`{"files":`), []byte(`{"unknown":true,"files":`), 1),
		"duplicate root key":  bytes.Replace(valid, []byte(`{"files":`), []byte(`{"files":[],"files":`), 1),
		"unknown entry field": bytes.Replace(valid, []byte(`"auth_index":`), []byte(`"unknown":true,"auth_index":`), 1),
		"duplicate entry key": bytes.Replace(valid, []byte(`"disabled":false`), []byte(`"disabled":false,"disabled":false`), 1),
		"wrong key type":      bytes.Replace(valid, []byte(`"disabled":false`), []byte(`"disabled":"false"`), 1),
		"fractional size":     bytes.Replace(valid, []byte(`"size":512`), []byte(`"size":1.5`), 1),
		"unsafe path":         bytes.Replace(valid, []byte(config.CLIProxyAuthDirectory+`/codex-production.json`), []byte(`/tmp/codex-production.json`), 1),
		"duplicate id":        bytes.Replace(valid, []byte(`"id":"kimi-id"`), []byte(`"id":"codex-id"`), 1),
		"duplicate index":     bytes.Replace(valid, []byte(`"auth_index":"kimi-index"`), []byte(`"auth_index":"codex-index"`), 1),
		"trailing data":       append(append([]byte(nil), valid...), []byte(` {}`)...),
		"embedded NUL":        append([]byte(`{"files":[]}`), 0),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if err := verifyProviderAuthFiles(payload, config.CLIProxyAuthDirectory); err == nil {
				t.Fatal("ambiguous or malformed provider OAuth response was accepted")
			}
		})
	}
}

func TestProviderOAuthStatusParserEnforcesResponseAndFileCountBounds(t *testing.T) {
	oversized := bytes.Repeat([]byte{' '}, maxProviderAuthResponse+1)
	if err := verifyProviderAuthFiles(oversized, config.CLIProxyAuthDirectory); err == nil {
		t.Fatal("oversized provider OAuth response was accepted")
	}
	providers := make([]string, maxProviderAuthFiles+1)
	for index := range providers {
		providers[index] = "provider-" + string(rune('a'+index%26))
	}
	// Use distinct IDs/indexes while retaining an otherwise valid locked shape.
	files := make([]any, 0, len(providers))
	for index := range providers {
		provider := providers[index]
		name := provider + "-" + strconv.Itoa(index) + ".json"
		recent := make([]any, providerRecentRequestSlots)
		for slot := range recent {
			recent[slot] = map[string]any{"time": "00:00-00:05", "success": 0, "failed": 0}
		}
		files = append(files, map[string]any{
			"id": provider + "-" + strconv.Itoa(index), "auth_index": "index-" + strconv.Itoa(index), "name": name,
			"type": provider, "provider": provider, "label": "", "status": "active", "status_message": "",
			"disabled": false, "unavailable": false, "runtime_only": false, "source": "file", "size": 1,
			"path": config.CLIProxyAuthDirectory + "/" + name, "success": 0, "failed": 0, "recent_requests": recent,
		})
	}
	payload, err := json.Marshal(map[string]any{"files": files})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProviderAuthFiles(payload, config.CLIProxyAuthDirectory); err == nil {
		t.Fatal("provider OAuth file-count overflow was accepted")
	}
}

func TestRuntimeConfigIdentityRejectsDuplicateOrMissingLoopbackPolicy(t *testing.T) {
	for name, payload := range map[string]string{
		"duplicate allow remote": "host: 127.0.0.1\nport: 8317\nremote-management:\n  allow-remote: false\n  allow-remote: false\n  disable-control-panel: true\n  disable-auto-update-panel: true\nauth-dir: /var/lib/cliproxyapi/auth\nlogs-max-total-size-mb: 256\nerror-logs-max-files: 10\n",
		"public host":            "host: 0.0.0.0\nport: 8317\nremote-management:\n  allow-remote: false\n  disable-control-panel: true\n  disable-auto-update-panel: true\nauth-dir: /var/lib/cliproxyapi/auth\nlogs-max-total-size-mb: 256\nerror-logs-max-files: 10\n",
		"missing allow remote":   "host: 127.0.0.1\nport: 8317\nremote-management:\n  disable-control-panel: true\n  disable-auto-update-panel: true\nauth-dir: /var/lib/cliproxyapi/auth\nlogs-max-total-size-mb: 256\nerror-logs-max-files: 10\n",
	} {
		t.Run(name, func(t *testing.T) {
			identity, err := parseRuntimeConfigIdentity([]byte(payload))
			if name == "public host" {
				err = verifyRuntimeConfigIdentity(identity, readinessEndpoint())
			}
			if err == nil {
				t.Fatal("unsafe runtime config was accepted")
			}
		})
	}
}
