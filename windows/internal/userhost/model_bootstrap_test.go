package userhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/config"
	"aionuiportal/internal/modelbootstrap"
)

func TestInitialCodexConfigUpdatesOnlyManagedTopLevelKeys(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.toml")
	existing := `model = "old-model"
openai_base_url = "https://old.example/v1"
model_reasoning_effort = "low"
approval_policy = "on-request"
developer_instructions = "默认使用简体中文回复。"

[features]
model = "table-value-must-survive"
web_search = true
`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeInitialCodexConfig(path, "http://43.134.118.158:8317/v1", "gpt-5.6-luna"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, required := range []string{`openai_base_url = "http://43.134.118.158:8317/v1"`, `model = "gpt-5.6-luna"`, `model_reasoning_effort = "low"`, `cli_auth_credentials_store = "file"`, `approval_policy = "on-request"`, `developer_instructions = "默认使用简体中文回复。"`, `model = "table-value-must-survive"`} {
		if !strings.Contains(got, required) {
			t.Fatalf("managed config is missing %q:\n%s", required, got)
		}
	}
	if strings.Contains(got, "old-model") || strings.Contains(got, "old.example") || strings.Contains(got, `model_reasoning_effort = "xhigh"`) {
		t.Fatalf("old managed values survived:\n%s", got)
	}
}

func TestKimiAPIKeyScriptReplacesOAuthAndPreservesUnrelatedConfig(t *testing.T) {
	root := filepath.Join(os.Getenv("ProgramFiles"), agentcli.RootDirectoryName)
	verified, err := agentcli.VerifyCurrent(root)
	if err != nil {
		t.Skipf("shared Kimi runtime is unavailable: %v", err)
	}
	kimiDirectory := filepath.Join(t.TempDir(), ".kimi")
	credentials := filepath.Join(kimiDirectory, "credentials")
	if err := os.MkdirAll(credentials, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(kimiDirectory, "config.toml")
	fixture := `# preserve this comment
default_model = "kimi-code/kimi-for-coding"
theme = "light"

[models."kimi-code/kimi-for-coding"]
provider = "managed:kimi-code"
model = "kimi-for-coding"
max_context_size = 262144

[providers."managed:kimi-code"]
type = "kimi"
base_url = "https://api.kimi.com/coding/v1"
api_key = ""

[providers."managed:kimi-code".oauth]
storage = "file"
key = "oauth/kimi-code"

[providers.custom]
type = "kimi"
base_url = "https://custom.example/v1"
api_key = "custom-secret"
`
	if err := os.WriteFile(configPath, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kimi-code.json", "kimi-code.lock"} {
		if err := os.WriteFile(filepath.Join(credentials, name), []byte("oauth-must-be-deleted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := []byte(`{"api_key":"cpa_abcdefghijklmnopqrstuvwxyz012345","base_url":"http://43.134.118.158:8317/v1"}`)
	python := filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiRelativePath))
	command := exec.Command(python, "-B", "-c", kimiAPIKeyConfigureScript, configPath)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PYTHONUTF8=1")
	command.Stdin = bytes.NewReader(payload)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Kimi API-key helper failed: %v: %s", err, output)
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, required := range []string{"# preserve this comment", `default_model = "kimi-code/kimi-k3"`, `theme = "light"`, `default_thinking = true`, `default_yolo = true`, `support_efforts = ["low", "high", "max"]`, `default_effort = "high"`, `display_name = "Kimi K2.7 Code"`, `[models."kimi-code/kimi-for-coding-highspeed"]`, `model = "kimi-for-coding-highspeed"`, `display_name = "Kimi K2.7 Code HighSpeed"`, `[models."kimi-code/kimi-k3"]`, `model = "kimi-k3"`, `max_context_size = 1048576`, `default_effort = "low"`, `[thinking]`, `enabled = true`, `[services.moonshot_search]`, `base_url = "http://43.134.118.158:8317/v1/search?model=kimi-k3"`, `[services.moonshot_fetch]`, `base_url = "http://43.134.118.158:8317/v1/fetch?model=kimi-k3"`, `[providers.custom]`, `base_url = "http://43.134.118.158:8317/v1"`, `api_key = "cpa_abcdefghijklmnopqrstuvwxyz012345"`} {
		if !strings.Contains(got, required) {
			t.Fatalf("Kimi config is missing %q:\n%s", required, got)
		}
	}
	if strings.Contains(got, "oauth/kimi-code") || strings.Contains(got, "api.kimi.com/coding") {
		t.Fatalf("Kimi OAuth configuration survived:\n%s", got)
	}
	for _, name := range []string{"kimi-code.json", "kimi-code.lock"} {
		if _, err := os.Stat(filepath.Join(credentials, name)); !os.IsNotExist(err) {
			t.Fatalf("Kimi OAuth file %s survived: %v", name, err)
		}
	}
	rebase := exec.Command(python, "-B", "-c", kimiAPIKeyConfigureScript, configPath)
	rebase.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PYTHONUTF8=1")
	rebase.Stdin = strings.NewReader(`{"base_url":"http://127.0.0.1:8317/v1"}`)
	output, err := rebase.CombinedOutput()
	if err != nil {
		t.Fatalf("Kimi Base URL rebase failed: %v: %s", err, output)
	}
	digest := sha256.Sum256([]byte("cpa_abcdefghijklmnopqrstuvwxyz012345"))
	if strings.TrimSpace(string(output)) != hex.EncodeToString(digest[:]) {
		t.Fatalf("Kimi Base URL rebase returned an unexpected key hash: %q", output)
	}
	rebased, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rebased), `base_url = "http://127.0.0.1:8317/v1"`) || !strings.Contains(string(rebased), `base_url = "http://127.0.0.1:8317/v1/search?model=kimi-k3"`) || !strings.Contains(string(rebased), `base_url = "http://127.0.0.1:8317/v1/fetch?model=kimi-k3"`) || !strings.Contains(string(rebased), `api_key = "cpa_abcdefghijklmnopqrstuvwxyz012345"`) {
		t.Fatalf("Kimi Base URL rebase did not preserve the API key:\n%s", rebased)
	}
}

func TestManagedProviderUpsertPreservesUnrelatedAndVerifiesExactSecrets(t *testing.T) {
	desired := []aionProvider{
		{ID: "managed-cliproxy-chatgpt", Platform: "custom", Name: "ChatGPT", BaseURL: "http://43.134.118.158:8317/v1", APIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", Models: []string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"}, Enabled: true},
		{ID: "managed-cliproxy-kimi", Platform: "custom", Name: "KIMI", BaseURL: "http://43.134.118.158:8317/v1", APIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654", Models: []string{"kimi-for-coding", "kimi-for-coding-highspeed", "kimi-k3"}, Enabled: true},
	}
	providers := []aionProvider{{ID: "custom-user-provider", Platform: "custom", Name: "Keep me", BaseURL: "https://example.test/v1", APIKey: "user-secret", Models: []string{"model"}, Enabled: true},
		{ID: desired[0].ID, Platform: "custom", Name: "stale", BaseURL: "https://stale.test/v1", APIKey: "stale", Models: []string{"stale"}, Enabled: false}}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/api/providers" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": providers})
			return
		}
		var incoming aionProvider
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api/providers/"+desired[0].ID {
			providers[1] = incoming
			_ = json.NewEncoder(w).Encode(incoming)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/providers" && incoming.ID == desired[1].ID {
			providers = append(providers, incoming)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(incoming)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	jar, _ := cookiejar.New(nil)
	client := &aionClient{base: base, client: &http.Client{Jar: jar}}
	if err := client.upsertManagedProviders(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(providers) != 3 || providers[0].ID != "custom-user-provider" || !reflect.DeepEqual(providers[1:], desired) {
		t.Fatalf("provider upsert changed unrelated state or failed exact replacement: %+v", providers)
	}
}

func TestPendingModelRebasePreservesProviderKeysAndCompletesMarker(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"credentials", "config"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := modelbootstrap.State{FormatVersion: modelbootstrap.FormatVersion, BaseURL: "http://43.134.118.158:8317/v1",
		CodexKeyID: "aionui-0123456789abcdef-chatgpt", KimiKeyID: "aionui-0123456789abcdef-kimi", CodexDefaultModel: "gpt-5.6-luna",
		CodexModels: modelbootstrap.ManagedCodexModels(), KimiModels: modelbootstrap.ManagedKimiModels()}
	bundle := modelbootstrap.Bundle{State: state, CodexAPIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", KimiAPIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654"}
	if err := modelbootstrap.Stage(root, bundle, false); err != nil {
		t.Fatal(err)
	}
	if err := modelbootstrap.Complete(root, state); err != nil {
		t.Fatal(err)
	}
	rebase, err := modelbootstrap.StageRebase(root, "http://127.0.0.1:8317/v1")
	if err != nil {
		t.Fatal(err)
	}
	providers := []aionProvider{
		{ID: modelbootstrap.CodexProviderID, Platform: "custom", Name: modelbootstrap.CodexProviderName, BaseURL: state.BaseURL, APIKey: bundle.CodexAPIKey, Models: state.CodexModels, Enabled: true},
		{ID: modelbootstrap.KimiProviderID, Platform: "custom", Name: modelbootstrap.KimiProviderName, BaseURL: state.BaseURL, APIKey: bundle.KimiAPIKey, Models: state.KimiModels, Enabled: true},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/providers" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": providers})
			return
		}
		for index := range providers {
			if r.Method == http.MethodPut && r.URL.Path == "/api/providers/"+providers[index].ID {
				if err := json.NewDecoder(r.Body).Decode(&providers[index]); err != nil {
					http.Error(w, "bad json", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(providers[index])
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	jar, _ := cookiejar.New(nil)
	client := server.Client()
	client.Jar = jar
	log, err := openPrivateLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	host := Host{cfg: config.UserHost{DataRoot: root}, client: &aionClient{base: base, client: client}, log: log}
	pending := &pendingModelBootstrap{rebase: &rebase, codexKeyHash: sha256.Sum256([]byte(bundle.CodexAPIKey)), kimiKeyHash: sha256.Sum256([]byte(bundle.KimiAPIKey))}
	if err := host.applyPendingModelRebase(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	status, err := modelbootstrap.Inspect(root)
	if err != nil || !status.Applied || status.RebasePending || status.State.BaseURL != rebase.Target.BaseURL {
		t.Fatalf("unexpected completed rebase status: %+v err=%v", status, err)
	}
	if providers[0].APIKey != bundle.CodexAPIKey || providers[1].APIKey != bundle.KimiAPIKey || providers[0].BaseURL != rebase.Target.BaseURL || providers[1].BaseURL != rebase.Target.BaseURL {
		t.Fatalf("provider rebase changed keys or missed Base URL: %+v", providers)
	}
}

func TestManagedProviderPolicyReplacesOnlyNamesAndModelLists(t *testing.T) {
	providers := []aionProvider{
		{ID: "custom-user-provider", Platform: "custom", Name: "Keep me", BaseURL: "https://example.test/v1", APIKey: "user-secret", Models: []string{"model"}, Enabled: true},
		{ID: modelbootstrap.CodexProviderID, Platform: "custom", Name: "ChatGPT (CLIProxyAPI)", BaseURL: "http://proxy.test/v1", APIKey: "codex-secret", Models: []string{"gpt-5.4"}, Enabled: false},
		{ID: modelbootstrap.KimiProviderID, Platform: "custom", Name: "Kimi for Coding (CLIProxyAPI)", BaseURL: "http://proxy.test/v1", APIKey: "kimi-secret", Models: []string{"kimi-k2.6"}, Enabled: true},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/providers" {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": providers})
			return
		}
		for index := 1; index < len(providers); index++ {
			if r.Method == http.MethodPut && r.URL.Path == "/api/providers/"+providers[index].ID {
				if err := json.NewDecoder(r.Body).Decode(&providers[index]); err != nil {
					http.Error(w, "bad json", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(providers[index])
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	jar, _ := cookiejar.New(nil)
	client := server.Client()
	client.Jar = jar
	host := Host{client: &aionClient{base: base, client: client}}
	if err := host.enforceManagedProviderPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if providers[0].Name != "Keep me" || providers[1].Name != "ChatGPT" || providers[1].APIKey != "codex-secret" || providers[1].Enabled || !reflect.DeepEqual(providers[1].Models, modelbootstrap.ManagedCodexModels()) {
		t.Fatalf("unexpected ChatGPT provider policy result: %+v", providers)
	}
	if providers[2].Name != "KIMI" || providers[2].APIKey != "kimi-secret" || !providers[2].Enabled || !reflect.DeepEqual(providers[2].Models, modelbootstrap.ManagedKimiModels()) {
		t.Fatalf("unexpected KIMI provider policy result: %+v", providers)
	}
}
