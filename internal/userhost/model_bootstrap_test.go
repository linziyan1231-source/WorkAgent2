package userhost

import (
	"bytes"
	"context"
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
	if err := writeInitialCodexConfig(path, "http://203.0.113.52:8317/v1", "example-reasoning"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, required := range []string{`openai_base_url = "http://203.0.113.52:8317/v1"`, `model = "example-reasoning"`, `model_reasoning_effort = "xhigh"`, `cli_auth_credentials_store = "file"`, `approval_policy = "on-request"`, `developer_instructions = "默认使用简体中文回复。"`, `model = "table-value-must-survive"`} {
		if !strings.Contains(got, required) {
			t.Fatalf("managed config is missing %q:\n%s", required, got)
		}
	}
	if strings.Contains(got, "old-model") || strings.Contains(got, "old.example") || strings.Contains(got, `model_reasoning_effort = "low"`) {
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
	payload := []byte(`{"api_key":"cpa_abcdefghijklmnopqrstuvwxyz012345","base_url":"http://203.0.113.52:8317/v1"}`)
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
	for _, required := range []string{"# preserve this comment", `theme = "light"`, `default_yolo = true`, `[providers.custom]`, `base_url = "http://203.0.113.52:8317/v1"`, `api_key = "cpa_abcdefghijklmnopqrstuvwxyz012345"`} {
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
}

func TestManagedProviderUpsertPreservesUnrelatedAndVerifiesExactSecrets(t *testing.T) {
	desired := []aionProvider{
		{ID: "managed-cliproxy-chatgpt", Platform: "custom", Name: "ChatGPT", BaseURL: "http://203.0.113.52:8317/v1", APIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", Models: []string{"example-reasoning", "example-balanced", "example-fast"}, Enabled: true},
		{ID: "managed-cliproxy-kimi", Platform: "custom", Name: "KIMI", BaseURL: "http://203.0.113.52:8317/v1", APIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654", Models: []string{"kimi-for-coding"}, Enabled: true},
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
