package userhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestInitialCodexConfigUpdatesOnlyManagedTopLevelKeys(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.toml")
	existing := `model = "old-model"
openai_base_url = "https://old.example/v1"
approval_policy = "on-request"

[features]
model = "table-value-must-survive"
web_search = true
`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeInitialCodexConfig(path, "http://203.0.113.52:8317/v1", "gpt-5.4"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, required := range []string{`openai_base_url = "http://203.0.113.52:8317/v1"`, `model = "gpt-5.4"`, `cli_auth_credentials_store = "file"`, `approval_policy = "on-request"`, `model = "table-value-must-survive"`} {
		if !strings.Contains(got, required) {
			t.Fatalf("managed config is missing %q:\n%s", required, got)
		}
	}
	if strings.Contains(got, "old-model") || strings.Contains(got, "old.example") {
		t.Fatalf("old managed values survived:\n%s", got)
	}
}

func TestManagedProviderUpsertPreservesUnrelatedAndVerifiesExactSecrets(t *testing.T) {
	desired := []aionProvider{
		{ID: "managed-cliproxy-chatgpt", Platform: "custom", Name: "ChatGPT (CLIProxyAPI)", BaseURL: "http://203.0.113.52:8317/v1", APIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", Models: []string{"gpt-5.4", "gpt-5.4-mini"}, Enabled: true},
		{ID: "managed-cliproxy-kimi", Platform: "custom", Name: "Kimi K2.6 (CLIProxyAPI)", BaseURL: "http://203.0.113.52:8317/v1", APIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654", Models: []string{"kimi-k2.6"}, Enabled: true},
	}
	providers := []aionProvider{{ID: "custom-user-provider", Platform: "custom", Name: "Keep me", BaseURL: "https://example.test/v1", APIKey: "user-secret", Models: []string{"model"}, Enabled: true},
		{ID: desired[0].ID, Platform: "custom", Name: "stale", BaseURL: "https://stale.test/v1", APIKey: "stale", Models: []string{"stale"}, Enabled: false}}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/api/providers" {
			_ = json.NewEncoder(w).Encode(providers)
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
