package userhost

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

const bootstrapTestTenant = "11111111-1111-4111-8111-111111111111"

func bootstrapTestBundle(t *testing.T, baseURL string) modelbootstrap.Bundle {
	t.Helper()
	ids := modelbootstrap.KeyIDsForTenant(bootstrapTestTenant)
	bundle := modelbootstrap.Bundle{State: modelbootstrap.State{
		FormatVersion: modelbootstrap.FormatVersion, PolicyID: "policy-production-v1", BaseURL: baseURL,
		CodexKeyID: ids.CodexKeyID, KimiKeyID: ids.KimiKeyID, CodexDefaultModel: modelbootstrap.DefaultCodexModel, KimiDefaultModel: modelbootstrap.DefaultKimiModel,
		CodexModels: modelbootstrap.ManagedCodexModels(), KimiModels: modelbootstrap.ManagedKimiModels(),
	}, CodexAPIKey: "cpa_AAAAAAAAAAAAAAAAAAAAAAAA", KimiAPIKey: "cpa_BBBBBBBBBBBBBBBBBBBBBBBB"}
	if err := bundle.ValidateManagedForTenant(bootstrapTestTenant); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestModelBootstrapPersistsClientsProvidersAndKeyFreeMarker(t *testing.T) {
	var mu sync.Mutex
	providers := make(map[string]aionProvider)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/providers", func(writer http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		values := make([]aionProvider, 0, len(providers))
		for _, provider := range providers {
			values = append(values, provider)
		}
		mu.Unlock()
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true, "data": values})
	})
	writeProvider := func(writer http.ResponseWriter, request *http.Request) {
		var provider aionProvider
		if err := json.NewDecoder(request.Body).Decode(&provider); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		providers[provider.ID] = provider
		mu.Unlock()
		_ = json.NewEncoder(writer).Encode(map[string]any{"success": true})
	}
	mux.HandleFunc("POST /api/providers", writeProvider)
	mux.HandleFunc("PUT /api/providers/{id}", writeProvider)
	backend := httptest.NewServer(mux)
	defer backend.Close()

	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, directory := range []string{"config", "config/codex", "credentials", "home", "home/.kimi-code"} {
		if err := root.EnsureDirectory(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	legacyKimi := legacyKimiTopBlockStart + "\ndefault_model = \"" + legacyKimiModelPrefix + "kimi-for-coding\"\n" + legacyKimiTopBlockEnd + "\n\n" +
		"[ui]\ntheme = \"dark\"\n\n" + legacyKimiTableBlockStart + "\n[providers.\"managed:kimi-code\"]\ntype = \"kimi\"\napi_key = \"legacy-secret\"\n" + legacyKimiTableBlockEnd + "\n"
	if err := root.WriteFileAtomic(kimiConfigPath, []byte(legacyKimi), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(backend.URL)
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root, backendURL: parsed, transport: backend.Client().Transport.(*http.Transport), logger: log.New(io.Discard, "", 0)}
	bundle := bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")
	pending, err := encodeStrictJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFileAtomic(modelBootstrapPendingPath, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(pending)
	if err := host.writeCLIModelConfiguration(bundle); err != nil {
		t.Fatal(err)
	}
	if err := host.completeModelBootstrap(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	marker, err := root.ReadFile(modelBootstrapMarkerPath, 256*1024)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(marker), "cpa_") {
		t.Fatal("applied marker retained a plaintext API key")
	}
	if _, err := root.ReadFile(modelBootstrapPendingPath, 256*1024); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending one-time key bundle was not consumed: %v", err)
	}
	kimi, err := root.ReadFile(kimiConfigPath, maxModelConfigBytes)
	if err != nil || !strings.Contains(string(kimi), "theme = \"dark\"") || !strings.Contains(string(kimi), bundle.KimiAPIKey) ||
		!strings.Contains(string(kimi), "WorkAgent2 MANAGED") || !strings.Contains(string(kimi), "workagent-managed/kimi-k3") || strings.Contains(string(kimi), legacyKimiBrand) || strings.Contains(string(kimi), legacyKimiModelPrefix) || strings.Contains(string(kimi), "legacy-secret") {
		t.Fatalf("Kimi configuration was not safely reconciled: err=%v", err)
	}
	loaded, found, err := host.loadStartupModelBundle()
	if err != nil || !found || !loaded.State.Equal(bundle.State) || loaded.CodexAPIKey != bundle.CodexAPIKey || loaded.KimiAPIKey != bundle.KimiAPIKey {
		t.Fatalf("applied configuration did not reload: found=%v err=%v", found, err)
	}
	loaded.Zero()
	mu.Lock()
	defer mu.Unlock()
	if len(providers) != 2 {
		t.Fatalf("managed provider count=%d", len(providers))
	}
}

func TestInternalRoutesRequirePortalControlCredential(t *testing.T) {
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, logger: log.New(io.Discard, "", 0)}
	request := httptest.NewRequest(http.MethodGet, "http://userhost/internal/status", nil)
	request.Header.Set("X-WorkAgent-Tenant", bootstrapTestTenant)
	recorder := httptest.NewRecorder()
	host.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated control request returned %d", recorder.Code)
	}
}

func TestModelBootstrapRejectsConflictingPendingAndAppliedState(t *testing.T) {
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, directory := range []string{"config", "credentials"} {
		if err := root.EnsureDirectory(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root}
	bundle := bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")
	pending, _ := encodeStrictJSON(bundle)
	if err := root.WriteFileAtomic(modelBootstrapPendingPath, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := bundle.State
	changed.PolicyID = "different-policy"
	marker, _ := encodeStrictJSON(changed)
	if err := root.WriteFileAtomic(modelBootstrapMarkerPath, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(pending)
	clear(marker)
	if _, _, err := host.loadStartupModelBundle(); err == nil {
		t.Fatal("conflicting pending and applied policies were accepted")
	}
}

func TestLiveModelBootstrapRejectsLegacyCodexDefault(t *testing.T) {
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, directory := range []string{"config", "credentials"} {
		if err := root.EnsureDirectory(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")
	bundle.CodexDefaultModel = "gpt-5.6-luna"
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root}
	request := httptest.NewRequest(http.MethodPost, "http://userhost/internal/model-bootstrap", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	host.modelBootstrapApply(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy live bootstrap returned %d: %s", response.Code, response.Body.String())
	}
	if _, err := root.ReadFile(modelBootstrapPendingPath, 256*1024); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy live bootstrap was staged: %v", err)
	}
}

func TestWriteCodexConfigPreservesUnmanagedTables(t *testing.T) {
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.EnsureDirectory(filepath.Dir(codexConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	existing := "model = \"old\"\n[projects.\"/workspace/kept\"]\ntrust_level = \"trusted\"\n"
	if err := root.WriteFileAtomic(codexConfigPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root}
	if err := host.writeCodexConfig(bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")); err != nil {
		t.Fatal(err)
	}
	payload, err := root.ReadFile(codexConfigPath, maxModelConfigBytes)
	if err != nil || strings.Count(string(payload), "model =") != 1 || !strings.Contains(string(payload), "trust_level = \"trusted\"") {
		t.Fatalf("unexpected reconciled Codex config: %s err=%v", payload, err)
	}
}
