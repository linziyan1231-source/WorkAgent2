package userhost

import (
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

func TestApplyCodexModelDefaultsMigratesStateAndConfigWithoutTouchingAuth(t *testing.T) {
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, directory := range []string{"config", "config/codex", "credentials"} {
		if err := root.EnsureDirectory(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")
	bundle.CodexDefaultModel = "gpt-5.6-luna"
	statePayload, _ := encodeStrictJSON(bundle.State)
	if err := root.WriteFileAtomic(modelBootstrapMarkerPath, statePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(statePayload)
	existing := `openai_base_url = "http://127.0.0.1:8317/v1"
model = "gpt-5.6-luna"
model_reasoning_effort = "xhigh"
cli_auth_credentials_store = "file"
approval_policy = "on-request"

[features]
model = "table-value-must-survive"
`
	if err := root.WriteFileAtomic(codexConfigPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := []byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"cpa_AAAAAAAAAAAAAAAAAAAAAAAA"}` + "\n")
	if err := root.WriteFileAtomic(codexAuthPath, auth, 0o600); err != nil {
		t.Fatal(err)
	}
	authHash := sha256.Sum256(auth)
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root}
	updated, applied, err := host.applyCodexModelDefaults()
	if err != nil || !applied {
		t.Fatalf("apply defaults: applied=%t state=%+v err=%v", applied, updated, err)
	}
	if updated.CodexDefaultModel != modelbootstrap.DefaultCodexModel || updated.CodexKeyID != bundle.CodexKeyID || updated.KimiKeyID != bundle.KimiKeyID {
		t.Fatalf("migration changed unrelated bootstrap state: %+v", updated)
	}
	content, err := root.ReadFile(codexConfigPath, maxModelConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`model = "gpt-5.6-sol"`, `model_reasoning_effort = "low"`, `openai_base_url = "http://127.0.0.1:8317/v1"`, `cli_auth_credentials_store = "file"`, `approval_policy = "on-request"`, `model = "table-value-must-survive"`} {
		if !strings.Contains(string(content), required) {
			t.Fatalf("migrated config is missing %q: %s", required, content)
		}
	}
	if strings.Contains(string(content), `model = "gpt-5.6-luna"`) || strings.Contains(string(content), `model_reasoning_effort = "xhigh"`) {
		t.Fatalf("legacy defaults survived migration: %s", content)
	}
	authAfter, err := root.ReadFile(codexAuthPath, 64*1024)
	if err != nil || sha256.Sum256(authAfter) != authHash {
		t.Fatalf("Codex auth changed during migration: err=%v", err)
	}
	if _, applied, err := host.applyCodexModelDefaults(); err != nil || applied {
		t.Fatalf("second migration was not a no-op: applied=%t err=%v", applied, err)
	}
}

func TestApplyCodexModelDefaultsDefersPendingBootstrapAndRequiresAppliedState(t *testing.T) {
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, directory := range []string{"config", "config/codex", "credentials"} {
		if err := root.EnsureDirectory(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root}
	if _, applied, err := host.applyCodexModelDefaults(); err == nil || applied || !strings.Contains(err.Error(), "must be applied") {
		t.Fatalf("missing applied bootstrap was accepted: applied=%t err=%v", applied, err)
	}
	bundle := bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")
	pending, _ := encodeStrictJSON(bundle)
	if err := root.WriteFileAtomic(modelBootstrapPendingPath, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(pending)
	if _, applied, err := host.applyCodexModelDefaults(); err != nil || applied {
		t.Fatalf("pending bootstrap was not deferred: applied=%t err=%v", applied, err)
	}
	if _, err := root.ReadFile(codexModelDefaultsMarkerPath, 4096); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("defaults marker exists while bootstrap is pending: %v", err)
	}
}
