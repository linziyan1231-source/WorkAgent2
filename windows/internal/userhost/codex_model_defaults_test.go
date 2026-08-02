package userhost

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aionuiportal/internal/modelbootstrap"
)

func TestApplyCodexModelDefaultsMigratesConfigAndStateWithoutTouchingAuth(t *testing.T) {
	root := t.TempDir()
	dirs, err := ensurePrivateDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dirs.Config, "codex", "config.toml")
	existing := `openai_base_url = "http://127.0.0.1:8317/v1"
model = "example-reasoning"
model_reasoning_effort = "xhigh"
cli_auth_credentials_store = "file"
approval_policy = "on-request"

[features]
model = "table-value-must-survive"
`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(dirs.Config, "codex", "auth.json")
	auth := []byte(`{"OPENAI_API_KEY":"cpa_abcdefghijklmnopqrstuvwxyz012345"}`)
	if err := os.WriteFile(authPath, auth, 0o600); err != nil {
		t.Fatal(err)
	}
	authHash := sha256.Sum256(auth)
	bundle := modelbootstrap.Bundle{State: modelbootstrap.State{
		FormatVersion:     modelbootstrap.FormatVersion,
		BaseURL:           "http://127.0.0.1:8317/v1",
		CodexKeyID:        "aionui-0123456789abcdef-chatgpt",
		KimiKeyID:         "aionui-0123456789abcdef-kimi",
		CodexDefaultModel: "example-reasoning",
		CodexModels:       modelbootstrap.ManagedCodexModels(),
		KimiModels:        modelbootstrap.ManagedKimiModels(),
	}, CodexAPIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", KimiAPIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654"}
	if err := modelbootstrap.Stage(root, bundle, false); err != nil {
		t.Fatal(err)
	}
	if err := modelbootstrap.Complete(root, bundle.State); err != nil {
		t.Fatal(err)
	}

	applied, err := applyCodexModelDefaults(root, dirs)
	if err != nil || !applied {
		t.Fatalf("apply defaults: applied=%t err=%v", applied, err)
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, required := range []string{`model = "example-balanced"`, `model_reasoning_effort = "low"`, `openai_base_url = "http://127.0.0.1:8317/v1"`, `cli_auth_credentials_store = "file"`, `approval_policy = "on-request"`, `model = "table-value-must-survive"`} {
		if !strings.Contains(got, required) {
			t.Fatalf("migrated config is missing %q: %s", required, got)
		}
	}
	if strings.Contains(got, `model = "example-reasoning"`) || strings.Contains(got, `model_reasoning_effort = "xhigh"`) {
		t.Fatalf("old defaults survived migration: %s", got)
	}
	status, err := modelbootstrap.Inspect(root)
	if err != nil || status.State.CodexDefaultModel != modelbootstrap.DefaultCodexModel || status.State.CodexKeyID != bundle.CodexKeyID || status.State.KimiKeyID != bundle.KimiKeyID {
		t.Fatalf("unexpected migrated bootstrap state: status=%+v err=%v", status, err)
	}
	authAfter, err := os.ReadFile(authPath)
	if err != nil || sha256.Sum256(authAfter) != authHash {
		t.Fatalf("Codex auth changed during default migration: err=%v", err)
	}
	beforeSecondApply := append([]byte(nil), content...)
	if applied, err := applyCodexModelDefaults(root, dirs); err != nil || applied {
		t.Fatalf("second apply was not a no-op: applied=%t err=%v", applied, err)
	}
	afterSecondApply, err := os.ReadFile(configPath)
	if err != nil || string(afterSecondApply) != string(beforeSecondApply) {
		t.Fatalf("second apply changed config: err=%v", err)
	}
}

func TestApplyCodexModelDefaultsRequiresAppliedBootstrap(t *testing.T) {
	root := t.TempDir()
	dirs, err := ensurePrivateDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := applyCodexModelDefaults(root, dirs); err == nil || applied || !strings.Contains(err.Error(), "must be applied") {
		t.Fatalf("missing bootstrap was not rejected: applied=%t err=%v", applied, err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Config, codexModelDefaultsMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("migration marker exists after failed migration: %v", err)
	}
}
