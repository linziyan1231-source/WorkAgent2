package cliproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestRuntimeConfigTemplateHashesCredentialWithoutPersistingPlaintext(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join(root, "deploy", "cliproxyapi", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH")
	rendered, err := renderRuntimeConfig(template, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rendered)
	if bytes.Contains(rendered, credential) || bytes.Contains(template, credential) {
		t.Fatal("plaintext management credential was persisted")
	}
	fields, _, _, err := parseYAMLTemplateFields(rendered)
	if err != nil {
		t.Fatal(err)
	}
	hash := fields["remote-management.secret-key"].value
	if err := bcrypt.CompareHashAndPassword([]byte(hash), credential); err != nil {
		t.Fatalf("rendered management hash does not match credential: %v", err)
	}
	if fields["remote-management.allow-remote"].value != "false" || fields["remote-management.disable-control-panel"].value != "true" || fields["remote-management.disable-auto-update-panel"].value != "true" || fields["logs-max-total-size-mb"].value != "256" || fields["error-logs-max-files"].value != "10" || fields["proxy-url"].value != "http://127.0.0.1:8118" || fields["plugins.configs.cpa-key-policy.state_file"].value != "/var/lib/cliproxyapi/policy/cpa-key-policy-state.json" {
		t.Fatalf("rendered contract drifted: %#v", fields)
	}
}

func TestCheckedInCLIProxyDeploymentNeverUsesRemoteEnablingPasswordEnvironment(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "cliproxyapi.service"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	for _, required := range []string{
		"User=cliproxyapi", "LoadCredentialEncrypted=cliproxy-management-key:",
		"workagent-cliproxy prepare", "workagent-cliproxy bootstrap", "ProtectSystem=strict", "ReadWritePaths=/var/lib/cliproxyapi",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("CLIProxy unit omitted %q", required)
		}
	}
	if strings.Contains(text, "MANAGEMENT_PASSWORD") || strings.Contains(text, "EnvironmentFile=") {
		t.Fatal("CLIProxy unit uses an environment path that enables remote management or leaks secrets")
	}
	sourceGate, err := os.ReadFile(filepath.Join(root, "scripts", "source-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sourceGate), "workagent-cliproxy") {
		t.Fatal("production source gate does not package the CLIProxy helper")
	}
}

func TestVendoredPatchHashesMatchSourceLocks(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"cliproxyapi-per-key-models.patch":                 "1e2b8331b049d83bf8f4fcb91aa679234b35ea4b650de14e637c119008ec9fda",
		"cpa-key-policy-0.4.4-state-concurrency.patch":     "3d2d12b2febb34ad245d1ff042b6a68123d8c548ff90976f48d45b7352d8a4ab",
		"cpa-key-policy-0.4.5-linux-directory-fsync.patch": "7707fee5123c5311523b219f9a1e7b20911a399a756a25233f14154ef3339cfe",
	}
	for name, wanted := range expected {
		payload, err := os.ReadFile(filepath.Join(root, "third_party", "cliproxyapi", "patches", name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		if got := hex.EncodeToString(digest[:]); got != wanted {
			t.Fatalf("%s SHA-256 = %s, want %s", name, got, wanted)
		}
	}
}
