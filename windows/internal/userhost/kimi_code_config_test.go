package userhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"aionuiportal/internal/agentcli"
)

const realShapedKimiConfig = `default_model = "kimi-code/kimi-for-coding"
default_thinking = true
default_yolo = true

[providers."managed:kimi-code"]
type = "kimi"
base_url = "http://127.0.0.1:8317/v1"
api_key = "cpa_test-shaped-key"

[models."kimi-code/kimi-for-coding"]
provider = "managed:kimi-code"
model = "kimi-for-coding"
max_context_size = 262144
capabilities = ["video_in", "image_in", "thinking"]
`

func TestKimiConfigPathFollowsTheActiveRuntime(t *testing.T) {
	profile := t.TempDir()
	legacy := kimiConfigPath(profile, agentcli.Manifest{Files: map[string]agentcli.File{}})
	if want := filepath.Join(profile, ".kimi", "config.toml"); legacy != want {
		t.Fatalf("legacy path = %q, want %q", legacy, want)
	}
	modern := kimiConfigPath(profile, agentcli.Manifest{Files: map[string]agentcli.File{
		agentcli.KimiCodeRelativePath: {},
	}})
	if want := filepath.Join(profile, ".kimi-code", "config.toml"); modern != want {
		t.Fatalf("Kimi Code path = %q, want %q", modern, want)
	}
}

func TestMigrateKimiConfigFileCopiesWithoutRemovingLegacy(t *testing.T) {
	profile := t.TempDir()
	source := filepath.Join(profile, ".kimi", "config.toml")
	target := filepath.Join(profile, ".kimi-code", "config.toml")
	if err := os.Mkdir(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(realShapedKimiConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	validated := ""
	migrated, err := migrateKimiConfigFile(source, target, func(path string) error {
		validated = path
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if string(data) != realShapedKimiConfig {
			return errors.New("candidate content differs")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !migrated || validated != target+".migrating-from-kimi-cli" {
		t.Fatalf("migration result = %v, validated = %q", migrated, validated)
	}
	for _, path := range []string{source, target} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != realShapedKimiConfig {
			t.Fatalf("%s content differs", path)
		}
	}
}

func TestMigrateKimiConfigFileValidationFailurePreservesRollbackState(t *testing.T) {
	profile := t.TempDir()
	source := filepath.Join(profile, ".kimi", "config.toml")
	target := filepath.Join(profile, ".kimi-code", "config.toml")
	if err := os.Mkdir(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(realShapedKimiConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("new runtime rejected config")
	if migrated, err := migrateKimiConfigFile(source, target, func(string) error { return want }); migrated || !errors.Is(err, want) {
		t.Fatalf("migration result = %v, error = %v", migrated, err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("legacy source was not preserved: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target unexpectedly exists: %v", err)
	}
	if _, err := os.Stat(target + ".migrating-from-kimi-cli"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate unexpectedly remains: %v", err)
	}
}

func TestMigrateKimiConfigFilePreservesExistingTarget(t *testing.T) {
	profile := t.TempDir()
	source := filepath.Join(profile, ".kimi", "config.toml")
	target := filepath.Join(profile, ".kimi-code", "config.toml")
	for _, directory := range []string{filepath.Dir(source), filepath.Dir(target)} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(source, []byte(realShapedKimiConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	const existing = "default_model = \"custom/user-model\"\n"
	if err := os.WriteFile(target, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := migrateKimiConfigFile(source, target, func(path string) error {
		if path != target {
			return errors.New("existing target was not validated in place")
		}
		return nil
	})
	if err != nil || migrated {
		t.Fatalf("migration result = %v, error = %v", migrated, err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatalf("existing target was overwritten: %q", data)
	}
}
