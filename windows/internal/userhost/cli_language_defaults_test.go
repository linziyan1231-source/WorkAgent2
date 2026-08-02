package userhost

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCLILanguageDefaultsDoNotCreateManagedPrompts(t *testing.T) {
	dirs, err := ensurePrivateDirs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(dirs.Config, "codex", "config.toml")
	if err := os.WriteFile(codexPath, []byte("model = \"existing-model\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied, err := applyInitialCLILanguageDefaults(dirs)
	if err != nil || !applied {
		t.Fatalf("first application applied=%t err=%v", applied, err)
	}
	codex, err := os.ReadFile(codexPath)
	if err != nil || string(codex) != "model = \"existing-model\"\n" {
		t.Fatalf("Codex config was changed: %q err=%v", codex, err)
	}
	agentPath := filepath.Join(dirs.Profile, filepath.FromSlash(legacyKimiLanguageAgentPath))
	if _, err := os.Stat(agentPath); !os.IsNotExist(err) {
		t.Fatalf("Kimi language agent was created: %v", err)
	}
	if err := os.WriteFile(codexPath, []byte("developer_instructions = \"用户后来选择英文\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied, err = applyInitialCLILanguageDefaults(dirs)
	if err != nil || applied {
		t.Fatalf("second application applied=%t err=%v", applied, err)
	}
	codex, _ = os.ReadFile(codexPath)
	if string(codex) != "developer_instructions = \"用户后来选择英文\"\n" {
		t.Fatalf("later user choice was overwritten: %q", codex)
	}
}

func TestCLILanguageDefaultsMigrateV2RemovingOnlyManagedCodexPrompt(t *testing.T) {
	dirs, err := ensurePrivateDirs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(dirs.Config, "codex", "config.toml")
	managed := codexLanguageDefaultComment + "\n" +
		"developer_instructions = " + strconv.Quote(cliChineseLanguageInstruction) + "\n\n" +
		"model = \"existing-model\"\n"
	if err := os.WriteFile(codexPath, []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	previousMarker := filepath.Join(dirs.Config, previousCLILanguageMarkerName)
	if err := os.WriteFile(previousMarker, []byte(previousCLILanguageMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, err := applyInitialCLILanguageDefaults(dirs); err != nil || !applied {
		t.Fatalf("v2 migration applied=%t err=%v", applied, err)
	}
	codex, _ := os.ReadFile(codexPath)
	if string(codex) != "model = \"existing-model\"\n" {
		t.Fatalf("v2 migration did not remove only the managed prompt: %q", codex)
	}
	if _, err := os.Stat(previousMarker); !os.IsNotExist(err) {
		t.Fatalf("previous marker survived migration: %s err=%v", previousMarker, err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Config, cliLanguageMarkerName)); err != nil {
		t.Fatalf("v3 marker is missing: %v", err)
	}
}

func TestCLILanguageDefaultsMigrateV1RemovingManagedCodexAndKimiPrompts(t *testing.T) {
	dirs, err := ensurePrivateDirs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(dirs.Config, "codex", "config.toml")
	managed := codexLanguageDefaultComment + "\n" +
		"developer_instructions = " + strconv.Quote(cliChineseLanguageInstruction) + "\n\n" +
		"model = \"existing-model\"\n"
	if err := os.WriteFile(codexPath, []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	kimiDirectory := filepath.Join(dirs.Profile, ".kimi")
	if err := os.Mkdir(kimiDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	agentPath := filepath.Join(kimiDirectory, "aion-default-agent.yaml")
	if err := os.WriteFile(agentPath, []byte(kimiLanguageAgentContent), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyMarker := filepath.Join(dirs.Config, legacyCLILanguageMarkerName)
	if err := os.WriteFile(legacyMarker, []byte(legacyCLILanguageMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, err := applyInitialCLILanguageDefaults(dirs); err != nil || !applied {
		t.Fatalf("v1 migration applied=%t err=%v", applied, err)
	}
	codex, _ := os.ReadFile(codexPath)
	if string(codex) != "model = \"existing-model\"\n" {
		t.Fatalf("v1 migration did not remove only the managed Codex prompt: %q", codex)
	}
	for _, path := range []string{agentPath, legacyMarker} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("legacy file survived migration: %s err=%v", path, err)
		}
	}
}

func TestCLILanguageDefaultsPreserveUserDeveloperInstructions(t *testing.T) {
	dirs, err := ensurePrivateDirs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(dirs.Config, "codex", "config.toml")
	if err := os.WriteFile(codexPath, []byte("developer_instructions = \"用户自己的指令\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousMarker := filepath.Join(dirs.Config, previousCLILanguageMarkerName)
	if err := os.WriteFile(previousMarker, []byte(previousCLILanguageMarkerContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, err := applyInitialCLILanguageDefaults(dirs); err != nil || !applied {
		t.Fatalf("migration applied=%t err=%v", applied, err)
	}
	codex, _ := os.ReadFile(codexPath)
	if string(codex) != "developer_instructions = \"用户自己的指令\"\n" {
		t.Fatalf("user instruction was changed: %q", codex)
	}
}

func TestCLILanguageDefaultsRefuseModifiedLegacyKimiAgent(t *testing.T) {
	dirs, err := ensurePrivateDirs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kimiDirectory := filepath.Join(dirs.Profile, ".kimi")
	if err := os.Mkdir(kimiDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dirs.Profile, filepath.FromSlash(legacyKimiLanguageAgentPath))
	if err := os.WriteFile(path, []byte("user-owned content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, err := applyInitialCLILanguageDefaults(dirs); err == nil || applied || !strings.Contains(err.Error(), "refusing to delete") {
		t.Fatalf("modified legacy file applied=%t err=%v", applied, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "user-owned content\n" {
		t.Fatalf("modified legacy file was changed: %q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Config, cliLanguageMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("v2 marker exists after failed migration: %v", err)
	}
}
