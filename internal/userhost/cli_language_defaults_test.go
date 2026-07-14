package userhost

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"aionuiportal/internal/agentcli"
)

func TestInitialCLILanguageDefaultsApplyOnceAndPreserveLaterUserChoice(t *testing.T) {
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
	if err != nil || !strings.Contains(string(codex), "developer_instructions = "+strconv.Quote(cliChineseLanguageInstruction)) || !strings.Contains(string(codex), `model = "existing-model"`) {
		t.Fatalf("Codex language default or preserved model is missing: %q err=%v", codex, err)
	}
	agentPath := filepath.Join(dirs.Profile, filepath.FromSlash(agentcli.KimiManagedAgentRelativePath))
	agent, err := os.ReadFile(agentPath)
	if err != nil || string(agent) != kimiLanguageAgentContent {
		t.Fatalf("Kimi language agent mismatch: %q err=%v", agent, err)
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

func TestInitialCLILanguageDefaultsRefuseUnexpectedManagedKimiAgent(t *testing.T) {
	dirs, err := ensurePrivateDirs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	kimiDirectory := filepath.Join(dirs.Profile, ".kimi")
	if err := os.Mkdir(kimiDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dirs.Profile, filepath.FromSlash(agentcli.KimiManagedAgentRelativePath))
	if err := os.WriteFile(path, []byte("user-owned content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, err := applyInitialCLILanguageDefaults(dirs); err == nil || applied || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("unexpected managed file applied=%t err=%v", applied, err)
	}
	if _, err := os.Stat(filepath.Join(dirs.Config, cliLanguageMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("marker exists after failed initialization: %v", err)
	}
}
