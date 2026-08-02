package userhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"aionuiportal/internal/agentcli"
)

func TestKimiThinkingDefaultScriptEnablesManagedThinkingAndPreservesConfig(t *testing.T) {
	root := filepath.Join(os.Getenv("ProgramFiles"), agentcli.RootDirectoryName)
	verified, err := agentcli.VerifyCurrent(root)
	if err != nil {
		t.Skipf("shared Kimi runtime is unavailable: %v", err)
	}
	kimiDirectory := filepath.Join(t.TempDir(), ".kimi")
	if err := os.MkdirAll(kimiDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(kimiDirectory, "config.toml")
	fixture := `# user comment must survive
default_model = "kimi-code/kimi-for-coding"
default_thinking = false
theme = "light"

[models."kimi-code/kimi-for-coding"]
provider = "managed:kimi-code"
model = "kimi-for-coding"
max_context_size = 262144
capabilities = ["video_in", "image_in", "thinking"]

[providers."managed:kimi-code"]
type = "kimi"
base_url = "http://example.test/v1"
api_key = "cpa_abcdefghijklmnopqrstuvwxyz012345"
`
	if err := os.WriteFile(configPath, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiRelativePath))
	command := exec.Command(python, "-B", "-c", kimiThinkingDefaultScript, configPath)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PYTHONUTF8=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Kimi thinking helper failed: %v: %s", err, output)
	}
	if _, ok := verified.Manifest.Files[agentcli.KimiCodeRelativePath]; ok {
		doctor := exec.Command(filepath.Join(verified.Path, filepath.FromSlash(agentcli.KimiCodeRelativePath)), "doctor", "config", configPath)
		doctor.Env = append(os.Environ(), "PYTHONUTF8=1")
		if output, err := doctor.CombinedOutput(); err != nil {
			t.Fatalf("Kimi Code rejected the generated effort configuration: %v: %s", err, output)
		}
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(content)
	for _, required := range []string{"# user comment must survive", `default_model = "kimi-code/kimi-k3"`, `default_thinking = true`, `theme = "light"`, `support_efforts = ["low", "high", "max"]`, `default_effort = "high"`, `[models."kimi-code/kimi-for-coding-highspeed"]`, `model = "kimi-for-coding-highspeed"`, `display_name = "Kimi for Coding HighSpeed"`, `[models."kimi-code/kimi-k3"]`, `model = "kimi-k3"`, `max_context_size = 1048576`, `default_effort = "low"`, `display_name = "Kimi K3"`, `[thinking]`, `enabled = true`, `api_key = "cpa_abcdefghijklmnopqrstuvwxyz012345"`} {
		if !strings.Contains(got, required) {
			t.Fatalf("Kimi config is missing %q:\n%s", required, got)
		}
	}
}
