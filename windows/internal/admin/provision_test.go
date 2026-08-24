package admin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"aionuiportal/internal/auth"
)

func TestLoginHealthPasswordSurvivesCalleeZeroing(t *testing.T) {
	password := []byte("correct horse battery staple")
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	retained := retainLoginHealthPassword(password)
	defer auth.Zero(retained)

	auth.Zero(password)
	if !auth.VerifyPassword(hash, retained) {
		t.Fatal("retained login health password was affected when the callee cleared its password buffer")
	}
}

func TestGenerateWindowsPasswordIsRandomAndMeetsRequiredClasses(t *testing.T) {
	first, err := generateWindowsPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateWindowsPassword(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || bytes.Equal(first, second) {
		t.Fatalf("generated passwords are invalid or unexpectedly equal")
	}
	var upper, lower, digit, symbol bool
	for _, character := range string(first) {
		upper = upper || unicode.IsUpper(character)
		lower = lower || unicode.IsLower(character)
		digit = digit || unicode.IsDigit(character)
		symbol = symbol || !unicode.IsLetter(character) && !unicode.IsDigit(character)
	}
	if !upper || !lower || !digit || !symbol {
		t.Fatalf("generated password lacks a required character class")
	}
}

func TestDiskQuotaScriptSupportsWindowsPowerShell(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "scripts", "Set-UserDiskQuota.ps1")
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "[IO.Path]::IsPathFullyQualified") {
		t.Fatal("Set-UserDiskQuota.ps1 uses IsPathFullyQualified, which is unavailable in Windows PowerShell 5.1")
	}
	text := string(content)
	for _, required := range []string{"/grant:r \"*$sid`:(RX)\"", "[Security.AccessControl.FileSystemRights]1179817", "/grant:r \"*$sid`:(X,RA,S)\"", "[Security.AccessControl.FileSystemRights]1048736", "$matching.Count -ne 1"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Set-UserDiskQuota.ps1 lacks exact metadata-traverse ACL enforcement %q", required)
		}
	}
	if strings.Contains(text, "*$sid`:(X)\"") {
		t.Fatal("Set-UserDiskQuota.ps1 still grants traverse without read-attributes and synchronize")
	}
}

func TestDefaultEmployeeModelQuotas(t *testing.T) {
	if DefaultEmployeeCodexDailyUSD != 40 || DefaultEmployeeCodexWeeklyUSD != 80 ||
		DefaultEmployeeKimiDailyUSD != 10 || DefaultEmployeeKimiWeeklyUSD != 20 {
		t.Fatal("new employee model quotas must use the doubled defaults")
	}
	if DefaultEmployeeCodexWeeklyUSD != DefaultEmployeeCodexDailyUSD*2 ||
		DefaultEmployeeKimiWeeklyUSD != DefaultEmployeeKimiDailyUSD*2 {
		t.Fatal("weekly model quota defaults must remain twice the daily defaults")
	}
}

func TestSkillPolicyInvocationUsesPublishedBundleAndProvisionedBuiltins(t *testing.T) {
	provisioner := EmployeeProvisioner{ScriptsDirectory: `C:\Program Files\AionUiPortal\admin-scripts`}
	dataRoot := `C:\ProgramData\AionUiPortal\users\S-1-5-21-1-2-3-1001`
	name, arguments := provisioner.skillPolicyInvocation(dataRoot)
	if name != filepath.Join("skill-policy", "Apply-UserSkillPolicy.ps1") {
		t.Fatalf("unexpected Skill policy script: %s", name)
	}
	expected := []string{
		"-DataRoot", dataRoot,
		"-PluginRoot", filepath.Join(provisioner.ScriptsDirectory, "skill-policy", "llm-wiki"),
		"-BuiltinReferenceRoot", filepath.Join(dataRoot, "data", "builtin-skills"),
	}
	if strings.Join(arguments, "\x00") != strings.Join(expected, "\x00") {
		t.Fatalf("unexpected Skill policy arguments: %#v", arguments)
	}
}

func TestAgentSwarmPolicyInvocationPrefersKimiCodeConfig(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "profile")
	modern := filepath.Join(profile, ".kimi-code", "config.toml")
	legacy := filepath.Join(profile, ".kimi", "config.toml")
	for _, path := range []string{modern, legacy} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("default_model = \"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	provisioner := EmployeeProvisioner{}
	name, arguments, err := provisioner.agentSwarmPolicyInvocation(root)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Set-KimiAgentSwarmPolicy.ps1" {
		t.Fatalf("unexpected AgentSwarm policy script: %s", name)
	}
	expected := []string{"-ConfigPath", modern, "-MaxNewAgentsPerSession", "4"}
	if strings.Join(arguments, "\x00") != strings.Join(expected, "\x00") {
		t.Fatalf("unexpected AgentSwarm policy arguments: %#v", arguments)
	}
}
