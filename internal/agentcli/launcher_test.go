package agentcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherSpecsUseStablePointerAndPreserveArguments(t *testing.T) {
	root := t.TempDir()
	releaseID := "codex-0.142.5_kimi-1.38.0_python-3.13.13"
	releasePath := makeRelease(t, root, releaseID)
	manifest, err := BuildManifest(releasePath, releaseID, "0.142.5", "1.38.0", "3.13.13")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManifest(releasePath, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(root, releaseID); err != nil {
		t.Fatal(err)
	}

	arguments := []string{"exec", "--json", `C:\work with spaces`}
	environment := []string{`Path=C:\Windows\System32`, `CODEX_HOME=C:\Users\user-87eba76e\AionUiPortal\config\codex`}
	codex, err := Spec(filepath.Join(root, "bin", "codex.exe"), arguments, environment)
	if err != nil {
		t.Fatal(err)
	}
	if codex.Target != filepath.Join(releasePath, filepath.FromSlash(CodexRelativePath)) || strings.Join(codex.Args, "|") != strings.Join(arguments, "|") {
		t.Fatalf("unexpected Codex launcher spec: %+v", codex)
	}
	if !strings.HasPrefix(environmentValue(codex.Env, "PATH"), filepath.Join(releasePath, "codex", "vendor", "x86_64-pc-windows-msvc", "codex-path")+string(os.PathListSeparator)) {
		t.Fatalf("Codex support PATH was not prepended: %s", environmentValue(codex.Env, "PATH"))
	}
	if environmentValue(codex.Env, "CODEX_HOME") != `C:\Users\user-87eba76e\AionUiPortal\config\codex` {
		t.Fatal("per-user CODEX_HOME was overwritten")
	}

	kimi, err := Spec(filepath.Join(root, "bin", "kimi.exe"), []string{"--version"}, environment)
	if err != nil {
		t.Fatal(err)
	}
	if kimi.Target != filepath.Join(releasePath, filepath.FromSlash(KimiRelativePath)) || environmentValue(kimi.Env, "PYTHONDONTWRITEBYTECODE") != "1" {
		t.Fatalf("unexpected Kimi launcher spec: %+v", kimi)
	}
	if _, err := Spec(filepath.Join(root, "bin", "unknown.exe"), nil, environment); err == nil {
		t.Fatal("unknown launcher name was accepted")
	}
}

func TestPrependPathIsCaseInsensitiveAndIdempotent(t *testing.T) {
	directory := `C:\Program Files\AionAgentCliShared\bin`
	environment := []string{`Path=C:\Windows;C:\PROGRAM FILES\AIONAGENTCLISHARED\BIN`}
	updated := PrependPath(environment, directory)
	if got := environmentValue(updated, "PATH"); got != `C:\Windows;C:\PROGRAM FILES\AIONAGENTCLISHARED\BIN` {
		t.Fatalf("existing PATH entry was duplicated: %s", got)
	}
}
