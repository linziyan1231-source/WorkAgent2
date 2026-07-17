package agentcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildActivateAndVerifyRealShapedAgentCLIRelease(t *testing.T) {
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
	verified, err := VerifyCurrent(root)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.CodexVersion != "0.142.5" || verified.Manifest.KimiVersion != "1.38.0" || len(verified.Manifest.Files) != 5 {
		t.Fatalf("unexpected verified release: %+v", verified.Manifest)
	}

	dependency := filepath.Join(releasePath, "kimi-tool", "Lib", "site-packages", "kimi_cli", "__main__.py")
	if err := os.WriteFile(dependency, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(root); err == nil {
		t.Fatal("tampered shared dependency passed full release verification")
	}
}

func TestCurrentPointerRejectsTraversalAndManifestMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	pointer := Pointer{FormatVersion: 1, ReleaseID: "..", ManifestSHA256: string(make([]byte, 64)),
		CodexVersion: "0.142.5", KimiVersion: "1.38.0", PythonVersion: "3.13.13"}
	data, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, CurrentName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(root); err == nil {
		t.Fatal("traversing release ID was accepted")
	}

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
	currentPath := filepath.Join(root, CurrentName)
	currentBytes, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	var current Pointer
	if err := json.Unmarshal(currentBytes, &current); err != nil {
		t.Fatal(err)
	}
	current.KimiVersion = "9.9.9"
	currentBytes, _ = json.Marshal(current)
	if err := os.WriteFile(currentPath, currentBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(root); err == nil {
		t.Fatal("pointer/manifest version mismatch was accepted")
	}
}

func TestKimiCodeBinaryBecomesCriticalWithoutChangingManifestSchema(t *testing.T) {
	root := t.TempDir()
	releaseID := "codex-0.142.5_kimi-code-0.26.0_python-3.13.13"
	releasePath := makeRelease(t, root, releaseID)
	kimiCode := filepath.Join(releasePath, filepath.FromSlash(KimiCodeRelativePath))
	if err := os.MkdirAll(filepath.Dir(kimiCode), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kimiCode, []byte("official-kimi-code"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(releasePath, releaseID, "0.142.5", "0.26.0", "3.13.13")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteManifest(releasePath, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(root, releaseID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(kimiCode); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(root); err == nil {
		t.Fatal("missing Kimi Code binary passed current release verification")
	}
}

func TestRootAndBinAreFixedSiblingsOfAionSharedRoot(t *testing.T) {
	aionReleases := filepath.Join(t.TempDir(), "AionUiWebShared", "releases")
	wantRoot := filepath.Join(filepath.Dir(filepath.Dir(aionReleases)), RootDirectoryName)
	if got := RootFromAionReleases(aionReleases); got != wantRoot {
		t.Fatalf("shared agent root = %s, want %s", got, wantRoot)
	}
	if got := BinFromAionReleases(aionReleases); got != filepath.Join(wantRoot, "bin") {
		t.Fatalf("shared agent bin = %s", got)
	}
}

func makeRelease(t *testing.T, root, releaseID string) string {
	t.Helper()
	releasePath := filepath.Join(root, "releases", releaseID)
	files := map[string]string{
		CodexRelativePath: "real-shaped-native-codex",
		"codex/vendor/x86_64-pc-windows-msvc/codex-resources/codex-windows-sandbox-setup.exe": "sandbox-helper",
		KimiRelativePath: "real-shaped-kimi-entrypoint",
		"kimi-tool/Lib/site-packages/kimi_cli/__main__.py": "def main(): pass",
		PythonRelativePath: "real-shaped-python-entrypoint",
	}
	for name, body := range files {
		path := filepath.Join(releasePath, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return releasePath
}
