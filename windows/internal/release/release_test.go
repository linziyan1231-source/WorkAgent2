package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func makeRelease(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "releases")
	version := "2.1.29"
	dir := filepath.Join(root, version)
	for name, body := range map[string]string{
		"aionui-web.exe": "web-binary", "package.json": `{"version":"2.1.29"}`,
		"static/index.html": "<html></html>", "bundled-aioncore/win32-x64/aioncore.exe": "core-binary",
		"static/assets/app.js":                                     "console.log('release')",
		"workagent-builtin-assistants/assistants.json":                 `{"assistants":[]}`,
		"workagent-builtin-assistants/rules/aionui-assistant.en-US.md": "# WorkAgent AI Butler",
		"workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md": "# WorkAgent AI",
		"workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md": "# WorkAgent AI 管家",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := BuildManifest(dir, version, "v0.1.42")
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := WriteManifest(filepath.Join(dir, ManifestName), m)
	if err != nil {
		t.Fatal(err)
	}
	pointer := Pointer{FormatVersion: 1, Version: version, ReleasePath: dir, ManifestSHA256: manifestHash}
	b, _ := json.Marshal(pointer)
	pointerPath := filepath.Join(filepath.Dir(root), "current.json")
	if err := os.WriteFile(pointerPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, pointerPath
}

func TestVerifyCurrentFastChecksProtectedMetadataAndCriticalShape(t *testing.T) {
	root, pointer := makeRelease(t)
	verified, err := VerifyCurrentFast(pointer, root, []string{"v0.1.42"})
	if err != nil || verified.Manifest.Version != "2.1.29" {
		t.Fatalf("valid fast verification failed: %+v %v", verified, err)
	}
	if err := os.Remove(filepath.Join(root, "2.1.29", "aionui-web.exe")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrentFast(pointer, root, []string{"v0.1.42"}); err == nil {
		t.Fatal("fast verification accepted a missing critical file")
	}
}

func TestVerifyCurrentFastDefersNonCriticalContentHashingToFullGate(t *testing.T) {
	root, pointer := makeRelease(t)
	asset := filepath.Join(root, "2.1.29", "static", "assets", "app.js")
	if err := os.WriteFile(asset, []byte("console.log('changed')"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrentFast(pointer, root, []string{"v0.1.42"}); err != nil {
		t.Fatalf("fast verification unexpectedly reread a noncritical asset: %v", err)
	}
	if _, err := VerifyCurrent(pointer, root, []string{"v0.1.42"}); err == nil {
		t.Fatal("full deployment gate accepted tampered noncritical content")
	}
}

func TestVerifyCurrentDetectsFileTampering(t *testing.T) {
	root, pointer := makeRelease(t)
	verified, err := VerifyCurrent(pointer, root, []string{"v0.1.42"})
	if err != nil || verified.Manifest.Version != "2.1.29" {
		t.Fatalf("valid release failed: %+v %v", verified, err)
	}
	if err := os.WriteFile(filepath.Join(root, "2.1.29", "static", "index.html"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(pointer, root, []string{"v0.1.42"}); err == nil {
		t.Fatal("tampered release verified")
	}
}

func TestPointerCannotEscapeReleaseRoot(t *testing.T) {
	root, pointer := makeRelease(t)
	b, _ := os.ReadFile(pointer)
	var p Pointer
	json.Unmarshal(b, &p)
	p.ReleasePath = filepath.Dir(root)
	manifestBytes, _ := os.ReadFile(filepath.Join(root, "2.1.29", ManifestName))
	sum := sha256.Sum256(manifestBytes)
	p.ManifestSHA256 = hex.EncodeToString(sum[:])
	b, _ = json.Marshal(p)
	os.WriteFile(pointer, b, 0o644)
	if _, err := VerifyCurrent(pointer, root, []string{"v0.1.42"}); err == nil {
		t.Fatal("escaping release pointer verified")
	}
}
