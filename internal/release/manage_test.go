package release

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallActivateAndRollbackImmutableReleases(t *testing.T) {
	root := t.TempDir()
	releases := filepath.Join(root, "releases")
	current := filepath.Join(root, "current.json")
	previous := filepath.Join(root, "previous.json")
	first := makePackedSource(t, root, "source-one", "one")
	installedOne, err := Install(first, releases, "2.1.29", "v0.1.42", []string{"v0.1.42"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Activate(installedOne, current, previous); err != nil {
		t.Fatal(err)
	}
	second := makePackedSource(t, root, "source-two", "two")
	installedTwo, err := Install(second, releases, "2.1.30", "v0.1.42", []string{"v0.1.42"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Activate(installedTwo, current, previous); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyCurrent(current, releases, []string{"v0.1.42"})
	if err != nil || verified.Manifest.Version != "2.1.30" {
		t.Fatalf("activation failed: %+v %v", verified, err)
	}
	rolledBack, err := Rollback(current, previous, releases, []string{"v0.1.42"})
	if err != nil || rolledBack.Manifest.Version != "2.1.29" {
		t.Fatalf("rollback failed: %+v %v", rolledBack, err)
	}
	verified, err = VerifyCurrent(current, releases, []string{"v0.1.42"})
	if err != nil || verified.Manifest.Version != "2.1.29" {
		t.Fatalf("rolled-back current pointer failed: %+v %v", verified, err)
	}
}

func TestInstallRejectsSymlinkAndMissingBackend(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if err := os.MkdirAll(filepath.Join(missing, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(missing, "aionui-web.exe"), []byte("web"), 0o644)
	os.WriteFile(filepath.Join(missing, "package.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(missing, "static", "index.html"), []byte("index"), 0o644)
	if _, err := Install(missing, filepath.Join(root, "releases"), "2.1.29", "v0.1.42", []string{"v0.1.42"}); err == nil {
		t.Fatal("frontend-only release was installed")
	}
}

func TestExistingImmutableVersionMustMatchSuppliedSourceAndCore(t *testing.T) {
	root := t.TempDir()
	releases := filepath.Join(root, "releases")
	source := makePackedSource(t, root, "source", "one")
	if _, err := Install(source, releases, "2.1.29", "v0.1.42", []string{"v0.1.42", "v0.1.43"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(source, releases, "2.1.29", "v0.1.42", []string{"v0.1.42", "v0.1.43"}); err != nil {
		t.Fatalf("identical idempotent install failed: %v", err)
	}
	if _, err := Install(source, releases, "2.1.29", "v0.1.43", []string{"v0.1.42", "v0.1.43"}); err == nil {
		t.Fatal("existing version was accepted with a different requested AionCore version")
	}
	if err := os.WriteFile(filepath.Join(source, "static", "index.html"), []byte("changed-renderer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(source, releases, "2.1.29", "v0.1.42", []string{"v0.1.42", "v0.1.43"}); err == nil {
		t.Fatal("same version with different source bits was accepted")
	}
}

func makePackedSource(t *testing.T, root, name, marker string) string {
	t.Helper()
	source := filepath.Join(root, name)
	for path, contents := range map[string]string{
		"aionui-web.exe": marker + "-web", "package.json": `{"version":"` + marker + `"}`,
		"static/index.html": marker + "-renderer", "bundled-aioncore/win32-x64/aioncore.exe": marker + "-core",
		"workagent-builtin-assistants/assistants.json":                 `{"assistants":[]}`,
		"workagent-builtin-assistants/rules/aionui-assistant.en-US.md": "# WorkAgent AI Butler",
		"workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md": "# WorkAgent AI",
		"workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md": "# WorkAgent AI 管家",
	} {
		full := filepath.Join(source, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return source
}
