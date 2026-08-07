package userhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveManagedSharedSkillLinksRemovesOnlyReparseEntries(t *testing.T) {
	root := t.TempDir()
	skills := filepath.Join(root, ".codex", "skills")
	source := filepath.Join(t.TempDir(), "source-skill")
	if err := os.MkdirAll(skills, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(skills, "regular-skill")
	if err := os.MkdirAll(regular, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(skills, "linked-skill")
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}

	if err := removeManagedSharedSkillLinks(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed skill link still exists: %v", err)
	}
	if info, err := os.Stat(regular); err != nil || !info.IsDir() {
		t.Fatalf("regular skill directory was changed: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("skill source was changed: info=%v err=%v", info, err)
	}
}

func TestRemoveManagedSharedSkillLinksRejectsReparseParent(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	linkedSkill := filepath.Join(external, "skills", "linked-skill")
	if err := os.MkdirAll(linkedSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, ".kimi")); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}

	err := removeManagedSharedSkillLinks(root)
	if err == nil || !strings.Contains(err.Error(), "parent must be a normal directory") {
		t.Fatalf("reparse parent was not rejected: %v", err)
	}
	if info, statErr := os.Stat(linkedSkill); statErr != nil || !info.IsDir() {
		t.Fatalf("external skill was changed: info=%v err=%v", info, statErr)
	}
}

func TestNormalizeSharedRelativePathUsesStableProjectID(t *testing.T) {
	projectID := strings.Repeat("a", 32)
	for _, test := range []struct {
		name  string
		value string
		want  string
		ok    bool
	}{
		{name: "root", value: "shared://" + projectID, want: "", ok: true},
		{name: "child", value: "shared://" + projectID + "/docs/readme.md", want: "docs/readme.md", ok: true},
		{name: "other project", value: "shared://" + strings.Repeat("b", 32) + "/secret", ok: false},
		{name: "traversal", value: "shared://" + projectID + "/../secret", ok: false},
		{name: "windows absolute", value: `C:\Users\other\secret`, ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeSharedRelativePath(projectID, test.value)
			if (err == nil) != test.ok || (err == nil && got != test.want) {
				t.Fatalf("normalizeSharedRelativePath() = %q, %v; want %q, ok=%v", got, err, test.want, test.ok)
			}
		})
	}
}

func TestSanitizeSharedFileJSONNeverExposesHostPath(t *testing.T) {
	root := filepath.Join(`C:\Data`, "shared", "S-1-5-21-1", strings.Repeat("a", 32))
	raw, _ := json.Marshal(map[string]any{
		"path": `\\?\` + filepath.Join(root, "docs", "readme.md"),
		"name": "readme.md",
	})
	stable := "shared://" + strings.Repeat("a", 32)
	got, err := sanitizeSharedFileJSON(raw, root, stable)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(got)), strings.ToLower(root)) || !strings.Contains(string(got), stable+"/docs/readme.md") {
		t.Fatalf("sanitized response leaked or lost the stable path: %s", got)
	}
	outside, _ := json.Marshal(map[string]any{"path": `C:\Data\shared\S-1-5-21-2\secret.txt`})
	if _, err := sanitizeSharedFileJSON(outside, root, stable); err == nil {
		t.Fatal("expected an outside absolute path to fail closed")
	}
}

func TestFilterSharedDirReparseEntriesSkipsLinks(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "notes.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(target, "linked")); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	raw := json.RawMessage(`[{"name":"notes.txt","type":"file"},{"name":"linked","type":"directory"}]`)

	filtered, err := filterSharedDirReparseEntries(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if string(filtered) != `[{"name":"notes.txt","type":"file"}]` {
		t.Fatalf("unexpected filtered response: %s", filtered)
	}
}

func TestWriteSharedCopyNoticeIsIdempotent(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "AGENTS.md"), []byte("# Existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := `C:\Data\shared\S-1-5-21-1\project`
	if err := writeSharedCopyNotice(source, target); err != nil {
		t.Fatal(err)
	}
	if err := writeSharedCopyNotice(source, target); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(source, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), "## Shared project copy") != 1 || !strings.Contains(string(contents), target) {
		t.Fatalf("unexpected AGENTS.md: %s", contents)
	}
}

func TestValidRuntimeConversationID(t *testing.T) {
	if !validRuntimeConversationID("abcDEF12_-") {
		t.Fatal("expected bounded stable id to be accepted")
	}
	for _, value := range []string{"short", "../../escape", "contains space", strings.Repeat("a", 129)} {
		if validRuntimeConversationID(value) {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
