package projectfs

import (
	"path/filepath"
	"testing"
)

func TestValidNameFollowsWindowsDirectoryRules(t *testing.T) {
	invalid := []string{"", " ", ".", "..", "../escape", `nested\escape`, "bad:name", "trailing.", " leading", "CON", "con.txt", "LPT9.log", "line\nbreak"}
	for _, name := range invalid {
		if ValidName(name) {
			t.Fatalf("unsafe project name accepted: %q", name)
		}
	}
	for _, name := range []string{"project", "网站项目", "project.name", "CONSOLE"} {
		if !ValidName(name) {
			t.Fatalf("valid project name rejected: %q", name)
		}
	}
}

func TestNameFromPathAcceptsOnlyDirectChildren(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	valid := filepath.Join(root, "project")
	if name, ok := NameFromPath(root, valid); !ok || name != "project" {
		t.Fatalf("direct child rejected: name=%q ok=%t", name, ok)
	}
	for _, path := range []string{root, filepath.Join(root, "nested", "project"), filepath.Join(filepath.Dir(root), "sibling")} {
		if _, ok := NameFromPath(root, path); ok {
			t.Fatalf("non-child path accepted: %s", path)
		}
	}
}
