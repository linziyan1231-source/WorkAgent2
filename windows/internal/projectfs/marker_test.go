package projectfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectMarkerIsStableAcrossRename(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := EnsureMarker(source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureMarker(source)
	if err != nil || second.ProjectID != first.ProjectID {
		t.Fatalf("marker was not idempotent: first=%+v second=%+v err=%v", first, second, err)
	}
	if err := os.Rename(source, target); err != nil {
		t.Fatal(err)
	}
	renamed, err := ReadMarker(target)
	if err != nil || renamed.ProjectID != first.ProjectID {
		t.Fatalf("project id changed after rename: first=%+v renamed=%+v err=%v", first, renamed, err)
	}
}

func TestProjectMarkerRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"project_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(project, MarkerFileName)); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := ReadMarker(project); err == nil {
		t.Fatal("symlink project marker was accepted")
	}
}
