package edgepublication

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssertCleanAtRequiresProtectedParentsAndExactAbsence(t *testing.T) {
	root := t.TempDir()
	journalParent := filepath.Join(root, "journal")
	permitParent := filepath.Join(root, "permit")
	for _, parent := range []string{journalParent, permitParent} {
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	journal := filepath.Join(journalParent, "publication.json")
	permit := filepath.Join(permitParent, "publication.permit")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := assertCleanAt(journal, permit, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(journal, permit, uid, gid); err == nil {
		t.Fatal("pending journal was accepted by the ordinary-writer gate")
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", permit); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(journal, permit, uid, gid); err == nil {
		t.Fatal("dangling permit symlink was accepted as absence")
	}
	if err := os.Remove(permit); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(permitParent, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(journal, permit, uid, gid); err == nil {
		t.Fatal("group-writable permit parent was accepted")
	}
}
