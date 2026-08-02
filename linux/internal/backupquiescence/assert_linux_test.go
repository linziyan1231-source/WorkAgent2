//go:build linux

package backupquiescence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newAdmissionLayout(t *testing.T) layout {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned quiescence admission fixture requires root")
	}
	parent := filepath.Join(t.TempDir(), "workagent-backup")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return layout{journalPath: filepath.Join(parent, filepath.Base(JournalPath)), uid: 0, gid: 0}
}

func TestBackupQuiescenceAdmissionRequiresStableProtectedAbsence(t *testing.T) {
	value := newAdmissionLayout(t)
	if err := assertCleanAt(value); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(value.journalPath, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(value); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("pending backup quiescence was admitted: %v", err)
	}
}

func TestBackupQuiescenceAdmissionRejectsEveryNamedEntryKind(t *testing.T) {
	for _, name := range []string{"symlink", "directory", "fifo"} {
		t.Run(name, func(t *testing.T) {
			value := newAdmissionLayout(t)
			var err error
			switch name {
			case "symlink":
				err = os.Symlink("missing", value.journalPath)
			case "directory":
				err = os.Mkdir(value.journalPath, 0o700)
			case "fifo":
				err = os.Mkdir(value.journalPath, 0o700)
				if err == nil {
					err = os.Remove(value.journalPath)
				}
				if err == nil {
					err = syscallMkfifo(value.journalPath, 0o600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := assertCleanAt(value); err == nil {
				t.Fatalf("named %s quiescence entry was admitted", name)
			}
		})
	}
}

func TestBackupQuiescenceAdmissionRejectsUnsafeOrReplacedParent(t *testing.T) {
	value := newAdmissionLayout(t)
	if err := os.Chmod(filepath.Dir(value.journalPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := assertCleanAt(value); err == nil {
		t.Fatal("world-traversable quiescence parent was admitted")
	}

	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	value = layout{journalPath: filepath.Join(linkedParent, filepath.Base(JournalPath)), uid: 0, gid: 0}
	if err := assertCleanAt(value); err == nil {
		t.Fatal("symlinked quiescence parent was admitted")
	}
}

func TestBackupQuiescenceAdmissionRejectsForeignLayout(t *testing.T) {
	value := newAdmissionLayout(t)
	value.journalPath = filepath.Join(filepath.Dir(value.journalPath), "other.json")
	if err := assertCleanAt(value); err == nil {
		t.Fatal("foreign quiescence journal basename was admitted")
	}
}
