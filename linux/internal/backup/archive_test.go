package backup

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedArchiveVerifyRestoreAndTamperDetection(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("tenant state fixture")
	if err := os.WriteFile(filepath.Join(source, "nested", "state.db"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nested/state.db", filepath.Join(source, "current")); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	created, err := CreateArchive(&encrypted, key, CreateInput{
		PortalConfig: "/etc/workagent/portal.json",
		Sources:      []Source{{Name: "fixture", Path: source}},
		Now:          time.Unix(1_800_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyArchive(bytes.NewReader(encrypted.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	if verified.BackupID != created.BackupID || len(verified.Entries) != 4 {
		t.Fatalf("unexpected verified manifest: %+v", verified)
	}
	restoreParent := t.TempDir()
	restoreTarget := filepath.Join(restoreParent, "restored")
	if _, err := RestoreArchive(bytes.NewReader(encrypted.Bytes()), key, restoreTarget); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRestoredFiles(restoreTarget, created, false); err != nil {
		t.Fatalf("exact restored tree was not resumable: %v", err)
	}
	restoredFile := filepath.Join(restoreTarget, stringsWithoutLeadingSlash(source), "nested", "state.db")
	got, err := os.ReadFile(restoredFile)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("restored payload mismatch: %q err=%v", got, err)
	}
	target, err := os.Readlink(filepath.Join(restoreTarget, stringsWithoutLeadingSlash(source), "current"))
	if err != nil || target != "nested/state.db" {
		t.Fatalf("restored link mismatch: %q err=%v", target, err)
	}
	extra := filepath.Join(restoreTarget, "unexpected")
	if err := os.WriteFile(extra, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRestoredFiles(restoreTarget, created, false); err == nil {
		t.Fatal("existing restore with an extra entry was accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restoredFile, []byte("tampered state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRestoredFiles(restoreTarget, created, false); err == nil {
		t.Fatal("existing restore with changed bytes was accepted")
	}
	tampered := append([]byte(nil), encrypted.Bytes()...)
	tampered[len(tampered)/2] ^= 0x80
	if _, err := VerifyArchive(bytes.NewReader(tampered), key); err == nil {
		t.Fatal("tampered encrypted archive was accepted")
	}
	if _, err := VerifyArchive(bytes.NewReader(encrypted.Bytes()[:len(encrypted.Bytes())-1]), key); err == nil {
		t.Fatal("truncated encrypted archive was accepted")
	}
}

func TestBackupKeyProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.key")
	if err := GenerateKey(path); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKey(path, false)
	if err != nil || len(key) != keySize {
		t.Fatalf("generated key could not be loaded: len=%d err=%v", len(key), err)
	}
	clear(key)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path, false); err == nil {
		t.Fatal("world-readable backup key was accepted")
	}
}

func stringsWithoutLeadingSlash(path string) string {
	for len(path) > 0 && path[0] == filepath.Separator {
		path = path[1:]
	}
	return path
}
