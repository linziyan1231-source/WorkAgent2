package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileHashVerifiesDurableBackup(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "aionui-backend.db")
	destination := filepath.Join(root, "backup", "aionui-backend.db")
	if err := os.Mkdir(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3<<20)
	for index := range data {
		data[index] = byte(index % 251)
	}
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := copyFile(source, destination)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	if hash != hex.EncodeToString(expected[:]) {
		t.Fatalf("backup hash=%s want=%x", hash, expected)
	}
	copied, err := os.ReadFile(destination)
	if err != nil || len(copied) != len(data) {
		t.Fatalf("backup copy size=%d err=%v", len(copied), err)
	}
	if _, err := copyFile(source, destination); err == nil {
		t.Fatal("existing immutable backup was overwritten")
	}
}
