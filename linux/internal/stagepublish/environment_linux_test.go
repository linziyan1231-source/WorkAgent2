//go:build linux

package stagepublish

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedAccountExecutablesUseFixedValidatedPaths(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	wanted := map[string]string{
		"useradd": "/usr/sbin/useradd",
		"usermod": "/usr/sbin/usermod",
		"passwd":  "/usr/bin/passwd",
	}
	for name, expected := range wanted {
		path, err := protectedAccountExecutable(name)
		if err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
		if path != expected || !filepath.IsAbs(path) {
			t.Fatalf("%s resolved to %q, want %q", name, path, expected)
		}
	}
	if _, err := protectedAccountExecutable("sh"); err == nil {
		t.Fatal("non-allowlisted account command was accepted")
	}
}

func TestValidatedCLIProxyLockRequiresExact0640Contract(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership fixture requires root")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cliproxy-migration.lock")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireValidatedCLIProxyLock(path, 65534)
	if err != nil {
		t.Fatalf("exact 0640 lock rejected: %v", err)
	}
	if _, err := acquireValidatedCLIProxyLock(path, 65534); err == nil {
		t.Fatal("concurrent exclusive lock acquisition succeeded")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireValidatedCLIProxyLock(path, 65534); err == nil {
		t.Fatal("legacy 0660 lock mode was accepted")
	}
}
