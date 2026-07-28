//go:build linux

package deployassets

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type recoveryAdmissionInstallerFixture struct {
	installer   string
	source      string
	destination string
	libexec     string
}

func newRecoveryAdmissionInstallerFixture(t *testing.T) recoveryAdmissionInstallerFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact immutable helper installation metadata is root-only")
	}
	root := t.TempDir()
	control := filepath.Join(root, "control-plane")
	adminDir := filepath.Join(control, "admin")
	shareDir := filepath.Join(control, "share", "deploy", "libexec")
	libexecDir := filepath.Join(root, "libexec")
	runDir := filepath.Join(root, "run", "workagent")
	for _, directory := range []string{adminDir, shareDir, libexecDir, runDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fixture := recoveryAdmissionInstallerFixture{
		installer:   filepath.Join(adminDir, "install-recovery-activation-admission-v1"),
		source:      filepath.Join(shareDir, "workagent-recovery-activation-admission-v1"),
		destination: filepath.Join(libexecDir, "workagent-recovery-activation-admission-v1"),
		libexec:     libexecDir,
	}
	helper := repositoryFile(t, "deploy/libexec/workagent-recovery-activation-admission-v1")
	if err := os.WriteFile(fixture.source, []byte(helper), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.source, 0o555); err != nil {
		t.Fatal(err)
	}
	installLock := filepath.Join(runDir, "fixed-root-exec-v1-install.lock")
	if err := os.WriteFile(installLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(installLock, 0o600); err != nil {
		t.Fatal(err)
	}
	installer := repositoryFile(t, "scripts/install-admission-helper-v1.sh")
	installer = strings.ReplaceAll(installer, "/usr/libexec", libexecDir)
	installer = strings.ReplaceAll(installer, "/run/workagent", runDir)
	if err := os.WriteFile(fixture.installer, []byte(installer), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.installer, 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func runRecoveryAdmissionInstaller(fixture recoveryAdmissionInstallerFixture) ([]byte, error) {
	return exec.Command(fixture.installer).CombinedOutput()
}

func assertRecoveryAdmissionInstalled(t *testing.T, fixture recoveryAdmissionInstallerFixture) {
	t.Helper()
	source, err := os.ReadFile(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.ReadFile(fixture.destination)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fixture.destination)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !bytes.Equal(source, destination) || info.Mode().Perm() != 0o555 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		t.Fatalf("installed recovery admission helper is unsafe: mode=%o stat=%+v", info.Mode().Perm(), stat)
	}
}

func TestRecoveryAdmissionInstallerIsNoReplaceAndIdempotent(t *testing.T) {
	fixture := newRecoveryAdmissionInstallerFixture(t)
	if output, err := runRecoveryAdmissionInstaller(fixture); err != nil {
		t.Fatalf("initial recovery admission install failed: %v\n%s", err, output)
	}
	assertRecoveryAdmissionInstalled(t, fixture)
	if output, err := runRecoveryAdmissionInstaller(fixture); err != nil {
		t.Fatalf("idempotent recovery admission install failed: %v\n%s", err, output)
	}
	assertRecoveryAdmissionInstalled(t, fixture)

	conflicting := newRecoveryAdmissionInstallerFixture(t)
	if err := os.WriteFile(conflicting.destination, []byte("foreign\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(conflicting.destination, 0o555); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(conflicting.destination)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runRecoveryAdmissionInstaller(conflicting); err == nil {
		t.Fatalf("conflicting immutable destination was accepted: %s", output)
	}
	after, err := os.ReadFile(conflicting.destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected immutable destination was modified")
	}
}

func TestRecoveryAdmissionInstallerReconcilesCrashStates(t *testing.T) {
	t.Run("mode-0600 work inode", func(t *testing.T) {
		fixture := newRecoveryAdmissionInstallerFixture(t)
		stage := filepath.Join(fixture.libexec, ".workagent-recovery-activation-admission-v1.ABCDEFGH")
		if err := os.WriteFile(stage, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := runRecoveryAdmissionInstaller(fixture); err != nil {
			t.Fatalf("authorized work-stage recovery failed: %v\n%s", err, output)
		}
		assertRecoveryAdmissionInstalled(t, fixture)
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatalf("reconciled work inode survived: %v", err)
		}
	})

	t.Run("linked committed inode", func(t *testing.T) {
		fixture := newRecoveryAdmissionInstallerFixture(t)
		payload, err := os.ReadFile(fixture.source)
		if err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(fixture.libexec, ".workagent-recovery-activation-admission-v1.ABCDEFGH")
		if err := os.WriteFile(stage, payload, 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stage, 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(stage, fixture.destination); err != nil {
			t.Fatal(err)
		}
		if output, err := runRecoveryAdmissionInstaller(fixture); err != nil {
			t.Fatalf("linked crash-state recovery failed: %v\n%s", err, output)
		}
		assertRecoveryAdmissionInstalled(t, fixture)
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatalf("linked stage survived reconciliation: %v", err)
		}
	})
}
