package winutil

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRestrictedPrivateTreeVerificationDoesNotEnumerateAncestors(t *testing.T) {
	const childRootEnvironment = "AIONUI_RESTRICTED_ACL_TEST_ROOT"
	if root := os.Getenv(childRootEnvironment); root != "" {
		identity, err := CurrentIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadDir(filepath.Dir(root)); !os.IsPermission(err) {
			t.Fatalf("metadata-traverse ancestor was enumerable: %v", err)
		}
		if err := VerifyTreeACL(root, PrivateTreePolicy(identity.SID)); err != nil {
			t.Fatalf("private tree verification required ancestor enumeration: %v", err)
		}
		return
	}

	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Admin || !identity.Elevated {
		t.Skip("ACL setup requires an elevated Administrators test process")
	}
	public := os.Getenv("PUBLIC")
	if public == "" {
		public = `C:\Users\Public`
	}
	container, err := os.MkdirTemp(public, "aion-private-acl-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(container)
	usersRoot := filepath.Join(container, "users")
	root := filepath.Join(usersRoot, identity.SID)
	target := filepath.Join(root, "data", "builtin-skills", "cron")
	linkDirectory := filepath.Join(root, "data", "conversations", "session", ".codex", "skills")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linkDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(linkDirectory, "cron")); err != nil {
		t.Skipf("directory symlink creation is unavailable: %v", err)
	}
	if err := ApplyTreeACL(root, PrivateTreePolicy(identity.SID)); err != nil {
		t.Fatal(err)
	}
	ancestorPolicy := ACLPolicy{OwnerSID: AdministratorsSID, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl, identity.SID: ACLTraverse,
	}}
	if err := os.MkdirAll(usersRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{container, usersRoot} {
		if err := ApplyACL(path, ancestorPolicy); err != nil {
			t.Fatal(err)
		}
	}

	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	token, err := newCurrentUserRestrictedToken(identity.SID, []*windows.SID{administratorsSID})
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestRestrictedPrivateTreeVerificationDoesNotEnumerateAncestors$")
	command.Env = append(os.Environ(), childRootEnvironment+"="+root)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	if err := token.Apply(command); err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("restricted private ACL verification failed: %v\n%s", err, output)
	}
	if len(output) == 0 {
		t.Log(fmt.Sprintf("restricted private ACL verification passed for %s", root))
	}
}

func TestRestrictedTokenAllowsOwnTreeAndDeniesAdministratorOnlyACL(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Admin || !identity.Elevated {
		t.Skip("ACL setup requires an elevated Administrators test process")
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	token, err := newCurrentUserRestrictedToken(identity.SID, []*windows.SID{administratorsSID})
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()

	root := t.TempDir()
	allowed := filepath.Join(root, "allowed.txt")
	deniedRoot := filepath.Join(root, "administrator-only")
	denied := filepath.Join(deniedRoot, "denied.txt")
	script := filepath.Join(root, "probe.cmd")
	if err := os.Mkdir(deniedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowed, []byte("allowed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denied, []byte("denied"), 0600); err != nil {
		t.Fatal(err)
	}
	probe := `@echo off
ping.exe -n 2 127.0.0.1 >nul
type "%~1" >nul
if errorlevel 1 exit /b 10
type "%~2" >nul 2>&1
if not errorlevel 1 exit /b 11
exit /b 0
`
	if err := os.WriteFile(script, []byte(probe), 0600); err != nil {
		t.Fatal(err)
	}
	administratorOnly := ACLPolicy{OwnerSID: AdministratorsSID, Principals: map[string]ACLPermission{
		SystemSID: ACLFullControl, AdministratorsSID: ACLFullControl,
	}}
	if err := ApplyTreeACL(deniedRoot, administratorOnly); err != nil {
		t.Fatal(err)
	}

	commandShell := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	command := exec.Command(commandShell, "/d", "/c", script, allowed, denied)
	command.Dir = root
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	if err := token.Apply(command); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := token.VerifyProcess(uint32(command.Process.Pid), identity.SID); err != nil {
		command.Process.Kill()
		command.Wait()
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("restricted access probe failed: %v (%s)", err, output.String())
	}
}
