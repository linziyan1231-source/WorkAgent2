package winutil

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

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
