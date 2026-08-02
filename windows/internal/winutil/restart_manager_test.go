package winutil

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestTerminateFileUsersStopsOnlyConfirmedFileHolder(t *testing.T) {
	if os.Getenv("AIONUI_RESTART_MANAGER_HOLDER") == "1" {
		restartManagerHolder()
		return
	}
	root := t.TempDir()
	path := filepath.Join(root, "locked.txt")
	if err := os.WriteFile(path, []byte("production-shaped project file"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=TestTerminateFileUsersStopsOnlyConfirmedFileHolder")
	command.Env = append(os.Environ(), "AIONUI_RESTART_MANAGER_HOLDER=1", "AIONUI_RESTART_MANAGER_FILE="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatalf("file holder did not start: %q err=%v", scanner.Text(), scanner.Err())
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	terminated, err := TerminateFileUsers(root, user.User.Sid.String(), map[uint32]bool{uint32(os.Getpid()): true})
	if err != nil {
		t.Fatal(err)
	}
	if len(terminated) != 1 || terminated[0] != uint32(command.Process.Pid) {
		t.Fatalf("terminated processes=%v, want holder pid %d", terminated, command.Process.Pid)
	}
	_ = command.Wait()
	if err := os.Rename(root, root+"-renamed"); err != nil {
		t.Fatalf("project remained locked after termination: %v", err)
	}
}

func restartManagerHolder() {
	path := os.Getenv("AIONUI_RESTART_MANAGER_FILE")
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		os.Exit(2)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		os.Exit(3)
	}
	defer windows.CloseHandle(handle)
	fmt.Println("ready")
	time.Sleep(30 * time.Second)
}
