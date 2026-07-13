package winutil

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestWhoamiMatchesNativeCurrentTokenSID(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWhoamiSID(context.Background(), identity.SID); err != nil {
		t.Fatal(err)
	}
}

func TestJobObjectContainsAndKillsAssignedProcess(t *testing.T) {
	job, err := NewJob("AionUiPortal-Test-"+time.Now().Format("150405.000000"), JobLimits{MemoryBytes: 512 * 1024 * 1024, CPUPercent: 50, ActiveProcesses: 5})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Wait-Event")
	if err := cmd.Start(); err != nil {
		job.Close()
		t.Fatal(err)
	}
	if err := job.AssignPID(uint32(cmd.Process.Pid)); err != nil {
		cmd.Process.Kill()
		job.Close()
		t.Fatal(err)
	}
	inside, err := job.ContainsPID(uint32(cmd.Process.Pid))
	if err != nil || !inside {
		cmd.Process.Kill()
		job.Close()
		t.Fatalf("assigned process not in job: inside=%v err=%v", inside, err)
	}
	stats, err := job.Stats()
	if err != nil || stats.ProcessCount < 1 {
		cmd.Process.Kill()
		job.Close()
		t.Fatalf("invalid job stats: %+v err=%v", stats, err)
	}
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("KILL_ON_JOB_CLOSE did not terminate assigned process")
	}
}

func TestVerifyLoopbackListenerUsesKernelOwnerTable(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := VerifyLoopbackListener(uint32(os.Getpid()), port); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLoopbackListener(uint32(os.Getpid()+1), port); err == nil {
		t.Fatal("listener accepted for wrong PID")
	}
}

func TestCPUPercent(t *testing.T) {
	previous := JobStats{CPUTime100ns: 10_000_000}
	current := JobStats{CPUTime100ns: 15_000_000}
	if got := CPUPercent(previous, current, time.Second); got != 50 {
		t.Fatalf("CPU percent=%v, want 50", got)
	}
}
