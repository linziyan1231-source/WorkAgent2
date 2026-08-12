package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/config"
	"aionuiportal/internal/release"
	"aionuiportal/internal/userhost"
	"golang.org/x/sys/windows"
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("aionui-userhost", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "absolute path to the fixed UserHost configuration")
	startupCapture := flags.String("startup-capture", "", "absolute private pre-log startup capture path")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *configPath == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: AionUiUserHost.exe --config <absolute-path> [--startup-capture <absolute-private-path>]")
		return 2
	}
	stage := "config_load"
	cfg, err := config.LoadUserHost(*configPath)
	if err != nil {
		message := fmt.Sprintf("UserHost configuration error: %v", err)
		fmt.Fprintln(os.Stderr, message)
		return 1
	}
	release.SetIntegrityVerification(cfg.VerifyReleaseIntegrity)
	agentcli.SetIntegrityVerification(cfg.VerifyReleaseIntegrity)
	expectedCapture := filepath.Join(cfg.DataRoot, "logs", "userhost-prestart.json")
	if *startupCapture == "" {
		// Tasks registered before startup capture was added remain valid. Their
		// protected fixed configuration is the authority for the SID-private path.
		*startupCapture = expectedCapture
	} else if !strings.EqualFold(filepath.Clean(*startupCapture), filepath.Clean(expectedCapture)) {
		message := "UserHost startup capture path does not match the configured private data root"
		fmt.Fprintln(os.Stderr, message)
		return 1
	}
	stage = "config_loaded"
	if err := writeStartupCapture(*startupCapture, startupCaptureRecord{Stage: stage, Status: "running", ExitCode: -1}); err != nil {
		fmt.Fprintln(os.Stderr, "UserHost startup capture could not be initialized")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runObservedCaptured(ctx, cfg, *startupCapture, &stage)
}

func runObservedCaptured(ctx context.Context, cfg config.UserHost, startupCapture string, stage *string) (exitCode int) {
	streams, err := startStartupStreams(startupCapture)
	if err != nil {
		_ = writeStartupCapture(startupCapture, startupCaptureRecord{Stage: *stage, Status: "failed", ExitCode: 1, Stderr: "pre-log stream capture could not be initialized"})
		return 1
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			stdout, stderr := streams.stop()
			stderr = strings.TrimSpace(stderr + "\nUserHost panicked before private logging was ready")
			_ = writeStartupCapture(startupCapture, startupCaptureRecord{Stage: *stage, Status: "failed", ExitCode: 1, Stdout: stdout, Stderr: stderr})
			exitCode = 1
		} else {
			streams.stop()
		}
	}()
	observe := func(next string) {
		*stage = next
		stdout, stderr := streams.snapshot()
		if next == "private_log_ready" {
			stdout, stderr = streams.stop()
		}
		_ = writeStartupCapture(startupCapture, startupCaptureRecord{Stage: *stage, Status: "running", ExitCode: -1, Stdout: stdout, Stderr: stderr})
	}
	if err := userhost.RunObserved(ctx, cfg, observe); err != nil {
		stdout, stderr := streams.stop()
		message := fmt.Sprintf("UserHost stopped with an error: %v", err)
		stderr = strings.TrimSpace(stderr + "\n" + message)
		_ = writeStartupCapture(startupCapture, startupCaptureRecord{Stage: *stage, Status: "failed", ExitCode: 1, Stdout: stdout, Stderr: stderr})
		fmt.Fprintln(os.Stderr, message)
		return 1
	}
	stdout, stderr := streams.stop()
	_ = writeStartupCapture(startupCapture, startupCaptureRecord{Stage: "completed", Status: "complete", ExitCode: 0, Stdout: stdout, Stderr: stderr})
	return 0
}

type startupStreams struct {
	stdoutWrite *os.File
	stderrWrite *os.File
	originalOut *os.File
	originalErr *os.File
	stdout      boundedStreamCapture
	stderr      boundedStreamCapture
	stdoutDone  chan struct{}
	stderrDone  chan struct{}
	mu          sync.Mutex
	stopped     bool
}

func startStartupStreams(_ string) (*startupStreams, error) {
	streams := &startupStreams{
		originalOut: os.Stdout,
		originalErr: os.Stderr,
		stdoutDone:  make(chan struct{}),
		stderrDone:  make(chan struct{}),
	}
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		stdoutRead.Close()
		stdoutWrite.Close()
		return nil, err
	}
	streams.stdoutWrite = stdoutWrite
	streams.stderrWrite = stderrWrite
	go func() {
		_, _ = io.Copy(&streams.stdout, stdoutRead)
		_ = stdoutRead.Close()
		close(streams.stdoutDone)
	}()
	go func() {
		_, _ = io.Copy(&streams.stderr, stderrRead)
		_ = stderrRead.Close()
		close(streams.stderrDone)
	}()
	os.Stdout = stdoutWrite
	os.Stderr = stderrWrite
	return streams, nil
}

func (s *startupStreams) snapshot() (string, string) {
	return s.stdout.String(), s.stderr.String()
}

func (s *startupStreams) stop() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped {
		os.Stdout = s.originalOut
		os.Stderr = s.originalErr
		_ = s.stdoutWrite.Close()
		_ = s.stderrWrite.Close()
		<-s.stdoutDone
		<-s.stderrDone
		s.stopped = true
	}
	return s.stdout.String(), s.stderr.String()
}

type boundedStreamCapture struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (c *boundedStreamCapture) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const limit = 8192
	remaining := limit - len(c.data)
	if remaining > 0 {
		take := len(data)
		if take > remaining {
			take = remaining
		}
		c.data = append(c.data, data[:take]...)
	}
	if len(data) > remaining {
		c.truncated = true
	}
	return len(data), nil
}

func (c *boundedStreamCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := strings.TrimSpace(string(c.data))
	if c.truncated {
		value += " [truncated]"
	}
	return value
}

type startupCaptureRecord struct {
	Version   int       `json:"version"`
	Stage     string    `json:"stage"`
	Status    string    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	Stdout    string    `json:"stdout"`
	Stderr    string    `json:"stderr"`
	UpdatedAt time.Time `json:"updated_at"`
}

func writeStartupCapture(path string, record startupCaptureRecord) error {
	record.Version = 1
	record.UpdatedAt = time.Now().UTC()
	record.Stdout = boundedStartupOutput(record.Stdout)
	record.Stderr = boundedStartupOutput(record.Stderr)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := fmt.Sprintf("%s.tmp-%d-%d", path, os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(temporary)
	to, _ := windows.UTF16PtrFromString(path)
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = os.Remove(temporary)
	return lastErr
}

func boundedStartupOutput(value string) string {
	value = strings.TrimSpace(value)
	const limit = 8192
	if len(value) > limit {
		return value[:limit] + " [truncated]"
	}
	return value
}
