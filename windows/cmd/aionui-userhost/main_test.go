package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupCapturePersistsStageStreamsAndExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "userhost-prestart.json")
	if err := writeStartupCapture(path, startupCaptureRecord{Stage: "release_verify", Status: "failed", ExitCode: 1, Stdout: "before log", Stderr: "release failed"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record startupCaptureRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Version != 1 || record.Stage != "release_verify" || record.ExitCode != 1 || record.Stdout != "before log" || record.Stderr != "release failed" {
		t.Fatalf("capture = %+v", record)
	}
}

func TestStartupCaptureBoundsOutput(t *testing.T) {
	value := boundedStartupOutput(strings.Repeat("x", 9000))
	if len(value) > 8220 || !strings.HasSuffix(value, "[truncated]") {
		t.Fatalf("bounded output length=%d", len(value))
	}
}

func TestStartupStreamsCaptureAndDeletePrivateTemporaryFiles(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "logs", "userhost-prestart.json")
	if err := os.MkdirAll(filepath.Dir(capture), 0o700); err != nil {
		t.Fatal(err)
	}
	streams, err := startStartupStreams(capture)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(os.Stdout, "pre-log stdout")
	fmt.Fprint(os.Stderr, "pre-log stderr")
	stdout, stderr := streams.stop()
	if stdout != "pre-log stdout" || stderr != "pre-log stderr" {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
	if _, err := os.Stat(capture + ".stdout.tmp"); !os.IsNotExist(err) {
		t.Fatalf("stdout temporary file remains: %v", err)
	}
	if _, err := os.Stat(capture + ".stderr.tmp"); !os.IsNotExist(err) {
		t.Fatalf("stderr temporary file remains: %v", err)
	}
}

func TestStartupStreamsRemainMemoryBounded(t *testing.T) {
	streams, err := startStartupStreams("")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(os.Stdout, strings.Repeat("x", 32*1024))
	stdout, _ := streams.stop()
	if len(stdout) > 8220 || !strings.HasSuffix(stdout, "[truncated]") {
		t.Fatalf("bounded stdout length=%d", len(stdout))
	}
}
