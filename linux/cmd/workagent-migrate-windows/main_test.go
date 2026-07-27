//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestParseArgumentsRequiresFrozenCaptureBindingInputs(t *testing.T) {
	base := []string{
		"--snapshot-root", "/private/workagent/capture-20260728",
		"--staging-dir", "/private/workagent/linux-staging",
		"--external-workspace-manifest", "/private/workagent/capture-20260728/external-workspaces.json",
	}
	if _, err := parseArguments(base); err == nil || !strings.Contains(err.Error(), "--capture-spec is required") {
		t.Fatalf("missing --capture-spec error = %v", err)
	}

	arguments := append(append([]string(nil), base...),
		"--capture-spec", "/private/workagent/final-capture/capture-spec.json",
		"--dry-run",
	)
	options, err := parseArguments(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if options.CaptureSpec != "/private/workagent/final-capture/capture-spec.json" ||
		options.SnapshotRoot != "/private/workagent/capture-20260728" || !options.DryRun {
		t.Fatalf("capture arguments were not preserved: %+v", options)
	}

	wrongManifest := append([]string(nil), arguments...)
	wrongManifest[5] = "/private/workagent/capture-20260728/another.json"
	if _, err := parseArguments(wrongManifest); err == nil || !strings.Contains(err.Error(), "exactly <snapshot-root>/external-workspaces.json") {
		t.Fatalf("detached external manifest error = %v", err)
	}
}
