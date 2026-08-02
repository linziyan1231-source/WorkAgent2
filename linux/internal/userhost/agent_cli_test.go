package userhost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestProbeAgentCLIsRequiresExactPinnedVersions(t *testing.T) {
	root := t.TempDir()
	writeVersionExecutable := func(name, version string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' '"+version+"'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	host := &Host{cfg: config.Tenant{DataRoot: root, Backend: config.Backend{
		WorkingDirectory: root, ActivityProbe: "aionui",
		AgentCLI: config.AgentCLI{BinDirectory: root, CodexExecutable: writeVersionExecutable("codex", "codex-cli 0.144.4"), KimiExecutable: writeVersionExecutable("kimi", "0.29.1"), PythonExecutable: writeVersionExecutable("python3", "Python 3.13.13"), ProbeTimeoutSeconds: 5},
	}}}
	if err := host.probeAgentCLIs(context.Background()); err != nil {
		t.Fatalf("exact Agent CLI versions rejected: %v", err)
	}
	host.cfg.Backend.AgentCLI.KimiExecutable = writeVersionExecutable("kimi-wrong", "0.29.0")
	if err := host.probeAgentCLIs(context.Background()); err == nil || !strings.Contains(err.Error(), "instead of") {
		t.Fatalf("wrong Agent CLI version was accepted: %v", err)
	}
}
