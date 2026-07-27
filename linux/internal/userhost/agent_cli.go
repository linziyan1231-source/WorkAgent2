package userhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const maximumVersionOutput = 4096

type boundedVersionOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (w *boundedVersionOutput) Write(payload []byte) (int, error) {
	if len(payload) > w.limit-w.buffer.Len() {
		return 0, errors.New("version output exceeded its limit")
	}
	return w.buffer.Write(payload)
}

func (h *Host) probeAgentCLIs(parent context.Context) error {
	agents := h.cfg.Backend.AgentCLI
	if agents.BinDirectory == "" {
		if h.cfg.Backend.ActivityProbe == "aionui" {
			return errors.New("production Agent CLI runtime is not configured")
		}
		return nil
	}
	checks := []struct {
		name       string
		executable string
		expected   string
	}{
		{name: "Codex", executable: agents.CodexExecutable, expected: "codex-cli 0.144.4"},
		{name: "Kimi Code", executable: agents.KimiExecutable, expected: "0.29.1"},
		{name: "Python", executable: agents.PythonExecutable, expected: "Python 3.13.13"},
	}
	for _, check := range checks {
		ctx, cancel := context.WithTimeout(parent, time.Duration(agents.ProbeTimeoutSeconds)*time.Second)
		command := exec.CommandContext(ctx, check.executable, "--version")
		command.Dir = h.cfg.Backend.WorkingDirectory
		// Version probes are not part of the trusted AionUi/AionCore transport and
		// must never receive its bearer credential.
		command.Env = h.runtimeEnvironment("127.0.0.1:1", false)
		output := &boundedVersionOutput{limit: maximumVersionOutput}
		command.Stdout, command.Stderr = output, output
		err := command.Run()
		contextErr := ctx.Err()
		cancel()
		if contextErr != nil {
			return fmt.Errorf("%s version probe timed out", check.name)
		}
		if err != nil {
			return fmt.Errorf("%s version probe failed: %w", check.name, err)
		}
		actual := strings.TrimSpace(output.buffer.String())
		if actual != check.expected {
			return fmt.Errorf("%s reported %q instead of %q", check.name, actual, check.expected)
		}
	}
	return nil
}

var _ io.Writer = (*boundedVersionOutput)(nil)
