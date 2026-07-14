package cliproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"

	"aionuiportal/internal/modelbootstrap"
)

const maxSSHOutput = 256 * 1024

var (
	sshTargetPattern  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9.-]{1,253}$`)
	helperPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,240}$`)
	plainKeyPattern   = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	secretTextPattern = regexp.MustCompile(`cpa_[A-Za-z0-9_-]+`)
)

type Client struct {
	SSHTarget  string
	HelperPath string
	Executable string
}

type ProvisionOptions struct {
	Username          string
	WindowsSID        string
	BaseURL           string
	CodexDefaultModel string
	CodexModels       []string
	KimiModels        []string
	RPM               int
	CodexDailyUSD     float64
	CodexWeeklyUSD    float64
	KimiDailyUSD      float64
	KimiWeeklyUSD     float64
}

type request struct {
	Version int          `json:"version"`
	Keys    []requestKey `json:"keys"`
}

type requestKey struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	RPM                 int      `json:"rpm"`
	Aliases             []string `json:"aliases"`
	DailyLimitUSD       float64  `json:"daily_limit_usd"`
	WeeklyLimitUSD      float64  `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool     `json:"allow_models_endpoint"`
}

type response struct {
	Version int           `json:"version"`
	Keys    []responseKey `json:"keys"`
}

type responseKey struct {
	ID       string `json:"id"`
	PlainKey string `json:"plain_key"`
	Action   string `json:"action"`
}

func (c Client) Provision(ctx context.Context, options ProvisionOptions) (modelbootstrap.Bundle, error) {
	state, err := stateFor(options)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	if !sshTargetPattern.MatchString(c.SSHTarget) {
		return modelbootstrap.Bundle{}, errors.New("CLIProxyAPI SSH target is invalid")
	}
	if !helperPathPattern.MatchString(c.HelperPath) || strings.Contains(c.HelperPath, "..") {
		return modelbootstrap.Bundle{}, errors.New("CLIProxyAPI remote helper path is invalid")
	}
	executable := c.Executable
	if executable == "" {
		executable = "ssh.exe"
	}
	payload := provisionRequest(options, state)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	command := exec.CommandContext(ctx, executable, "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", c.SSHTarget, c.HelperPath, "provision")
	command.Stdin = bytes.NewReader(encoded)
	stdout, stderr := &cappedBuffer{limit: maxSSHOutput}, &cappedBuffer{limit: 16 * 1024}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		message := redact(strings.TrimSpace(stderr.String()))
		if message == "" {
			message = "remote helper failed without a diagnostic"
		}
		return modelbootstrap.Bundle{}, fmt.Errorf("provision CLIProxyAPI employee keys: %s", message)
	}
	if stdout.overflow {
		return modelbootstrap.Bundle{}, errors.New("CLIProxyAPI provision response exceeded the output limit")
	}
	parsed, err := parseResponse(stdout.Bytes(), state)
	if err != nil {
		return modelbootstrap.Bundle{}, err
	}
	bundle := modelbootstrap.Bundle{State: state, CodexAPIKey: parsed[state.CodexKeyID], KimiAPIKey: parsed[state.KimiKeyID]}
	if err := bundle.Validate(); err != nil {
		return modelbootstrap.Bundle{}, fmt.Errorf("validate CLIProxyAPI provision result: %w", err)
	}
	return bundle, nil
}

func provisionRequest(options ProvisionOptions, state modelbootstrap.State) request {
	return request{Version: 1, Keys: []requestKey{
		{ID: state.CodexKeyID, Name: options.Username + " / ChatGPT-Codex", Enabled: true, RPM: options.RPM, Aliases: append([]string(nil), state.CodexModels...), DailyLimitUSD: options.CodexDailyUSD, WeeklyLimitUSD: options.CodexWeeklyUSD, AllowModelsEndpoint: true},
		{ID: state.KimiKeyID, Name: options.Username + " / Kimi", Enabled: true, RPM: options.RPM, Aliases: append([]string(nil), state.KimiModels...), DailyLimitUSD: options.KimiDailyUSD, WeeklyLimitUSD: options.KimiWeeklyUSD, AllowModelsEndpoint: true},
	}}
}

func stateFor(options ProvisionOptions) (modelbootstrap.State, error) {
	if strings.TrimSpace(options.Username) == "" || len(options.Username) > 64 || strings.ContainsAny(options.Username, "\r\n") {
		return modelbootstrap.State{}, errors.New("Portal username is invalid for CLIProxyAPI provisioning")
	}
	if options.RPM < 0 || options.RPM > 100000 || options.CodexDailyUSD <= 0 || options.CodexWeeklyUSD != options.CodexDailyUSD*2 || options.KimiDailyUSD <= 0 || options.KimiWeeklyUSD != options.KimiDailyUSD*2 {
		return modelbootstrap.State{}, errors.New("CLIProxyAPI quota policy is invalid")
	}
	digest := sha256.Sum256([]byte(strings.ToUpper(options.WindowsSID)))
	prefix := "aionui-" + hex.EncodeToString(digest[:10])
	state := modelbootstrap.State{FormatVersion: modelbootstrap.FormatVersion, BaseURL: options.BaseURL,
		CodexKeyID: prefix + "-chatgpt", KimiKeyID: prefix + "-kimi", CodexDefaultModel: options.CodexDefaultModel,
		CodexModels: append([]string(nil), options.CodexModels...), KimiModels: append([]string(nil), options.KimiModels...)}
	if err := state.Validate(); err != nil {
		return modelbootstrap.State{}, err
	}
	return state, nil
}

func parseResponse(data []byte, state modelbootstrap.State) (map[string]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response response
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("CLIProxyAPI provision response was invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || response.Version != 1 || len(response.Keys) != 2 {
		return nil, errors.New("CLIProxyAPI provision response had an unsupported shape")
	}
	expected := map[string]bool{state.CodexKeyID: true, state.KimiKeyID: true}
	result := make(map[string]string, 2)
	for _, key := range response.Keys {
		if !expected[key.ID] || result[key.ID] != "" || !plainKeyPattern.MatchString(key.PlainKey) || (key.Action != "created" && key.Action != "rotated") {
			return nil, errors.New("CLIProxyAPI provision response contained an invalid key result")
		}
		result[key.ID] = key.PlainKey
	}
	if len(result) != 2 || result[state.CodexKeyID] == result[state.KimiKeyID] {
		return nil, errors.New("CLIProxyAPI provision response did not contain two unique employee keys")
	}
	return result, nil
}

func redact(value string) string {
	value = secretTextPattern.ReplaceAllString(value, "<redacted-key>")
	value = strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 32 && r != 127) {
			return r
		}
		return ' '
	}, value)
	if len(value) > 1000 {
		value = value[:1000]
	}
	return strings.TrimSpace(value)
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.buffer.Write(data)
	}
	if original > remaining {
		b.overflow = true
	}
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *cappedBuffer) String() string { return b.buffer.String() }
