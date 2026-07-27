package systemdctl

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Controller interface {
	Properties(context.Context, string, ...string) (map[string]string, error)
	Action(context.Context, ...string) error
}

// UnitLister is implemented by the production client for privileged gates
// that must discover every loaded tenant instance, including an instance that
// is not present in the current migration report.
type UnitLister interface {
	ListUnits(context.Context, ...string) ([]string, error)
}

type Client struct {
	Command string
	Timeout time.Duration
}

func Default() Client {
	return Client{Command: "/usr/bin/systemctl", Timeout: 2 * time.Minute}
}

func (c Client) Properties(ctx context.Context, unit string, names ...string) (map[string]string, error) {
	if !validUnit(unit) || len(names) == 0 || len(names) > 32 {
		return nil, errors.New("systemd property request is invalid")
	}
	arguments := []string{"show"}
	for _, name := range names {
		if !validProperty(name) {
			return nil, errors.New("systemd property name is invalid")
		}
		arguments = append(arguments, "--property="+name)
	}
	arguments = append(arguments, unit)
	output, err := c.run(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	properties := make(map[string]string, len(names))
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || !validProperty(name) {
			return nil, errors.New("systemd returned malformed properties")
		}
		properties[name] = value
	}
	for _, name := range names {
		if _, ok := properties[name]; !ok {
			return nil, fmt.Errorf("systemd omitted property %s", name)
		}
	}
	return properties, nil
}

func (c Client) Action(ctx context.Context, arguments ...string) error {
	if len(arguments) < 1 || len(arguments) > 64 {
		return errors.New("systemd action is invalid")
	}
	switch arguments[0] {
	case "daemon-reload", "enable", "disable", "start", "stop", "restart", "reset-failed":
	default:
		return errors.New("systemd action is not permitted")
	}
	if arguments[0] == "daemon-reload" {
		if len(arguments) != 1 {
			return errors.New("systemd daemon-reload does not accept units")
		}
		_, err := c.run(ctx, arguments...)
		return err
	}
	if len(arguments) < 2 {
		return errors.New("systemd action requires a unit")
	}
	for _, argument := range arguments[1:] {
		if strings.HasPrefix(argument, "--") {
			if argument != "--now" {
				return errors.New("systemd action option is not permitted")
			}
			continue
		}
		if !validUnit(argument) {
			return errors.New("systemd action unit is invalid")
		}
	}
	_, err := c.run(ctx, arguments...)
	return err
}

func (c Client) ListUnits(ctx context.Context, patterns ...string) ([]string, error) {
	if len(patterns) == 0 || len(patterns) > 8 {
		return nil, errors.New("systemd unit-list request is invalid")
	}
	for _, pattern := range patterns {
		if pattern != "workagent-userhost@*.service" && pattern != "workagent-userhost@*.socket" {
			return nil, errors.New("systemd unit-list pattern is not permitted")
		}
	}
	arguments := []string{"list-units", "--all", "--plain", "--no-legend", "--no-pager"}
	arguments = append(arguments, patterns...)
	output, err := c.run(ctx, arguments...)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var units []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		if unit == "●" && len(fields) > 1 {
			unit = fields[1]
		} else {
			unit = strings.TrimPrefix(unit, "●")
		}
		if !validUnit(unit) || seen[unit] {
			return nil, errors.New("systemd returned an invalid or duplicate tenant unit")
		}
		seen[unit] = true
		units = append(units, unit)
	}
	return units, nil
}

func (c Client) run(ctx context.Context, arguments ...string) (string, error) {
	commandName := c.Command
	if commandName == "" {
		commandName = "/usr/bin/systemctl"
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 2 * time.Minute
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(commandContext, commandName, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl %s failed: %w: %s", arguments[0], err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func validUnit(value string) bool {
	switch value {
	case "workagent-portal.service", "workagent-backup.service", "workagent-backup.timer", "workagent-healthcheck.service", "workagent-healthcheck.timer",
		"workagent-notification.service", "workagent-chatforward.service", "workagent-chatforward-browser.service", "cliproxyapi.service", "caddy.service", "mihomo.service":
		return true
	}
	for _, suffix := range []string{".service", ".socket"} {
		if strings.HasPrefix(value, "workagent-userhost@") && strings.HasSuffix(value, suffix) {
			identity := strings.TrimSuffix(strings.TrimPrefix(value, "workagent-userhost@"), suffix)
			parsed, err := uuid.Parse(identity)
			return err == nil && parsed.String() == identity
		}
	}
	return false
}

func validProperty(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}
