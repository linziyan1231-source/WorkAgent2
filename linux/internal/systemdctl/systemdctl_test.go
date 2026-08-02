package systemdctl

import (
	"os"
	"path/filepath"
	"context"
	"testing"
)

func TestUnitValidationIsFailClosed(t *testing.T) {
	for _, value := range []string{
		"workagent-portal.service",
		"workagent-backup.service",
		"workagent-backup.timer",
		"workagent-healthcheck.service",
		"workagent-healthcheck.timer",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-tenant-config-reconcile.service",
		"workagent-tenant-catalog-ready.target",
		"cliproxyapi.service",
		"caddy.service",
		"mihomo.service",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.service",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.socket",
	} {
		if !validUnit(value) {
			t.Fatalf("valid unit rejected: %s", value)
		}
	}
	for _, value := range []string{
		"ssh.service",
		"workagent-userhost@../x.service",
		"workagent-userhost@.service",
		"workagent-userhost@------------------------------------.service",
		"workagent-userhost@111111111111111111111111111111111111.socket",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.timer",
	} {
		if validUnit(value) {
			t.Fatalf("unsafe unit accepted: %s", value)
		}
	}
}

func TestNonblockingActionIsRestrictedToExactGuardedCaddyStart(t *testing.T) {
	client := Client{Command: "/bin/true"}
	if err := client.Action(context.Background(), "start", "--no-block", "caddy.service"); err != nil {
		t.Fatalf("exact guarded Caddy start was rejected: %v", err)
	}
	for _, arguments := range [][]string{
		{"stop", "--no-block", "caddy.service"},
		{"restart", "--no-block", "caddy.service"},
		{"enable", "--no-block", "caddy.service"},
		{"start", "--no-block", "--no-block", "caddy.service"},
		{"start", "caddy.service", "--no-block"},
		{"start", "--no-block", "caddy.service", "workagent-portal.service"},
		{"start", "--no-block", "workagent-portal.service"},
	} {
		if err := client.Action(context.Background(), arguments...); err == nil {
			t.Fatalf("unsafe nonblocking action was accepted: %v", arguments)
		}
	}
}

func TestPropertiesJoinsRepeatedExecRecordsAndDefaultsOmitted(t *testing.T) {
	script := filepath.Join(t.TempDir(), "systemctl")
	payload := "#!/bin/sh\nprintf '%s\\n' 'ExecStartPre={ one }' 'ExecStartPre={ two }' 'LoadState=loaded'\n"
	if err := os.WriteFile(script, []byte(payload), 0o755); err != nil {
		t.Fatal(err)
	}
	client := Client{Command: script}
	properties, err := client.Properties(context.Background(), "workagent-portal.service", "LoadState", "ExecStartPre", "ExecReload")
	if err != nil {
		t.Fatal(err)
	}
	if properties["ExecStartPre"] != "{ one } ; { two }" || properties["LoadState"] != "loaded" {
		t.Fatalf("repeated Exec records were not joined: %#v", properties)
	}
	if value, ok := properties["ExecReload"]; !ok || value != "" {
		t.Fatalf("omitted property did not default to empty: %#v", properties)
	}
}
