package systemdctl

import "testing"

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
