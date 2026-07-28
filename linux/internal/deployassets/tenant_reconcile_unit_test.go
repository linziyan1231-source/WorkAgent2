package deployassets

import (
	"strings"
	"testing"
)

func TestTenantConfigReconcileUnitIsExactAndBootBlocking(t *testing.T) {
	unit := repositoryFile(t, "deploy/systemd/workagent-tenant-config-reconcile.service")
	requireContains(t, unit,
		"Type=oneshot",
		"Before=workagent-tenant-catalog-ready.target",
		"ConditionFileIsExecutable=/usr/libexec/workagent-recovery-activation-admission-v1",
		"ConditionPathExists=/run/workagent/activation.lock",
		recoveryAdmissionExecStartPre,
		"ExecStartPre=+/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --scope portal --required-executable bin/workagent-admin --required-executable bin/workagent-release",
		"ExecStart=/opt/workagent/control/bin/workagent-admin reconcile-tenant-files --config /etc/workagent/portal.json",
		"ProtectSystem=strict",
		"ReadWritePaths=/run/workagent/release-config.lock /etc/workagent /etc/systemd/system /var/lib/workagent",
	)
	for _, forbidden := range []string{"RemainAfterExit=yes", "OpenFile=", "workagent-fixed-root-exec-v1", "ReadWritePaths=/run/workagent ", "ReadWritePaths=/run "} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("tenant reconciliation unit contains unsafe lifecycle/sandbox setting %q", forbidden)
		}
	}
	target := repositoryFile(t, "deploy/systemd/workagent-tenant-catalog-ready.target")
	requireContains(t, target,
		"Requires=workagent-tenant-config-reconcile.service",
		"After=workagent-tenant-config-reconcile.service",
		"ConditionFileIsExecutable=/usr/libexec/workagent-recovery-activation-admission-v1",
		"ConditionPathExists=/run/workagent/activation.lock",
	)
	if strings.Contains(target, "StopWhenUnneeded") {
		t.Fatal("tenant catalog ready target must remain a boot-lifetime latch")
	}
	portal := repositoryFile(t, "deploy/systemd/workagent-portal.service")
	requireContains(t, portal,
		"Requires=workagent-tenant-catalog-ready.target",
		"After=network-online.target workagent-tenant-catalog-ready.target",
	)
	userHost := repositoryFile(t, "deploy/systemd/workagent-userhost@.service")
	requireContains(t, userHost,
		"Requires=workagent-userhost@%i.socket mihomo.service workagent-tenant-catalog-ready.target",
		"After=network-online.target mihomo.service srv-workagent-users.mount workagent-tenant-catalog-ready.target",
	)
	socket := repositoryFile(t, "deploy/systemd/workagent-userhost@.socket")
	requireContains(t, socket,
		"Requires=workagent-tenant-catalog-ready.target",
		"After=workagent-tenant-catalog-ready.target",
	)
}
