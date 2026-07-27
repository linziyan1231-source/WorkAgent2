//go:build linux

package stagepublish

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

type stoppedController struct {
	override map[string]map[string]string
	seen     map[string]bool
}

func TestValidateTenantDropInNamespaceUsesExactTopLevelAllowlist(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production systemd ownership fixture requires root")
	}
	tenantID := "11111111-1111-4111-8111-111111111111"
	wanted := map[string]bool{tenantID + ".json": true}
	for _, attack := range []struct {
		name    string
		regular bool
	}{
		{name: "workagent-userhost@" + tenantID + ".socket.d"},
		{name: "workagent-userhost@.service.d"},
		{name: "workagent-userhost@-.service.d"},
		{name: "workagent-userhost@" + tenantID + ".service", regular: true},
		{name: "workagent-userhost@" + tenantID + ".service.wants"},
		{name: "workagent-userhost@" + tenantID + ".service.requires"},
	} {
		t.Run(attack.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, attack.name)
			if attack.regular {
				if err := os.WriteFile(path, []byte("[Unit]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			r := runner{layout: layout{systemdRoot: root}}
			if err := r.validateTenantDropInNamespace(wanted); err == nil {
				t.Fatalf("unexpected UserHost top-level entry %q was accepted", attack.name)
			}
		})
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, template := range []string{"workagent-userhost@.service", "workagent-userhost@.socket"} {
		if err := os.WriteFile(filepath.Join(root, template), []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	approved := filepath.Join(root, "workagent-userhost@"+tenantID+".service.d")
	if err := os.Mkdir(approved, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, child := range []string{"identity.conf", "resources.conf"} {
		if err := os.WriteFile(filepath.Join(approved, child), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := runner{layout: layout{systemdRoot: root}}
	if err := r.validateTenantDropInNamespace(wanted); err != nil {
		t.Fatalf("canonical service drop-in was rejected: %v", err)
	}
}

func (c *stoppedController) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	if c.seen == nil {
		c.seen = make(map[string]bool)
	}
	c.seen[unit] = true
	if value, ok := c.override[unit]; ok {
		return value, nil
	}
	unitFileState := "disabled"
	if unit == "workagent-backup.service" || unit == "workagent-healthcheck.service" || unit == "workagent-tenant-catalog-ready.target" || unit == "workagent-tenant-config-reconcile.service" ||
		(strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service")) {
		unitFileState = "static"
	}
	return map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "UnitFileState": unitFileState}, nil
}
func (*stoppedController) Action(context.Context, ...string) error {
	return errors.New("unexpected action")
}

func TestRequireUnitsStoppedIncludesEveryDiscoveredAndReportedInstance(t *testing.T) {
	tenantID := "11111111-1111-4111-8111-111111111111"
	otherID := "22222222-2222-4222-8222-222222222222"
	verified := winmigration.PublicationStage{Report: winmigration.Report{Tenants: []winmigration.TenantReport{{TenantID: tenantID}}}}
	controller := &stoppedController{}
	discovered := []string{"workagent-userhost@" + otherID + ".socket", "workagent-userhost@" + otherID + ".service"}
	if err := requireUnitsStopped(context.Background(), controller, verified, discovered); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"caddy.service", "cliproxyapi.service", "workagent-portal.service", "workagent-tenant-catalog-ready.target", "workagent-tenant-config-reconcile.service", "workagent-userhost@" + tenantID + ".socket", "workagent-userhost@" + otherID + ".service"} {
		if !controller.seen[required] {
			t.Fatalf("required unit %s was not checked", required)
		}
	}
	controller.override = map[string]map[string]string{
		"workagent-userhost@" + otherID + ".service": {"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "99", "ControlPID": "0", "UnitFileState": "static"},
	}
	if err := requireUnitsStopped(context.Background(), controller, verified, discovered); err == nil {
		t.Fatal("active discovered UserHost instance was accepted")
	}
	controller.override = map[string]map[string]string{
		"workagent-portal.service": {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "UnitFileState": "enabled"},
	}
	if err := requireUnitsStopped(context.Background(), controller, verified, discovered); err == nil {
		t.Fatal("enabled future boot entrypoint was accepted")
	}
}

func TestOptionsRequireExplicitApplyConfirmation(t *testing.T) {
	for _, options := range []Options{
		{}, {Check: true, Apply: true}, {Apply: true}, {Apply: true, Confirm: "almost"}, {Check: true, Confirm: ConfirmPublication},
	} {
		if err := options.validate(); err == nil {
			t.Fatalf("unsafe options accepted: %+v", options)
		}
	}
	if err := (Options{Check: true}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Options{Apply: true, Confirm: ConfirmPublication}).validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConvergeTenantQuotaRecoversKillAfterChownBeforeQuota(t *testing.T) {
	assigned := 0
	if err := convergeTenantQuota(
		false,
		func() error { return errors.New("quota was not assigned before the crash") },
		func() (bool, error) { return true, nil },
		func() error { assigned++; return nil },
	); err != nil {
		t.Fatal(err)
	}
	if assigned != 1 {
		t.Fatalf("quota assignments=%d, want 1", assigned)
	}

	assigned = 0
	existingErr := errors.New("existing quota conflicts")
	err := convergeTenantQuota(
		false,
		func() error { return existingErr },
		func() (bool, error) { return false, nil },
		func() error { assigned++; return nil },
	)
	if !errors.Is(err, existingErr) || assigned != 0 {
		t.Fatalf("populated conflicting directory was not rejected: err=%v assignments=%d", err, assigned)
	}

	assigned = 0
	if err := convergeTenantQuota(
		true,
		func() error { return errors.New("must not verify a new directory") },
		func() (bool, error) { return false, errors.New("must not inspect a new directory") },
		func() error { assigned++; return nil },
	); err != nil || assigned != 1 {
		t.Fatalf("new directory quota convergence: err=%v assignments=%d", err, assigned)
	}
}
