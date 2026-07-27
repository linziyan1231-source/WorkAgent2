//go:build linux

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

type recoveryGateController struct {
	values map[string]map[string]string
	err    error
}

func (controller recoveryGateController) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	if controller.err != nil {
		return nil, controller.err
	}
	return controller.values[unit], nil
}

func (recoveryGateController) Action(context.Context, ...string) error { return nil }

type recordingRecoveryController struct {
	values  map[string]map[string]string
	actions [][]string
	errAt   string
}

type recoveryTenantLister struct {
	recoveryGateController
	units []string
	err   error
}

func TestRecoveryTenantReadbackUsesCanonicalJSONEquality(t *testing.T) {
	expected := config.Tenant{Backend: config.Backend{Environment: map[string]string{}, RequiredReleaseFiles: []string{}}}
	payload, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var installed config.Tenant
	if err := json.Unmarshal(payload, &installed); err != nil {
		t.Fatal(err)
	}
	if !admin.CanonicalTenantConfigEqual(installed, expected) {
		t.Fatal("recovery rejected a canonical omitempty round trip")
	}
}

func (controller recoveryTenantLister) ListUnits(context.Context, ...string) ([]string, error) {
	return append([]string(nil), controller.units...), controller.err
}

func TestRecoveryActivationJournalIsPersistent(t *testing.T) {
	if recoveryInstallLockPath != "/run/workagent-backup/recovery-install.lock" {
		t.Fatalf("unexpected ephemeral install-lock path %q", recoveryInstallLockPath)
	}
	if recoveryActivationJournalPath != "/var/lib/workagent-backup/recovery-activation.json" || strings.HasPrefix(recoveryActivationJournalPath, "/run/") {
		t.Fatalf("activation journal is not power-loss durable: %q", recoveryActivationJournalPath)
	}
}

func TestRecoveryRejectsUnexpectedLoadedTenantUnits(t *testing.T) {
	first := "11111111-1111-4111-8111-111111111111"
	second := "22222222-2222-4222-8222-222222222222"
	tenants := []config.Tenant{{TenantID: first}}
	controller := recoveryTenantLister{units: []string{
		"workagent-userhost@" + first + ".socket",
		"workagent-userhost@" + first + ".service",
	}}
	if err := requireExactRecoveryTenantUnits(context.Background(), controller, tenants); err != nil {
		t.Fatalf("expected loaded tenant units were rejected: %v", err)
	}
	controller.units = append(controller.units, "workagent-userhost@"+second+".service")
	if err := requireExactRecoveryTenantUnits(context.Background(), controller, tenants); err == nil {
		t.Fatal("foreign loaded tenant unit was accepted")
	}
	controller.units = []string{"workagent-userhost@" + first + ".socket", "workagent-userhost@" + first + ".socket"}
	if err := requireExactRecoveryTenantUnits(context.Background(), controller, tenants); err == nil {
		t.Fatal("duplicate loaded tenant unit was accepted")
	}
	controller.units = []string{"workagent-userhost@" + first + ".socket"}
	if err := requireExactRecoveryTenantUnits(context.Background(), controller, tenants); err == nil {
		t.Fatal("tenant-unit enumeration missing the expected service was accepted")
	}
}

func (controller *recordingRecoveryController) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	return controller.values[unit], nil
}

func (controller *recordingRecoveryController) Action(_ context.Context, arguments ...string) error {
	copy := append([]string(nil), arguments...)
	controller.actions = append(controller.actions, copy)
	if len(arguments) > 0 && arguments[0] == controller.errAt {
		return errors.New("injected systemd failure")
	}
	return nil
}

func stoppedRecoveryProperties() map[string]string {
	return map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "UnitFileState": "disabled"}
}

func TestRequireRecoveryUnitFileState(t *testing.T) {
	controller := recoveryGateController{values: map[string]map[string]string{
		"cliproxyapi.service": {"LoadState": "loaded", "UnitFileState": "disabled"},
		"workagent-userhost@11111111-1111-4111-8111-111111111111.service": {"LoadState": "loaded", "UnitFileState": "static"},
	}}
	if err := requireRecoveryUnitFileState(context.Background(), controller, []string{"cliproxyapi.service"}, "disabled"); err != nil {
		t.Fatalf("disabled unit rejected: %v", err)
	}
	if err := requireRecoveryUnitFileState(context.Background(), controller, []string{"workagent-userhost@11111111-1111-4111-8111-111111111111.service"}, "static"); err != nil {
		t.Fatalf("static unit rejected: %v", err)
	}
	for name, values := range map[string]map[string]string{
		"enabled":  {"LoadState": "loaded", "UnitFileState": "enabled"},
		"missing":  {"LoadState": "loaded"},
		"unloaded": {"LoadState": "not-found", "UnitFileState": "disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := recoveryGateController{values: map[string]map[string]string{"cliproxyapi.service": values}}
			if err := requireRecoveryUnitFileState(context.Background(), bad, []string{"cliproxyapi.service"}, "disabled"); err == nil {
				t.Fatal("unsafe unit-file state was accepted")
			}
		})
	}
	if err := requireRecoveryUnitFileState(context.Background(), controller, []string{"cliproxyapi.service", "cliproxyapi.service"}, "disabled"); err == nil {
		t.Fatal("duplicate unit-file-state proof input was accepted")
	}
	if err := requireRecoveryUnitFileState(context.Background(), controller, []string{"cliproxyapi.service"}, "masked"); err == nil {
		t.Fatal("unsupported expected unit-file state was accepted")
	}
}

func TestRequireRecoveryUnitsStopped(t *testing.T) {
	controller := recoveryGateController{values: map[string]map[string]string{
		"cliproxyapi.service":      stoppedRecoveryProperties(),
		"workagent-portal.service": stoppedRecoveryProperties(),
	}}
	units := []string{"cliproxyapi.service", "workagent-portal.service"}
	if err := requireRecoveryUnitsStopped(context.Background(), controller, units); err != nil {
		t.Fatalf("stopped units rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"active": func(value map[string]string) {
			value["ActiveState"], value["SubState"], value["MainPID"] = "active", "running", "42"
		},
		"starting": func(value map[string]string) {
			value["ActiveState"], value["SubState"], value["ControlPID"] = "activating", "start", "43"
		},
		"failed":        func(value map[string]string) { value["ActiveState"], value["SubState"] = "failed", "failed" },
		"malformed pid": func(value map[string]string) { value["MainPID"] = "not-a-pid" },
	} {
		t.Run(name, func(t *testing.T) {
			value := stoppedRecoveryProperties()
			mutate(value)
			bad := recoveryGateController{values: map[string]map[string]string{"cliproxyapi.service": value}}
			if err := requireRecoveryUnitsStopped(context.Background(), bad, []string{"cliproxyapi.service"}); err == nil {
				t.Fatal("unsafe systemd state was accepted")
			}
		})
	}
	if err := requireRecoveryUnitsStopped(context.Background(), recoveryGateController{err: errors.New("systemd unavailable")}, units); err == nil {
		t.Fatal("systemd inspection failure was accepted")
	}
}

func TestRequireRecoveryUnitRunning(t *testing.T) {
	running := map[string]string{"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42", "ControlPID": "0"}
	for _, unit := range []string{"cliproxyapi.service", "workagent-portal.service"} {
		controller := recoveryGateController{values: map[string]map[string]string{unit: running}}
		if err := requireRecoveryUnitRunning(context.Background(), controller, unit); err != nil {
			t.Fatalf("running %s rejected: %v", unit, err)
		}
	}
	for name, mutate := range map[string]func(map[string]string){
		"unloaded": func(value map[string]string) { value["LoadState"] = "not-found" },
		"inactive": func(value map[string]string) {
			value["ActiveState"], value["SubState"], value["MainPID"] = "inactive", "dead", "0"
		},
		"control active": func(value map[string]string) { value["ControlPID"] = "43" },
		"malformed pid":  func(value map[string]string) { value["MainPID"] = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			value := make(map[string]string, len(running))
			for key, item := range running {
				value[key] = item
			}
			mutate(value)
			controller := recoveryGateController{values: map[string]map[string]string{"workagent-portal.service": value}}
			if err := requireRecoveryUnitRunning(context.Background(), controller, "workagent-portal.service"); err == nil {
				t.Fatal("unsafe running state was accepted")
			}
		})
	}
	if err := requireRecoveryUnitRunning(context.Background(), recoveryGateController{err: errors.New("systemd unavailable")}, "cliproxyapi.service"); err == nil {
		t.Fatal("systemd inspection failure was accepted")
	}
	if err := requireRecoveryUnitRunning(context.Background(), recoveryGateController{}, "unknown.service"); err == nil {
		t.Fatal("unexpected recovery unit was accepted")
	}
}

func TestCLIProxyPolicySourceEligibleOnlyAtCanonicalPath(t *testing.T) {
	allowed := map[string]string{"cliproxy-policy-state": "/var/lib/cliproxyapi/policy/cpa-key-policy-state.json"}
	if !eligibleForBlankHostInstall(Source{Name: "cliproxy-policy-state", Path: allowed["cliproxy-policy-state"]}, allowed) {
		t.Fatal("canonical CLIProxy policy state was rejected")
	}
	for _, source := range []Source{
		{Name: "cliproxy-policy-state", Path: "/var/lib/cliproxyapi/auth/provider.json"},
		{Name: "cliproxy-auth", Path: "/var/lib/cliproxyapi/auth"},
	} {
		if eligibleForBlankHostInstall(source, allowed) {
			t.Fatalf("unsafe CLIProxy recovery source was accepted: %+v", source)
		}
	}
}

func TestRecoveryActivationJournalAndRollbackOrder(t *testing.T) {
	first := "workagent-userhost@11111111-1111-4111-8111-111111111111.socket"
	second := "workagent-userhost@22222222-2222-4222-8222-222222222222.socket"
	firstService := strings.TrimSuffix(first, ".socket") + ".service"
	secondService := strings.TrimSuffix(second, ".socket") + ".service"
	value, err := activationJournalForUnits([]string{
		"workagent-tenant-catalog-ready.target", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service",
		second, first, "workagent-chatforward-browser.service", "workagent-portal.service",
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedUnits := []string{
		"workagent-tenant-catalog-ready.target", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service",
		firstService, secondService, first, second, "workagent-chatforward-browser.service", "workagent-portal.service",
	}
	if strings.Join(value.Units, ",") != strings.Join(expectedUnits, ",") {
		t.Fatalf("activation units were not canonicalized: %v", value.Units)
	}
	values := make(map[string]map[string]string, len(value.Units))
	for _, unit := range value.Units {
		values[unit] = stoppedRecoveryProperties()
	}
	values["workagent-tenant-config-reconcile.service"] = stoppedRecoveryProperties()
	values["workagent-tenant-config-reconcile.service"]["UnitFileState"] = "static"
	values[firstService]["UnitFileState"] = "static"
	values[secondService]["UnitFileState"] = "static"
	values["workagent-tenant-catalog-ready.target"]["UnitFileState"] = "static"
	controller := &recordingRecoveryController{values: values}
	if err := stopRecoveryActivationUnits(controller, value); err != nil {
		t.Fatal(err)
	}
	expectedActions := [][]string{
		{"disable", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", first, second, "workagent-chatforward-browser.service", "workagent-portal.service"},
		{"stop", "workagent-portal.service"},
		{"stop", "workagent-chatforward-browser.service"},
		{"stop", second},
		{"stop", first},
		{"stop", secondService},
		{"stop", firstService},
		{"stop", "workagent-chatforward.service"},
		{"stop", "workagent-notification.service"},
		{"stop", "cliproxyapi.service"},
		{"stop", "workagent-tenant-catalog-ready.target"},
		{"stop", "workagent-tenant-config-reconcile.service"},
	}
	if len(controller.actions) != len(expectedActions) {
		t.Fatalf("rollback actions=%v", controller.actions)
	}
	for index := range expectedActions {
		if strings.Join(controller.actions[index], ",") != strings.Join(expectedActions[index], ",") {
			t.Fatalf("rollback action %d=%v expected=%v", index, controller.actions[index], expectedActions[index])
		}
	}
	for _, invalid := range []recoveryActivationJournal{
		{SchemaVersion: 1, Units: []string{"workagent-portal.service", "cliproxyapi.service"}},
		{SchemaVersion: 1, Units: []string{"workagent-tenant-catalog-ready.target", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", "ssh.service", "workagent-chatforward-browser.service", "workagent-portal.service"}},
		{SchemaVersion: 1, Units: []string{"workagent-tenant-catalog-ready.target", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", secondService, firstService, second, first, "workagent-chatforward-browser.service", "workagent-portal.service"}},
		{SchemaVersion: 1, Units: []string{"workagent-tenant-catalog-ready.target", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", firstService, second, "workagent-chatforward-browser.service", "workagent-portal.service"}},
	} {
		if err := validateRecoveryActivationJournal(invalid); err == nil {
			t.Fatalf("unsafe activation journal accepted: %+v", invalid)
		}
	}
}

func TestKnownActivationRollbackRetainsJournalUntilStopProofSucceeds(t *testing.T) {
	value := recoveryActivationJournal{SchemaVersion: 1, Units: []string{
		"workagent-tenant-catalog-ready.target",
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
	}}
	values := make(map[string]map[string]string, len(value.Units))
	for _, unit := range value.Units {
		values[unit] = stoppedRecoveryProperties()
	}
	values["workagent-tenant-config-reconcile.service"] = stoppedRecoveryProperties()
	values["workagent-tenant-config-reconcile.service"]["UnitFileState"] = "static"
	values["workagent-tenant-catalog-ready.target"]["UnitFileState"] = "static"
	loaded, removed := false, false
	controller := &recordingRecoveryController{values: values, errAt: "disable"}
	err := rollbackKnownRecoveryActivationWithIO(
		controller,
		value,
		recoveryActivationJournalPath,
		func(string) (recoveryActivationJournal, bool, error) {
			loaded = true
			return value, true, nil
		},
		func(string) error {
			removed = true
			return nil
		},
	)
	if err == nil {
		t.Fatal("failed activation rollback was accepted")
	}
	if loaded || removed {
		t.Fatalf("durable activation journal was inspected or removed after an incomplete stop proof: loaded=%t removed=%t", loaded, removed)
	}

	// A successful `systemctl disable` exit is insufficient if the durable
	// unit-file state still reads enabled. The journal must remain for a later
	// retry in exactly the same way as a stop/readiness failure.
	loaded, removed = false, false
	values["cliproxyapi.service"]["UnitFileState"] = "enabled"
	controller = &recordingRecoveryController{values: values}
	err = rollbackKnownRecoveryActivationWithIO(
		controller,
		value,
		recoveryActivationJournalPath,
		func(string) (recoveryActivationJournal, bool, error) {
			loaded = true
			return value, true, nil
		},
		func(string) error {
			removed = true
			return nil
		},
	)
	if err == nil || loaded || removed {
		t.Fatalf("enabled unit-file readback did not retain the activation journal: err=%v loaded=%t removed=%t", err, loaded, removed)
	}
	values["cliproxyapi.service"]["UnitFileState"] = "disabled"

	controller = &recordingRecoveryController{values: values}
	err = rollbackKnownRecoveryActivationWithIO(
		controller,
		value,
		recoveryActivationJournalPath,
		func(string) (recoveryActivationJournal, bool, error) { return recoveryActivationJournal{}, false, nil },
		func(string) error {
			removed = true
			return nil
		},
	)
	if err == nil || removed {
		t.Fatalf("missing activation journal was accepted or removed: err=%v removed=%t", err, removed)
	}

	controller = &recordingRecoveryController{values: values}
	err = rollbackKnownRecoveryActivationWithIO(
		controller,
		value,
		recoveryActivationJournalPath,
		func(string) (recoveryActivationJournal, bool, error) { return value, true, nil },
		func(path string) error {
			if path != recoveryActivationJournalPath {
				t.Fatalf("unexpected activation journal path %q", path)
			}
			removed = true
			return nil
		},
	)
	if err != nil || !removed {
		t.Fatalf("completed activation rollback did not remove its journal: err=%v removed=%t", err, removed)
	}
}

func TestRecoveryRollbackRetainsJournalUntilPulledInReconcileStops(t *testing.T) {
	value := recoveryActivationJournal{SchemaVersion: 1, Units: []string{
		"workagent-tenant-catalog-ready.target",
		"cliproxyapi.service",
		"workagent-notification.service",
		"workagent-chatforward.service",
		"workagent-chatforward-browser.service",
		"workagent-portal.service",
	}}
	values := make(map[string]map[string]string, len(value.Units)+1)
	for _, unit := range value.Units {
		values[unit] = stoppedRecoveryProperties()
	}
	values["workagent-tenant-catalog-ready.target"]["UnitFileState"] = "static"
	values["workagent-tenant-config-reconcile.service"] = map[string]string{
		"LoadState": "loaded", "ActiveState": "activating", "SubState": "start", "MainPID": "123", "ControlPID": "0", "UnitFileState": "static",
	}
	loaded, removed := false, false
	controller := &recordingRecoveryController{values: values}
	err := rollbackKnownRecoveryActivationWithIO(
		controller, value, recoveryActivationJournalPath,
		func(string) (recoveryActivationJournal, bool, error) {
			loaded = true
			return value, true, nil
		},
		func(string) error {
			removed = true
			return nil
		},
	)
	if err == nil || loaded || removed {
		t.Fatalf("running pulled-in reconciliation did not retain recovery journal: err=%v loaded=%t removed=%t", err, loaded, removed)
	}
	last := controller.actions[len(controller.actions)-1]
	if strings.Join(last, ",") != "stop,workagent-tenant-config-reconcile.service" {
		t.Fatalf("rollback did not explicitly stop the pulled-in reconciliation unit: %v", controller.actions)
	}
}

func TestRecoverySystemdBulkActionIsBounded(t *testing.T) {
	units := make([]string, 130)
	for index := range units {
		units[index] = "workagent-portal.service"
	}
	controller := &recordingRecoveryController{}
	if err := recoverySystemdActionUnits(context.Background(), controller, "enable", units); err != nil {
		t.Fatal(err)
	}
	if len(controller.actions) != 3 || len(controller.actions[0]) != 64 || len(controller.actions[1]) != 64 || len(controller.actions[2]) != 5 {
		t.Fatalf("bulk systemd action was not bounded: %v", controller.actions)
	}
}

func TestAcquireRecoveredPortalLockAcceptsOnlyAuthenticatedCrashOwners(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership crash-window coverage requires root")
	}
	root := t.TempDir()
	portalRoot := filepath.Join(root, "portal")
	first := recoveredIdentity{uid: 12345, gid: 12345}
	second := recoveredIdentity{uid: 12346, gid: 12346}
	if err := os.Mkdir(portalRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(portalRoot, int(first.uid), int(first.gid)); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(portalRoot, ".runtime.lock")
	created, err := acquireRecoveredPortalLock(lockPath, []recoveredIdentity{first, second})
	if err != nil {
		t.Fatalf("package-owned missing lock was not safely created: %v", err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(lockPath, int(second.uid), int(second.gid)); err != nil {
		t.Fatal(err)
	}
	mixed, err := acquireRecoveredPortalLock(lockPath, []recoveredIdentity{first, second})
	if err != nil {
		t.Fatalf("authenticated parent/lock crash-owner mix was rejected: %v", err)
	}
	if _, err := acquireRecoveredPortalLock(lockPath, []recoveredIdentity{first, second}); err == nil {
		t.Fatal("concurrent Portal recovery lock was accepted")
	}
	if err := mixed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(lockPath, 12347, 12347); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRecoveredPortalLock(lockPath, []recoveredIdentity{first, second}); err == nil {
		t.Fatal("foreign Portal recovery lock owner was accepted")
	}
}

func TestRecoveredConfigurationGroupMappingsRejectAmbiguity(t *testing.T) {
	mappings := map[uint32]uint32{}
	if err := addRecoveredGroupMapping(mappings, 1001, 2001); err != nil {
		t.Fatal(err)
	}
	if err := addRecoveredGroupMapping(mappings, 1001, 2001); err != nil {
		t.Fatalf("idempotent group mapping was rejected: %v", err)
	}
	if err := addRecoveredGroupMapping(mappings, 1002, 2002); err != nil {
		t.Fatal(err)
	}
	if err := addRecoveredGroupMapping(mappings, 1001, 2999); err == nil {
		t.Fatal("ambiguous archived GID was accepted")
	}
}

func recoveryRegularStat(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("regular-file stat unavailable")
	}
	copy := *stat
	return &copy
}

func TestCopyRecoveredRegularFileCrashSafeCases(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("recovered production file ownership requires root")
	}
	for name, payload := range map[string][]byte{"nonempty": []byte("restored state"), "empty": {}} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
			if err := os.WriteFile(source, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := copyRecoveredRegularFile(source, destination, recoveryRegularStat(t, source), 0o600, false); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(destination)
			if err != nil || string(actual) != string(payload) {
				t.Fatalf("destination mismatch: %q err=%v", actual, err)
			}
			if err := copyRecoveredRegularFile(source, destination, recoveryRegularStat(t, source), 0o600, true); err != nil {
				t.Fatalf("identical existing destination was not resumable: %v", err)
			}
		})
	}

	t.Run("concurrent destination", func(t *testing.T) {
		root := t.TempDir()
		source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
		if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := copyRecoveredRegularFile(source, destination, recoveryRegularStat(t, source), 0o600, false)
		if err == nil || !strings.Contains(err.Error(), "appeared concurrently") {
			t.Fatalf("concurrent destination was not rejected: %v", err)
		}
		actual, readErr := os.ReadFile(destination)
		if readErr != nil || string(actual) != "foreign" {
			t.Fatalf("foreign destination changed: %q err=%v", actual, readErr)
		}
	})

	t.Run("source drift", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		if err := os.WriteFile(source, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
		expected := recoveryRegularStat(t, source)
		if err := os.WriteFile(source, []byte("after-longer"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := copyRecoveredRegularFile(source, filepath.Join(root, "destination"), expected, 0o600, false); err == nil {
			t.Fatal("source drift was accepted")
		}
	})

	t.Run("unsupported destination filesystem", func(t *testing.T) {
		if _, err := os.Stat("/proc"); err != nil {
			t.Skip("procfs unavailable")
		}
		root := t.TempDir()
		source := filepath.Join(root, "source")
		if err := os.WriteFile(source, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
		destination := "/proc/workagent-recovery-atomic-test"
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Skip("fixed procfs test path unexpectedly exists")
		}
		if err := copyRecoveredRegularFile(source, destination, recoveryRegularStat(t, source), 0o600, false); err == nil {
			t.Fatal("filesystem without writable O_TMPFILE support was accepted")
		}
	})
}

func TestCopyRecoveredRegularFileFailsClosedAsUnprivilegedOwner(t *testing.T) {
	if os.Getenv("WORKAGENT_RECOVERY_NONROOT_HELPER") == "1" {
		source, destination := os.Getenv("WORKAGENT_RECOVERY_SOURCE"), os.Getenv("WORKAGENT_RECOVERY_DESTINATION")
		if err := copyRecoveredRegularFile(source, destination, recoveryRegularStat(t, source), 0o600, false); err == nil {
			t.Fatal("unprivileged recovery copy unexpectedly published a destination")
		}
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed unprivileged copy left a destination: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("credential-drop coverage requires a root test runner")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("nobody account unavailable")
	}
	uid, uidErr := strconv.ParseUint(nobody.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(nobody.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		t.Skip("nobody identity invalid")
	}
	root := t.TempDir()
	if err := os.Chmod(filepath.Dir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "owned")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(work, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	source, destination := filepath.Join(work, "source"), filepath.Join(work, "destination")
	if err := os.WriteFile(source, []byte("unprivileged state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(source, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(root, "recovery-test-helper")
	input, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	outputFile, err := os.OpenFile(helperPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		input.Close()
		t.Fatal(err)
	}
	if err := outputFile.Chmod(0o755); err != nil {
		input.Close()
		outputFile.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(outputFile, input)
	syncErr := outputFile.Sync()
	closeOutputErr := outputFile.Close()
	closeInputErr := input.Close()
	if err := errors.Join(copyErr, syncErr, closeOutputErr, closeInputErr); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helperPath, "-test.run=^TestCopyRecoveredRegularFileFailsClosedAsUnprivilegedOwner$")
	command.Env = append(os.Environ(), "WORKAGENT_RECOVERY_NONROOT_HELPER=1", "WORKAGENT_RECOVERY_SOURCE="+source, "WORKAGENT_RECOVERY_DESTINATION="+destination)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged recovery copy failed: %v: %s", err, output)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unprivileged recovery attempt left a destination: %v", err)
	}
}
