//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/coreactivation"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/serviceaction"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

type coreActivationSystemd struct {
	states               map[string]map[string]string
	actions              [][]string
	invocations          int
	skipReconcile        bool
	preserveFailedOnStop map[string]bool
}

func (controller *coreActivationSystemd) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	state, ok := controller.states[unit]
	if !ok {
		return nil, errors.New("unexpected core unit")
	}
	return cloneCoreProperties(state), nil
}

func (controller *coreActivationSystemd) Action(_ context.Context, arguments ...string) error {
	controller.actions = append(controller.actions, append([]string(nil), arguments...))
	if len(arguments) == 0 {
		return errors.New("empty core action")
	}
	if arguments[0] == "daemon-reload" {
		return nil
	}
	unit := arguments[len(arguments)-1]
	state, ok := controller.states[unit]
	if !ok {
		return errors.New("unexpected core action unit")
	}
	switch arguments[0] {
	case "enable":
		state["UnitFileState"] = "enabled"
	case "disable":
		state["UnitFileState"] = "disabled"
		if !controller.preserveFailedOnStop[unit] {
			setCoreInactive(state)
		}
	case "stop":
		if !controller.preserveFailedOnStop[unit] {
			setCoreInactive(state)
		}
	case "reset-failed":
		setCoreInactive(state)
	case "start":
		if strings.HasSuffix(unit, ".timer") {
			state["ActiveState"], state["SubState"] = "active", "waiting"
			if target, ok := serviceaction.TimerTargetService(unit); ok {
				targetState := controller.states[target]
				targetState["ActiveState"], targetState["SubState"] = "activating", "start"
				targetState["MainPID"], targetState["ControlPID"] = "4242", "0"
			}
		} else if strings.HasSuffix(unit, ".target") {
			if reconcile := controller.states["workagent-tenant-config-reconcile.service"]; reconcile != nil {
				controller.invocations++
				setCoreInactive(reconcile)
				reconcile["InvocationID"] = fmt.Sprintf("fresh-%d", controller.invocations)
				reconcile["ExecMainStartTimestampMonotonic"] = fmt.Sprintf("%d", controller.invocations+100)
				reconcile["ExecMainExitTimestampMonotonic"] = fmt.Sprintf("%d", controller.invocations+101)
				reconcile["ExecMainCode"], reconcile["ExecMainStatus"] = "1", "0"
				reconcile["ConditionResult"] = map[bool]string{true: "no", false: "yes"}[controller.skipReconcile]
			}
			state["ActiveState"], state["SubState"] = "active", "active"
		} else {
			state["ActiveState"], state["SubState"] = "active", "running"
			state["MainPID"], state["ControlPID"], state["Result"] = "4242", "0", "success"
		}
	default:
		return errors.New("unexpected core action")
	}
	return nil
}

func cloneCoreProperties(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func setCoreInactive(state map[string]string) {
	state["ActiveState"], state["SubState"] = "inactive", "dead"
	state["MainPID"], state["ControlPID"], state["Result"] = "0", "0", "success"
}

func coreTestState(unit string, unitFileState string, active bool) map[string]string {
	state := map[string]string{
		"LoadState": "loaded", "UnitFileState": unitFileState,
		"FragmentPath": "/usr/lib/systemd/system/" + unit, "DropInPaths": "", "NeedDaemonReload": "no",
		"ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "Result": "success",
		"InvocationID": "fixture", "ActiveEnterTimestampMonotonic": "1",
	}
	if active {
		if strings.HasSuffix(unit, ".timer") {
			state["ActiveState"], state["SubState"] = "active", "waiting"
		} else if strings.HasSuffix(unit, ".target") {
			state["ActiveState"], state["SubState"] = "active", "active"
		} else {
			state["ActiveState"], state["SubState"], state["MainPID"] = "active", "running", "4242"
		}
	}
	return state
}

func newCoreRollbackSystemd() *coreActivationSystemd {
	states := make(map[string]map[string]string)
	for _, unit := range coreactivation.CoreUnits() {
		unitState := "static"
		active := false
		if unit == "workagent-tenant-catalog-ready.target" {
			active = true
		}
		if unit == "caddy.service" || slicesContainsCore(corePersistentServiceUnits, unit) || slicesContainsCore(coreTimerUnits, unit) {
			unitState, active = "enabled", true
		}
		states[unit] = coreTestState(unit, unitState, active)
	}
	return &coreActivationSystemd{states: states}
}

func slicesContainsCore(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestActivateCoreFleetRequiresExactConfirmationAndNoPositionals(t *testing.T) {
	if err := activateCoreFleet(nil); err == nil || !strings.Contains(err.Error(), coreActivationConfirmation) {
		t.Fatalf("missing core activation confirmation was accepted: %v", err)
	}
	if err := activateCoreFleet([]string{"--confirm", coreActivationConfirmation, "extra"}); err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("core activation positional input was accepted: %v", err)
	}
	if err := activateCoreFleet([]string{"--confirm", coreActivationConfirmation, "--unknown"}); err == nil {
		t.Fatal("unknown core activation flag was accepted")
	}
}

func TestCoreRollbackDisablesFleetWithoutMutatingTenantSockets(t *testing.T) {
	controller := newCoreRollbackSystemd()
	original := rollbackCoreCaddy
	t.Cleanup(func() { rollbackCoreCaddy = original })
	rollbackCoreCaddy = func(_ context.Context, _ systemdctl.Controller) error {
		state := controller.states["caddy.service"]
		state["UnitFileState"] = "disabled"
		setCoreInactive(state)
		controller.actions = append(controller.actions, []string{"disable", "--now", "caddy.service"})
		return nil
	}
	verify := func(string, map[string]string) error { return nil }
	sync := func(bool, string, string) error { return nil }
	if err := rollbackCoreFleetFailClosed(context.Background(), controller, verify, sync); err != nil {
		t.Fatal(err)
	}
	for _, action := range controller.actions {
		joined := strings.Join(action, " ")
		if strings.Contains(joined, "workagent-userhost@") || strings.HasSuffix(joined, ".socket") {
			t.Fatalf("core rollback mutated a tenant socket: %q", action)
		}
	}
	for _, timer := range coreTimerUnits {
		if state := controller.states[timer]; state["UnitFileState"] != "disabled" || state["ActiveState"] != "inactive" {
			t.Fatalf("timer was not rolled back: %s=%v", timer, state)
		}
	}
	if target := controller.states[tenantCatalogReadyTarget]; target["ActiveState"] != "inactive" || target["SubState"] != "dead" {
		t.Fatalf("readiness target was not reset for a fresh reconciliation: %v", target)
	}
}

func TestCorePersistentTimerMayLaunchTargetWithoutWaitingForAEX(t *testing.T) {
	controller := &coreActivationSystemd{states: map[string]map[string]string{
		"workagent-backup.timer":   coreTestState("workagent-backup.timer", "disabled", false),
		"workagent-backup.service": coreTestState("workagent-backup.service", "static", false),
	}}
	verify := func(string, map[string]string) error { return nil }
	sync := func(bool, string, string) error { return nil }
	if err := enableAndProveCoreTimer(context.Background(), controller, "workagent-backup.timer", verify, sync); err != nil {
		t.Fatal(err)
	}
	target := controller.states["workagent-backup.service"]
	if target["ActiveState"] != "activating" || target["MainPID"] == "0" {
		t.Fatalf("timer target did not exercise the A_EX-waiting state: %v", target)
	}
	wantActions := [][]string{{"enable", "workagent-backup.timer"}, {"start", "workagent-backup.timer"}}
	if !reflect.DeepEqual(controller.actions, wantActions) {
		t.Fatalf("timer activation took a blocking target action: got %v want %v", controller.actions, wantActions)
	}
}

func TestCoreRollbackResetsProcessFreeFailedUnitsForRetry(t *testing.T) {
	controller := newCoreRollbackSystemd()
	controller.preserveFailedOnStop = map[string]bool{}
	failedUnits := []string{"workagent-portal.service", "workagent-backup.timer", "workagent-tenant-config-reconcile.service"}
	for _, unit := range failedUnits {
		state := controller.states[unit]
		state["ActiveState"], state["SubState"], state["MainPID"], state["ControlPID"], state["Result"] = "failed", "failed", "0", "0", "exit-code"
		controller.preserveFailedOnStop[unit] = true
	}
	original := rollbackCoreCaddy
	t.Cleanup(func() { rollbackCoreCaddy = original })
	rollbackCoreCaddy = func(_ context.Context, _ systemdctl.Controller) error {
		state := controller.states["caddy.service"]
		state["UnitFileState"] = "disabled"
		setCoreInactive(state)
		return nil
	}
	if err := rollbackCoreFleetFailClosed(context.Background(), controller, func(string, map[string]string) error { return nil }, func(bool, string, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, unit := range failedUnits {
		state := controller.states[unit]
		if state["ActiveState"] != "inactive" || state["SubState"] != "dead" || state["Result"] != "success" {
			t.Fatalf("failed unit %s did not reset cleanly: %v", unit, state)
		}
		found := false
		for _, action := range controller.actions {
			if reflect.DeepEqual(action, []string{"reset-failed", unit}) {
				found = true
			}
		}
		if !found {
			t.Fatalf("failed unit %s was not reset: actions=%v", unit, controller.actions)
		}
	}
}

func TestFreshTenantCatalogReadinessRequiresNewSuccessfulUnskippedInvocation(t *testing.T) {
	newController := func(skip bool) *coreActivationSystemd {
		reconcile := coreTestState("workagent-tenant-config-reconcile.service", "static", false)
		reconcile["InvocationID"] = "old"
		reconcile["ExecMainStartTimestampMonotonic"] = "10"
		reconcile["ExecMainExitTimestampMonotonic"] = "11"
		reconcile["ExecMainCode"], reconcile["ExecMainStatus"], reconcile["ConditionResult"] = "1", "0", "yes"
		return &coreActivationSystemd{
			states: map[string]map[string]string{
				"workagent-tenant-config-reconcile.service": reconcile,
				tenantCatalogReadyTarget:                    coreTestState(tenantCatalogReadyTarget, "static", false),
			},
			skipReconcile: skip,
		}
	}
	verify := func(string, map[string]string) error { return nil }
	for _, test := range []struct {
		name    string
		skip    bool
		wantErr bool
	}{{name: "fresh success"}, {name: "condition skipped", skip: true, wantErr: true}} {
		t.Run(test.name, func(t *testing.T) {
			controller := newController(test.skip)
			evidenceChecks := 0
			err := startAndProveFreshTenantCatalogReady(context.Background(), controller, verify, func() error {
				evidenceChecks++
				return nil
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("fresh reconciliation error=%v wantErr=%v", err, test.wantErr)
			}
			if !test.wantErr && evidenceChecks != 2 {
				t.Fatalf("transaction evidence checks=%d want=2", evidenceChecks)
			}
			if got := controller.actions; len(got) != 1 || !reflect.DeepEqual(got[0], []string{"start", tenantCatalogReadyTarget}) {
				t.Fatalf("fresh reconciliation actions=%v", got)
			}
		})
	}
}


func TestImmutableCoreFleetHelperSetBindsEveryInstalledHelper(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned helper fixture requires root")
	}
	makeFixture := func(t *testing.T) ([]coreFleetHelperBinding, []string) {
		t.Helper()
		root := t.TempDir()
		installedRoot := filepath.Join(root, "installed")
		referenceRoot := filepath.Join(root, "reference")
		if err := os.Mkdir(installedRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(referenceRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		var bindings []coreFleetHelperBinding
		for _, name := range []string{"core", "recovery", "fixed"} {
			installed := filepath.Join(installedRoot, name)
			reference := filepath.Join(referenceRoot, name)
			for _, path := range []string{installed, reference} {
				if err := os.WriteFile(path, []byte(name+"\n"), 0o555); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o555); err != nil {
					t.Fatal(err)
				}
			}
			bindings = append(bindings, coreFleetHelperBinding{installed: installed, reference: reference})
		}
		return bindings, []string{root, installedRoot}
	}
	bindings, ancestors := makeFixture(t)
	if err := verifyInstalledCoreFleetHelpersAt(bindings, ancestors); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, []coreFleetHelperBinding)
	}{
		{name: "missing helper", mutate: func(t *testing.T, values []coreFleetHelperBinding) { t.Helper(); _ = os.Remove(values[1].installed) }},
		{name: "digest drift", mutate: func(t *testing.T, values []coreFleetHelperBinding) {
			t.Helper()
			_ = os.Chmod(values[1].installed, 0o755)
			_ = os.WriteFile(values[1].installed, []byte("drift\n"), 0o555)
			_ = os.Chmod(values[1].installed, 0o555)
		}},
		{name: "writable mode", mutate: func(t *testing.T, values []coreFleetHelperBinding) {
			t.Helper()
			_ = os.Chmod(values[1].installed, 0o755)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values, roots := makeFixture(t)
			test.mutate(t, values)
			if err := verifyInstalledCoreFleetHelpersAt(values, roots); err == nil {
				t.Fatal("unsafe or incomplete helper set was accepted")
			}
		})
	}
}

func TestCoreCommitAlwaysPrecedesNestedEdgeCommit(t *testing.T) {
	for _, test := range []struct {
		name              string
		coreErr           error
		edgeErr           error
		wantCoreCommitted bool
		wantEvents        []string
	}{
		{name: "success", wantCoreCommitted: true, wantEvents: []string{"core", "edge"}},
		{name: "core failure", coreErr: errors.New("core failed"), wantEvents: []string{"core"}},
		{name: "edge failure", edgeErr: errors.New("edge failed"), wantCoreCommitted: true, wantEvents: []string{"core", "edge"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			committed, err := commitCoreBeforeNestedEdge(func() error {
				events = append(events, "core")
				return test.coreErr
			}, func() error {
				events = append(events, "edge")
				return test.edgeErr
			})
			if committed != test.wantCoreCommitted || !reflect.DeepEqual(events, test.wantEvents) || (err != nil) != (test.coreErr != nil || test.edgeErr != nil) {
				t.Fatalf("commit result committed=%t events=%v err=%v", committed, events, err)
			}
		})
	}
}

func TestCommittedCaddySettlementFailureAlwaysFailsClosed(t *testing.T) {
	originalSettle, originalRollback := settleCoreCaddy, rollbackCoreCaddy
	t.Cleanup(func() { settleCoreCaddy, rollbackCoreCaddy = originalSettle, originalRollback })
	settleCoreCaddy = func(context.Context, systemdctl.Controller, serviceaction.CaddyPublishingGeneration) error {
		return errors.New("watcher failed")
	}
	rolledBack := false
	rollbackCoreCaddy = func(context.Context, systemdctl.Controller) error { rolledBack = true; return nil }
	controller := &coreActivationSystemd{states: map[string]map[string]string{}}
	if err := settleCommittedCoreCaddyFailClosed(context.Background(), controller, serviceaction.CaddyPublishingGeneration{MainPID: "1"}); err == nil || !rolledBack {
		t.Fatalf("settlement failure was not failed closed: err=%v rolledBack=%t", err, rolledBack)
	}
}

func TestCorePreflightFailureEstablishesCompleteFailClosedBaseline(t *testing.T) {
	originalVerifier, originalSync, originalRollback := verifyCorePreflightRollback, syncCorePreflightEnablement, rollbackCoreCaddy
	t.Cleanup(func() {
		verifyCorePreflightRollback, syncCorePreflightEnablement, rollbackCoreCaddy = originalVerifier, originalSync, originalRollback
	})
	controller := newCoreRollbackSystemd()
	verifyCorePreflightRollback = func(string, map[string]string) error { return nil }
	syncCorePreflightEnablement = func(bool, string, string) error { return nil }
	rollbackCoreCaddy = func(context.Context, systemdctl.Controller) error {
		state := controller.states["caddy.service"]
		state["UnitFileState"] = "disabled"
		setCoreInactive(state)
		return nil
	}
	if err := rejectCorePreflightFailClosed(controller, errors.New("gate failed")); err == nil {
		t.Fatal("preflight rejection did not return its cause")
	}
	for _, unit := range append(append([]string(nil), corePersistentServiceUnits...), append([]string{"caddy.service", tenantCatalogReadyTarget}, coreTimerUnits...)...) {
		state := controller.states[unit]
		if state["ActiveState"] != "inactive" || (unit != tenantCatalogReadyTarget && unit != "caddy.service" && slicesContainsCore(corePersistentServiceUnits, unit) && state["UnitFileState"] != "disabled") {
			t.Fatalf("preflight failure left core unit live: %s=%v", unit, state)
		}
	}
}

func TestCoreActivationStructuralCrashBoundariesAreOrdered(t *testing.T) {
	payload, err := os.ReadFile("core_activation_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	function := func(name string) string {
		t.Helper()
		start := strings.Index(source, "func "+name+"(")
		if start < 0 {
			t.Fatalf("function %s not found", name)
		}
		end := strings.Index(source[start+1:], "\nfunc ")
		if end < 0 {
			return source[start:]
		}
		return source[start : start+1+end]
	}
	ordered := func(body string, tokens ...string) {
		t.Helper()
		position := -1
		for _, token := range tokens {
			next := strings.Index(body[position+1:], token)
			if next < 0 {
				t.Fatalf("ordered crash boundary %q is missing", token)
			}
			position += next + 1
		}
	}

	activate := function("activateCoreFleet")
	ordered(activate,
		"AcquireActivationExclusiveForCoreReconciliation",
		"acquireAuthenticatedControlConsumer(ctx)",
		"edgepublication.ReconcilePending",
		"reconcilePendingCoreActivation",
		"backupquiescence.AssertClean()",
		"backup.AssertNoPendingRecoveryActivation()",
		"admin.AssertTenantActivationClean()",
	)
	ordered(activate,
		"establish fail-closed core baseline before transaction begin",
		"fixed.Close()",
		"coreactivation.Begin()",
		"transaction.Verify()",
		"startAndProveFreshTenantCatalogReady",
		"convergeCoreFleet",
		"commitCoreBeforeNestedEdge",
		"edgepublication.FailClosedAfterCommitError",
		"settleCommittedCoreCaddyFailClosed",
	)
	if strings.Count(activate, "acquireAuthenticatedControlConsumer(ctx)") != 2 {
		t.Fatal("core activation must have exactly one authenticated snapshot before recovery and one after C_EX reconciliation")
	}
	firstAcquire := strings.Index(activate, "acquireAuthenticatedControlConsumer(ctx)")
	firstReplay := strings.Index(activate, "edgepublication.ReconcilePending")
	if firstAcquire < 0 || firstReplay < 0 || firstAcquire >= firstReplay || strings.Contains(activate[firstAcquire:firstReplay], "controller.Action") || strings.Contains(activate[firstAcquire:firstReplay], "rejectCorePreflightFailClosed") {
		t.Fatal("initial running-control authentication failure can reach a systemd mutation")
	}
	firstClose := strings.Index(activate, "if err := fixed.Close()")
	begin := strings.Index(activate, "coreactivation.Begin()")
	fresh := strings.Index(activate, "startAndProveFreshTenantCatalogReady")
	secondAcquire := strings.LastIndex(activate, "acquireAuthenticatedControlConsumer(ctx)")
	if firstClose < 0 || begin < 0 || fresh < 0 || secondAcquire <= firstAcquire || !(firstClose < begin && begin < fresh && fresh < secondAcquire) {
		t.Fatal("catalog/control guard lifetime crosses C_EX reconciliation or is not reacquired afterward")
	}
	for _, bounds := range [][2]string{
		{"backupquiescence.AssertClean()", "backup.AssertNoPendingRecoveryActivation()"},
		{"backup.AssertNoPendingRecoveryActivation()", "admin.AssertTenantActivationClean()"},
		{"admin.AssertTenantActivationClean()", "verifySource :="},
	} {
		start := strings.Index(activate, bounds[0])
		end := strings.Index(activate[start+1:], bounds[1])
		if start < 0 || end < 0 || strings.Contains(activate[start:start+1+end], "rejectCorePreflightFailClosed") {
			t.Fatalf("cross-protocol gate %q performs a core rollback mutation", bounds[0])
		}
	}

	converge := function("convergeCoreFleet")
	ordered(converge, "publishCoreCaddyEdge", "for _, timer := range coreTimerUnits", "verifyCoreBackupEnvironment()", "serviceaction.VerifyPublishedEdge")
	publish := function("publishCoreCaddyEdge")
	if strings.Contains(publish, "edgeTransaction.Commit()") || strings.Contains(publish, "edgeTransaction.Close()") {
		t.Fatal("nested edge ownership was committed or closed inside publishCoreCaddyEdge")
	}
	abort := function("abortCoreFleetActivation")
	ordered(abort, "rollbackCoreCaddy", "edgeTransaction.Close()", "edgepublication.ReconcilePending", "transaction.Close()", "rollbackCoreFleetFailClosed")
}
