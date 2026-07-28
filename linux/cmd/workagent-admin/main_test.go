package main

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

func TestMain(testingMain *testing.M) {
	original := syncCaddyEnablementForAction
	syncCaddyEnablementForAction = func(bool, string) error { return nil }
	code := testingMain.Run()
	syncCaddyEnablementForAction = original
	os.Exit(code)
}

func TestReconcileTenantFilesPassesRequiredRunningControlAuthenticator(t *testing.T) {
	sentinel := errors.New("stop after authentication wiring proof")
	authenticationCalls := 0
	runnerCalls := 0
	authenticate := func() error {
		authenticationCalls++
		return nil
	}
	runner := func(ctx context.Context, portalPath string, controller systemdctl.Controller, received func() error) (admin.TenantFileReconcileResult, error) {
		runnerCalls++
		if ctx == nil || portalPath != "/etc/workagent/portal.json" || controller == nil || received == nil {
			t.Fatal("reconcile command did not pass the complete authenticated production boundary")
		}
		if err := received(); err != nil {
			t.Fatal(err)
		}
		return admin.TenantFileReconcileResult{}, sentinel
	}
	err := reconcileTenantFilesWithDependencies(nil, runner, authenticate)
	if !errors.Is(err, sentinel) || runnerCalls != 1 || authenticationCalls != 1 {
		t.Fatalf("runnerCalls=%d authenticationCalls=%d err=%v", runnerCalls, authenticationCalls, err)
	}
}

func TestVerifyTenantQuiescenceIsExplicitStartupOnlyMode(t *testing.T) {
	const runtimeUID = 2001
	options, err := parseVerifyTenantOptions([]string{"--config", "/etc/workagent/portal.json", "--tenant-id", "tenant-one"})
	if err != nil {
		t.Fatal(err)
	}
	if options.requireQuiescent {
		t.Fatal("ordinary online verify-tenant unexpectedly requires an empty runtime UID")
	}
	called := 0
	sentinel := errors.New("residual process")
	check := func(uid uint32) error {
		called++
		if uid != runtimeUID {
			t.Fatalf("runtime UID=%d want %d", uid, runtimeUID)
		}
		return sentinel
	}
	if err := verifyTenantQuiescence(runtimeUID, options.requireQuiescent, check); err != nil || called != 0 {
		t.Fatalf("ordinary online verification invoked quiescence check: calls=%d err=%v", called, err)
	}

	options, err = parseVerifyTenantOptions([]string{"--tenant-id", "tenant-one", "--require-quiescent"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.requireQuiescent {
		t.Fatal("startup verify-tenant mode did not require runtime UID quiescence")
	}
	if err := verifyTenantQuiescence(runtimeUID, options.requireQuiescent, check); !errors.Is(err, sentinel) || called != 1 {
		t.Fatalf("startup verification did not fail closed through the quiescence check: calls=%d err=%v", called, err)
	}
}

func TestInitialTenantCatalogActivationCannotBypassImportedOrDisabledCatalog(t *testing.T) {
	userValue := store.User{
		Username: "admin", TenantID: "11111111-1111-4111-8111-111111111111",
		RuntimeUser: "workagent-u2001", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111",
		Admin: true, Enabled: true,
	}
	identity := store.PortalUserIdentity{
		TenantID: userValue.TenantID, RuntimeUser: userValue.RuntimeUser, DataRoot: userValue.DataRoot, Enabled: true,
	}
	if err := validateInitialTenantCatalogShape([]store.User{userValue}, []store.PortalUserIdentity{identity}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		users      []store.User
		identities []store.PortalUserIdentity
	}{
		{name: "multiple imported users", users: []store.User{userValue, userValue}, identities: []store.PortalUserIdentity{identity, identity}},
		{name: "non-admin", users: []store.User{func() store.User { value := userValue; value.Admin = false; return value }()}, identities: []store.PortalUserIdentity{identity}},
		{name: "disabled database", users: []store.User{func() store.User { value := userValue; value.Enabled = false; return value }()}, identities: []store.PortalUserIdentity{identity}},
		{name: "disabled activation identity", users: []store.User{userValue}, identities: []store.PortalUserIdentity{func() store.PortalUserIdentity { value := identity; value.Enabled = false; return value }()}},
		{name: "identity drift", users: []store.User{userValue}, identities: []store.PortalUserIdentity{func() store.PortalUserIdentity {
			value := identity
			value.RuntimeUser = "workagent-u2002"
			return value
		}()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateInitialTenantCatalogShape(test.users, test.identities); err == nil {
				t.Fatal("unsafe initial tenant catalog was accepted")
			}
		})
	}
}

type recordingSystemd struct {
	actions  [][]string
	onAction func([]string)
}

func (r *recordingSystemd) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	if strings.HasSuffix(unit, ".socket") {
		return map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"}, nil
	}
	return map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}, nil
}

func (r *recordingSystemd) Action(_ context.Context, arguments ...string) error {
	r.actions = append(r.actions, append([]string(nil), arguments...))
	if r.onAction != nil {
		r.onAction(arguments)
	}
	return nil
}

type catalogReadySystemd struct {
	active    bool
	unitState string
	actions   int
	reads     int
}

type serviceActionSystemd struct {
	actions          [][]string
	propertyRequests [][]string
	before           map[string]string
	after            map[string]string
	reads            int
}

func allowServiceActionSource(string, map[string]string) error { return nil }

type scriptedServiceActionSystemd struct {
	actions      [][]string
	actionErrors []error
	snapshots    []map[string]string
	reads        int
}

type unitSnapshotSystemd struct {
	snapshots map[string][]map[string]string
	reads     map[string]int
	actions   [][]string
}

func (controller *unitSnapshotSystemd) Action(_ context.Context, arguments ...string) error {
	controller.actions = append(controller.actions, append([]string(nil), arguments...))
	return nil
}

func (controller *unitSnapshotSystemd) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	values := controller.snapshots[unit]
	if len(values) == 0 {
		return nil, errors.New("missing unit snapshot")
	}
	if controller.reads == nil {
		controller.reads = make(map[string]int)
	}
	index := controller.reads[unit]
	controller.reads[unit]++
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index], nil
}

func (controller *scriptedServiceActionSystemd) Action(_ context.Context, arguments ...string) error {
	controller.actions = append(controller.actions, append([]string(nil), arguments...))
	index := len(controller.actions) - 1
	if index < len(controller.actionErrors) {
		return controller.actionErrors[index]
	}
	return nil
}

func (controller *scriptedServiceActionSystemd) Properties(_ context.Context, _ string, _ ...string) (map[string]string, error) {
	if len(controller.snapshots) == 0 {
		return nil, errors.New("no scripted service snapshot")
	}
	index := controller.reads
	controller.reads++
	if index >= len(controller.snapshots) {
		index = len(controller.snapshots) - 1
	}
	return controller.snapshots[index], nil
}

func (controller *serviceActionSystemd) Action(_ context.Context, arguments ...string) error {
	controller.actions = append(controller.actions, append([]string(nil), arguments...))
	return nil
}

func (controller *serviceActionSystemd) Properties(_ context.Context, _ string, names ...string) (map[string]string, error) {
	controller.propertyRequests = append(controller.propertyRequests, append([]string(nil), names...))
	controller.reads++
	if controller.reads == 1 {
		return controller.before, nil
	}
	return controller.after, nil
}

func caddyServiceState(active, enabled bool, invocation string, stamp uint64) map[string]string {
	state := map[string]string{
		"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "UnitFileState": "disabled", "Result": "success",
		"FragmentPath": "/usr/lib/systemd/system/caddy.service", "DropInPaths": "/etc/systemd/system/caddy.service.d/workagent.conf",
		"InvocationID": invocation, "ActiveEnterTimestampMonotonic": strconv.FormatUint(stamp, 10), "NeedDaemonReload": "no",
		"ExecStart":                       "{ path=/usr/bin/caddy ; argv[]=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecStartEx":                     "{ path=/usr/bin/caddy ; argv[]=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile ; flags= ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecStartPre":                    "{ path=/usr/libexec/workagent-core-activation-admission-v1 ; argv[]=/usr/libexec/workagent-core-activation-admission-v1 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 } ; { path=/usr/libexec/workagent-edge-publication-admission-v1 ; argv[]=/usr/libexec/workagent-edge-publication-admission-v1 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecStartPreEx":                  "{ path=/usr/libexec/workagent-core-activation-admission-v1 ; argv[]=/usr/libexec/workagent-core-activation-admission-v1 ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 } ; { path=/usr/libexec/workagent-edge-publication-admission-v1 ; argv[]=/usr/libexec/workagent-edge-publication-admission-v1 ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecStartPost":                   "{ path=/usr/libexec/workagent-edge-publication-admission-v1 ; argv[]=/usr/libexec/workagent-edge-publication-admission-v1 --watch $MAINPID ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecStartPostEx":                 "{ path=/usr/libexec/workagent-edge-publication-admission-v1 ; argv[]=/usr/libexec/workagent-edge-publication-admission-v1 --watch $MAINPID ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecReload":                      "{ path=/usr/bin/caddy ; argv[]=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecReloadEx":                    "{ path=/usr/bin/caddy ; argv[]=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force ; flags= ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"ExecStop":                        "",
		"ExecStopEx":                      "",
		"ExecStopPost":                    "",
		"ExecStopPostEx":                  "",
		"ExecMainStartTimestampMonotonic": strconv.FormatUint(stamp, 10),
		"TimeoutStartUSec":                "6min",
		"TimeoutStartFailureMode":         "kill",
		"KillMode":                        "control-group",
		"SendSIGKILL":                     "yes",
		"FinalKillSignal":                 "9",
		"Restart":                         "no",
		"Type":                            "notify",
		"User":                            "caddy",
		"Group":                           "caddy",
		"RuntimeDirectory":                "caddy-admin",
		"RuntimeDirectoryMode":            "0700",
		"NoNewPrivileges":                 "yes",
		"AmbientCapabilities":             "cap_net_bind_service",
		"CapabilityBoundingSet":           "cap_net_bind_service",
	}
	if enabled {
		state["UnitFileState"] = "enabled"
	}
	if active {
		state["ActiveState"] = "active"
		state["SubState"] = "running"
		state["MainPID"] = "42"
	}
	return state
}

func caddyPublishingState(invocation string, stamp uint64) map[string]string {
	state := caddyServiceState(false, true, invocation, 0)
	state["ActiveState"] = "activating"
	state["SubState"] = "start-post"
	state["MainPID"] = "42"
	state["ControlPID"] = "43"
	state["ExecMainStartTimestampMonotonic"] = strconv.FormatUint(stamp, 10)
	return state
}

func TestAllowlistedServiceActionUsesExactArgvAndReadback(t *testing.T) {
	controller := &serviceActionSystemd{
		before: map[string]string{
			"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "41", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
			"FragmentPath": "/usr/lib/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "before", "ActiveEnterTimestampMonotonic": "100",
		},
		after: map[string]string{
			"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
			"FragmentPath": "/usr/lib/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "after", "ActiveEnterTimestampMonotonic": "101",
		},
	}
	if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "restart", "cliproxyapi.service", allowServiceActionSource); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"restart", "cliproxyapi.service"}}; !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("actions=%v want=%v", controller.actions, want)
	}
	controller.actions = nil
	controller.reads = 0
	if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "restart", "workagent-backup.timer", allowServiceActionSource); err == nil || len(controller.actions) != 0 {
		t.Fatalf("non-allowlisted pair reached systemd: actions=%v err=%v", controller.actions, err)
	}
	controller.before = map[string]string{
		"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled",
		"FragmentPath": "/usr/lib/systemd/system/workagent-backup.timer", "DropInPaths": "",
	}
	controller.after = map[string]string{
		"LoadState": "loaded", "ActiveState": "active", "SubState": "waiting", "UnitFileState": "enabled",
		"FragmentPath": "/usr/lib/systemd/system/workagent-backup.timer", "DropInPaths": "",
	}
	controller.reads = 0
	if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "enable-now", "workagent-backup.timer", allowServiceActionSource); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"enable", "--now", "workagent-backup.timer"}}; !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("actions=%v want=%v", controller.actions, want)
	}
	for _, request := range controller.propertyRequests[len(controller.propertyRequests)-2:] {
		for _, serviceOnly := range []string{"MainPID", "ControlPID", "Result", "InvocationID", "ActiveEnterTimestampMonotonic"} {
			if slices.Contains(request, serviceOnly) {
				t.Fatalf("timer readback requested service-only property %s: %v", serviceOnly, request)
			}
		}
	}
}

func TestCLIProxyStartOnRunningForcesANewAuthenticatedInvocation(t *testing.T) {
	controller := &serviceActionSystemd{
		before: map[string]string{
			"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "41", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
			"FragmentPath": "/usr/lib/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "old", "ActiveEnterTimestampMonotonic": "100",
		},
		after: map[string]string{
			"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
			"FragmentPath": "/usr/lib/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "new", "ActiveEnterTimestampMonotonic": "101",
		},
	}
	if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "start", "cliproxyapi.service", allowServiceActionSource); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"restart", "cliproxyapi.service"}}; !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("running CLIProxy start actions=%v want=%v", controller.actions, want)
	}
}

func TestCaddyPublicationAlwaysReloadsAndRestartsIntoANewGeneration(t *testing.T) {
	disabled := caddyServiceState(false, false, "old", 100)
	enabledInactive := caddyServiceState(false, true, "old", 100)
	publishing := caddyPublishingState("new", 101)
	controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{disabled, enabledInactive, publishing, publishing}}
	if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "enable-now", "caddy.service", allowServiceActionSource); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"daemon-reload"}, {"enable", "caddy.service"}, {"start", "--no-block", "caddy.service"}}
	if !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("Caddy publication actions=%v want=%v", controller.actions, want)
	}
}

func TestCaddyPublicationFailsClosedToDurablyDisabled(t *testing.T) {
	oldGeneration := caddyServiceState(false, false, "old", 100)
	enabledInactive := caddyServiceState(false, true, "old", 100)
	bypassedGuard := caddyServiceState(true, true, "new", 101)
	disabled := caddyServiceState(false, false, "old", 100)
	controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{oldGeneration, enabledInactive, bypassedGuard, disabled}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := executeAllowlistedServiceActionWithVerifier(ctx, controller, "enable-now", "caddy.service", allowServiceActionSource)
	if err == nil || !strings.Contains(err.Error(), "durably disabled") {
		t.Fatalf("failed Caddy generation result=%v", err)
	}
	want := [][]string{{"daemon-reload"}, {"enable", "caddy.service"}, {"start", "--no-block", "caddy.service"}, {"disable", "--now", "caddy.service"}}
	if !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("Caddy rollback actions=%v want=%v", controller.actions, want)
	}
}

func TestCaddyPublicationRejectsStaleManagerCacheBeforeMutation(t *testing.T) {
	stale := caddyServiceState(false, false, "", 0)
	stale["NeedDaemonReload"] = "yes"
	controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{stale}}
	if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "enable-now", "caddy.service", allowServiceActionSource); err == nil {
		t.Fatal("Caddy manager cache requiring daemon reload was accepted")
	}
	if want := [][]string{{"daemon-reload"}}; !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("unsafe manager state reached Caddy mutation: %v", controller.actions)
	}
}

func TestCaddyCrashCleanupResetsOnlyProcessFreeTerminalFailure(t *testing.T) {
	for _, result := range []string{"exit-code", "timeout", "canceled"} {
		t.Run(result, func(t *testing.T) {
			failed := caddyServiceState(false, false, "failed", 100)
			failed["ActiveState"] = "failed"
			failed["SubState"] = "failed"
			failed["Result"] = result
			clean := caddyServiceState(false, false, "", 0)
			controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{failed, failed, clean, clean}}
			if err := disableCaddyFailClosed(context.Background(), controller, serviceActionPropertyNames(false, "caddy.service"), allowServiceActionSource); err != nil {
				t.Fatal(err)
			}
			want := [][]string{{"disable", "--now", "caddy.service"}, {"reset-failed", "caddy.service"}}
			if !reflect.DeepEqual(controller.actions, want) {
				t.Fatalf("crash cleanup actions=%v want=%v", controller.actions, want)
			}
		})
	}

	failedWithProcess := caddyServiceState(false, false, "failed", 100)
	failedWithProcess["ActiveState"] = "failed"
	failedWithProcess["SubState"] = "failed"
	failedWithProcess["Result"] = "exit-code"
	failedWithProcess["MainPID"] = "42"
	controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{failedWithProcess}}
	if err := disableCaddyFailClosed(context.Background(), controller, serviceActionPropertyNames(false, "caddy.service"), allowServiceActionSource); err == nil {
		t.Fatal("failed Caddy with a live MainPID was reset as process-free")
	}
	for _, action := range controller.actions {
		if len(action) > 0 && action[0] == "reset-failed" {
			t.Fatalf("reset-failed reached a live Caddy process: %v", controller.actions)
		}
	}
}

func TestCaddyManagerContractRejectsIgnoredOrUnprivilegedAdmissionHooks(t *testing.T) {
	base := caddyServiceState(false, false, "", 0)
	if err := verifyCaddyManagerContract(base); err != nil {
		t.Fatal(err)
	}
	ignored := maps.Clone(base)
	ignored["ExecStartPost"] = strings.Replace(ignored["ExecStartPost"], "ignore_errors=no", "ignore_errors=yes", 1)
	if err := verifyCaddyManagerContract(ignored); err == nil {
		t.Fatal("ignored edge-publication watcher failure was accepted")
	}
	unprivileged := maps.Clone(base)
	unprivileged["ExecStartPostEx"] = strings.Replace(unprivileged["ExecStartPostEx"], "flags=privileged", "flags=", 1)
	if err := verifyCaddyManagerContract(unprivileged); err == nil {
		t.Fatal("unprivileged edge-publication watcher was accepted")
	}
	for _, field := range []string{"ExecStartEx", "ExecReloadEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx"} {
		t.Run(field, func(t *testing.T) {
			tampered := maps.Clone(base)
			if tampered[field] == "" {
				tampered[field] = "{ path=/bin/true ; argv[]=/bin/true ; flags= ; pid=0 ; code=(null) ; status=0/0 }"
			} else {
				tampered[field] += " drift"
			}
			if err := verifyCaddyManagerContract(tampered); err == nil {
				t.Fatalf("Caddy manager-only tampering of %s was accepted", field)
			}
		})
	}
}

func TestPortalEdgeManagerContractRejectsCompleteManagerOnlyCommandDrift(t *testing.T) {
	plain := func(executable, arguments string) string {
		return "{ path=" + executable + " ; argv[]=" + arguments + " ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }"
	}
	extended := func(executable, arguments string, privileged bool) string {
		flags := ""
		if privileged {
			flags = "privileged"
		}
		return "{ path=" + executable + " ; argv[]=" + arguments + " ; flags=" + flags + " ; pid=0 ; code=(null) ; status=0/0 }"
	}
	join := func(records ...string) string { return strings.Join(records, " ; ") }
	const core = "/usr/libexec/workagent-core-activation-admission-v1"
	const recovery = "/usr/libexec/workagent-recovery-activation-admission-v1"
	const start = `/bin/bash -c /usr/bin/flock --shared 3 || exit 70; exec "$@" workagent-runtime-start /opt/workagent/control/bin/workagent-portal --config /etc/workagent/portal.json`
	const verify = "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-release --required-executable bin/workagent-portal"
	base := map[string]string{
		"LoadState": "loaded", "NeedDaemonReload": "no", "FragmentPath": "/usr/lib/systemd/system/workagent-portal.service", "DropInPaths": "/etc/systemd/system/workagent-portal.service.d/chatforward.conf /etc/systemd/system/workagent-portal.service.d/credentials.conf", "UnitFileState": "enabled",
		"ActiveState": "active", "SubState": "running", "MainPID": "42", "ControlPID": "0", "Result": "success", "InvocationID": "portal-generation", "ActiveEnterTimestampMonotonic": "100",
		"Type": "notify", "User": "workagent", "Group": "workagent",
		"ExecStart":   plain("/bin/bash", start),
		"ExecStartEx": extended("/bin/bash", start, false),
		"ExecStartPre": join(
			plain(core, core), plain(recovery, recovery), plain("/usr/bin/flock", verify),
		),
		"ExecStartPreEx": join(
			extended(core, core, true), extended(recovery, recovery, true), extended("/usr/bin/flock", verify, true),
		),
		"ExecStartPost": "", "ExecStartPostEx": "", "ExecStop": "", "ExecStopEx": "",
		"ExecStopPost": "", "ExecStopPostEx": "", "ExecReload": "", "ExecReloadEx": "",
	}
	if err := verifyPortalEdgeManagerContract(base); err != nil {
		t.Fatalf("exact Portal manager contract was rejected: %v", err)
	}
	for _, field := range []string{"ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx"} {
		t.Run(field, func(t *testing.T) {
			tampered := maps.Clone(base)
			if tampered[field] == "" {
				tampered[field] = extended("/bin/true", "/bin/true", false)
			} else {
				tampered[field] += " drift"
			}
			if err := verifyPortalEdgeManagerContract(tampered); err == nil {
				t.Fatalf("Portal edge accepted manager-only %s drift", field)
			}
		})
	}
	unprivileged := maps.Clone(base)
	unprivileged["ExecStartPreEx"] = strings.Replace(unprivileged["ExecStartPreEx"], "flags=privileged", "flags=", 1)
	if err := verifyPortalEdgeManagerContract(unprivileged); err == nil {
		t.Fatal("Portal edge accepted an unprivileged admission hook")
	}
}

func TestServiceActionManagerContractsBindCLIProxyAndTimerTargets(t *testing.T) {
	plain := func(executable, arguments string) string {
		return "{ path=" + executable + " ; argv[]=" + arguments + " ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }"
	}
	extended := func(executable, arguments string, privileged bool) string {
		flags := ""
		if privileged {
			flags = "privileged"
		}
		return "{ path=" + executable + " ; argv[]=" + arguments + " ; flags=" + flags + " ; pid=0 ; code=(null) ; status=0/0 }"
	}
	join := func(records ...string) string { return strings.Join(records, " ; ") }
	const core = "/usr/libexec/workagent-core-activation-admission-v1"
	const recovery = "/usr/libexec/workagent-recovery-activation-admission-v1"
	const start = "/usr/libexec/workagent-fixed-root-exec-v1 cliproxyapi /opt/workagent/shared/cliproxyapi/bin/cli-proxy-api --config /var/lib/cliproxyapi/config.yaml"
	const controlVerify = "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-cliproxy --required-executable bin/workagent-release"
	const sharedVerify = "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/shared --public-key /etc/workagent/trust/release-signing.pub --scope shared --required-executable cliproxyapi/bin/cli-proxy-api --required-executable cliproxyapi/plugins/cpa-key-policy-v0.4.5.so"
	const prepare = "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-cliproxy prepare --template /etc/cliproxyapi/config.yaml --output /var/lib/cliproxyapi/config.yaml --credential /run/credentials/cliproxyapi.service/cliproxy-management-key --state-root /var/lib/cliproxyapi"
	const bootstrap = "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-cliproxy bootstrap --portal-config /etc/workagent/portal.json --credential /run/credentials/cliproxyapi.service/cliproxy-management-key --wait 30s"
	cliproxy := map[string]string{
		"LoadState": "loaded", "NeedDaemonReload": "no", "FragmentPath": "/usr/lib/systemd/system/cliproxyapi.service", "UnitFileState": "enabled",
		"Type": "exec", "User": "cliproxyapi", "Group": "cliproxyapi",
		"ExecStart":   plain("/usr/libexec/workagent-fixed-root-exec-v1", start),
		"ExecStartEx": extended("/usr/libexec/workagent-fixed-root-exec-v1", start, false),
		"ExecStartPre": join(
			plain(core, core), plain(recovery, recovery), plain("/usr/bin/flock", controlVerify), plain("/usr/bin/flock", sharedVerify), plain("/usr/bin/flock", prepare),
		),
		"ExecStartPreEx": join(
			extended(core, core, true), extended(recovery, recovery, true), extended("/usr/bin/flock", controlVerify, true), extended("/usr/bin/flock", sharedVerify, true), extended("/usr/bin/flock", prepare, true),
		),
		"ExecStartPost":   plain("/usr/bin/flock", bootstrap),
		"ExecStartPostEx": extended("/usr/bin/flock", bootstrap, true),
		"ExecStop":        "", "ExecStopEx": "", "ExecStopPost": "", "ExecStopPostEx": "", "ExecReload": "", "ExecReloadEx": "",
	}
	if err := verifyServiceActionManagerContract("cliproxyapi.service", cliproxy); err != nil {
		t.Fatal(err)
	}
	stale := maps.Clone(cliproxy)
	stale["NeedDaemonReload"] = "yes"
	if err := verifyServiceActionManagerContract("cliproxyapi.service", stale); err == nil {
		t.Fatal("stale CLIProxy manager cache was accepted")
	}
	for _, field := range []string{"ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx"} {
		t.Run("cliproxy-"+field, func(t *testing.T) {
			tampered := maps.Clone(cliproxy)
			if tampered[field] == "" {
				tampered[field] = extended("/bin/true", "/bin/true", false)
			} else {
				tampered[field] += " drift"
			}
			if err := verifyServiceActionManagerContract("cliproxyapi.service", tampered); err == nil {
				t.Fatalf("manager-only CLIProxy tampering of %s was accepted", field)
			}
		})
	}

	const backupStart = "/usr/bin/flock --exclusive --no-fork /run/workagent/activation.lock /usr/libexec/workagent-fixed-root-exec-v1 backup /opt/workagent/control/bin/workagent-backup create --portal-config /etc/workagent/portal.json --config /etc/workagent/backup.json --quiesce-systemd"
	const backupVerify = "/usr/bin/flock --shared /run/workagent/release-config.lock /opt/workagent/control/bin/workagent-release verify --root /opt/workagent/control --public-key /etc/workagent/trust/release-signing.pub --scope portal --required-executable bin/workagent-backup --required-executable bin/workagent-release"
	const backupResume = "/usr/bin/flock --exclusive --nonblock --conflict-exit-code 0 /run/workagent/activation.lock /usr/bin/flock --shared /run/workagent/release-config.lock /usr/bin/flock --shared /opt/workagent/control.lock /opt/workagent/control/bin/workagent-backup resume"
	backupService := map[string]string{
		"LoadState": "loaded", "NeedDaemonReload": "no", "FragmentPath": "/usr/lib/systemd/system/workagent-backup.service", "UnitFileState": "static",
		"Type": "oneshot", "User": "root", "Group": "root",
		"ExecStart":   plain("/usr/bin/flock", backupStart),
		"ExecStartEx": extended("/usr/bin/flock", backupStart, false),
		"ExecStartPre": join(
			plain(core, core), plain("/usr/bin/flock", backupVerify),
		),
		"ExecStartPreEx": join(
			extended(core, core, true), extended("/usr/bin/flock", backupVerify, true),
		),
		"ExecStartPost": "", "ExecStartPostEx": "", "ExecStop": "", "ExecStopEx": "",
		"ExecStopPost": plain("/usr/bin/flock", backupResume), "ExecStopPostEx": extended("/usr/bin/flock", backupResume, false),
		"ExecReload": "", "ExecReloadEx": "",
	}
	if err := verifyServiceActionManagerContract("workagent-backup.service", backupService); err != nil {
		t.Fatalf("exact backup service manager contract was rejected: %v", err)
	}
	for _, field := range []string{"ExecStopPost", "ExecStopPostEx", "ExecReloadEx"} {
		t.Run("backup-"+field, func(t *testing.T) {
			tampered := maps.Clone(backupService)
			if tampered[field] == "" {
				tampered[field] = extended("/bin/true", "/bin/true", false)
			} else {
				tampered[field] = strings.Replace(tampered[field], "--nonblock", "--wait", 1)
			}
			if err := verifyServiceActionManagerContract("workagent-backup.service", tampered); err == nil {
				t.Fatalf("manager-only backup tampering of %s was accepted", field)
			}
		})
	}

	timer := map[string]string{
		"LoadState": "loaded", "NeedDaemonReload": "no", "FragmentPath": "/usr/lib/systemd/system/workagent-backup.timer", "UnitFileState": "enabled",
		"Unit": "workagent-backup.service", "Persistent": "yes",
	}
	if err := verifyServiceActionManagerContract("workagent-backup.timer", timer); err != nil {
		t.Fatal(err)
	}
	timer["Unit"] = "foreign.service"
	if err := verifyServiceActionManagerContract("workagent-backup.timer", timer); err == nil {
		t.Fatal("timer targeting a foreign service was accepted")
	}
}

func TestTimerDependencySnapshotAndFailClosedStopPairedService(t *testing.T) {
	targetIdle := map[string]string{"InvocationID": "one", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0"}
	controller := &unitSnapshotSystemd{snapshots: map[string][]map[string]string{
		"workagent-backup.service": {targetIdle, targetIdle},
	}}
	if err := verifyServiceActionDependencies(context.Background(), controller, "workagent-backup.timer", allowServiceActionSource); err != nil {
		t.Fatal(err)
	}
	controller = &unitSnapshotSystemd{snapshots: map[string][]map[string]string{
		"workagent-backup.service": {targetIdle, {"InvocationID": "two", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0"}},
	}}
	if err := verifyServiceActionDependencies(context.Background(), controller, "workagent-backup.timer", allowServiceActionSource); err == nil {
		t.Fatal("timer target generation drift during authentication was accepted")
	}
	timerDisabled := map[string]string{"ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled"}
	targetStopped := map[string]string{"ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0"}
	controller = &unitSnapshotSystemd{snapshots: map[string][]map[string]string{
		"workagent-backup.timer":   {timerDisabled},
		"workagent-backup.service": {targetStopped},
	}}
	if err := disableTimerFailClosed(context.Background(), controller, "workagent-backup.timer", serviceActionPropertyNames(true, "workagent-backup.timer"), allowServiceActionSource); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"disable", "--now", "workagent-backup.timer"}, {"stop", "workagent-backup.service"}}
	if !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("timer fail-closed actions=%v want=%v", controller.actions, want)
	}
}

func TestServiceActionCleanupUsesFreshBoundedContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if cancelled.Err() == nil {
		t.Fatal("test operation context was not cancelled")
	}
	if err := withServiceActionCleanup(func(cleanupContext context.Context) error {
		if cleanupContext.Err() != nil {
			return errors.New("cleanup inherited the cancelled operation context")
		}
		deadline, ok := cleanupContext.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Minute {
			return errors.New("cleanup context is not positively bounded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistedServiceActionRejectsLifecycleAndSourceDrift(t *testing.T) {
	baseBefore := map[string]string{
		"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "41", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
		"FragmentPath": "/etc/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "before", "ActiveEnterTimestampMonotonic": "100",
	}
	baseAfter := map[string]string{
		"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
		"FragmentPath": "/etc/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "after", "ActiveEnterTimestampMonotonic": "101",
	}
	tests := []struct {
		name   string
		before func(map[string]string)
		after  func(map[string]string)
	}{
		{name: "preexisting control process", before: func(values map[string]string) { values["ControlPID"] = "40" }},
		{name: "fragment replacement", after: func(values map[string]string) { values["FragmentPath"] = "/run/systemd/system/cliproxyapi.service" }},
		{name: "drop-in replacement", after: func(values map[string]string) { values["DropInPaths"] = "/run/systemd/system/foreign.conf" }},
		{name: "persistent state mutation", after: func(values map[string]string) { values["UnitFileState"] = "disabled" }},
		{name: "same invocation", after: func(values map[string]string) { values["InvocationID"] = "before" }},
		{name: "non-advancing start timestamp", after: func(values map[string]string) { values["ActiveEnterTimestampMonotonic"] = "100" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := make(map[string]string, len(baseBefore))
			for key, value := range baseBefore {
				before[key] = value
			}
			after := make(map[string]string, len(baseAfter))
			for key, value := range baseAfter {
				after[key] = value
			}
			if test.before != nil {
				test.before(before)
			}
			if test.after != nil {
				test.after(after)
			}
			controller := &serviceActionSystemd{before: before, after: after}
			if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "restart", "cliproxyapi.service", allowServiceActionSource); err == nil {
				t.Fatal("unsafe service lifecycle readback was accepted")
			}
			if test.before != nil && len(controller.actions) != 0 {
				t.Fatalf("unsafe precondition reached systemd: %v", controller.actions)
			}
		})
	}
	for _, unit := range []string{"workagent-portal.service", "workagent-chatforward.service", "workagent-userhost@11111111-1111-4111-8111-111111111111.service"} {
		controller := &serviceActionSystemd{before: baseBefore, after: baseAfter}
		if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "restart", unit, allowServiceActionSource); err == nil || len(controller.actions) != 0 {
			t.Fatalf("tenant-path unit %q reached service-action: actions=%v err=%v", unit, controller.actions, err)
		}
	}
}

func TestServiceActionRetriesAndCompensatesToExplicitStates(t *testing.T) {
	stopped := map[string]string{
		"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
		"FragmentPath": "/etc/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "old", "ActiveEnterTimestampMonotonic": "100",
	}
	running := map[string]string{
		"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
		"FragmentPath": "/etc/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "new", "ActiveEnterTimestampMonotonic": "101",
	}
	starting := map[string]string{
		"LoadState": "loaded", "ActiveState": "activating", "SubState": "start", "MainPID": "0", "ControlPID": "0", "UnitFileState": "enabled", "Result": "success",
		"FragmentPath": "/etc/systemd/system/cliproxyapi.service", "DropInPaths": "", "InvocationID": "", "ActiveEnterTimestampMonotonic": "100",
	}
	t.Run("retry reaches desired state", func(t *testing.T) {
		controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{stopped, starting, running}}
		if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "start", "cliproxyapi.service", allowServiceActionSource); err != nil {
			t.Fatal(err)
		}
		if want := [][]string{{"start", "cliproxyapi.service"}, {"start", "cliproxyapi.service"}}; !reflect.DeepEqual(controller.actions, want) {
			t.Fatalf("retry actions=%v want=%v", controller.actions, want)
		}
	})
	t.Run("failed start is compensated", func(t *testing.T) {
		controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{stopped, starting, starting, stopped}}
		err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "start", "cliproxyapi.service", allowServiceActionSource)
		if err == nil || !strings.Contains(err.Error(), "compensated to a proved inactive state") {
			t.Fatalf("compensation result=%v", err)
		}
		if want := [][]string{{"start", "cliproxyapi.service"}, {"start", "cliproxyapi.service"}, {"stop", "cliproxyapi.service"}}; !reflect.DeepEqual(controller.actions, want) {
			t.Fatalf("compensation actions=%v want=%v", controller.actions, want)
		}
	})
	t.Run("action error with proved desired state succeeds", func(t *testing.T) {
		controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{stopped, running}, actionErrors: []error{errors.New("job response lost")}}
		if err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "start", "cliproxyapi.service", allowServiceActionSource); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEnableNowFailurePreservesDurableRollForwardIntent(t *testing.T) {
	before := map[string]string{
		"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled",
		"FragmentPath": "/etc/systemd/system/workagent-backup.timer", "DropInPaths": "",
	}
	pending := map[string]string{
		"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "enabled",
		"FragmentPath": "/etc/systemd/system/workagent-backup.timer", "DropInPaths": "",
	}
	controller := &scriptedServiceActionSystemd{snapshots: []map[string]string{before, pending, pending}}
	err := executeAllowlistedServiceActionWithVerifier(context.Background(), controller, "enable-now", "workagent-backup.timer", allowServiceActionSource)
	if err == nil || !strings.Contains(err.Error(), "durable intent is committed") {
		t.Fatalf("pending durable result=%v", err)
	}
	if want := [][]string{{"enable", "--now", "workagent-backup.timer"}, {"enable", "--now", "workagent-backup.timer"}}; !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("pending durable actions=%v want=%v", controller.actions, want)
	}
}

func TestServiceActionSourceMustMatchSignedControlAssets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned source contract requires root")
	}
	root := t.TempDir()
	controlRoot := filepath.Join(root, "control")
	systemdRoot := filepath.Join(root, "systemd")
	for _, directory := range []string{
		filepath.Join(controlRoot, "share/deploy/systemd/caddy.service.d"),
		filepath.Join(systemdRoot, "caddy.service.d"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, payload string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(controlRoot, "share/deploy/systemd/caddy.service"), "trusted fragment\n")
	write(filepath.Join(systemdRoot, "caddy.service"), "trusted fragment\n")
	write(filepath.Join(controlRoot, "share/deploy/systemd/caddy.service.d/workagent.conf"), "trusted drop-in\n")
	write(filepath.Join(systemdRoot, "caddy.service.d/workagent.conf"), "trusted drop-in\n")
	properties := map[string]string{
		"FragmentPath": filepath.Join(systemdRoot, "caddy.service"),
		"DropInPaths":  filepath.Join(systemdRoot, "caddy.service.d/workagent.conf"),
	}
	if err := verifyServiceActionSourceAt("caddy.service", properties, controlRoot, []string{systemdRoot}); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(systemdRoot, "caddy.service"), "foreign fragment\n")
	if err := verifyServiceActionSourceAt("caddy.service", properties, controlRoot, []string{systemdRoot}); err == nil {
		t.Fatal("foreign Caddy fragment was accepted")
	}
	write(filepath.Join(systemdRoot, "caddy.service"), "trusted fragment\n")
	properties["DropInPaths"] += " " + filepath.Join(systemdRoot, "foreign.conf")
	if err := verifyServiceActionSourceAt("caddy.service", properties, controlRoot, []string{systemdRoot}); err == nil {
		t.Fatal("extra Caddy drop-in was accepted")
	}
}

func TestPortalEdgeSourceMustMatchSignedUnitAndCredentialTemplate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned source contract requires root")
	}
	root := t.TempDir()
	controlRoot := filepath.Join(root, "control")
	systemdRoot := filepath.Join(root, "systemd")
	controlDropIns := filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service.d")
	installedDropIns := filepath.Join(systemdRoot, "workagent-portal.service.d")
	for _, directory := range []string{controlDropIns, installedDropIns} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, payload string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const fragment = "trusted Portal fragment\n"
	const chat = "trusted ChatForward drop-in\n"
	const credentials = "[Service]\nLoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/cliproxy-management-key.cred\n# LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred\n"
	write(filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service"), fragment)
	write(filepath.Join(systemdRoot, "workagent-portal.service"), fragment)
	write(filepath.Join(controlDropIns, "chatforward.conf"), chat)
	write(filepath.Join(installedDropIns, "chatforward.conf"), chat)
	write(filepath.Join(controlDropIns, "credentials.conf.example"), credentials)
	write(filepath.Join(installedDropIns, "credentials.conf"), credentials)
	properties := map[string]string{
		"FragmentPath": filepath.Join(systemdRoot, "workagent-portal.service"),
		"DropInPaths":  filepath.Join(installedDropIns, "credentials.conf") + " " + filepath.Join(installedDropIns, "chatforward.conf"),
	}
	portal := config.Portal{}
	if err := verifyPortalEdgeUnitSourceAt(properties, portal, controlRoot, []string{systemdRoot}, systemdRoot); err != nil {
		t.Fatal(err)
	}
	portal.AdminMasterPasswordHashFile = "/run/credentials/workagent-portal.service/admin-master-password-hash"
	enabledCredentials := strings.Replace(credentials, "# LoadCredentialEncrypted=admin-master-password-hash:", "LoadCredentialEncrypted=admin-master-password-hash:", 1)
	write(filepath.Join(installedDropIns, "credentials.conf"), enabledCredentials)
	if err := verifyPortalEdgeUnitSourceAt(properties, portal, controlRoot, []string{systemdRoot}, systemdRoot); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(installedDropIns, "credentials.conf"), enabledCredentials+"Environment=FOREIGN=1\n")
	if err := verifyPortalEdgeUnitSourceAt(properties, portal, controlRoot, []string{systemdRoot}, systemdRoot); err == nil {
		t.Fatal("foreign Portal credential drop-in directive was accepted")
	}
}

func TestCaddyLiveConfigMatchesRunningAdminAPI(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned signed Caddyfile contract requires root")
	}
	root := t.TempDir()
	// Go 1.26+ creates t.TempDir with 0o755; the Caddy admin contract
	// requires the protected parent directory to be exactly 0o700.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "admin.sock")
	caddyfilePath := filepath.Join(root, "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte("example.test { respond 200 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(caddyfilePath, 0o644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var live atomic.Value
	live.Store(`{"apps":{"http":{"servers":{"edge":{"listen":[":443"]}}}},"admin":{"listen":"unix//admin.sock"}}`)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Host != "localhost" {
			http.Error(writer, "invalid admin origin", http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/adapt":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "text/caddyfile" {
				http.Error(writer, "invalid adapt request", http.StatusBadRequest)
				return
			}
			_, _ = writer.Write([]byte(`{"admin":{"listen":"unix//admin.sock"},"apps":{"http":{"servers":{"edge":{"listen":[":443"]}}}}}`))
		case "/config/":
			_, _ = writer.Write([]byte(live.Load().(string)))
		default:
			http.NotFound(writer, request)
		}
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serveDone
	}()
	if err := verifyCaddyLiveConfigAt(context.Background(), socketPath, caddyfilePath, int32(os.Getpid()), uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	if err := verifyCaddyLiveConfigAt(context.Background(), socketPath, caddyfilePath, int32(os.Getpid()+1), uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("Caddy admin peer from a different process generation was accepted")
	}
	live.Store(`{"apps":{"http":{"servers":{"foreign":{"listen":[":80"]}}}}}`)
	if err := verifyCaddyLiveConfigAt(context.Background(), socketPath, caddyfilePath, int32(os.Getpid()), uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("running Caddy configuration drift was accepted")
	}
}

func TestCaddyEdgePublicationRequiresExplicitConfirmationAndFullReadiness(t *testing.T) {
	if err := validateServiceActionConfirmation("enable-now", "caddy.service", edgePublicationConfirmation); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ action, unit, confirm string }{
		{action: "enable-now", unit: "caddy.service"},
		{action: "enable-now", unit: "caddy.service", confirm: "YES"},
		{action: "start", unit: "caddy.service", confirm: edgePublicationConfirmation},
		{action: "start", unit: "cliproxyapi.service", confirm: edgePublicationConfirmation},
	} {
		if err := validateServiceActionConfirmation(input.action, input.unit, input.confirm); err == nil {
			t.Fatalf("unsafe edge confirmation was accepted: %+v", input)
		}
	}
	portal := config.Portal{Listener: config.Listener{Address: productionPortalAddress, PublicOrigin: productionPortalPublicOrigin}}
	if err := validateProductionPortalEdgeBinding(portal); err != nil {
		t.Fatal(err)
	}
	portal.Listener.PublicOrigin = "https://foreign.example.test"
	if err := validateProductionPortalEdgeBinding(portal); err == nil {
		t.Fatal("Portal origin not represented by the signed Caddyfile was accepted")
	}
	now := time.Now().UTC()
	components := map[string]edgeReadinessComponent{}
	for _, name := range []string{"audit", "brand", "chat_forward", "cli_proxy", "database", "host", "notifications", "policy", "renderer", "tenants"} {
		components[name] = edgeReadinessComponent{Ready: true}
	}
	report := edgeReadinessReport{Status: "ready", Ready: true, CheckedAt: now, PolicyID: "policy", BrandID: "brand", Components: components}
	if err := validatePortalEdgeReadinessReport(report, now, "policy", "brand"); err != nil {
		t.Fatal(err)
	}
	components["cli_proxy"] = edgeReadinessComponent{}
	if err := validatePortalEdgeReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("unready dependency was accepted for edge publication")
	}
	components["cli_proxy"] = edgeReadinessComponent{Ready: true}
	report.CheckedAt = now.Add(-time.Minute)
	if err := validatePortalEdgeReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("stale readiness evidence was accepted for edge publication")
	}
	report.CheckedAt = now
	components["foreign"] = edgeReadinessComponent{Ready: true}
	if err := validatePortalEdgeReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("unexpected readiness component set was accepted")
	}
	delete(components, "foreign")
	report.PolicyID = "foreign-policy"
	if err := validatePortalEdgeReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("readiness from a different protected policy was accepted")
	}
}

func TestAdoptInheritedActivationLockBindsExactReadWriteInode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned activation lock metadata requires root")
	}
	path := filepath.Join(t.TempDir(), "activation.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := adoptInheritedActivationLock(int(file.Fd()), path); err != nil {
		t.Fatal(err)
	}
	competitor, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(competitor)
	if err := unix.Flock(competitor, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("adopted lock was not retained on the inherited open description: %v", err)
	}
	alias := filepath.Join(filepath.Dir(path), "alias.lock")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := adoptInheritedActivationLock(int(file.Fd()), alias); err == nil {
		t.Fatal("symlink activation pathname was accepted")
	}
	readOnlyPath := filepath.Join(filepath.Dir(path), "activation-read-only.lock")
	if err := os.WriteFile(readOnlyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(readOnlyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := adoptInheritedActivationLock(int(readOnly.Fd()), readOnlyPath); err != nil {
		t.Fatalf("systemd-style read-only activation capability was rejected: %v", err)
	}
	writeOnly, err := os.OpenFile(filepath.Join(filepath.Dir(path), "activation-write-only.lock"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writeOnly.Close()
	if err := adoptInheritedActivationLock(int(writeOnly.Fd()), writeOnly.Name()); err == nil {
		t.Fatal("write-only activation capability was accepted")
	}
}

func TestAdoptedActivationCleanlinessRejectsPendingEdgePublicationFirst(t *testing.T) {
	originalBackup := assertBackupQuiescenceCleanForInheritedActivation
	originalCore := assertCoreActivationCleanForInheritedActivation
	original := assertEdgePublicationCleanForInheritedActivation
	t.Cleanup(func() {
		assertBackupQuiescenceCleanForInheritedActivation = originalBackup
		assertCoreActivationCleanForInheritedActivation = originalCore
		assertEdgePublicationCleanForInheritedActivation = original
	})
	assertBackupQuiescenceCleanForInheritedActivation = func() error { return nil }
	assertCoreActivationCleanForInheritedActivation = func() error { return nil }
	sentinel := errors.New("pending edge publication fixture")
	calls := 0
	assertEdgePublicationCleanForInheritedActivation = func() error {
		calls++
		return sentinel
	}
	err := assertActivationStateCleanUnderAdoptedLock()
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "refuse activation mutation with a pending edge publication") {
		t.Fatalf("pending edge-publication result=%v", err)
	}
	if calls != 1 {
		t.Fatalf("edge-publication cleanliness calls=%d want 1", calls)
	}
}

func TestAdoptedActivationCleanlinessRejectsPendingCoreBeforeOtherProtocols(t *testing.T) {
	originalBackup := assertBackupQuiescenceCleanForInheritedActivation
	originalCore := assertCoreActivationCleanForInheritedActivation
	originalEdge := assertEdgePublicationCleanForInheritedActivation
	t.Cleanup(func() {
		assertBackupQuiescenceCleanForInheritedActivation = originalBackup
		assertCoreActivationCleanForInheritedActivation = originalCore
		assertEdgePublicationCleanForInheritedActivation = originalEdge
	})
	sentinel := errors.New("pending core activation fixture")
	edgeCalls := 0
	assertBackupQuiescenceCleanForInheritedActivation = func() error { return nil }
	assertCoreActivationCleanForInheritedActivation = func() error { return sentinel }
	assertEdgePublicationCleanForInheritedActivation = func() error {
		edgeCalls++
		return nil
	}
	err := assertActivationStateCleanUnderAdoptedLock()
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "pending core activation") {
		t.Fatalf("pending core-activation result=%v", err)
	}
	if edgeCalls != 0 {
		t.Fatalf("edge cleanliness ran after pending core evidence: calls=%d", edgeCalls)
	}
}

func TestAdoptedActivationCleanlinessRejectsPendingBackupQuiescenceBeforeOtherProtocols(t *testing.T) {
	originalBackup := assertBackupQuiescenceCleanForInheritedActivation
	originalCore := assertCoreActivationCleanForInheritedActivation
	originalEdge := assertEdgePublicationCleanForInheritedActivation
	t.Cleanup(func() {
		assertBackupQuiescenceCleanForInheritedActivation = originalBackup
		assertCoreActivationCleanForInheritedActivation = originalCore
		assertEdgePublicationCleanForInheritedActivation = originalEdge
	})
	sentinel := errors.New("pending backup quiescence fixture")
	coreCalls, edgeCalls := 0, 0
	assertBackupQuiescenceCleanForInheritedActivation = func() error { return sentinel }
	assertCoreActivationCleanForInheritedActivation = func() error {
		coreCalls++
		return nil
	}
	assertEdgePublicationCleanForInheritedActivation = func() error {
		edgeCalls++
		return nil
	}
	err := assertActivationStateCleanUnderAdoptedLock()
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "pending backup quiescence recovery") {
		t.Fatalf("pending backup-quiescence result=%v", err)
	}
	if coreCalls != 0 || edgeCalls != 0 {
		t.Fatalf("later cleanliness protocols ran after pending backup evidence: core=%d edge=%d", coreCalls, edgeCalls)
	}
}

func (controller *catalogReadySystemd) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	controller.reads++
	if unit != tenantCatalogReadyTarget {
		return nil, errors.New("unexpected unit")
	}
	active := "inactive"
	if controller.active {
		active = "active"
	}
	return map[string]string{"LoadState": "loaded", "ActiveState": active, "UnitFileState": controller.unitState}, nil
}

func (controller *catalogReadySystemd) Action(_ context.Context, arguments ...string) error {
	if !reflect.DeepEqual(arguments, []string{"start", tenantCatalogReadyTarget}) {
		return errors.New("unexpected action")
	}
	controller.actions++
	controller.active = true
	return nil
}

func TestTenantCatalogReadyStartsColdLatchBeforeReadback(t *testing.T) {
	controller := &catalogReadySystemd{unitState: "static"}
	if err := requireTenantCatalogReady(context.Background(), controller); err != nil {
		t.Fatal(err)
	}
	if controller.actions != 1 || controller.reads != 2 || !controller.active {
		t.Fatalf("cold readiness latch was not started and read back exactly: %+v", controller)
	}
	unsafe := &catalogReadySystemd{unitState: "enabled"}
	if err := requireTenantCatalogReady(context.Background(), unsafe); err == nil || unsafe.actions != 0 {
		t.Fatalf("non-static readiness latch was activated: actions=%d err=%v", unsafe.actions, err)
	}
}

func TestDisableUserCommitsSessionRevocationBeforeSystemdReplay(t *testing.T) {
	originalPrepare := prepareTenantActivation
	originalReplay := replayTenantActivation
	t.Cleanup(func() {
		prepareTenantActivation = originalPrepare
		replayTenantActivation = originalReplay
	})
	root := t.TempDir()
	data, err := store.Open(filepath.Join(root, "state", "portal.db"), filepath.Join(root, "state", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	hash, err := auth.HashPassword([]byte("a sufficiently long password"))
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "11111111-1111-4111-8111-111111111111"
	userValue, err := data.CreateUser(context.Background(), "alice", hash, tenantID, "workagent_alice", filepath.Join(root, "tenant"), false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := data.CreateSession(context.Background(), "session-token", "csrf-token", userValue, "192.0.2.1", "test", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	controller := &recordingSystemd{}
	prepareTenantActivation = func(_ context.Context, identities []store.PortalUserIdentity, gotTenantID string, desired bool) error {
		if len(identities) != 1 || identities[0].TenantID != tenantID || !identities[0].Enabled || gotTenantID != tenantID || desired {
			t.Fatalf("unexpected durable intent: identities=%+v tenant=%q desired=%t", identities, gotTenantID, desired)
		}
		return nil
	}
	replayTenantActivation = func(ctx context.Context, identities []store.PortalUserIdentity, systemd systemdctl.Controller) error {
		current, err := data.UserByUsername(context.Background(), "alice")
		if err != nil || current.Enabled || len(identities) != 1 || identities[0].Enabled {
			t.Errorf("database revocation was not the replay linearization point: current=%+v identities=%+v err=%v", current, identities, err)
		}
		if _, err := data.SessionByToken(ctx, "session-token"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Portal session survived database revocation: %v", err)
		}
		if err := systemd.Action(ctx, "disable", "--now", "workagent-userhost@"+tenantID+".socket"); err != nil {
			return err
		}
		return systemd.Action(ctx, "stop", "workagent-userhost@"+tenantID+".service")
	}
	if _, err := commitUserEnabledState(context.Background(), data, userValue, false, controller); err != nil {
		t.Fatal(err)
	}
	current, err := data.UserByUsername(context.Background(), "alice")
	if err != nil || current.Enabled {
		t.Fatalf("user remains enabled: %+v err=%v", current, err)
	}
	want := [][]string{{"disable", "--now", "workagent-userhost@" + tenantID + ".socket"}, {"stop", "workagent-userhost@" + tenantID + ".service"}}
	if !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("actions=%v want=%v", controller.actions, want)
	}
}

func TestFailedRuntimeRestorationUsesDurableRevocationReplay(t *testing.T) {
	originalPrepare := prepareTenantActivation
	originalReplay := replayTenantActivation
	t.Cleanup(func() {
		prepareTenantActivation = originalPrepare
		replayTenantActivation = originalReplay
	})
	root := t.TempDir()
	data, err := store.Open(filepath.Join(root, "portal.db"), filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	hash, err := auth.HashPassword([]byte("a sufficiently long password"))
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "11111111-1111-4111-8111-111111111111"
	userValue, err := data.CreateUser(context.Background(), "alice", hash, tenantID, "workagent_alice", filepath.Join(root, "tenant"), false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prepared := false
	prepareTenantActivation = func(_ context.Context, identities []store.PortalUserIdentity, gotTenantID string, desired bool) error {
		prepared = true
		if len(identities) != 1 || !identities[0].Enabled || gotTenantID != tenantID || desired {
			t.Fatalf("unexpected compensation intent: identities=%+v tenant=%q desired=%t", identities, gotTenantID, desired)
		}
		return nil
	}
	controller := &recordingSystemd{}
	replayTenantActivation = func(ctx context.Context, identities []store.PortalUserIdentity, systemd systemdctl.Controller) error {
		if !prepared || len(identities) != 1 || identities[0].Enabled {
			t.Fatalf("revocation replay did not follow its durable intent: prepared=%t identities=%+v", prepared, identities)
		}
		current, err := data.UserByUsername(ctx, "alice")
		if err != nil || current.Enabled {
			t.Fatalf("revocation replay ran before the database commit: user=%+v err=%v", current, err)
		}
		if err := systemd.Action(ctx, "disable", "--now", "workagent-userhost@"+tenantID+".socket"); err != nil {
			return err
		}
		return systemd.Action(ctx, "stop", "workagent-userhost@"+tenantID+".service")
	}
	sentinel := errors.New("runtime activation failed")
	err = restoreEnabledTenantRuntimeAfterFailure(context.Background(), config.Portal{}, data, userValue, controller,
		"workagent-userhost@"+tenantID+".socket", "workagent-userhost@"+tenantID+".service", sentinel)
	if !errors.Is(err, sentinel) {
		t.Fatalf("original activation failure was lost: %v", err)
	}
	current, lookupErr := data.UserByUsername(context.Background(), "alice")
	if lookupErr != nil || current.Enabled {
		t.Fatalf("failed restoration did not revoke the user: user=%+v err=%v", current, lookupErr)
	}
	want := [][]string{
		{"stop", "workagent-userhost@" + tenantID + ".service"},
		{"enable", "--now", "workagent-userhost@" + tenantID + ".socket"},
		{"disable", "--now", "workagent-userhost@" + tenantID + ".socket"},
		{"stop", "workagent-userhost@" + tenantID + ".service"},
	}
	if !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("actions=%v want=%v", controller.actions, want)
	}
}

func TestPortalRuntimePrivilegeDropRequiresExactUnprivilegedIdentity(t *testing.T) {
	if err := validatePortalRuntimeIdentity(1001, 1002, 1001, 1001, 1002, 1002, nil); err != nil {
		t.Fatalf("exact Portal runtime identity rejected: %v", err)
	}
	for name, test := range map[string]struct {
		realUID, effectiveUID, realGID, effectiveGID int
		groups                                       []int
	}{
		"retained-root":        {realUID: 0, effectiveUID: 1001, realGID: 1002, effectiveGID: 1002},
		"wrong-effective-user": {realUID: 1001, effectiveUID: 1003, realGID: 1002, effectiveGID: 1002},
		"wrong-primary-group":  {realUID: 1001, effectiveUID: 1001, realGID: 1003, effectiveGID: 1002},
		"supplementary-group":  {realUID: 1001, effectiveUID: 1001, realGID: 1002, effectiveGID: 1002, groups: []int{1002, 1004}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePortalRuntimeIdentity(1001, 1002, test.realUID, test.effectiveUID, test.realGID, test.effectiveGID, test.groups); err == nil {
				t.Fatal("unsafe post-drop identity was accepted")
			}
		})
	}
}

func TestRootAdminDropCreatesPortalStateAsRuntimeIdentity(t *testing.T) {
	if root := os.Getenv("WORKAGENT_TEST_DROPPED_STATE_ROOT"); root != "" {
		runtimeUser := os.Getenv("WORKAGENT_TEST_DROPPED_RUNTIME_USER")
		if err := dropToPortalRuntime(runtimeUser); err != nil {
			t.Fatal(err)
		}
		data, err := store.Open(filepath.Join(root, "portal.db"), filepath.Join(root, "audit.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if err := data.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required to exercise the real irreversible privilege drop in a child process")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("nobody test identity is unavailable: %v", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		t.Skip("nobody test identity is invalid")
	}
	root, err := os.MkdirTemp("", "workagent-admin-drop-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chown(root, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestRootAdminDropCreatesPortalStateAsRuntimeIdentity$")
	command.Env = append(os.Environ(), "WORKAGENT_TEST_DROPPED_STATE_ROOT="+root, "WORKAGENT_TEST_DROPPED_RUNTIME_USER="+account.Username)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("privilege-drop child failed: %v: %s", err, output)
	}
	for _, name := range []string{".runtime.lock", "portal.db", "audit.jsonl"} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("post-drop state %s has no stat identity", name)
		}
		if stat.Uid != uint32(uid) || stat.Gid != uint32(gid) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("post-drop state %s has unsafe identity: mode=%v uid=%d gid=%d", name, info.Mode(), stat.Uid, stat.Gid)
		}
	}
}
