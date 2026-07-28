package main

import (
	"context"
	"errors"


	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"

	"strconv"
	"strings"

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
