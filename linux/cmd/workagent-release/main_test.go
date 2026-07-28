package main

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fixedroot"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

type releaseMutationTestCloser struct {
	events *[]string
	err    error
}

func (closer *releaseMutationTestCloser) Close() error {
	*closer.events = append(*closer.events, "close-a")
	return closer.err
}

func TestCleanReleaseMutationAcquiresActivationBeforeJournalProofs(t *testing.T) {
	events := []string{}
	guard, err := acquireCleanReleaseMutationWith(
		context.Background(),
		func(context.Context) (io.Closer, error) {
			events = append(events, "acquire-a")
			return &releaseMutationTestCloser{events: &events}, nil
		},
		func() error { events = append(events, "recovery-clean"); return nil },
		func() error { events = append(events, "tenant-clean"); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"acquire-a", "recovery-clean", "tenant-clean", "close-a"}
	if !slices.Equal(events, want) {
		t.Fatalf("release mutation order=%v want=%v", events, want)
	}
}

func TestCleanReleaseMutationClosesActivationOnDirtyJournal(t *testing.T) {
	sentinel := errors.New("pending activation")
	for _, failAt := range []string{"recovery", "tenant"} {
		t.Run(failAt, func(t *testing.T) {
			events := []string{}
			guard, err := acquireCleanReleaseMutationWith(
				context.Background(),
				func(context.Context) (io.Closer, error) {
					events = append(events, "acquire-a")
					return &releaseMutationTestCloser{events: &events}, nil
				},
				func() error {
					events = append(events, "recovery-clean")
					if failAt == "recovery" {
						return sentinel
					}
					return nil
				},
				func() error {
					events = append(events, "tenant-clean")
					if failAt == "tenant" {
						return sentinel
					}
					return nil
				},
			)
			if guard != nil || !errors.Is(err, sentinel) || events[len(events)-1] != "close-a" {
				t.Fatalf("dirty journal result guard=%v err=%v events=%v", guard, err, events)
			}
		})
	}
}

func TestReleaseTenantEvidenceRejectsDirtyFileCatalogAfterPortalProof(t *testing.T) {
	sentinel := errors.New("pending tenant file transaction")
	events := []string{}
	portal := config.Portal{SchemaVersion: 5}
	err := verifyReleaseTenantCatalogAdmission(
		portal,
		"/etc/workagent/portal.json",
		func(value config.Portal, path string) error {
			events = append(events, "verify-portal-files")
			if value.SchemaVersion != portal.SchemaVersion || path != "/etc/workagent/portal.json" {
				t.Fatal("release tenant admission changed its protected Portal evidence")
			}
			return nil
		},
		func(value config.Portal) error {
			events = append(events, "assert-tenant-file-catalog-clean")
			if value.SchemaVersion != portal.SchemaVersion {
				t.Fatal("release tenant admission changed the Portal catalog root")
			}
			return sentinel
		},
	)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "uncommitted tenant file catalog") {
		t.Fatalf("dirty tenant file catalog was not rejected: %v", err)
	}
	if want := []string{"verify-portal-files", "assert-tenant-file-catalog-clean"}; !slices.Equal(events, want) {
		t.Fatalf("release tenant admission order=%v want=%v", events, want)
	}
	if err := verifyReleaseTenantCatalogAdmission(portal, "/etc/workagent/portal.json", nil, func(config.Portal) error { return nil }); err == nil {
		t.Fatal("release tenant admission accepted a missing Portal-file verifier")
	}
}

type releaseSystemd struct {
	states   map[string]string
	checked  *[]string
	loaded   []string
	override map[string]map[string]string
}

func useTrustedTestRevision(t *testing.T, revision string) {
	t.Helper()
	previous := trustedExecutingSourceRevision
	trustedExecutingSourceRevision = func() (string, error) { return revision, nil }
	t.Cleanup(func() { trustedExecutingSourceRevision = previous })
}

func TestAdmissionExecutableRevisionRequiresCleanEmbeddedGitEvidence(t *testing.T) {
	revision := strings.Repeat("a", 40)
	clean := &debug.BuildInfo{Path: "github.com/linziyan1231-source/WorkAgent2/linux/cmd/workagent-release", Settings: []debug.BuildSetting{
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: revision},
		{Key: "vcs.modified", Value: "false"},
	}}
	if got, err := sourceRevisionFromBuildInfo(clean, true); err != nil || got != revision {
		t.Fatalf("clean embedded Git revision rejected: got=%q err=%v", got, err)
	}
	for name, mutate := range map[string]func(*debug.BuildInfo){
		"dirty":        func(info *debug.BuildInfo) { info.Settings[2].Value = "true" },
		"missing":      func(info *debug.BuildInfo) { info.Settings = info.Settings[:2] },
		"wrong length": func(info *debug.BuildInfo) { info.Settings[1].Value = strings.Repeat("a", 64) },
		"uppercase":    func(info *debug.BuildInfo) { info.Settings[1].Value = strings.Repeat("A", 40) },
	} {
		t.Run(name, func(t *testing.T) {
			copyInfo := *clean
			copyInfo.Settings = append([]debug.BuildSetting(nil), clean.Settings...)
			mutate(&copyInfo)
			if _, err := sourceRevisionFromBuildInfo(&copyInfo, true); err == nil {
				t.Fatal("unsafe embedded revision evidence was accepted")
			}
		})
	}
	if _, err := sourceRevisionFromBuildInfo(nil, false); err == nil {
		t.Fatal("missing build information was accepted")
	}
	foreign := *clean
	foreign.Path = "example.test/foreign"
	if _, err := sourceRevisionFromBuildInfo(&foreign, true); err == nil {
		t.Fatal("foreign Go main package build evidence was accepted")
	}
}

func TestPreflightRequiresAnEnabledAdministrator(t *testing.T) {
	if err := validatePreflightUserSet(nil); err == nil || !strings.Contains(err.Error(), "enabled tenant") {
		t.Fatalf("empty identity set was accepted: %v", err)
	}
	if err := validatePreflightUserSet([]store.User{{Enabled: true}}); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatalf("enabled non-admin-only identity set was accepted: %v", err)
	}
	if err := validatePreflightUserSet([]store.User{{Enabled: true, Admin: true}}); err != nil {
		t.Fatalf("enabled administrator was rejected: %v", err)
	}
}

func TestMaintenanceNoticeIsObservedThroughAuthenticatedPortalEndpoint(t *testing.T) {
	const targetRelease = "runtime-20260726"
	const session = "portal-session-abcdefghijklmnopqrstuvwxyz"
	observedAt := time.Unix(1_800_000_000, 0).UTC()
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("__Host-aionui-portal")
		if err != nil || cookie.Value != session || request.Host != "portal.example.test" || request.Header.Get("X-Forwarded-Proto") != "https" || request.URL.Path != "/api/portal/me/notifications" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"data":{"notifications":[{"id":"` + release.ExpectedMaintenanceNoticeID(targetRelease) + `","message":"` + release.MaintenanceNoticeMessage + `","published_at":"` + observedAt.Add(-2*time.Minute).Format(time.RFC3339) + `"}]}}`))
	}))
	defer upstream.Close()
	address := upstream.Listener.Addr().String()
	if host, _, err := net.SplitHostPort(address); err != nil || host != "127.0.0.1" {
		t.Skipf("test server did not bind an IPv4 loopback address: %s", address)
	}
	portal := config.Portal{
		Listener: config.Listener{Network: "tcp", Address: address, PublicOrigin: "https://portal.example.test", RequireForwardedHTTPS: true},
		Session:  config.SessionPolicy{CookieName: "__Host-aionui-portal"},
	}
	notice, err := checkMaintenanceNoticeWithSession(context.Background(), portal, []byte(session), targetRelease, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if notice.ID != release.ExpectedMaintenanceNoticeID(targetRelease) || notice.Message != release.MaintenanceNoticeMessage || !notice.PublishedAt.Equal(observedAt.Add(-2*time.Minute)) {
		t.Fatalf("unexpected maintenance notice evidence: %+v", notice)
	}
}

func (s releaseSystemd) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	if s.checked != nil {
		*s.checked = append(*s.checked, unit)
	}
	state := s.states[unit]
	properties := map[string]string{"LoadState": "loaded", "ActiveState": state, "SubState": "dead", "ControlPID": "0", "MainPID": "0", "Result": "success", "UnitFileState": "disabled"}
	if state == "active" {
		properties["SubState"] = "running"
	}
	if state == "failed" {
		properties["SubState"] = "failed"
		properties["Result"] = "exit-code"
	}
	for name, value := range s.override[unit] {
		properties[name] = value
	}
	return properties, nil
}

func (releaseSystemd) Action(context.Context, ...string) error { return nil }

func (s releaseSystemd) ListUnits(context.Context, ...string) ([]string, error) {
	if s.loaded != nil {
		return append([]string(nil), s.loaded...), nil
	}
	var result []string
	for unit := range s.states {
		if strings.HasPrefix(unit, "workagent-userhost@") {
			result = append(result, unit)
		}
	}
	slices.Sort(result)
	return result, nil
}

func TestReleaseDrainGateIncludesSocketsAndServices(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	configs := map[string]string{tenantID: "/etc/workagent/users/" + tenantID + ".json"}
	controller := releaseSystemd{states: map[string]string{
		"workagent-userhost@" + tenantID + ".socket":  "active",
		"workagent-userhost@" + tenantID + ".service": "inactive",
		"workagent-portal.service":                    "inactive",
	}}
	portal := config.Portal{Renderer: config.RendererRelease{Scope: release.ScopeRuntime}}
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, controller); err == nil {
		t.Fatal("active socket was accepted during release activation")
	}
	controller.states["workagent-userhost@"+tenantID+".socket"] = "inactive"
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, controller); err != nil {
		t.Fatalf("fully stopped runtime fleet was rejected: %v", err)
	}
}

func TestReleaseDrainGateRejectsFailedBusyAndUnconfiguredTenantUnits(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	service := "workagent-userhost@" + tenantID + ".service"
	socket := "workagent-userhost@" + tenantID + ".socket"
	configs := map[string]string{tenantID: "/etc/workagent/users/" + tenantID + ".json"}
	portal := config.Portal{Renderer: config.RendererRelease{Scope: release.ScopeRuntime}}
	baseStates := map[string]string{service: "inactive", socket: "inactive", "workagent-portal.service": "inactive"}

	failed := releaseSystemd{states: maps.Clone(baseStates)}
	failed.states[service] = "failed"
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, failed); err == nil {
		t.Fatal("failed tenant service was accepted as drained")
	}

	busy := releaseSystemd{states: maps.Clone(baseStates), override: map[string]map[string]string{service: {"MainPID": "42"}}}
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, busy); err == nil {
		t.Fatal("tenant service with a live PID was accepted as drained")
	}

	unknownID := "22222222-2222-4222-8222-222222222222"
	unknown := releaseSystemd{states: maps.Clone(baseStates), loaded: []string{service, socket, "workagent-userhost@" + unknownID + ".service"}}
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, unknown); err == nil {
		t.Fatal("loaded unit without a protected tenant configuration was accepted")
	}
}

func TestSharedReleaseDrainGateRequiresChatForwardBrowserThenBridge(t *testing.T) {
	checked := []string{}
	controller := releaseSystemd{
		states: map[string]string{
			"workagent-chatforward-browser.service": "active",
			"workagent-chatforward.service":         "inactive",
		},
		checked: &checked,
	}
	if err := ensureReleaseFleetStopped(context.Background(), config.Portal{}, nil, release.ScopeShared, controller); err == nil {
		t.Fatal("active ChatForward browser was accepted during shared release activation")
	}
	if len(checked) != 1 || checked[0] != "workagent-chatforward-browser.service" {
		t.Fatalf("ChatForward drain check did not start with the browser: %#v", checked)
	}

	checked = checked[:0]
	controller.states["workagent-chatforward-browser.service"] = "inactive"
	controller.states["workagent-chatforward.service"] = "inactive"
	if err := ensureReleaseFleetStopped(context.Background(), config.Portal{}, nil, release.ScopeShared, controller); err != nil {
		t.Fatalf("stopped ChatForward services were rejected: %v", err)
	}
	want := []string{"workagent-chatforward-browser.service", "workagent-chatforward.service"}
	if len(checked) != len(want) || checked[0] != want[0] || checked[1] != want[1] {
		t.Fatalf("unexpected ChatForward drain order: got %#v want %#v", checked, want)
	}
}

func TestConfiguredRuntimeConsumerContractMatchesProductionExamples(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	portal, err := config.LoadPortal(filepath.Join(repositoryRoot, "config", "portal.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	tenantPath := filepath.Join(repositoryRoot, "config", "tenant.example.json")
	contract, err := deriveChannelConsumerContract(
		portal,
		map[string]string{"11111111-1111-4111-8111-111111111111": tenantPath},
		portal.Renderer.ReleasesRoot,
		portal.Renderer.PointerFile,
		portal.Renderer.Scope,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantData := []string{
		"workagent-builtin-assistants/assistants.json",
		"workagent-builtin-assistants/rules/aionui-assistant.en-US.md",
		"workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md",
		"workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md",
		"static/index.html",
	}
	wantExecutables := []string{"bin/aioncore", "bin/aionui-web", "bin/codex", "bin/kimi", "bin/python3"}
	if !slices.Equal(contract.RequiredPaths, wantData) || !slices.Equal(contract.RequiredExecutablePaths, wantExecutables) {
		t.Fatalf("production runtime consumer contract drifted:\ngot  %#v / %#v\nwant %#v / %#v", contract.RequiredPaths, contract.RequiredExecutablePaths, wantData, wantExecutables)
	}
	if _, err := deriveChannelConsumerContract(portal, map[string]string{"11111111-1111-4111-8111-111111111111": tenantPath}, portal.Renderer.ReleasesRoot, portal.Renderer.PointerFile, release.ScopeCombined); err == nil {
		t.Fatal("combined-scope mutable release activation was accepted")
	}
}

func TestFixedRootConsumerContractsMatchProductionEvidence(t *testing.T) {
	control, err := productionFixedRootSpec(fixedroot.ControlPath)
	if err != nil {
		t.Fatal(err)
	}
	wantControlData := []string{
		"share/deploy/caddy/Caddyfile",
		"share/deploy/systemd/caddy.service",
		"share/deploy/systemd/caddy.service.d/workagent.conf",
		"share/deploy/systemd/cliproxyapi.service",
		"share/deploy/systemd/srv-workagent-users.mount",
		"share/deploy/systemd/workagent-backup.service",
		"share/deploy/systemd/workagent-backup.timer",
		"share/deploy/systemd/workagent-chatforward-browser.service",
		"share/deploy/systemd/workagent-chatforward.service",
		"share/deploy/systemd/workagent-healthcheck.service",
		"share/deploy/systemd/workagent-healthcheck.timer",
		"share/deploy/systemd/workagent-notification.service",
		"share/deploy/systemd/workagent-portal.service",
		"share/deploy/systemd/workagent-portal.service.d/chatforward.conf",
		"share/deploy/systemd/workagent-portal.service.d/credentials.conf.example",
		"share/deploy/systemd/workagent-tenant-catalog-ready.target",
		"share/deploy/systemd/workagent-tenant-config-reconcile.service",
		"share/deploy/systemd/workagent-userhost@.service",
		"share/deploy/systemd/workagent-userhost@.socket",
	}
	wantControl := []string{
		"admin/install-core-activation-admission-v1",
		"admin/install-edge-publication-admission-v1",
		"admin/install-fixed-root-exec-v1",
		"admin/install-recovery-activation-admission-v1",
		"admin/production-host-prepare",
		"admin/production-preflight",
		"admin/smoke-chatforward-browser-sandbox",
		"admin/verify-host-rpms",
		"bin/workagent-admin",
		"bin/workagent-backup",
		"bin/workagent-cliproxy",
		"bin/workagent-healthcheck",
		"bin/workagent-notification",
		"bin/workagent-portal",
		"bin/workagent-provision",
		"bin/workagent-release",
		"bin/workagent-secret",
		"bin/workagent-userhost",
		"share/deploy/libexec/workagent-core-activation-admission-v1",
		"share/deploy/libexec/workagent-edge-publication-admission-v1",
		"share/deploy/libexec/workagent-fixed-root-exec-v1",
		"share/deploy/libexec/workagent-recovery-activation-admission-v1",
	}
	if control.scope != release.ScopePortal || !slices.Equal(control.contract.RequiredPaths, wantControlData) || !slices.Equal(control.contract.RequiredExecutablePaths, wantControl) {
		t.Fatalf("control fixed-root contract drifted: %+v", control)
	}

	shared, err := productionFixedRootSpec(fixedroot.SharedPath)
	if err != nil {
		t.Fatal(err)
	}
	wantSharedData := []string{"chatforward/app/extension/manifest.json", "chatforward/app/src/server.js"}
	wantSharedExecutables := []string{
		"chatforward/integration/login.sh",
		"chatforward/integration/readiness.mjs",
		"chatforward/integration/run-browser.sh",
		"chatforward/integration/run-server.sh",
		"chatforward/node/bin/node",
		"cliproxyapi/bin/cli-proxy-api",
		"cliproxyapi/plugins/cpa-key-policy-v0.4.5.so",
	}
	if shared.scope != release.ScopeShared || !slices.Equal(shared.contract.RequiredPaths, wantSharedData) || !slices.Equal(shared.contract.RequiredExecutablePaths, wantSharedExecutables) {
		t.Fatalf("shared fixed-root contract drifted: %+v", shared)
	}
	if _, err := productionFixedRootSpec("/opt/workagent/other"); err == nil {
		t.Fatal("non-production fixed-root destination was accepted")
	}
}

func TestFixedRootDrainProvesExactControlFleetAndOrder(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	tenantSocket := "workagent-userhost@" + tenantID + ".socket"
	tenantService := "workagent-userhost@" + tenantID + ".service"
	wantOrder := []string{
		"caddy.service",
		"workagent-backup.timer",
		"workagent-healthcheck.timer",
		"workagent-chatforward-browser.service",
		"workagent-chatforward.service",
		"cliproxyapi.service",
		"workagent-portal.service",
		"workagent-backup.service",
		"workagent-healthcheck.service",
		"workagent-notification.service",
		"workagent-tenant-catalog-ready.target",
		"workagent-tenant-config-reconcile.service",
		tenantSocket,
		tenantService,
	}
	states := make(map[string]string, len(wantOrder))
	for _, unit := range wantOrder {
		states[unit] = "inactive"
	}
	checked := []string{}
	controller := releaseSystemd{states: states, checked: &checked, loaded: []string{tenantSocket, tenantService}}
	configs := map[string]string{tenantID: "/etc/workagent/users/" + tenantID + ".json"}
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.ControlPath, configs, controller); err != nil {
		t.Fatalf("clean control fleet was rejected: %v", err)
	}
	if !slices.Equal(checked, wantOrder) {
		t.Fatalf("fixed-root drain order drifted: got %#v want %#v", checked, wantOrder)
	}
	controller.override = map[string]map[string]string{"caddy.service": {"UnitFileState": "enabled"}}
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.ControlPath, configs, controller); err == nil {
		t.Fatal("durably enabled Caddy was accepted for a control-root swap")
	}
	controller.override = nil

	unknownID := "22222222-2222-4222-8222-222222222222"
	controller.loaded = append(controller.loaded, "workagent-userhost@"+unknownID+".service")
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.ControlPath, configs, controller); err == nil {
		t.Fatal("unconfigured loaded tenant consumer was accepted")
	}

	controller.loaded = []string{tenantSocket}
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.ControlPath, configs, controller); err == nil {
		t.Fatal("missing protected tenant service instance was accepted")
	}
}

func TestFixedRootDrainRejectsActiveSharedConsumerAndUnknownInitialTenant(t *testing.T) {
	states := map[string]string{
		"workagent-chatforward-browser.service": "inactive",
		"workagent-chatforward.service":         "inactive",
		"cliproxyapi.service":                   "active",
	}
	controller := releaseSystemd{states: states}
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.SharedPath, nil, controller); err == nil {
		t.Fatal("active shared-root consumer was accepted")
	}
	controller.states["cliproxyapi.service"] = "inactive"
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.SharedPath, nil, controller); err != nil {
		t.Fatalf("clean shared-root fleet was rejected: %v", err)
	}

	controlStates := map[string]string{
		"caddy.service":                             "inactive",
		"workagent-backup.timer":                    "inactive",
		"workagent-healthcheck.timer":               "inactive",
		"workagent-chatforward-browser.service":     "inactive",
		"workagent-chatforward.service":             "inactive",
		"cliproxyapi.service":                       "inactive",
		"workagent-portal.service":                  "inactive",
		"workagent-backup.service":                  "inactive",
		"workagent-healthcheck.service":             "inactive",
		"workagent-notification.service":            "inactive",
		"workagent-tenant-catalog-ready.target":     "inactive",
		"workagent-tenant-config-reconcile.service": "inactive",
	}
	unknownID := "22222222-2222-4222-8222-222222222222"
	initial := releaseSystemd{states: controlStates, loaded: []string{"workagent-userhost@" + unknownID + ".socket"}}
	if err := ensureFixedRootFleetStopped(context.Background(), fixedroot.ControlPath, map[string]string{}, initial); err == nil {
		t.Fatal("initial fixed-root drain hid a loaded tenant instance behind an empty config set")
	}
	initial.loaded = []string{}
	_, drain, err := fixedRootCallbacks(fixedroot.ControlPath, "/missing/bootstrap-portal.json", true, initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := drain(context.Background(), fixedroot.ControlPath); err != nil {
		t.Fatalf("bootstrap drain incorrectly required Portal or tenant configuration: %v", err)
	}
	if err := fixedReconcile([]string{"--destination", fixedroot.SharedPath, "--initial"}); err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("shared-root initial reconciliation was accepted: %v", err)
	}
}

func TestStandaloneVerifyAllowsManifestReleaseIDButRequiresAConsumer(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "missing-release")
	_, err := verifyRelease(missingRoot, "", release.ScopePortal, nil, []string{"bin/workagent-release"}, false)
	if err == nil || strings.Contains(err.Error(), "release-id") {
		t.Fatalf("standalone root verification still requires a release ID: %v", err)
	}
	_, err = verifyRelease(missingRoot, "", release.ScopePortal, nil, nil, false)
	if err == nil || !strings.Contains(err.Error(), "consumer contract") {
		t.Fatalf("standalone verification without a consumer contract was accepted: %v", err)
	}
}

func TestStandaloneVerifyAcceptsFixedRootWithoutReleaseIDFlag(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("fixed-root verification requires root-owned release evidence")
	}
	const releaseID = "control-20260727"
	sourceRevision := strings.Repeat("1", 40)
	useTrustedTestRevision(t, sourceRevision)
	root := filepath.Join(t.TempDir(), releaseID)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]struct {
		payload string
		mode    os.FileMode
	}{
		"bin/workagent-release": {payload: "fixed verifier", mode: 0o555},
		"provenance.json":       {payload: `{"schema_version":1,"release_id":"` + releaseID + `","source_revision":"` + sourceRevision + `","builder_id":"approved-builder","build_type":"production-build","invocation_id":"invocation-one","reproducible":true,"materials":[{"uri":"source:workagent","revision":"` + sourceRevision + `"},{"uri":"component:workagent-control@git-111111111111","revision":"` + sourceRevision + `"}]}`, mode: 0o444},
	}
	for relative, file := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.WriteFile(path, []byte(file.payload), file.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	manifestValue, err := release.BuildManifest(root, release.Manifest{
		ReleaseID: releaseID, SourceRevision: sourceRevision, BuiltAt: time.Now().UTC(), BrandingVersion: "brand-one", PolicyVersion: "policy-one",
		ComponentScope: release.ScopePortal, DataSchemaVersion: 1, MinimumReadableDataSchema: 1, MaximumReadableDataSchema: 1,
		Components: []release.Component{{Name: "workagent-control", Version: "git-111111111111", SourceRevision: sourceRevision}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := release.WriteManifest(manifestPath, manifestValue); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(root, "bin"), root} {
		if err := os.Chmod(directory, 0o555); err != nil {
			t.Fatal(err)
		}
	}
	verified, err := verifyRelease(root, "", release.ScopePortal, nil, []string{"bin/workagent-release"}, true)
	if err != nil {
		t.Fatalf("valid fixed root was rejected without --release-id: %v", err)
	}
	if verified.Manifest.ReleaseID != releaseID {
		t.Fatalf("verified release ID %q, want %q", verified.Manifest.ReleaseID, releaseID)
	}
	trustedExecutingSourceRevision = func() (string, error) { return strings.Repeat("2", 40), nil }
	if _, err := verifyRelease(root, "", release.ScopePortal, nil, []string{"bin/workagent-release"}, true); err == nil || !strings.Contains(err.Error(), "trusted admission executable") {
		t.Fatalf("candidate from a different source revision was accepted: %v", err)
	}
}

func TestManifestRejectsComponentBaselineBeforeCreatingManifest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("manifest admission requires root-owned release evidence")
	}
	releaseRoot := filepath.Join(t.TempDir(), "release-one")
	useTrustedTestRevision(t, strings.Repeat("1", 40))
	if err := os.Mkdir(releaseRoot, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(releaseRoot, 0o555); err != nil {
		t.Fatal(err)
	}
	componentsPath := filepath.Join(t.TempDir(), "components.json")
	components := `[{"name":"unapproved-component","version":"1.0.0","source_revision":"` + strings.Repeat("1", 40) + `"}]`
	if err := os.WriteFile(componentsPath, []byte(components), 0o444); err != nil {
		t.Fatal(err)
	}
	err := manifest([]string{
		"--root", releaseRoot,
		"--release-id", "release-one",
		"--source-revision", strings.Repeat("1", 40),
		"--branding-version", "brand-one",
		"--policy-version", "policy-one",
		"--scope", release.ScopeRuntime,
		"--data-schema-version", "1",
		"--minimum-readable-data-schema", "1",
		"--maximum-readable-data-schema", "1",
		"--components", componentsPath,
		"--required-executable", "bin/aioncore",
	})
	if err == nil || !strings.Contains(err.Error(), "component baseline") {
		t.Fatalf("unapproved component baseline was not rejected before manifest creation: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(releaseRoot, "manifest.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed manifest admission created manifest.json: %v", err)
	}
}

func TestManifestRejectsSourceRevisionDifferentFromAdmissionExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("manifest admission requires root-owned release evidence")
	}
	trustedRevision := strings.Repeat("1", 40)
	useTrustedTestRevision(t, trustedRevision)
	releaseRoot := filepath.Join(t.TempDir(), "release-one")
	if err := os.Mkdir(releaseRoot, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(releaseRoot, 0o555); err != nil {
		t.Fatal(err)
	}
	err := manifest([]string{
		"--root", releaseRoot,
		"--release-id", "release-one",
		"--source-revision", strings.Repeat("2", 40),
		"--scope", release.ScopePortal,
	})
	if err == nil || !strings.Contains(err.Error(), "trusted admission executable") {
		t.Fatalf("foreign manifest source revision was accepted: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(releaseRoot, "manifest.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed source admission created manifest.json: %v", statErr)
	}
}

func TestNamedReleaseCommandsRejectUnsafeIDBeforeReadingHostState(t *testing.T) {
	channel := t.TempDir()
	releasesRoot := filepath.Join(channel, "releases")
	pointer := filepath.Join(channel, "current.json")
	common := []string{
		"--releases-root", releasesRoot,
		"--pointer", pointer,
		"--release-id", "..",
		"--scope", release.ScopeRuntime,
	}
	if err := preflight(common); err == nil || !strings.Contains(err.Error(), "release-id") {
		t.Fatalf("preflight did not reject an unsafe release ID before host inspection: %v", err)
	}
	if err := activate(common); err == nil || !strings.Contains(err.Error(), "release-id") {
		t.Fatalf("activation did not reject an unsafe release ID before pointer/config inspection: %v", err)
	}
}

func TestPreflightOutputRejectsEveryProtectedInputPath(t *testing.T) {
	root := t.TempDir()
	write := func(relative string) string {
		t.Helper()
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(relative), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	pointerPath := write("channel/current.json")
	maintenanceSessionPath := write("secrets/maintenance-session")
	inputs := release.PreflightInputs{
		TargetManifestPath: write("channel/releases/release-one/manifest.json"),
		PortalConfigPath:   write("config/portal.json"),
		TenantConfigPaths: map[string]string{
			"11111111-1111-4111-8111-111111111111": write("config/users/11111111-1111-4111-8111-111111111111.json"),
		},
		BackupConfigPath: write("config/backup.json"),
		BackupKeyPath:    write("keys/backup.key"),
		BrandID:          "brand-one",
		BrandConfigPath:  write("config/brand.json"),
		BrandAssetPaths: map[string]string{
			"app-icon":  write("brand/app-icon.png"),
			"favicon":   write("brand/favicon.ico"),
			"logo":      write("brand/logo.png"),
			"logo-dark": write("brand/logo-dark.png"),
		},
		PolicyID:         "policy-one",
		PolicyConfigPath: write("config/policy.json"),
	}
	protected := []string{
		pointerPath,
		inputs.TargetManifestPath,
		inputs.PortalConfigPath,
		inputs.TenantConfigPaths["11111111-1111-4111-8111-111111111111"],
		inputs.BackupConfigPath,
		inputs.BackupKeyPath,
		inputs.BrandConfigPath,
		inputs.BrandAssetPaths["app-icon"],
		inputs.BrandAssetPaths["favicon"],
		inputs.BrandAssetPaths["logo"],
		inputs.BrandAssetPaths["logo-dark"],
		inputs.PolicyConfigPath,
		maintenanceSessionPath,
	}
	for _, outputPath := range protected {
		if err := validatePreflightOutputPath(outputPath, pointerPath, maintenanceSessionPath, inputs); err == nil || !strings.Contains(err.Error(), "aliases protected") {
			t.Errorf("protected preflight input was accepted as --output (%s): %v", outputPath, err)
		}
	}

	reportDirectory := filepath.Join(root, "reports")
	if err := os.Mkdir(reportDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePreflightOutputPath(filepath.Join(reportDirectory, "preflight.json"), pointerPath, maintenanceSessionPath, inputs); err != nil {
		t.Fatalf("independent preflight output was rejected: %v", err)
	}
	existingReport := write("reports/existing.json")
	if err := validatePreflightOutputPath(existingReport, pointerPath, maintenanceSessionPath, inputs); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("existing independent file was accepted as a mutable report target: %v", err)
	}
}

func TestPreflightOutputRejectsSymlinkHardlinkAndCanonicalAliases(t *testing.T) {
	root := t.TempDir()
	write := func(relative string) string {
		t.Helper()
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(relative), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	channelDirectory := filepath.Join(root, "channel")
	if err := os.MkdirAll(filepath.Join(channelDirectory, "releases", "release-one"), 0o700); err != nil {
		t.Fatal(err)
	}
	pointerPath := filepath.Join(channelDirectory, "current.json")
	inputs := release.PreflightInputs{
		TargetManifestPath: write("channel/releases/release-one/manifest.json"),
		PortalConfigPath:   write("config/portal.json"),
		TenantConfigPaths: map[string]string{
			"11111111-1111-4111-8111-111111111111": write("config/users/11111111-1111-4111-8111-111111111111.json"),
		},
		BackupConfigPath: write("config/backup.json"),
		BackupKeyPath:    write("keys/backup.key"),
		BrandID:          "brand-one",
		BrandConfigPath:  write("config/brand.json"),
		BrandAssetPaths: map[string]string{
			"app-icon":  write("brand/app-icon.png"),
			"favicon":   write("brand/favicon.ico"),
			"logo":      write("brand/logo.png"),
			"logo-dark": write("brand/logo-dark.png"),
		},
		PolicyID:         "policy-one",
		PolicyConfigPath: write("config/policy.json"),
	}
	reportDirectory := filepath.Join(root, "reports")
	if err := os.Mkdir(reportDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	symlinkOutput := filepath.Join(reportDirectory, "policy-symlink.json")
	if err := os.Symlink(inputs.PolicyConfigPath, symlinkOutput); err != nil {
		t.Fatal(err)
	}
	if err := validatePreflightOutputPath(symlinkOutput, pointerPath, "", inputs); err == nil || !strings.Contains(err.Error(), "aliases protected policy config") {
		t.Fatalf("symlink alias was accepted as preflight output: %v", err)
	}

	hardlinkOutput := filepath.Join(reportDirectory, "backup-key-hardlink.json")
	if err := os.Link(inputs.BackupKeyPath, hardlinkOutput); err != nil {
		t.Fatal(err)
	}
	if err := validatePreflightOutputPath(hardlinkOutput, pointerPath, "", inputs); err == nil || !strings.Contains(err.Error(), "aliases protected backup encryption key") {
		t.Fatalf("hardlink alias was accepted as preflight output: %v", err)
	}

	configAlias := filepath.Join(root, "config-alias")
	if err := os.Symlink(filepath.Join(root, "config"), configAlias); err != nil {
		t.Fatal(err)
	}
	canonicalAliasOutput := filepath.Join(configAlias, "portal.json")
	if err := validatePreflightOutputPath(canonicalAliasOutput, pointerPath, "", inputs); err == nil || !strings.Contains(err.Error(), "aliases protected Portal config") {
		t.Fatalf("parent-directory symlink alias was accepted as preflight output: %v", err)
	}

	channelAlias := filepath.Join(root, "channel-alias")
	if err := os.Symlink(channelDirectory, channelAlias); err != nil {
		t.Fatal(err)
	}
	missingPointerAlias := filepath.Join(channelAlias, "current.json")
	if err := validatePreflightOutputPath(missingPointerAlias, pointerPath, "", inputs); err == nil || !strings.Contains(err.Error(), "aliases protected release pointer") {
		t.Fatalf("missing pointer's canonical alias was accepted as preflight output: %v", err)
	}
}
