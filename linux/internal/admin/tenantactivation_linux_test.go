//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

type tenantActivationUnitState struct {
	loadState     string
	activeState   string
	unitFileState string
	subState      string
	mainPID       string
}

type tenantActivationSystemd struct {
	units       map[string]*tenantActivationUnitState
	actions     []string
	failAction  string
	failOnce    bool
	propertyErr error
}

func newTenantActivationSystemd(identities []store.PortalUserIdentity) *tenantActivationSystemd {
	controller := &tenantActivationSystemd{units: make(map[string]*tenantActivationUnitState)}
	for _, identity := range identities {
		controller.units[tenantActivationSocket(identity.TenantID)] = &tenantActivationUnitState{
			loadState: "loaded", activeState: "active", unitFileState: "enabled",
		}
		controller.units[tenantActivationService(identity.TenantID)] = &tenantActivationUnitState{
			loadState: "loaded", activeState: "active", subState: "running", mainPID: "1234",
		}
	}
	return controller
}

func (controller *tenantActivationSystemd) Action(_ context.Context, arguments ...string) error {
	joined := strings.Join(arguments, " ")
	controller.actions = append(controller.actions, joined)
	if controller.failAction == joined {
		if controller.failOnce {
			controller.failAction = ""
		}
		return errors.New("simulated systemd action failure")
	}
	switch {
	case len(arguments) == 2 && arguments[0] == "enable":
		state := controller.units[arguments[1]]
		if state == nil {
			return errors.New("unknown unit")
		}
		state.unitFileState = "enabled"
	case len(arguments) == 3 && arguments[0] == "disable" && arguments[1] == "--now":
		state := controller.units[arguments[2]]
		if state == nil {
			return errors.New("unknown unit")
		}
		state.unitFileState = "disabled"
		state.activeState = "inactive"
	case len(arguments) == 2 && arguments[0] == "stop":
		state := controller.units[arguments[1]]
		if state == nil {
			return errors.New("unknown unit")
		}
		state.activeState = "inactive"
		state.subState = "dead"
		state.mainPID = "0"
	default:
		return fmt.Errorf("unexpected systemd action %q", joined)
	}
	return nil
}

func (controller *tenantActivationSystemd) Properties(_ context.Context, unit string, names ...string) (map[string]string, error) {
	if controller.propertyErr != nil {
		return nil, controller.propertyErr
	}
	state := controller.units[unit]
	if state == nil {
		return nil, errors.New("unknown unit")
	}
	values := map[string]string{
		"LoadState": state.loadState, "ActiveState": state.activeState, "UnitFileState": state.unitFileState,
		"SubState": state.subState, "MainPID": state.mainPID,
	}
	result := make(map[string]string, len(names))
	for _, name := range names {
		result[name] = values[name]
	}
	return result, nil
}

func tenantActivationSocket(tenantID string) string {
	return "workagent-userhost@" + tenantID + ".socket"
}

func tenantActivationService(tenantID string) string {
	return "workagent-userhost@" + tenantID + ".service"
}

func tenantActivationTestIdentities() []store.PortalUserIdentity {
	return []store.PortalUserIdentity{
		{TenantID: "11111111-1111-4111-8111-111111111111", RuntimeUser: "workagent_first", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111", Enabled: true},
		{TenantID: "22222222-2222-4222-8222-222222222222", RuntimeUser: "workagent_second", DataRoot: "/srv/workagent/users/22222222-2222-4222-8222-222222222222", Enabled: false},
		{TenantID: "33333333-3333-4333-8333-333333333333", RuntimeUser: "workagent_third", DataRoot: "/srv/workagent/users/33333333-3333-4333-8333-333333333333", Enabled: false},
	}
}

func tenantActivationTestJournalPath(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("tenant activation journal ownership tests require root")
	}
	return filepath.Join(t.TempDir(), tenantActivationJournalName)
}

func assertTenantActivationJournalExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("durable tenant activation journal is unavailable: info=%v err=%v", info, err)
	}
}

func assertTenantActivationJournalAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tenant activation journal was not durably committed: %v", err)
	}
}

func TestTenantActivationReplayChoosesCompletePreviousOrDesiredDatabaseState(t *testing.T) {
	for _, test := range []struct {
		name        string
		databaseNew bool
		secondWant  bool
	}{
		{name: "database still previous rolls systemd back", databaseNew: false, secondWant: false},
		{name: "database committed desired finishes systemd", databaseNew: true, secondWant: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := tenantActivationTestJournalPath(t)
			previous := tenantActivationTestIdentities()
			if err := prepareTenantActivationAt(context.Background(), path, 0, previous, previous[1].TenantID, true, nil); err != nil {
				t.Fatal(err)
			}
			current := append([]store.PortalUserIdentity(nil), previous...)
			if test.databaseNew {
				current[1].Enabled = true
			}
			controller := newTenantActivationSystemd(current)
			if err := replayTenantActivationAt(context.Background(), path, 0, current, controller, nil); err != nil {
				t.Fatal(err)
			}
			assertTenantActivationJournalAbsent(t, path)
			secondSocket := controller.units[tenantActivationSocket(current[1].TenantID)]
			if (secondSocket.unitFileState == "enabled") != test.secondWant {
				t.Fatalf("database linearization decision was not honored: %+v", secondSocket)
			}
			first := controller.units[tenantActivationSocket(current[0].TenantID)]
			if first.unitFileState != "enabled" {
				t.Fatalf("unrelated previous-enabled tenant was disabled: %+v", first)
			}
			thirdSocket := controller.units[tenantActivationSocket(current[2].TenantID)]
			thirdService := controller.units[tenantActivationService(current[2].TenantID)]
			if thirdSocket.unitFileState != "disabled" || thirdSocket.activeState != "inactive" ||
				thirdService.activeState != "inactive" || thirdService.subState != "dead" || thirdService.mainPID != "0" {
				t.Fatalf("disabled catalog member was not fully stopped: socket=%+v service=%+v", thirdSocket, thirdService)
			}
		})
	}
}

func TestTenantActivationEnabledIsPersistentOnlyAndDisabledIsFullyStopped(t *testing.T) {
	path := tenantActivationTestJournalPath(t)
	identities := tenantActivationTestIdentities()
	identities[0].Enabled = false
	controller := newTenantActivationSystemd(identities)
	controller.units[tenantActivationSocket(identities[1].TenantID)].activeState = "inactive"
	controller.units[tenantActivationService(identities[1].TenantID)].activeState = "inactive"
	controller.units[tenantActivationService(identities[1].TenantID)].subState = "dead"
	controller.units[tenantActivationService(identities[1].TenantID)].mainPID = "0"
	if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
		t.Fatal(err)
	}
	identities[1].Enabled = true
	if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err != nil {
		t.Fatal(err)
	}
	for _, action := range controller.actions {
		if strings.HasPrefix(action, "start ") || strings.HasPrefix(action, "restart ") || action == "enable --now "+tenantActivationSocket(identities[1].TenantID) {
			t.Fatalf("enabled replay started runtime instead of persistent-only enable: %v", controller.actions)
		}
	}
	enabledSocket := controller.units[tenantActivationSocket(identities[1].TenantID)]
	if enabledSocket.unitFileState != "enabled" || enabledSocket.activeState != "inactive" {
		t.Fatalf("persistent enable unexpectedly started the socket: %+v", enabledSocket)
	}
	disabledSocket := controller.units[tenantActivationSocket(identities[0].TenantID)]
	disabledService := controller.units[tenantActivationService(identities[0].TenantID)]
	if disabledSocket.unitFileState != "disabled" || disabledSocket.activeState != "inactive" ||
		disabledService.activeState != "inactive" || disabledService.subState != "dead" || disabledService.mainPID != "0" {
		t.Fatalf("disabled replay was incomplete: socket=%+v service=%+v", disabledSocket, disabledService)
	}
}

func TestTenantActivationRejectsIdentityCardinalityAndMixedDatabaseTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]store.PortalUserIdentity) []store.PortalUserIdentity
	}{
		{name: "cardinality", mutate: func(values []store.PortalUserIdentity) []store.PortalUserIdentity { return values[:2] }},
		{name: "runtime identity", mutate: func(values []store.PortalUserIdentity) []store.PortalUserIdentity {
			values[0].RuntimeUser = "workagent_tampered"
			return values
		}},
		{name: "data identity", mutate: func(values []store.PortalUserIdentity) []store.PortalUserIdentity {
			values[0].DataRoot += "-tampered"
			return values
		}},
		{name: "mixed enabled", mutate: func(values []store.PortalUserIdentity) []store.PortalUserIdentity {
			values[2].Enabled = true
			return values
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := tenantActivationTestJournalPath(t)
			identities := tenantActivationTestIdentities()
			if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
				t.Fatal(err)
			}
			current := test.mutate(append([]store.PortalUserIdentity(nil), identities...))
			controller := newTenantActivationSystemd(identities)
			if err := replayTenantActivationAt(context.Background(), path, 0, current, controller, nil); err == nil {
				t.Fatal("tampered Portal database catalog was accepted")
			}
			if len(controller.actions) != 0 {
				t.Fatalf("systemd changed before database catalog authentication: %v", controller.actions)
			}
			assertTenantActivationJournalExists(t, path)
		})
	}
}

func TestTenantActivationRejectsJournalIdentityAndStrictJSONTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown field", mutate: func(payload []byte) []byte { return append(payload[:len(payload)-2], []byte(`,"unknown":true}\n`)...) }},
		{name: "trailing JSON", mutate: func(payload []byte) []byte { return append(payload, []byte(`{}\n`)...) }},
		{name: "noncanonical whitespace", mutate: func(payload []byte) []byte { return append([]byte(" "), payload...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := tenantActivationTestJournalPath(t)
			identities := tenantActivationTestIdentities()
			if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
				t.Fatal(err)
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, test.mutate(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadTenantActivationJournal(path); err == nil {
				t.Fatal("non-strict journal JSON was accepted")
			}
		})
	}

	t.Run("frozen identity", func(t *testing.T) {
		path := tenantActivationTestJournalPath(t)
		identities := tenantActivationTestIdentities()
		if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
			t.Fatal(err)
		}
		journal, found, err := loadTenantActivationJournal(path)
		if err != nil || !found {
			t.Fatalf("load journal: found=%t err=%v", found, err)
		}
		journal.Tenants[0].RuntimeUser = "workagent_attacker"
		payload, err := encodeTenantActivationJournal(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		controller := newTenantActivationSystemd(identities)
		if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err == nil {
			t.Fatal("journal identity mutation was accepted")
		}
		if len(controller.actions) != 0 {
			t.Fatalf("systemd changed for a mutated journal identity: %v", controller.actions)
		}
	})

	t.Run("more than one desired row", func(t *testing.T) {
		path := tenantActivationTestJournalPath(t)
		identities := tenantActivationTestIdentities()
		if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
			t.Fatal(err)
		}
		journal, found, err := loadTenantActivationJournal(path)
		if err != nil || !found {
			t.Fatalf("load journal: found=%t err=%v", found, err)
		}
		journal.Tenants[2].DesiredEnabled = true
		payload, err := encodeTenantActivationJournal(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadTenantActivationJournal(path); err == nil {
			t.Fatal("multi-row desired mutation was accepted")
		}
	})
}

func TestTenantActivationPartialSystemdFailureRetainsJournalForIdempotentReplay(t *testing.T) {
	path := tenantActivationTestJournalPath(t)
	identities := tenantActivationTestIdentities()
	if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
		t.Fatal(err)
	}
	controller := newTenantActivationSystemd(identities)
	failedUnit := tenantActivationService(identities[1].TenantID)
	// Database remains previous, so the target tenant must be disabled.  Fail
	// after disable --now has already changed its socket.
	controller.failAction = "stop " + failedUnit
	controller.failOnce = true
	if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err == nil {
		t.Fatal("partial systemd failure was accepted")
	}
	assertTenantActivationJournalExists(t, path)
	if controller.units[tenantActivationSocket(identities[1].TenantID)].unitFileState != "disabled" {
		t.Fatal("test did not reach the intended partial systemd state")
	}
	if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err != nil {
		t.Fatalf("idempotent replay did not finish the retained intent: %v", err)
	}
	assertTenantActivationJournalAbsent(t, path)
}

func TestTenantActivationReadbackFailureRetainsJournal(t *testing.T) {
	path := tenantActivationTestJournalPath(t)
	identities := tenantActivationTestIdentities()
	if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
		t.Fatal(err)
	}
	controller := newTenantActivationSystemd(identities)
	controller.propertyErr = errors.New("simulated systemd property failure")
	if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err == nil {
		t.Fatal("systemd readback failure was accepted")
	}
	assertTenantActivationJournalExists(t, path)
	controller.propertyErr = nil
	if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err != nil {
		t.Fatalf("retained journal did not recover after readback failure: %v", err)
	}
	assertTenantActivationJournalAbsent(t, path)
}

func TestTenantActivationJournalRejectsPathAndMetadataAttacks(t *testing.T) {
	identities := tenantActivationTestIdentities()
	for _, test := range []struct {
		name   string
		attack func(*testing.T, string)
	}{
		{name: "mode", attack: func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", attack: func(t *testing.T, path string) {
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", attack: func(t *testing.T, path string) {
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			target := path + ".target"
			if err := os.WriteFile(target, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := tenantActivationTestJournalPath(t)
			if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
				t.Fatal(err)
			}
			test.attack(t, path)
			controller := newTenantActivationSystemd(identities)
			if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err == nil {
				t.Fatal("unsafe journal object was accepted")
			}
			if len(controller.actions) != 0 {
				t.Fatalf("systemd changed before journal metadata authentication: %v", controller.actions)
			}
		})
	}

	t.Run("symlinked parent", func(t *testing.T) {
		root := tenantActivationTestJournalPath(t)
		realParent := filepath.Join(filepath.Dir(root), "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(filepath.Dir(root), "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(linkedParent, tenantActivationJournalName)
		if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err == nil {
			t.Fatal("symlinked journal parent was accepted")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		path := tenantActivationTestJournalPath(t)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(tenantActivationJournalMaximum + 1); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadTenantActivationJournal(path); err == nil {
			t.Fatal("oversized activation journal was accepted")
		}
	})
}

func TestTenantActivationCommitRevalidatesInodeAndDeletionFailureRetainsJournal(t *testing.T) {
	t.Run("inode replacement", func(t *testing.T) {
		path := tenantActivationTestJournalPath(t)
		identities := tenantActivationTestIdentities()
		if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
			t.Fatal(err)
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hook := func(point string) error {
			if point != "activation-before-unlink" {
				return nil
			}
			if err := os.Rename(path, path+".displaced"); err != nil {
				return err
			}
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0o600)
		}
		controller := newTenantActivationSystemd(identities)
		if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, hook); err == nil {
			t.Fatal("journal inode replacement before unlink was accepted")
		}
		assertTenantActivationJournalExists(t, path)
	})

	t.Run("final deletion fault", func(t *testing.T) {
		path := tenantActivationTestJournalPath(t)
		identities := tenantActivationTestIdentities()
		if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
			t.Fatal(err)
		}
		controller := newTenantActivationSystemd(identities)
		failure := errors.New("simulated final deletion failure")
		hook := func(point string) error {
			if point == "activation-before-unlink" {
				return failure
			}
			return nil
		}
		if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, hook); !errors.Is(err, failure) {
			t.Fatalf("wrong deletion failure: %v", err)
		}
		assertTenantActivationJournalExists(t, path)
		if err := replayTenantActivationAt(context.Background(), path, 0, identities, controller, nil); err != nil {
			t.Fatalf("retained journal did not replay: %v", err)
		}
		assertTenantActivationJournalAbsent(t, path)
	})
}

func TestTenantActivationJournalPublicationDoesNotReplaceExistingPath(t *testing.T) {
	path := tenantActivationTestJournalPath(t)
	sentinel := []byte("do-not-replace")
	if err := os.WriteFile(path, sentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	identities := tenantActivationTestIdentities()
	if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err == nil {
		t.Fatal("existing activation journal pathname was replaced")
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(sentinel) {
		t.Fatalf("existing journal bytes changed: %q err=%v", actual, err)
	}
}

func TestTenantActivationBootstrapConvergesCurrentFullCatalog(t *testing.T) {
	path := tenantActivationTestJournalPath(t)
	identities := tenantActivationTestIdentities()
	controller := newTenantActivationSystemd(identities)
	if err := convergeTenantActivationCatalogAt(context.Background(), path, 0, identities, controller, nil); err != nil {
		t.Fatal(err)
	}
	assertTenantActivationJournalAbsent(t, path)
	if err := VerifyTenantActivationCatalog(context.Background(), identities, controller); err != nil {
		t.Fatalf("bootstrap did not converge the full DB catalog: %v", err)
	}
}

func TestTenantActivationRootOnlyAndCleanAssertionFailClosed(t *testing.T) {
	identities := tenantActivationTestIdentities()
	path := filepath.Join(t.TempDir(), tenantActivationJournalName)
	if err := prepareTenantActivationAt(context.Background(), path, 1000, identities, identities[0].TenantID, false, nil); err == nil || !strings.Contains(err.Error(), "require root") {
		t.Fatalf("non-root activation preparation was accepted: %v", err)
	}
	if err := assertTenantActivationCleanAt(path, 1000); err == nil {
		t.Fatal("non-root clean assertion was accepted")
	}
	if os.Geteuid() != 0 {
		return
	}
	if err := assertTenantActivationCleanAt(path, 0); err != nil {
		t.Fatalf("absent journal was not clean: %v", err)
	}
	if err := os.WriteFile(path, []byte("unsafe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := assertTenantActivationCleanAt(path, 0); err == nil {
		t.Fatal("unsafe object at the journal pathname was reported clean")
	}
}
