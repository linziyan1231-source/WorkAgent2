package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestTenantFileBatchJournalRecoversCrashBetweenTenantCommits(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for protected tenant batch tests")
	}
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl is unavailable")
	}
	portalAccount, err := user.Lookup("workagent")
	if err != nil {
		t.Skipf("workagent account is unavailable: %v", err)
	}
	firstAccount, err := user.Lookup("workagent_stage_one")
	if err != nil {
		t.Skipf("first test tenant account is unavailable: %v", err)
	}
	secondAccount, err := user.Lookup("workagent_stage_two")
	if err != nil {
		t.Skipf("second test tenant account is unavailable: %v", err)
	}
	portalUID, _ := strconv.ParseUint(portalAccount.Uid, 10, 32)
	firstUID, _ := strconv.ParseUint(firstAccount.Uid, 10, 32)
	secondUID, _ := strconv.ParseUint(secondAccount.Uid, 10, 32)
	if portalUID == 0 || firstUID == 0 || secondUID == 0 {
		t.Skip("test accounts must be unprivileged")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "configs"), filepath.Join(root, "systemd"), filepath.Join(root, "users"),
		filepath.Join(root, "run"), filepath.Join(root, "releases"), filepath.Join(root, "state"),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	portal := tenantBatchTestPortal(root, portalAccount.Username)
	tenants := []config.Tenant{
		tenantBatchTestTenant(portal, "11111111-1111-4111-8111-111111111111", firstAccount.Username, uint32(portalUID)),
		tenantBatchTestTenant(portal, "22222222-2222-4222-8222-222222222222", secondAccount.Username, uint32(portalUID)),
		tenantBatchTestTenant(portal, "33333333-3333-4333-8333-333333333333", firstAccount.Username, uint32(portalUID)),
	}
	// Canonical equality must survive JSON's omitempty normalization instead of
	// treating empty non-nil containers as a different authenticated tenant.
	tenants[0].Backend.Environment = map[string]string{}
	tenants[1].Backend.RequiredReleaseFiles = []string{}
	systemdRoot := filepath.Join(root, "systemd")
	publications := make([]tenantFilePublication, 0, len(tenants))
	for _, tenant := range tenants {
		publication, err := prepareTenantFilePublication(portal, tenant, systemdRoot)
		if err != nil {
			t.Fatal(err)
		}
		publications = append(publications, publication)
	}
	journal, err := makeTenantFileBatchJournal(portal, systemdRoot, publications)
	if err != nil {
		t.Fatal(err)
	}
	journalPayload, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	var contradictory tenantFileBatchJournal
	if err := json.Unmarshal(journalPayload, &contradictory); err != nil {
		t.Fatal(err)
	}
	changedTenant := contradictory.Members[0].Tenant
	changedTenant.Limits = config.DefaultResourceLimits()
	changedConfig, err := json.MarshalIndent(changedTenant, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	changedConfig = append(changedConfig, '\n')
	contradictory.Members[0].Entries[2].Payload = changedConfig
	contradictory.Members[0].Entries[2].Desired = desiredTenantFileJournalState(changedConfig, 0o640, contradictory.Members[0].Entries[2].UID, contradictory.Members[0].Entries[2].GID)
	if err := validateTenantFileBatchJournal(portal, systemdRoot, contradictory); err == nil {
		t.Fatal("global batch member payload differing from Member.Tenant was accepted")
	}
	faultPoints := []string{
		"batch-journal-anonymous-created", "batch-journal-write-started", "batch-journal-anonymous-written",
		"batch-journal-anonymous-synced", "batch-journal-linked", "batch-journal-linked-verified", "batch-journal-durable",
	}
	for _, point := range faultPoints {
		t.Run("marker-fault-"+point, func(t *testing.T) {
			sentinel := errors.New("simulated batch marker crash")
			called := false
			err := writeTenantFileBatchJournalWithHook(portal, systemdRoot, journal, func(actual string) error {
				if actual == point {
					called = true
					return sentinel
				}
				return nil
			})
			if !called || !errors.Is(err, sentinel) {
				t.Fatalf("fault %s was not reached: called=%v err=%v", point, called, err)
			}
			exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal))
			if existsErr != nil {
				t.Fatal(existsErr)
			}
			linked := point == "batch-journal-linked" || point == "batch-journal-linked-verified" || point == "batch-journal-durable"
			if exists != linked {
				t.Fatalf("fault %s marker existence=%v want %v", point, exists, linked)
			}
			if linked {
				if err := removeTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if err := writeTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFinalTenantFileCatalog(portal, nil); err == nil {
		t.Fatal("unauthenticated final catalog scan accepted the global transaction marker")
	}
	// A root-owned foreign third state is not provenance. Replay may converge
	// earlier sorted members, but must not overwrite this unrecorded target.
	foreignPath := publications[1].configPath
	foreignPayload := []byte("foreign operator state\n")
	if err := os.WriteFile(foreignPath, foreignPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reconcileTenantFileBatch(context.Background(), portal, systemdRoot, journal); err == nil {
		t.Fatal("batch replay overwrote a target outside its recorded Before/Desired states")
	}
	if payload, err := os.ReadFile(foreignPath); err != nil || string(payload) != string(foreignPayload) {
		t.Fatalf("foreign third state changed: payload=%q err=%v", payload, err)
	}
	if err := os.Remove(foreignPath); err != nil {
		t.Fatal(err)
	}
	if exists, err := tenantPathExists(tenantFileBatchJournalPath(portal)); err != nil || !exists {
		t.Fatalf("global batch intent disappeared between tenant commits: exists=%v err=%v", exists, err)
	}
	for _, tenant := range tenants {
		for _, prefix := range []string{"batch-before-member:", "batch-member-converged:"} {
			point := prefix + tenant.TenantID
			sentinel := errors.New("simulated inter-tenant crash")
			called := false
			err := reconcileTenantFileBatchWithHook(context.Background(), portal, systemdRoot, journal, func(actual string) error {
				if actual == point {
					called = true
					return sentinel
				}
				return nil
			})
			if !called || !errors.Is(err, sentinel) {
				t.Fatalf("member fault %s was not reached: called=%v err=%v", point, called, err)
			}
			if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
				t.Fatalf("global marker did not survive %s: exists=%v err=%v", point, exists, existsErr)
			}
		}
	}
	if err := reconcileTenantFileBatch(context.Background(), portal, systemdRoot, journal); err != nil {
		t.Fatalf("boot replay after inter-tenant crash: %v", err)
	}
	if exists, err := tenantPathExists(tenantFileBatchJournalPath(portal)); err != nil || !exists {
		t.Fatalf("batch intent did not survive file-only convergence before reload/readback: exists=%v err=%v", exists, err)
	}
	for _, tenant := range tenants {
		publication, err := prepareTenantFilePublication(portal, tenant, systemdRoot)
		if err != nil {
			t.Fatal(err)
		}
		matches, err := tenantFileSetMatchesIntents(publication.plan.Entries)
		if err != nil || !matches {
			t.Fatalf("tenant %s did not converge: matches=%v err=%v", tenant.TenantID, matches, err)
		}
	}
	extra := tenantBatchTestTenant(portal, "44444444-4444-4444-8444-444444444444", secondAccount.Username, uint32(portalUID))
	extraPublication, err := prepareTenantFilePublication(portal, extra, systemdRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishPreparedTenantFiles(context.Background(), extraPublication); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFinalTenantFileCatalog(portal, &journal); err == nil {
		t.Fatal("valid extra tenant outside the authenticated full batch was blessed")
	}
	if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
		t.Fatalf("global marker did not survive extra-tenant rejection: exists=%v err=%v", exists, existsErr)
	}
	for _, intent := range extraPublication.plan.Entries {
		if err := os.Remove(intent.Target); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Dir(extraPublication.plan.JournalPath)); err != nil {
		t.Fatal(err)
	}
	controller := tenantBatchSystemd{tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser}
	orphan := filepath.Join(systemdRoot, tenantDropInPrefix+"55555555-5555-4555-8555-555555555555"+tenantDropInSuffix)
	if err := os.Mkdir(orphan, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, controller, &journal); err == nil {
		t.Fatal("orphan canonical tenant drop-in directory was accepted")
	}
	if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
		t.Fatalf("global marker did not survive orphan drop-in rejection: exists=%v err=%v", exists, existsErr)
	}
	if err := os.Remove(orphan); err != nil {
		t.Fatal(err)
	}
	extraChild := filepath.Join(filepath.Dir(publications[0].plan.JournalPath), "noop.conf")
	if err := os.WriteFile(extraChild, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, controller, &journal); err == nil {
		t.Fatal("extra no-op tenant drop-in child was accepted")
	}
	if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
		t.Fatalf("global marker did not survive extra drop-in child rejection: exists=%v err=%v", exists, existsErr)
	}
	if err := os.Remove(extraChild); err != nil {
		t.Fatal(err)
	}
	identityPath := publications[0].plan.Entries[0].Target
	savedIdentity := filepath.Join(root, "saved-identity.conf")
	if err := os.Rename(identityPath, savedIdentity); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(savedIdentity, identityPath); err != nil {
		t.Fatal(err)
	}
	reloadActions := 0
	symlinkController := tenantBatchSystemd{tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser, actions: &reloadActions}
	if _, _, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, symlinkController, &journal); err == nil {
		t.Fatal("symlink tenant drop-in child was accepted before daemon-reload")
	}
	if reloadActions != 0 {
		t.Fatalf("daemon-reload ran %d times before rejecting a symlink drop-in child", reloadActions)
	}
	if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
		t.Fatalf("global marker did not survive symlink drop-in rejection: exists=%v err=%v", exists, existsErr)
	}
	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedIdentity, identityPath); err != nil {
		t.Fatal(err)
	}
	for _, unauthenticated := range []struct {
		name      string
		directory bool
	}{
		{name: tenantDropInPrefix + tenants[0].TenantID + ".service"},
		{name: tenantDropInPrefix + tenants[0].TenantID + ".socket"},
		{name: tenantDropInPrefix + tenants[0].TenantID + ".service.wants", directory: true},
	} {
		path := filepath.Join(systemdRoot, unauthenticated.name)
		if unauthenticated.directory {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		reloadActions = 0
		if _, _, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, symlinkController, &journal); err == nil {
			t.Fatalf("unauthenticated top-level tenant systemd entry %s was accepted", unauthenticated.name)
		}
		if reloadActions != 0 {
			t.Fatalf("daemon-reload ran %d times before rejecting %s", reloadActions, unauthenticated.name)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, forbiddenDirectory := range []string{
		filepath.Join(systemdRoot, tenantDropInPrefix+tenantDropInSuffix),
		filepath.Join(systemdRoot, tenantDropInPrefix+tenants[0].TenantID+".socket.d"),
	} {
		if err := os.Mkdir(forbiddenDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, _, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, controller, &journal); err == nil {
			t.Fatalf("forbidden tenant drop-in directory %s was accepted", filepath.Base(forbiddenDirectory))
		}
		if err := os.Remove(forbiddenDirectory); err != nil {
			t.Fatal(err)
		}
	}
	for name, failing := range map[string]tenantBatchSystemd{
		"reload": {tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser, actionErr: errors.New("reload failed")},
		"verify": {tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser, propertyErrUnit: tenantDropInPrefix + tenants[1].TenantID + ".service"},
		"list":   {tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser, listErr: errors.New("enumeration failed")},
		"socket": {tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser, unloadedUnit: tenantDropInPrefix + tenants[2].TenantID + ".socket"},
		"service-fragment": {
			tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser,
			wrongFragmentUnit: tenantDropInPrefix + tenants[0].TenantID + ".service",
		},
		"service-dropin": {
			tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser,
			extraDropInUnit: tenantDropInPrefix + tenants[0].TenantID + ".service",
		},
		"socket-fragment": {
			tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser,
			wrongFragmentUnit: tenantDropInPrefix + tenants[0].TenantID + ".socket",
		},
		"socket-dropin": {
			tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser,
			extraDropInUnit: tenantDropInPrefix + tenants[0].TenantID + ".socket",
		},
		"socket-static": {
			tenants: tenants, systemdRoot: systemdRoot, portalRuntimeUser: portal.RuntimeUser,
			wrongSocketStaticUnit: tenantDropInPrefix + tenants[0].TenantID + ".socket",
		},
	} {
		if _, _, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, failing, &journal); err == nil {
			t.Fatalf("%s finalization failure was accepted", name)
		}
		if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
			t.Fatalf("global marker did not survive %s failure: exists=%v err=%v", name, exists, existsErr)
		}
	}
	for _, point := range []string{
		"batch-before-daemon-reload", "batch-daemon-reloaded",
		"batch-tenant-verified:" + tenants[0].TenantID,
		"batch-tenant-verified:" + tenants[1].TenantID,
		"batch-tenant-verified:" + tenants[2].TenantID,
		"batch-before-exact-unit-catalog", "batch-exact-unit-catalog-verified",
	} {
		sentinel := errors.New("simulated final catalog crash")
		called := false
		_, _, err := finalizeTenantFileCatalogWithHook(context.Background(), portal, systemdRoot, controller, &journal, func(actual string) error {
			if actual == point {
				called = true
				return sentinel
			}
			return nil
		})
		if !called || !errors.Is(err, sentinel) {
			t.Fatalf("finalization fault %s was not reached: called=%v err=%v", point, called, err)
		}
		if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
			t.Fatalf("global marker did not survive %s: exists=%v err=%v", point, exists, existsErr)
		}
	}
	if finalTenants, loaded, err := finalizeTenantFileCatalog(context.Background(), portal, systemdRoot, controller, &journal); err != nil || len(finalTenants) != 3 || loaded != 6 {
		t.Fatalf("complete authenticated finalization failed: tenants=%d loaded=%d err=%v", len(finalTenants), loaded, err)
	}
	// Production removes this only after reload and full service/unit readback;
	// this lower-level test explicitly models that final verified commit.
	markerPayload, err := os.ReadFile(tenantFileBatchJournalPath(portal))
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{"batch-commit-revalidated", "batch-before-unlink"} {
		sentinel := errors.New("simulated final commit crash")
		called := false
		err := removeTenantFileBatchJournalWithHook(portal, systemdRoot, journal, func(actual string) error {
			if actual == point {
				called = true
				return sentinel
			}
			return nil
		})
		if !called || !errors.Is(err, sentinel) {
			t.Fatalf("commit fault %s was not reached: called=%v err=%v", point, called, err)
		}
		if exists, existsErr := tenantPathExists(tenantFileBatchJournalPath(portal)); existsErr != nil || !exists {
			t.Fatalf("marker did not survive commit fault %s: exists=%v err=%v", point, exists, existsErr)
		}
	}
	replacementAttempted := false
	err = removeTenantFileBatchJournalWithHook(portal, systemdRoot, journal, func(point string) error {
		if point != "batch-before-unlink" {
			return nil
		}
		replacementAttempted = true
		path := tenantFileBatchJournalPath(portal)
		if err := os.Rename(path, path+".attacker-original"); err != nil {
			return err
		}
		return os.WriteFile(path, markerPayload, 0o600)
	})
	if !replacementAttempted || err == nil {
		t.Fatalf("same-content marker inode replacement was accepted: attempted=%v err=%v", replacementAttempted, err)
	}
	path := tenantFileBatchJournalPath(portal)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".attacker-original", path); err != nil {
		t.Fatal(err)
	}
	if err := removeTenantFileBatchJournal(portal, systemdRoot, journal); err != nil {
		t.Fatal(err)
	}
	if exists, err := tenantPathExists(tenantFileBatchJournalPath(portal)); err != nil || exists {
		t.Fatalf("completed global batch intent remains: exists=%v err=%v", exists, err)
	}
}

func TestTenantFileJournalRejectsRuntimeACLIdentityDrift(t *testing.T) {
	intent := tenantFileIntent{
		Name: tenantFileConfig, ProtectedRoot: "/protected", Target: "/protected/tenant.json",
		Stage: "/protected/tenant.json.workagent-stage", Payload: []byte("{}\n"), Mode: 0o640,
		UID: 0, GID: 992, ACLUser: 1001,
	}
	journal := tenantFileJournal{
		SchemaVersion: tenantFileJournalSchema,
		TenantID:      "11111111-1111-4111-8111-111111111111",
		Entries: []tenantFileJournalEntry{{
			Name: intent.Name, Target: intent.Target, Stage: intent.Stage, Payload: intent.Payload,
			Mode: uint32(intent.Mode), UID: intent.UID, GID: intent.GID, ACLUser: 1002,
			Desired: desiredTenantFileJournalState(intent.Payload, intent.Mode, intent.UID, intent.GID),
		}},
	}
	plan := tenantFileSetPlan{TenantID: journal.TenantID, JournalPath: "/protected/journal", Entries: []tenantFileIntent{intent}}
	if err := validateTenantFileJournal(journal, plan); err == nil {
		t.Fatal("durable journal bound to a stale runtime ACL UID was accepted")
	}
}

func TestTenantCatalogCleanAssertionsRejectReservedMarkers(t *testing.T) {
	root := t.TempDir()
	configRoot := filepath.Join(root, "configs")
	systemdRoot := filepath.Join(root, "systemd")
	for _, path := range []string{configRoot, systemdRoot} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	portal := config.Portal{Paths: config.PortalPaths{TenantConfigs: configRoot}}
	if err := assertTenantFileCatalogClean(portal, systemdRoot); err != nil {
		t.Fatalf("empty catalog was not clean: %v", err)
	}
	marker := tenantFileBatchJournalPath(portal)
	if err := os.WriteFile(marker, []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := assertTenantFileCatalogClean(portal, systemdRoot); err == nil {
		t.Fatal("global reserved marker was accepted by the shared-lock clean assertion")
	}
	tenant := config.Tenant{TenantID: "11111111-1111-4111-8111-111111111111"}
	configPath := filepath.Join(configRoot, tenant.TenantID+".json")
	if err := AssertRuntimeTenantFileCatalogClean(tenant, configPath); err == nil {
		t.Fatal("global reserved marker was accepted by the least-privilege runtime assertion")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(systemdRoot, tenantDropInPrefix+tenant.TenantID+tenantDropInSuffix)
	if err := os.Mkdir(dropIn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropIn, ".workagent-tenant-files.transaction.json"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := assertTenantFileCatalogClean(portal, systemdRoot); err == nil {
		t.Fatal("per-tenant reserved marker was accepted by the shared-lock clean assertion")
	}
}

func TestTenantFileCatalogMergeFreezesCompleteSortedGeneration(t *testing.T) {
	first := config.Tenant{TenantID: "11111111-1111-4111-8111-111111111111", RuntimeUser: "old"}
	second := config.Tenant{TenantID: "22222222-2222-4222-8222-222222222222", RuntimeUser: "unchanged"}
	third := config.Tenant{TenantID: "33333333-3333-4333-8333-333333333333", RuntimeUser: "new"}
	replacement := first
	replacement.RuntimeUser = "replacement"
	merged, err := mergeTenantFileCatalog([]config.Tenant{second, first}, []config.Tenant{third, replacement})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 || merged[0].RuntimeUser != "replacement" || merged[1].RuntimeUser != "unchanged" || merged[2].RuntimeUser != "new" {
		t.Fatalf("full catalog merge drifted: %+v", merged)
	}
	if _, err := mergeTenantFileCatalog([]config.Tenant{first}, []config.Tenant{replacement, replacement}); err == nil {
		t.Fatal("duplicate requested tenant was accepted by the full catalog merge")
	}
}

func TestTenantBatchAggregateLimitIsExactAtBoundary(t *testing.T) {
	journal := tenantFileBatchJournal{
		SchemaVersion: tenantFileBatchJournalSchema,
		PortalSHA256:  strings.Repeat("a", 64),
		SystemdRoot:   "/etc/systemd/system",
		Members: []tenantFileBatchMember{{
			Tenant:  config.Tenant{TenantID: "11111111-1111-4111-8111-111111111111"},
			Entries: []tenantFileJournalEntry{{Name: tenantFileConfig, Payload: []byte(strings.Repeat("x", 257))}},
		}},
	}
	payload, err := encodeTenantFileBatchJournal(journal, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if exact, err := encodeTenantFileBatchJournal(journal, len(payload)); err != nil || string(exact) != string(payload) {
		t.Fatalf("exact aggregate boundary was rejected or changed: bytes=%d err=%v", len(payload), err)
	}
	if _, err := encodeTenantFileBatchJournal(journal, len(payload)-1); err == nil {
		t.Fatal("one-byte-over aggregate catalog transaction was accepted")
	}
}

func TestTenantAlternateSystemdNamespaceRejectsInstanceOverridesAndDependencies(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for protected systemd namespace tests")
	}
	root := t.TempDir()
	mutable := filepath.Join(root, "mutable")
	vendor := filepath.Join(root, "vendor")
	for _, path := range []string{mutable, vendor} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{tenantDropInPrefix + ".service", tenantDropInPrefix + ".socket"} {
		if err := os.WriteFile(filepath.Join(vendor, name), []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	roots := []tenantSystemdSearchRoot{{path: filepath.Join(root, "missing")}, {path: mutable}, {path: vendor, allowTemplates: true}}
	if err := verifyTenantSystemdOverrideRoots(roots); err != nil {
		t.Fatalf("clean alternate namespace was rejected: %v", err)
	}
	for _, attack := range []struct {
		root      string
		name      string
		directory bool
	}{
		{root: mutable, name: tenantDropInPrefix + "11111111-1111-4111-8111-111111111111.service"},
		{root: mutable, name: tenantDropInPrefix + "11111111-1111-4111-8111-111111111111.service.wants", directory: true},
		{root: vendor, name: tenantDropInPrefix + "11111111-1111-4111-8111-111111111111.socket"},
	} {
		path := filepath.Join(attack.root, attack.name)
		if attack.directory {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyTenantSystemdOverrideRoots(roots); err == nil {
			t.Fatalf("alternate systemd override %s was accepted", attack.name)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

type tenantBatchSystemd struct {
	tenants               []config.Tenant
	systemdRoot           string
	portalRuntimeUser     string
	actionErr             error
	propertyErrUnit       string
	listErr               error
	unloadedUnit          string
	wrongFragmentUnit     string
	extraDropInUnit       string
	wrongSocketStaticUnit string
	actions               *int
}

func (controller tenantBatchSystemd) Action(_ context.Context, arguments ...string) error {
	if controller.actions != nil {
		(*controller.actions)++
	}
	if controller.actionErr != nil {
		return controller.actionErr
	}
	if len(arguments) != 1 || arguments[0] != "daemon-reload" {
		return errors.New("unexpected batch test systemd action")
	}
	return nil
}

func (controller tenantBatchSystemd) Properties(_ context.Context, unit string, names ...string) (map[string]string, error) {
	if unit == controller.propertyErrUnit {
		return nil, errors.New("property readback failed")
	}
	systemdRoot := controller.systemdRoot
	if systemdRoot == "" {
		systemdRoot = tenantProductionSystemdRoot
	}
	for _, tenant := range controller.tenants {
		service := tenantDropInPrefix + tenant.TenantID + ".service"
		socket := tenantDropInPrefix + tenant.TenantID + ".socket"
		if unit == socket {
			values := map[string]string{
				"LoadState":     "loaded",
				"ActiveState":   "inactive",
				"UnitFileState": "disabled",
				"FragmentPath":  filepath.Join(systemdRoot, tenantDropInPrefix+".socket"),
				"DropInPaths":   "",
				"Listen":        tenant.SocketPath,
				"SocketUser":    controller.portalRuntimeUser,
				"SocketGroup":   controller.portalRuntimeUser,
				"SocketMode":    "0600",
				"DirectoryMode": "0700",
			}
			if unit == controller.wrongFragmentUnit {
				values["FragmentPath"] = "/run/systemd/system/" + filepath.Base(values["FragmentPath"])
			}
			if unit == controller.extraDropInUnit {
				values["DropInPaths"] = "/run/systemd/system/unauthenticated.conf"
			}
			if unit == controller.wrongSocketStaticUnit {
				values["Listen"] = tenant.SocketPath + " (Stream) /run/workagent/foreign.sock (Stream)"
			}
			result := make(map[string]string, len(names))
			for _, name := range names {
				if name == "LoadState" && unit == controller.unloadedUnit {
					result[name] = "not-found"
				} else {
					result[name] = values[name]
				}
			}
			return result, nil
		}
		if unit != service {
			continue
		}
		limits := tenant.Limits.Effective()
		values := map[string]string{
			"LoadState": "loaded", "User": tenant.RuntimeUser, "Group": tenant.RuntimeUser, "SupplementaryGroups": "workagent-slots",
			"FragmentPath": filepath.Join(systemdRoot, tenantDropInPrefix+".service"),
			"DropInPaths": strings.Join([]string{
				filepath.Join(systemdRoot, tenantDropInPrefix+tenant.TenantID+tenantDropInSuffix, "identity.conf"),
				filepath.Join(systemdRoot, tenantDropInPrefix+tenant.TenantID+tenantDropInSuffix, "resources.conf"),
			}, " "),
			"NoNewPrivileges": "yes", "MemoryHigh": strconv.FormatUint(limits.MemoryBytes, 10), "MemoryMax": strconv.FormatUint(limits.MemoryBytes, 10),
			"CPUQuotaPerSecUSec": (time.Duration(limits.CPUPercent) * time.Second / 100).String(), "TasksMax": strconv.FormatUint(uint64(limits.ActiveProcesses), 10),
			"UMask": "0077", "KillMode": "control-group", "PrivateDevices": "yes", "PrivateTmp": "yes", "ProtectClock": "yes",
			"ProtectControlGroups": "yes", "ProtectHome": "yes", "ProtectHostname": "yes", "ProtectKernelLogs": "yes", "ProtectKernelModules": "yes",
			"ProtectKernelTunables": "yes", "ProtectProc": "invisible", "ProcSubset": "pid", "ProtectSystem": "strict", "RestrictRealtime": "yes",
			"LockPersonality": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
			"SystemCallArchitectures": "native", "ReadWritePaths": strings.Join([]string{tenant.DataRoot, filepath.Dir(tenant.SocketPath), tenant.Capacity.SlotDirectory}, " "),
			"KeyringMode": "private", "LimitCORE": "0",
		}
		if unit == controller.wrongFragmentUnit {
			values["FragmentPath"] = "/run/systemd/system/" + filepath.Base(values["FragmentPath"])
		}
		if unit == controller.extraDropInUnit {
			values["DropInPaths"] += " /run/systemd/system/unauthenticated.conf"
		}
		result := make(map[string]string, len(names))
		for _, name := range names {
			result[name] = values[name]
		}
		return result, nil
	}
	return nil, errors.New("unknown batch test unit")
}

func (controller tenantBatchSystemd) ListUnits(_ context.Context, _ ...string) ([]string, error) {
	if controller.listErr != nil {
		return nil, controller.listErr
	}
	units := make([]string, 0, len(controller.tenants)*2)
	for _, tenant := range controller.tenants {
		units = append(units, tenantDropInPrefix+tenant.TenantID+".service", tenantDropInPrefix+tenant.TenantID+".socket")
	}
	return units, nil
}

func tenantBatchTestPortal(root, runtimeUser string) config.Portal {
	return config.Portal{
		SchemaVersion: config.PortalSchemaVersion,
		RuntimeUser:   runtimeUser,
		BrandFile:     filepath.Join(root, "brand.json"),
		PolicyFile:    filepath.Join(root, "policy.json"),
		Listener: config.Listener{
			Network: "tcp", Address: "127.0.0.1:42580", PublicOrigin: "https://portal.example.test",
			TrustedProxyCIDRs: []string{"127.0.0.1/32"}, RequireForwardedHTTPS: true,
		},
		Session: config.SessionPolicy{
			CookieName: "__Host-aionui-portal", Secure: true, HTTPOnly: true, SameSite: "strict",
			IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 43200,
		},
		Paths: config.PortalPaths{
			PortalState: filepath.Join(root, "state"), TenantConfigs: filepath.Join(root, "configs"),
			TenantData: filepath.Join(root, "users"), RuntimeSockets: filepath.Join(root, "run"),
			ReleaseRoot: filepath.Join(root, "releases"),
		},
		Runtime:       config.RuntimePolicy{MaxConcurrentInstances: 3, IdleReapSeconds: 900, RequireDedicatedUID: true, RequireReleaseHashes: true},
		Usage:         config.UsagePolicy{QueryTimeoutSeconds: 3, CacheTTLSeconds: 15},
		Observability: config.ObservabilityPolicy{AuditRetentionDays: 365, AuditMinimumEvents: 1000},
	}
}

func tenantBatchTestTenant(portal config.Portal, tenantID, runtimeUser string, portalUID uint32) config.Tenant {
	releaseRoot := filepath.Join(portal.Paths.ReleaseRoot, tenantID, "releases")
	dataRoot := filepath.Join(portal.Paths.TenantData, tenantID)
	return config.Tenant{
		SchemaVersion: config.TenantSchemaVersion, TenantID: tenantID, RuntimeUser: runtimeUser,
		DataRoot: dataRoot, SocketPath: filepath.Join(portal.Paths.RuntimeSockets, tenantID+".sock"), SocketActivation: true,
		PortalUID: portalUID, PortalOrigin: portal.Listener.PublicOrigin,
		Capacity:        config.TenantCapacity{SlotDirectory: filepath.Join(filepath.Dir(portal.Paths.RuntimeSockets), "capacity"), MaxInstances: portal.Runtime.MaxConcurrentInstances},
		IdleReapSeconds: portal.Runtime.IdleReapSeconds,
		Release: config.TenantRelease{
			ReleasesRoot: releaseRoot, PointerFile: filepath.Join(filepath.Dir(releaseRoot), "current.json"),
			PublicKeyFile: filepath.Join(portal.Paths.ReleaseRoot, "trust.pub"), Scope: "runtime",
		},
		Backend: config.Backend{
			Executable: "bin/runtime", WorkingDirectory: filepath.Join(dataRoot, "workspace"), HealthPath: "/healthz",
			ActivityProbe: "aggregate", ActivityPath: "/api/activity", StartupTimeoutSeconds: 30,
		},
	}
}
