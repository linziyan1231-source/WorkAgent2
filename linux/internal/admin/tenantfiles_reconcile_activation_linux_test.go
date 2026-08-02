//go:build linux

package admin

import (
	"context"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

func TestOfflineBootGateReplaysDurableActivationBeforeFinalProof(t *testing.T) {
	path := tenantActivationTestJournalPath(t)
	portal := tenantBatchTestPortal(t.TempDir(), "workagent")
	identities := tenantActivationTestIdentities()
	tenants := make([]config.Tenant, 0, len(identities))
	for _, identity := range identities {
		tenant := tenantBatchTestTenant(portal, identity.TenantID, identity.RuntimeUser, 1000)
		identities[len(tenants)].DataRoot = tenant.DataRoot
		tenants = append(tenants, tenant)
	}
	if err := prepareTenantActivationAt(context.Background(), path, 0, identities, identities[1].TenantID, true, nil); err != nil {
		t.Fatal(err)
	}
	identities[1].Enabled = true // Simulate DB commit before a power loss.
	controller := newTenantActivationSystemd(identities)
	// The third tenant is disabled in the database but initially active and
	// enabled in systemd, so the unconditional final proof can pass only after
	// the injected production replay has converged the catalog.
	replayCalls := 0
	if err := reconcileOfflineTenantActivationCatalog(
		context.Background(), tenants, identities, controller,
		func(ctx context.Context, current []store.PortalUserIdentity, controllerArg systemdctl.Controller) error {
			replayCalls++
			return replayTenantActivationAt(ctx, path, 0, current, controllerArg, nil)
		},
	); err != nil {
		t.Fatal(err)
	}
	if replayCalls != 1 {
		t.Fatalf("offline boot gate replay calls = %d, want 1", replayCalls)
	}
	assertTenantActivationJournalAbsent(t, path)
	if err := VerifyTenantActivationCatalog(context.Background(), identities, controller); err != nil {
		t.Fatalf("offline boot gate did not finish with a complete activation proof: %v", err)
	}
}

func TestOfflineBootGateAuthenticatesIdentityBeforeActivationReplay(t *testing.T) {
	portal := tenantBatchTestPortal(t.TempDir(), "workagent")
	identities := tenantActivationTestIdentities()
	tenants := make([]config.Tenant, 0, len(identities))
	for index, identity := range identities {
		tenant := tenantBatchTestTenant(portal, identity.TenantID, identity.RuntimeUser, 1000)
		identities[index].DataRoot = tenant.DataRoot
		tenants = append(tenants, tenant)
	}
	identities[0].RuntimeUser = "workagent_tampered"
	controller := newTenantActivationSystemd(identities)
	replayCalled := false
	err := reconcileOfflineTenantActivationCatalog(
		context.Background(), tenants, identities, controller,
		func(context.Context, []store.PortalUserIdentity, systemdctl.Controller) error {
			replayCalled = true
			return nil
		},
	)
	if err == nil || replayCalled || len(controller.actions) != 0 {
		t.Fatalf("identity drift reached activation replay: replay=%t actions=%v err=%v", replayCalled, controller.actions, err)
	}
}

func TestOfflineBootGateRetainsUnconditionalProofWhenReplayIsClean(t *testing.T) {
	portal := tenantBatchTestPortal(t.TempDir(), "workagent")
	identities := tenantActivationTestIdentities()
	tenants := make([]config.Tenant, 0, len(identities))
	for index, identity := range identities {
		tenant := tenantBatchTestTenant(portal, identity.TenantID, identity.RuntimeUser, 1000)
		identities[index].DataRoot = tenant.DataRoot
		tenants = append(tenants, tenant)
	}
	controller := newTenantActivationSystemd(identities)
	replayCalls := 0
	err := reconcileOfflineTenantActivationCatalog(
		context.Background(), tenants, identities, controller,
		func(context.Context, []store.PortalUserIdentity, systemdctl.Controller) error {
			replayCalls++
			return nil // Simulate an absent, clean activation journal.
		},
	)
	if err == nil || replayCalls != 1 {
		t.Fatalf("clean replay bypassed the final activation proof: calls=%d err=%v", replayCalls, err)
	}
}
