//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

// VerifyTenantIdentityCatalog proves bidirectional equality between the
// complete protected tenant generation and every Portal user row. Disabled
// rows are deliberately included: enabled state controls activation, not
// durable tenant identity membership.
func VerifyTenantIdentityCatalog(tenants []config.Tenant, identities []store.PortalUserIdentity) error {
	if len(tenants) != len(identities) {
		return errors.New("Portal database and tenant configuration catalogs have different cardinality")
	}
	tenantByID := make(map[string]config.Tenant, len(tenants))
	tenantUsers := make(map[string]bool, len(tenants))
	tenantRoots := make(map[string]bool, len(tenants))
	for _, tenant := range tenants {
		if err := tenant.Validate(); err != nil || !canonicalTenantFileID(tenant.TenantID) {
			return errors.New("tenant configuration identity catalog contains an invalid tenant")
		}
		if _, duplicate := tenantByID[tenant.TenantID]; duplicate || tenantUsers[tenant.RuntimeUser] || tenantRoots[tenant.DataRoot] {
			return errors.New("tenant configuration identity catalog contains a duplicate identity")
		}
		tenantByID[tenant.TenantID] = tenant
		tenantUsers[tenant.RuntimeUser] = true
		tenantRoots[tenant.DataRoot] = true
	}
	seenIDs := make(map[string]bool, len(identities))
	seenUsers := make(map[string]bool, len(identities))
	seenRoots := make(map[string]bool, len(identities))
	for _, identity := range identities {
		if !canonicalTenantFileID(identity.TenantID) || identity.RuntimeUser == "" || identity.DataRoot == "" ||
			seenIDs[identity.TenantID] || seenUsers[identity.RuntimeUser] || seenRoots[identity.DataRoot] {
			return errors.New("Portal database identity catalog contains an invalid or duplicate identity")
		}
		seenIDs[identity.TenantID] = true
		seenUsers[identity.RuntimeUser] = true
		seenRoots[identity.DataRoot] = true
		tenant, found := tenantByID[identity.TenantID]
		if !found || tenant.RuntimeUser != identity.RuntimeUser || tenant.DataRoot != identity.DataRoot {
			return fmt.Errorf("Portal database identity for tenant %s does not match its protected configuration", identity.TenantID)
		}
	}
	for tenantID := range tenantByID {
		if !seenIDs[tenantID] {
			return fmt.Errorf("protected tenant %s has no Portal database identity", tenantID)
		}
	}
	return nil
}

// VerifyLiveTenantIdentityCatalog performs the same proof against an already
// open Portal store. Its caller must retain C_SH (or C_EX) from before the
// clean-marker proof through this call and the subsequent activation.
func VerifyLiveTenantIdentityCatalog(ctx context.Context, portal config.Portal, data *store.Store) error {
	_, err := verifyLiveTenantIdentityCatalog(ctx, portal, data, nil, false)
	return err
}

// VerifyLiveTenantIdentityCatalogAllowEmpty is the pre-publication form used
// before the very first tenant is added. It accepts only the exact empty/empty
// state; once either side is non-empty the normal bidirectional proof applies.
func VerifyLiveTenantIdentityCatalogAllowEmpty(ctx context.Context, portal config.Portal, data *store.Store) error {
	_, err := verifyLiveTenantIdentityCatalog(ctx, portal, data, nil, true)
	return err
}

// VerifyLiveTenantIdentityCatalogWithPendingCreate proves that inserting one
// exact tenant identity will close the only permitted config-before-DB gap.
// It is used while C_SH is held immediately before CreateUser commits.
func VerifyLiveTenantIdentityCatalogWithPendingCreate(ctx context.Context, portal config.Portal, data *store.Store, pending store.PortalUserIdentity) error {
	_, err := verifyLiveTenantIdentityCatalog(ctx, portal, data, &pending, false)
	return err
}

// VerifyLiveTenantActivationCatalog couples exact config/database identity
// equality with the durable systemd enablement invariant. Enabled users must
// have a persistently enabled socket. Disabled users must have a disabled,
// inactive socket and an inactive, process-free service. Enabled sockets may
// be temporarily inactive while an activation-locked backup or resource
// update is quiescing the fleet.
func VerifyLiveTenantActivationCatalog(ctx context.Context, portal config.Portal, data *store.Store, controller systemdctl.Controller) error {
	if controller == nil {
		controller = systemdctl.Default()
	}
	identities, err := verifyLiveTenantIdentityCatalog(ctx, portal, data, nil, false)
	if err != nil {
		return err
	}
	return VerifyTenantActivationCatalog(ctx, identities, controller)
}

func verifyLiveTenantIdentityCatalog(ctx context.Context, portal config.Portal, data *store.Store, pending *store.PortalUserIdentity, allowEmpty bool) ([]store.PortalUserIdentity, error) {
	if ctx == nil || data == nil {
		return nil, errors.New("live Portal identity catalog verifier is unavailable")
	}
	if err := AssertTenantFileCatalogClean(portal); err != nil {
		return nil, err
	}
	tenants, err := loadFinalTenantFileCatalog(portal, nil)
	if err != nil {
		return nil, fmt.Errorf("load protected tenant catalog for Portal identity comparison: %w", err)
	}
	users, err := data.ListTenantUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Portal user identities for tenant comparison: %w", err)
	}
	identities := make([]store.PortalUserIdentity, 0, len(users))
	for _, user := range users {
		identities = append(identities, store.PortalUserIdentity{
			TenantID: user.TenantID, RuntimeUser: user.RuntimeUser, DataRoot: user.DataRoot, Enabled: user.Enabled,
		})
	}
	if pending != nil {
		identities = append(identities, *pending)
	}
	_ = allowEmpty // Empty managed catalogs are valid for a Portal-only administrator.
	if err := VerifyTenantIdentityCatalog(tenants, identities); err != nil {
		return nil, err
	}
	return identities, nil
}

// VerifyTenantActivationCatalog is also used by the boot reconciler with a
// WAL-aware offline identity snapshot. It intentionally rejects transient
// enablement: reboot safety requires a persistent sockets.target link.
func VerifyTenantActivationCatalog(ctx context.Context, identities []store.PortalUserIdentity, controller systemdctl.Controller) error {
	if ctx == nil || controller == nil {
		return errors.New("tenant activation catalog verifier is unavailable")
	}
	ordered := append([]store.PortalUserIdentity(nil), identities...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].TenantID < ordered[j].TenantID })
	seen := make(map[string]bool, len(ordered))
	for _, identity := range ordered {
		if !canonicalTenantFileID(identity.TenantID) || seen[identity.TenantID] {
			return errors.New("tenant activation catalog contains an invalid or duplicate identity")
		}
		seen[identity.TenantID] = true
		socketUnit := "workagent-userhost@" + identity.TenantID + ".socket"
		serviceUnit := "workagent-userhost@" + identity.TenantID + ".service"
		socket, err := controller.Properties(ctx, socketUnit, "LoadState", "ActiveState", "UnitFileState")
		if err != nil {
			return fmt.Errorf("inspect tenant activation socket %s: %w", socketUnit, err)
		}
		service, err := controller.Properties(ctx, serviceUnit, "LoadState", "ActiveState", "SubState", "MainPID")
		if err != nil {
			return fmt.Errorf("inspect tenant activation service %s: %w", serviceUnit, err)
		}
		pid, pidErr := strconv.ParseUint(service["MainPID"], 10, 64)
		if socket["LoadState"] != "loaded" || service["LoadState"] != "loaded" || pidErr != nil {
			return fmt.Errorf("tenant %s activation units are not loaded with a valid process identity", identity.TenantID)
		}
		if identity.Enabled {
			if socket["UnitFileState"] != "enabled" || (socket["ActiveState"] != "active" && socket["ActiveState"] != "inactive") {
				return fmt.Errorf("enabled tenant %s does not have a persistently enabled stable socket", identity.TenantID)
			}
			continue
		}
		serviceInactive := service["ActiveState"] == "inactive" && service["SubState"] == "dead" && pid == 0
		if socket["UnitFileState"] != "disabled" || socket["ActiveState"] != "inactive" || !serviceInactive {
			return fmt.Errorf("disabled tenant %s has an enabled or active runtime", identity.TenantID)
		}
	}
	return nil
}
