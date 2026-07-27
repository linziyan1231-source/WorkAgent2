//go:build linux

package admin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

type tenantActivationController struct {
	properties map[string]map[string]string
}

func (controller *tenantActivationController) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	properties, ok := controller.properties[unit]
	if !ok {
		return nil, errors.New("unexpected unit")
	}
	result := make(map[string]string, len(properties))
	for name, value := range properties {
		result[name] = value
	}
	return result, nil
}

func (*tenantActivationController) Action(context.Context, ...string) error { return nil }

func TestVerifyTenantActivationCatalogEnforcesEnabledSocketAndDisabledQuiescence(t *testing.T) {
	const enabledID = "11111111-1111-4111-8111-111111111111"
	const disabledID = "22222222-2222-4222-8222-222222222222"
	identities := []store.PortalUserIdentity{{TenantID: enabledID, Enabled: true}, {TenantID: disabledID, Enabled: false}}
	controller := &tenantActivationController{properties: map[string]map[string]string{
		"workagent-userhost@" + enabledID + ".socket":   {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"},
		"workagent-userhost@" + enabledID + ".service":  {"LoadState": "loaded", "ActiveState": "activating", "SubState": "start-pre", "MainPID": "0"},
		"workagent-userhost@" + disabledID + ".socket":  {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"},
		"workagent-userhost@" + disabledID + ".service": {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0"},
	}}
	if err := VerifyTenantActivationCatalog(context.Background(), identities, controller); err != nil {
		t.Fatalf("exact durable activation catalog rejected an enabled service transition: %v", err)
	}
	for name, mutate := range map[string]func(){
		"transient enablement": func() {
			controller.properties["workagent-userhost@"+enabledID+".socket"]["UnitFileState"] = "enabled-runtime"
		},
		"disabled active socket": func() { controller.properties["workagent-userhost@"+disabledID+".socket"]["ActiveState"] = "active" },
		"disabled running service": func() {
			controller.properties["workagent-userhost@"+disabledID+".service"] = map[string]string{"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "44"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fresh := &tenantActivationController{properties: make(map[string]map[string]string, len(controller.properties))}
			for unit, properties := range controller.properties {
				fresh.properties[unit] = make(map[string]string, len(properties))
				for key, value := range properties {
					fresh.properties[unit][key] = value
				}
			}
			// Restore the common valid baseline before applying this case.
			fresh.properties["workagent-userhost@"+enabledID+".socket"]["UnitFileState"] = "enabled"
			fresh.properties["workagent-userhost@"+disabledID+".socket"]["ActiveState"] = "inactive"
			fresh.properties["workagent-userhost@"+disabledID+".service"] = map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
			controller = fresh
			mutate()
			if err := VerifyTenantActivationCatalog(context.Background(), identities, controller); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("unsafe activation catalog was accepted")
			}
		})
	}
}

func TestVerifyTenantIdentityCatalogRequiresExactBidirectionalBindings(t *testing.T) {
	first := config.Tenant{SchemaVersion: config.TenantSchemaVersion, TenantID: "11111111-1111-4111-8111-111111111111", RuntimeUser: "workagent_first", DataRoot: "/srv/workagent/users/11111111-1111-4111-8111-111111111111"}
	second := config.Tenant{SchemaVersion: config.TenantSchemaVersion, TenantID: "22222222-2222-4222-8222-222222222222", RuntimeUser: "workagent_second", DataRoot: "/srv/workagent/users/22222222-2222-4222-8222-222222222222"}
	// Fill the remaining schema with a known-valid fixture, then retain only the
	// identity fields under comparison.
	portal := tenantBatchTestPortal(t.TempDir(), "workagent")
	first = tenantBatchTestTenant(portal, first.TenantID, first.RuntimeUser, 1000)
	second = tenantBatchTestTenant(portal, second.TenantID, second.RuntimeUser, 1000)
	identities := []store.PortalUserIdentity{
		{TenantID: first.TenantID, RuntimeUser: first.RuntimeUser, DataRoot: first.DataRoot, Enabled: true},
		{TenantID: second.TenantID, RuntimeUser: second.RuntimeUser, DataRoot: second.DataRoot, Enabled: false},
	}
	if err := VerifyTenantIdentityCatalog([]config.Tenant{first, second}, identities); err != nil {
		t.Fatalf("exact enabled+disabled identity catalog rejected: %v", err)
	}
	for _, test := range []struct {
		name       string
		tenants    []config.Tenant
		identities []store.PortalUserIdentity
	}{
		{name: "missing row", tenants: []config.Tenant{first, second}, identities: identities[:1]},
		{name: "extra row", tenants: []config.Tenant{first}, identities: identities},
		{name: "runtime mismatch", tenants: []config.Tenant{first, second}, identities: []store.PortalUserIdentity{identities[0], {TenantID: second.TenantID, RuntimeUser: "workagent_other", DataRoot: second.DataRoot}}},
		{name: "root mismatch", tenants: []config.Tenant{first, second}, identities: []store.PortalUserIdentity{identities[0], {TenantID: second.TenantID, RuntimeUser: second.RuntimeUser, DataRoot: first.DataRoot}}},
		{name: "duplicate DB user", tenants: []config.Tenant{first, second}, identities: []store.PortalUserIdentity{identities[0], {TenantID: second.TenantID, RuntimeUser: first.RuntimeUser, DataRoot: second.DataRoot}}},
		{name: "empty", tenants: nil, identities: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyTenantIdentityCatalog(test.tenants, test.identities); err == nil {
				t.Fatal("non-bidirectional Portal identity catalog was accepted")
			}
		})
	}
}
