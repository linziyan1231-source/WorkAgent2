package admin

import (
	"path/filepath"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

const bindingTenant = "11111111-1111-4111-8111-111111111111"

func TestValidateTenantBinding(t *testing.T) {
	root := t.TempDir()
	portal := config.Portal{
		SchemaVersion: config.PortalSchemaVersion, RuntimeUser: "workagent",
		BrandFile: filepath.Join(root, "brand.json"), PolicyFile: filepath.Join(root, "policy.json"),
		Listener:      config.Listener{Network: "tcp", Address: "127.0.0.1:42580", PublicOrigin: "https://portal.example.test", TrustedProxyCIDRs: []string{"127.0.0.1/32"}, RequireForwardedHTTPS: true},
		Session:       config.SessionPolicy{CookieName: "__Host-aionui-portal", Secure: true, HTTPOnly: true, SameSite: "strict", IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 43200},
		Paths:         config.PortalPaths{PortalState: filepath.Join(root, "state"), TenantConfigs: filepath.Join(root, "tenants"), TenantData: filepath.Join(root, "users"), RuntimeSockets: filepath.Join(root, "run"), ReleaseRoot: filepath.Join(root, "releases")},
		Runtime:       config.RuntimePolicy{MaxConcurrentInstances: 3, IdleReapSeconds: 900, RequireDedicatedUID: true, RequireReleaseHashes: true},
		Usage:         config.UsagePolicy{QueryTimeoutSeconds: 3, CacheTTLSeconds: 15},
		Observability: config.ObservabilityPolicy{AuditRetentionDays: 365, AuditMinimumEvents: 1000},
	}
	releasesRoot := filepath.Join(root, "releases", "runtime", "releases")
	portal.Renderer = config.RendererRelease{
		ReleasesRoot: releasesRoot, PointerFile: filepath.Join(filepath.Dir(releasesRoot), "current.json"),
		PublicKeyFile: filepath.Join(root, "trust", "release.pub"), Scope: "runtime", RelativeRoot: "static",
	}
	tenant := config.Tenant{
		SchemaVersion: config.TenantSchemaVersion, TenantID: bindingTenant, RuntimeUser: "workagent_test", DataRoot: filepath.Join(root, "users", bindingTenant), SocketPath: filepath.Join(root, "run", bindingTenant+".sock"), SocketActivation: true, PortalUID: 991, PortalOrigin: "https://portal.example.test", Capacity: config.TenantCapacity{SlotDirectory: filepath.Join(root, "capacity"), MaxInstances: 3},
		IdleReapSeconds: 900,
		Release: config.TenantRelease{
			ReleasesRoot: releasesRoot, PointerFile: filepath.Join(filepath.Dir(releasesRoot), "current.json"),
			PublicKeyFile: filepath.Join(root, "trust", "release.pub"), Scope: "runtime",
		},
		Backend: config.Backend{Executable: "bin/runtime", WorkingDirectory: filepath.Join(root, "users", bindingTenant, "workspace"), HealthPath: "/healthz", ActivityProbe: "aggregate", ActivityPath: "/api/activity", StartupTimeoutSeconds: 30},
	}
	if err := ValidateTenantBinding(portal, tenant); err != nil {
		t.Fatal(err)
	}
	tenant.DataRoot = filepath.Join(root, "other")
	if err := ValidateTenantBinding(portal, tenant); err == nil {
		t.Fatal("foreign tenant data root was accepted")
	}
	tenant.DataRoot = filepath.Join(root, "users", bindingTenant)
	tenant.Release.PublicKeyFile = filepath.Join(root, "trust", "other.pub")
	if err := ValidateTenantBinding(portal, tenant); err == nil {
		t.Fatal("tenant channel with a foreign release trust root was accepted")
	}
}
