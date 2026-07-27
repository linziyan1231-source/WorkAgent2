package tenantprovision

import (
	"errors"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

// Identity is the immutable, non-secret Linux identity recorded by a reviewed
// Windows migration report or chosen for a newly provisioned tenant.
type Identity struct {
	TenantID           string
	RuntimeUser        string
	ProjectID          uint32
	DiskHardLimitBytes uint64
}

// BuildConfig constructs the canonical schema-v5 runtime configuration used by
// the privileged migration publisher. It is kept in a focused internal package
// so normal provisioning can adopt the same template without importing the
// migration implementation.
func BuildConfig(portal config.Portal, portalUID uint32, identity Identity, limits config.ResourceLimits) (config.Tenant, error) {
	parsed, err := uuid.Parse(identity.TenantID)
	if err != nil || parsed.String() != identity.TenantID || portalUID == 0 || identity.RuntimeUser == "" || identity.ProjectID == 0 || identity.DiskHardLimitBytes == 0 {
		return config.Tenant{}, errors.New("tenant provisioning identity is invalid")
	}
	dataRoot := filepath.Join(portal.Paths.TenantData, identity.TenantID)
	tenant := config.Tenant{
		SchemaVersion: config.TenantSchemaVersion, TenantID: identity.TenantID, RuntimeUser: identity.RuntimeUser, DataRoot: dataRoot,
		SocketPath: filepath.Join(portal.Paths.RuntimeSockets, identity.TenantID+".sock"), SocketActivation: true, PortalUID: portalUID, PortalOrigin: portal.Listener.PublicOrigin,
		IdleReapSeconds:  portal.Runtime.IdleReapSeconds,
		OutboundProxyURL: portal.OutboundProxyURL,
		Capacity:         config.TenantCapacity{SlotDirectory: "/run/workagent/capacity", MaxInstances: portal.Runtime.MaxConcurrentInstances, ProjectID: identity.ProjectID, DiskHardLimitBytes: identity.DiskHardLimitBytes},
		Limits:           limits.Effective(),
		Release:          config.TenantRelease{ReleasesRoot: "/opt/workagent/aionui/releases", PointerFile: "/opt/workagent/aionui/current.json", PublicKeyFile: "/etc/workagent/trust/release-signing.pub", Scope: "runtime"},
		Backend: config.Backend{
			Executable: "bin/aionui-web", Arguments: []string{"start", "--port", "{listen_port}", "--data-dir", "{data_root}/data", "--work-dir", "{data_root}/workspace", "--log-dir", "{data_root}/logs", "--static-dir", "{release_root}/static", "--backend-bin", "{release_root}/bin/aioncore", "--no-open"},
			RequiredReleaseFiles: []string{"static/index.html", "workagent-builtin-assistants/assistants.json", "workagent-builtin-assistants/rules/aionui-assistant.en-US.md", "workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md", "workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md"}, WorkingDirectory: filepath.Join(dataRoot, "workspace"),
			HealthPath: "/healthz", ActivityProbe: "aionui", StartupTimeoutSeconds: 60, RequireModelBootstrap: true, ModelBootstrapTimeoutSeconds: 120,
			AgentCLI:     config.AgentCLI{BinDirectory: "bin", CodexExecutable: "bin/codex", KimiExecutable: "bin/kimi", PythonExecutable: "bin/python3", ProbeTimeoutSeconds: 30},
			Migration:    config.BackendMigration{Enabled: true, Executable: "bin/aioncore", Arguments: []string{"--port", "{listen_port}", "--data-dir", "{data_root}/data", "--work-dir", "{data_root}/workspace", "--log-dir", "{data_root}/logs", "--managed-resources-mode", "bundled"}, WorkingDirectory: filepath.Join(dataRoot, "workspace"), HealthPath: "/health", StartupTimeoutSeconds: 60, ShutdownTimeoutSeconds: 10},
			InternalAuth: config.BackendInternalAuth{Enabled: true, DatabasePath: filepath.Join(dataRoot, "data", "aionui-backend.db")},
		},
	}
	if err := tenant.Validate(); err != nil {
		return config.Tenant{}, err
	}
	return tenant, nil
}
