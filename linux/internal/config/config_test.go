package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const tenantOne = "11111111-1111-4111-8111-111111111111"

func validPortal(root string) Portal {
	return Portal{
		SchemaVersion: PortalSchemaVersion,
		RuntimeUser:   "workagent",
		BrandFile:     filepath.Join(root, "etc", "brand.json"),
		PolicyFile:    filepath.Join(root, "etc", "policy.json"),
		Listener:      Listener{Network: "tcp", Address: "127.0.0.1:42580", PublicOrigin: "https://portal.example.test", TrustedProxyCIDRs: []string{"127.0.0.1/32"}, RequireForwardedHTTPS: true},
		Session:       SessionPolicy{CookieName: "__Host-aionui-portal", Secure: true, HTTPOnly: true, SameSite: "strict", IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 43200},
		Paths:         PortalPaths{PortalState: filepath.Join(root, "state"), TenantConfigs: filepath.Join(root, "tenants"), TenantData: filepath.Join(root, "data"), RuntimeSockets: filepath.Join(root, "run"), ReleaseRoot: filepath.Join(root, "releases")},
		Runtime:       RuntimePolicy{MaxConcurrentInstances: 3, IdleReapSeconds: 900, RequireDedicatedUID: true, RequireReleaseHashes: true},
		Usage:         UsagePolicy{QueryTimeoutSeconds: 3, CacheTTLSeconds: 15},
		Observability: ObservabilityPolicy{AuditRetentionDays: 365, AuditMinimumEvents: 1000},
	}
}

func TestPortalValidationRejectsPublicAndUnsafeListeners(t *testing.T) {
	root := t.TempDir()
	for name, mutate := range map[string]func(*Portal){
		"public bind":         func(value *Portal) { value.Listener.Address = "0.0.0.0:42580" },
		"hostname bind":       func(value *Portal) { value.Listener.Address = "localhost:42580" },
		"insecure origin":     func(value *Portal) { value.Listener.PublicOrigin = "http://portal.example.test" },
		"credentialed origin": func(value *Portal) { value.Listener.PublicOrigin = "https://contact@example.invalid" },
		"weak cookie":         func(value *Portal) { value.Session.Secure = false },
		"too many runtimes":   func(value *Portal) { value.Runtime.MaxConcurrentInstances = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			value := validPortal(root)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestPortalRendererChannelMustBeCompleteAndCanonical(t *testing.T) {
	root := t.TempDir()
	value := validPortal(root)
	value.Renderer = RendererRelease{
		ReleasesRoot:  filepath.Join(root, "runtime", "releases"),
		PointerFile:   filepath.Join(root, "runtime", "current.json"),
		PublicKeyFile: filepath.Join(root, "trust", "release.pub"),
		Scope:         "runtime",
		RelativeRoot:  "renderer",
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("valid Renderer release channel rejected: %v", err)
	}
	value.Renderer.RelativeRoot = "../renderer"
	if err := value.Validate(); err == nil {
		t.Fatal("Renderer path escape was accepted")
	}
	value.Renderer.RelativeRoot = "renderer"
	value.Renderer.PointerFile = filepath.Join(root, "other", "current.json")
	if err := value.Validate(); err == nil {
		t.Fatal("unbound Renderer pointer was accepted")
	}
}

func TestPortalAdminMasterCredentialMustBeAbsolute(t *testing.T) {
	value := validPortal(t.TempDir())
	value.AdminMasterPasswordHashFile = "admin-master.hash"
	if err := value.Validate(); err == nil {
		t.Fatal("relative administrator master-password credential was accepted")
	}
}

func TestOutboundProxyURLIsOptionalAndStrictlyValidated(t *testing.T) {
	portal := validPortal(t.TempDir())
	portal.OutboundProxyURL = "http://127.0.0.1:7897"
	if err := portal.Validate(); err != nil {
		t.Fatalf("valid Portal proxy rejected: %v", err)
	}
	for _, invalid := range []string{"socks5://127.0.0.1:7897", "http://user@127.0.0.1:7897", "http://127.0.0.1:7897/path", "//127.0.0.1:7897"} {
		candidate := portal
		candidate.OutboundProxyURL = invalid
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid Portal proxy accepted: %q", invalid)
		}
	}
	tenant := validTenant(t.TempDir())
	tenant.OutboundProxyURL = "https://proxy.example.test:8443"
	if err := tenant.Validate(); err != nil {
		t.Fatalf("valid tenant proxy rejected: %v", err)
	}
}

func TestChatForwardRequiresWindowsParityReleaseCapabilities(t *testing.T) {
	value := validPortal(t.TempDir())
	value.ChatForward = ChatForwardService{
		Enabled: true, Endpoint: "http://127.0.0.1:3210", CredentialFile: "/run/credentials/chatforward-key",
		ProModels: []string{"gpt-5-4-pro", "gpt-5-5-pro", "gpt-5-6-pro"}, WeeklyProLimit: 7,
		MaxPairs: 3, ExtensionProtocol: "quota-v1", QuotaProtection: true, SourceAssetProxy: true,
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("current ChatForward contract rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ChatForwardService){
		"old pair cap":      func(service *ChatForwardService) { service.MaxPairs = 20 },
		"no quota protocol": func(service *ChatForwardService) { service.ExtensionProtocol = "" },
		"quota bypass":      func(service *ChatForwardService) { service.QuotaProtection = false },
		"no asset proxy":    func(service *ChatForwardService) { service.SourceAssetProxy = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := value
			mutate(&candidate.ChatForward)
			if err := candidate.Validate(); err == nil {
				t.Fatal("stale ChatForward capability contract was accepted")
			}
		})
	}
}

func TestLoadPortalIsStrict(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "portal.json")
	value := validPortal(root)
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] = ','
	payload = append(payload, []byte(`"unexpected":true}`)...)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPortal(path); err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}

func TestCheckedInPortalAndTenantExamplesValidate(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	portal, err := LoadPortal(filepath.Join(repositoryRoot, "config", "portal.example.json"))
	if err != nil {
		t.Fatalf("checked-in Portal example is invalid: %v", err)
	}
	if err := portal.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		t.Fatalf("checked-in Portal example is not production-shaped: %v", err)
	}
	if _, err := LoadTenant(filepath.Join(repositoryRoot, "config", "tenant.example.json")); err != nil {
		t.Fatalf("checked-in tenant example is invalid: %v", err)
	}
}

func TestProductionLayoutRequiresSharedHTTPSProxyBoundary(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadPortal(filepath.Join(repositoryRoot, "config", "portal.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Portal){
		"legacy branding path": func(value *Portal) { value.BrandFile = "/etc/workagent/branding/workagent/brand.json" },
		"unix listener without a peer identity contract": func(value *Portal) {
			value.Listener.Network = "unix"
			value.Listener.Address = "/run/workagent/portal.sock"
		},
		"missing HTTPS attestation": func(value *Portal) { value.Listener.RequireForwardedHTTPS = false },
		"insecure loopback bypass":  func(value *Portal) { value.Listener.AllowInsecureLoopback = true },
		"direct TLS termination": func(value *Portal) {
			value.Listener.TLSCertificateFile = "/etc/workagent/tls/portal.crt"
			value.Listener.TLSPrivateKeyFile = "/etc/workagent/tls/portal.key"
		},
		"non-loopback trusted proxy": func(value *Portal) { value.Listener.TrustedProxyCIDRs = []string{"0.0.0.0/0"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := baseline
			mutate(&candidate)
			if err := candidate.ValidateProductionLayout("/etc/workagent/portal.json"); err == nil {
				t.Fatal("unsafe production proxy boundary was accepted")
			}
		})
	}
}

func TestResourceLimitsUseWindowsParityDefaultsAndRejectPartialValues(t *testing.T) {
	defaults := (ResourceLimits{}).Effective()
	if defaults.MemoryBytes != 6*1024*1024*1024 || defaults.CPUPercent != 50 || defaults.ActiveProcesses != 64 {
		t.Fatalf("unexpected parity defaults: %+v", defaults)
	}
	if err := (ResourceLimits{MemoryBytes: defaults.MemoryBytes}).Validate(); err == nil {
		t.Fatal("partial resource limits were accepted")
	}
}

func validTenant(root string) Tenant {
	releasesRoot := filepath.Join(root, "runtime", "releases")
	dataRoot := filepath.Join(root, "users", tenantOne)
	return Tenant{
		SchemaVersion:    TenantSchemaVersion,
		TenantID:         tenantOne,
		RuntimeUser:      "workagent_tenant_one",
		DataRoot:         dataRoot,
		SocketPath:       filepath.Join(root, "run", tenantOne+".sock"),
		SocketActivation: true,
		PortalUID:        991,
		PortalOrigin:     "https://portal.example.test",
		IdleReapSeconds:  900,
		Capacity:         TenantCapacity{SlotDirectory: filepath.Join(root, "capacity"), MaxInstances: 3},
		Release: TenantRelease{
			ReleasesRoot: releasesRoot, PointerFile: filepath.Join(filepath.Dir(releasesRoot), "current.json"),
			PublicKeyFile: filepath.Join(root, "trust", "release.pub"), Scope: "runtime",
		},
		Backend: Backend{Executable: "bin/runtime", WorkingDirectory: filepath.Join(dataRoot, "workspace"), HealthPath: "/healthz", ActivityProbe: "aggregate", ActivityPath: "/api/activity", StartupTimeoutSeconds: 30},
	}
}

func TestTenantValidationBindsIdentityAndPaths(t *testing.T) {
	root := t.TempDir()
	for name, mutate := range map[string]func(*Tenant){
		"noncanonical tenant":  func(value *Tenant) { value.TenantID = "11111111-1111-1111-1111-111111111111" },
		"root runtime":         func(value *Tenant) { value.PortalUID = 0 },
		"socket mismatch":      func(value *Tenant) { value.SocketPath = filepath.Join(root, "run", "other.sock") },
		"release escape":       func(value *Tenant) { value.Backend.Executable = "../other/runtime" },
		"data escape":          func(value *Tenant) { value.Backend.WorkingDirectory = filepath.Join(root, "other") },
		"secret environment":   func(value *Tenant) { value.Backend.Environment = map[string]string{"PROVIDER_TOKEN": "placeholder"} },
		"reserved environment": func(value *Tenant) { value.Backend.Environment = map[string]string{"PATH": "/untrusted"} },
		"runtime token override": func(value *Tenant) {
			value.Backend.Environment = map[string]string{"WORKAGENT_RUNTIME_TOKEN": "placeholder"}
		},
		"runtime tenant override": func(value *Tenant) {
			value.Backend.Environment = map[string]string{"WORKAGENT_TENANT_ID": tenantOne}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := validTenant(root)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
	if err := validTenant(root).Validate(); err != nil {
		t.Fatalf("valid tenant rejected: %v", err)
	}
}
