package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
)

const (
	PortalSchemaVersion = 5
	TenantSchemaVersion = 5

	CLIProxyCoreVersion       = "7.2.81"
	CLIProxyCorePatch         = "per-key-models.4"
	CLIProxyPluginID          = "cpa-key-policy"
	CLIProxyPluginVersion     = "0.4.5"
	CLIProxyAPIBaseURL        = "http://127.0.0.1:8317/v1"
	CLIProxyManagementURL     = "http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy"
	CLIProxyAuthDirectory     = "/var/lib/cliproxyapi/auth"
	CLIProxyPluginDirectory   = "/opt/workagent/shared/cliproxyapi/plugins"
	CLIProxyPolicyStateFile   = "/var/lib/cliproxyapi/policy/cpa-key-policy-state.json"
	CLIProxyManagementKeyFile = "/run/credentials/workagent-portal.service/cliproxy-management-key"
)

var (
	runtimeUserPattern       = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	tenantRuntimeUserPattern = regexp.MustCompile(`^workagent_[a-z0-9][a-z0-9_-]{0,25}$`)
	chatModelPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

type Portal struct {
	SchemaVersion               int                 `json:"schema_version"`
	RuntimeUser                 string              `json:"runtime_user"`
	BrandFile                   string              `json:"brand_file"`
	PolicyFile                  string              `json:"policy_file"`
	AdminMasterPasswordHashFile string              `json:"admin_master_password_hash_file,omitempty"`
	OutboundProxyURL            string              `json:"outbound_proxy_url,omitempty"`
	Listener                    Listener            `json:"listener"`
	Session                     SessionPolicy       `json:"session"`
	Paths                       PortalPaths         `json:"paths"`
	Runtime                     RuntimePolicy       `json:"runtime"`
	Usage                       UsagePolicy         `json:"usage"`
	Observability               ObservabilityPolicy `json:"observability"`
	Renderer                    RendererRelease     `json:"renderer"`
	CLIProxy                    CLIProxy            `json:"cli_proxy"`
	ChatForward                 ChatForwardService  `json:"chat_forward"`
	Notifications               OptionalService     `json:"notifications"`
}

type Listener struct {
	Network               string   `json:"network"`
	Address               string   `json:"address"`
	PublicOrigin          string   `json:"public_origin"`
	TrustedProxyCIDRs     []string `json:"trusted_proxy_cidrs"`
	RequireForwardedHTTPS bool     `json:"require_forwarded_https"`
	TLSCertificateFile    string   `json:"tls_certificate_file,omitempty"`
	TLSPrivateKeyFile     string   `json:"tls_private_key_file,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
}

type SessionPolicy struct {
	CookieName             string `json:"cookie_name"`
	Secure                 bool   `json:"secure"`
	HTTPOnly               bool   `json:"http_only"`
	SameSite               string `json:"same_site"`
	IdleTimeoutSeconds     int    `json:"idle_timeout_seconds"`
	AbsoluteTimeoutSeconds int    `json:"absolute_timeout_seconds"`
}

type PortalPaths struct {
	PortalState    string `json:"portal_state"`
	TenantConfigs  string `json:"tenant_configs"`
	TenantData     string `json:"tenant_data"`
	RuntimeSockets string `json:"runtime_sockets"`
	ReleaseRoot    string `json:"release_root"`
}

type RendererRelease struct {
	ReleasesRoot string `json:"releases_root,omitempty"`
	PointerFile  string `json:"pointer_file,omitempty"`
	Scope        string `json:"scope,omitempty"`
	RelativeRoot string `json:"relative_root,omitempty"`
}

type RuntimePolicy struct {
	MaxConcurrentInstances int  `json:"max_concurrent_instances"`
	IdleReapSeconds        int  `json:"idle_reap_seconds"`
	RequireDedicatedUID    bool `json:"require_dedicated_uid"`
	RequireProjectQuota    bool `json:"require_project_quota"`
	RequireReleaseHashes   bool `json:"require_release_hashes"`
}

type UsagePolicy struct {
	QueryTimeoutSeconds int `json:"query_timeout_seconds"`
	CacheTTLSeconds     int `json:"cache_ttl_seconds"`
}

type ObservabilityPolicy struct {
	AuditRetentionDays int `json:"audit_retention_days"`
	AuditMinimumEvents int `json:"audit_minimum_events"`
}

type Endpoint struct {
	BaseURL        string `json:"base_url"`
	CredentialFile string `json:"credential_file"`
}

type CLIProxy struct {
	APIBaseURL               string `json:"api_base_url"`
	ManagementURL            string `json:"management_url"`
	ManagementCredentialFile string `json:"management_credential_file"`
	CoreVersion              string `json:"core_version"`
	CorePatch                string `json:"core_patch"`
	PluginID                 string `json:"plugin_id"`
	PluginVersion            string `json:"plugin_version"`
	AuthDirectory            string `json:"auth_dir"`
	PluginDirectory          string `json:"plugin_dir"`
	PolicyStateFile          string `json:"policy_state_file"`
	AllowRemote              *bool  `json:"allow_remote"`
}

type OptionalService struct {
	Enabled        bool   `json:"enabled"`
	Endpoint       string `json:"endpoint"`
	CredentialFile string `json:"credential_file"`
}

type ChatForwardService struct {
	Enabled           bool     `json:"enabled"`
	Endpoint          string   `json:"endpoint"`
	CredentialFile    string   `json:"credential_file"`
	ProModels         []string `json:"pro_models"`
	WeeklyProLimit    int      `json:"weekly_pro_limit"`
	MaxPairs          int      `json:"max_pairs"`
	ExtensionProtocol string   `json:"extension_protocol"`
	QuotaProtection   bool     `json:"quota_protection"`
	SourceAssetProxy  bool     `json:"source_asset_proxy"`
}

type Tenant struct {
	SchemaVersion    int            `json:"schema_version"`
	TenantID         string         `json:"tenant_id"`
	RuntimeUser      string         `json:"runtime_user"`
	DataRoot         string         `json:"data_root"`
	SocketPath       string         `json:"socket_path"`
	SocketActivation bool           `json:"socket_activation"`
	PortalUID        uint32         `json:"portal_uid"`
	PortalOrigin     string         `json:"portal_origin"`
	IdleReapSeconds  int            `json:"idle_reap_seconds"`
	Capacity         TenantCapacity `json:"capacity"`
	Limits           ResourceLimits `json:"limits,omitempty"`
	Release          TenantRelease  `json:"release"`
	Backend          Backend        `json:"backend"`
	OutboundProxyURL string         `json:"outbound_proxy_url,omitempty"`
}

type ResourceLimits struct {
	MemoryBytes     uint64 `json:"memory_bytes"`
	CPUPercent      uint32 `json:"cpu_percent"`
	ActiveProcesses uint32 `json:"active_processes"`
}

func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{MemoryBytes: 6 * 1024 * 1024 * 1024, CPUPercent: 50, ActiveProcesses: 64}
}

func (r ResourceLimits) Effective() ResourceLimits {
	if r == (ResourceLimits{}) {
		return DefaultResourceLimits()
	}
	return r
}

func (r ResourceLimits) Validate() error {
	if r == (ResourceLimits{}) {
		return nil
	}
	if r.MemoryBytes < 256*1024*1024 || r.MemoryBytes > 1024*1024*1024*1024 || r.MemoryBytes%(1024*1024) != 0 || r.CPUPercent < 1 || r.CPUPercent > 100 || r.ActiveProcesses < 3 || r.ActiveProcesses > 4096 {
		return errors.New("tenant resource limits are outside the supported range")
	}
	return nil
}

type TenantCapacity struct {
	SlotDirectory      string `json:"slot_directory"`
	MaxInstances       int    `json:"max_instances"`
	ProjectID          uint32 `json:"project_id,omitempty"`
	DiskHardLimitBytes uint64 `json:"disk_hard_limit_bytes,omitempty"`
}

type TenantRelease struct {
	ReleasesRoot string `json:"releases_root"`
	PointerFile  string `json:"pointer_file"`
	Scope        string `json:"scope"`
}

type Backend struct {
	Executable                   string              `json:"executable"`
	Arguments                    []string            `json:"arguments"`
	RequiredReleaseFiles         []string            `json:"required_release_files,omitempty"`
	WorkingDirectory             string              `json:"working_directory"`
	HealthPath                   string              `json:"health_path"`
	ActivityProbe                string              `json:"activity_probe"`
	ActivityPath                 string              `json:"activity_path,omitempty"`
	StartupTimeoutSeconds        int                 `json:"startup_timeout_seconds"`
	RequireModelBootstrap        bool                `json:"require_model_bootstrap"`
	ModelBootstrapTimeoutSeconds int                 `json:"model_bootstrap_timeout_seconds,omitempty"`
	Environment                  map[string]string   `json:"environment,omitempty"`
	AgentCLI                     AgentCLI            `json:"agent_cli"`
	Migration                    BackendMigration    `json:"migration"`
	InternalAuth                 BackendInternalAuth `json:"internal_auth"`
}

type AgentCLI struct {
	BinDirectory        string `json:"bin_directory,omitempty"`
	CodexExecutable     string `json:"codex_executable,omitempty"`
	KimiExecutable      string `json:"kimi_executable,omitempty"`
	PythonExecutable    string `json:"python_executable,omitempty"`
	ProbeTimeoutSeconds int    `json:"probe_timeout_seconds,omitempty"`
}

type BackendMigration struct {
	Enabled                bool     `json:"enabled"`
	Executable             string   `json:"executable,omitempty"`
	Arguments              []string `json:"arguments,omitempty"`
	WorkingDirectory       string   `json:"working_directory,omitempty"`
	HealthPath             string   `json:"health_path,omitempty"`
	StartupTimeoutSeconds  int      `json:"startup_timeout_seconds,omitempty"`
	ShutdownTimeoutSeconds int      `json:"shutdown_timeout_seconds,omitempty"`
}

type BackendInternalAuth struct {
	Enabled      bool   `json:"enabled"`
	DatabasePath string `json:"database_path,omitempty"`
}

func LoadPortal(path string) (Portal, error) {
	var value Portal
	if err := loadStrict(path, &value); err != nil {
		return Portal{}, err
	}
	if err := value.Validate(); err != nil {
		return Portal{}, fmt.Errorf("validate Portal configuration: %w", err)
	}
	return value, nil
}

func LoadTenant(path string) (Tenant, error) {
	var value Tenant
	if err := loadStrict(path, &value); err != nil {
		return Tenant{}, err
	}
	if err := value.Validate(); err != nil {
		return Tenant{}, fmt.Errorf("validate tenant configuration: %w", err)
	}
	return value, nil
}

func loadStrict(path string, destination any) error {
	if !filepath.IsAbs(path) {
		return errors.New("configuration path must be absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("configuration must contain one JSON value")
	}
	return nil
}

func (p Portal) Validate() error {
	if runtime.GOOS != "linux" {
		return errors.New("WorkAgent2 is supported on Linux only")
	}
	if p.SchemaVersion != PortalSchemaVersion {
		return fmt.Errorf("schema_version must be %d", PortalSchemaVersion)
	}
	if !runtimeUserPattern.MatchString(p.RuntimeUser) {
		return errors.New("runtime_user is not a valid locked Linux account name")
	}
	for name, value := range map[string]string{
		"brand_file": p.BrandFile, "policy_file": p.PolicyFile,
		"portal_state": p.Paths.PortalState, "tenant_configs": p.Paths.TenantConfigs,
		"tenant_data": p.Paths.TenantData, "runtime_sockets": p.Paths.RuntimeSockets,
		"release_root": p.Paths.ReleaseRoot,
	} {
		if err := absoluteCleanPath(name, value); err != nil {
			return err
		}
	}
	if p.AdminMasterPasswordHashFile != "" {
		if err := absoluteCleanPath("admin_master_password_hash_file", p.AdminMasterPasswordHashFile); err != nil {
			return err
		}
	}
	if err := validateOutboundProxyURL(p.OutboundProxyURL); err != nil {
		return err
	}
	if err := p.Renderer.validate(); err != nil {
		return err
	}
	if err := p.Listener.validate(); err != nil {
		return err
	}
	if err := p.Session.validate(); err != nil {
		return err
	}
	if p.Runtime.MaxConcurrentInstances < 1 || p.Runtime.MaxConcurrentInstances > 1000 {
		return errors.New("runtime.max_concurrent_instances must be between 1 and 1000")
	}
	if p.Runtime.IdleReapSeconds < 60 || p.Runtime.IdleReapSeconds > 86400 {
		return errors.New("runtime.idle_reap_seconds must be between 60 and 86400")
	}
	if p.Usage.QueryTimeoutSeconds < 1 || p.Usage.QueryTimeoutSeconds > 30 || p.Usage.CacheTTLSeconds < 1 || p.Usage.CacheTTLSeconds > 300 {
		return errors.New("usage query timeout or cache TTL is outside the allowed range")
	}
	if p.Observability.AuditRetentionDays < 30 || p.Observability.AuditRetentionDays > 3650 || p.Observability.AuditMinimumEvents < 1000 || p.Observability.AuditMinimumEvents > 10_000_000 {
		return errors.New("observability audit retention policy is outside the allowed range")
	}
	if err := p.CLIProxy.validate(); err != nil {
		return err
	}
	if err := p.ChatForward.validate(); err != nil {
		return err
	}
	if err := p.Notifications.validate("notifications"); err != nil {
		return err
	}
	return nil
}

func (p Portal) ValidateProductionLayout(configPath string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if configPath != "/etc/workagent/portal.json" || p.RuntimeUser != "workagent" || p.BrandFile != "/etc/workagent/branding/workagent/brand.json" || p.PolicyFile != "/etc/workagent/policy.json" {
		return errors.New("Portal production identity and configuration paths are not canonical")
	}
	expectedPaths := PortalPaths{PortalState: "/var/lib/workagent/portal", TenantConfigs: "/etc/workagent/users", TenantData: "/srv/workagent/users", RuntimeSockets: "/run/workagent/users", ReleaseRoot: "/opt/workagent"}
	if p.Paths != expectedPaths {
		return errors.New("Portal production data paths are not canonical")
	}
	if !p.Runtime.RequireDedicatedUID || !p.Runtime.RequireProjectQuota || !p.Runtime.RequireReleaseHashes {
		return errors.New("Portal production isolation requirements must all be enabled")
	}
	if p.Listener.Network != "tcp" || p.Listener.AllowInsecureLoopback || !p.Listener.RequireForwardedHTTPS || p.Listener.TLSCertificateFile != "" || p.Listener.TLSPrivateKeyFile != "" {
		return errors.New("Portal production traffic must use the shared HTTPS proxy and a cleartext loopback TCP listener with forwarded-HTTPS attestation")
	}
	for _, value := range p.Listener.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !loopbackPrefix(prefix) {
			return errors.New("Portal production trusted proxies must be restricted to loopback CIDRs")
		}
	}
	if !p.Renderer.Configured() || p.Renderer.ReleasesRoot != "/opt/workagent/aionui/releases" || p.Renderer.PointerFile != "/opt/workagent/aionui/current.json" || p.Renderer.Scope != "runtime" || p.Renderer.RelativeRoot != "static" {
		return errors.New("Portal production Renderer channel is not canonical")
	}
	if p.AdminMasterPasswordHashFile != "" && p.AdminMasterPasswordHashFile != "/run/credentials/workagent-portal.service/admin-master-password-hash" {
		return errors.New("Portal administrator master-password hash must use the canonical systemd credential path")
	}
	if !p.CLIProxy.Configured() || p.CLIProxy.ManagementCredentialFile != CLIProxyManagementKeyFile {
		return errors.New("Portal production CLIProxy contract is not canonical")
	}
	if !p.ChatForward.Enabled || p.ChatForward.Endpoint != "http://127.0.0.1:3210" || p.ChatForward.CredentialFile != "/run/credentials/workagent-portal.service/chatforward-key" {
		return errors.New("Portal production ChatForward integration is not canonical")
	}
	if !p.Notifications.Enabled || p.Notifications.CredentialFile != "/run/credentials/workagent-portal.service/notifications-key" {
		return errors.New("Portal production notification integration is not configured")
	}
	return nil
}

func loopbackPrefix(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	address := prefix.Addr()
	if address.Is4() {
		return address.IsLoopback() && prefix.Bits() >= 8
	}
	return address == netip.IPv6Loopback() && prefix.Bits() == 128
}

func (r RendererRelease) Configured() bool {
	return r.ReleasesRoot != "" || r.PointerFile != "" || r.Scope != "" || r.RelativeRoot != ""
}

func (r RendererRelease) validate() error {
	if !r.Configured() {
		return nil
	}
	for name, value := range map[string]string{
		"renderer.releases_root": r.ReleasesRoot,
		"renderer.pointer_file":  r.PointerFile,
	} {
		if err := absoluteCleanPath(name, value); err != nil {
			return err
		}
	}
	if r.PointerFile != filepath.Join(filepath.Dir(r.ReleasesRoot), "current.json") {
		return errors.New("renderer.pointer_file must be current.json beside renderer.releases_root")
	}
	if r.Scope != "runtime" && r.Scope != "combined" {
		return errors.New("renderer.scope must be runtime or combined")
	}
	return cleanRelativePath("renderer.relative_root", r.RelativeRoot)
}

func (s ChatForwardService) validate() error {
	if !s.Enabled {
		if s.Endpoint != "" || s.CredentialFile != "" || len(s.ProModels) != 0 || s.WeeklyProLimit != 0 || s.MaxPairs != 0 || s.ExtensionProtocol != "" || s.QuotaProtection || s.SourceAssetProxy {
			return errors.New("chat_forward is disabled but still contains configuration")
		}
		return nil
	}
	parsed, err := url.Parse(s.Endpoint)
	if err != nil || parsed.Scheme != "http" || !originIsLoopback(parsed) || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("chat_forward.endpoint must be an exact loopback HTTP origin")
	}
	if err := absoluteCleanPath("chat_forward.credential_file", s.CredentialFile); err != nil {
		return err
	}
	if s.WeeklyProLimit < 1 || s.WeeklyProLimit > 10000 || len(s.ProModels) == 0 || len(s.ProModels) > 32 {
		return errors.New("chat_forward requires a weekly Pro limit and model catalog")
	}
	if s.MaxPairs != 3 || s.ExtensionProtocol != "quota-v1" || !s.QuotaProtection || !s.SourceAssetProxy {
		return errors.New("chat_forward must require three pairs, quota-v1, quota protection, and the source asset proxy")
	}
	seen := make(map[string]bool, len(s.ProModels))
	for _, value := range s.ProModels {
		model := strings.ToLower(strings.TrimSpace(value))
		if !strings.HasPrefix(model, "gpt-") || !strings.HasSuffix(model, "-pro") || !chatModelPattern.MatchString(model) || seen[model] {
			return fmt.Errorf("chat_forward contains invalid or duplicate Pro model %q", value)
		}
		seen[model] = true
	}
	return nil
}

func (c CLIProxy) validate() error {
	if !c.Configured() {
		return nil
	}
	if c.APIBaseURL == "" || c.ManagementURL == "" || c.ManagementCredentialFile == "" || c.CoreVersion == "" || c.CorePatch == "" || c.PluginID == "" || c.PluginVersion == "" || c.AuthDirectory == "" || c.PluginDirectory == "" || c.PolicyStateFile == "" || c.AllowRemote == nil {
		return errors.New("cli_proxy contract is incomplete")
	}
	if c.APIBaseURL != CLIProxyAPIBaseURL || c.ManagementURL != CLIProxyManagementURL {
		return errors.New("cli_proxy URLs must match the locked 127.0.0.1:8317 contract")
	}
	if c.CoreVersion != CLIProxyCoreVersion || c.CorePatch != CLIProxyCorePatch || c.PluginID != CLIProxyPluginID || c.PluginVersion != CLIProxyPluginVersion {
		return errors.New("cli_proxy core, patch, or plugin identity does not match the production lock")
	}
	if *c.AllowRemote {
		return errors.New("cli_proxy.allow_remote must be false")
	}
	if c.AuthDirectory != CLIProxyAuthDirectory || c.PluginDirectory != CLIProxyPluginDirectory || c.PolicyStateFile != CLIProxyPolicyStateFile {
		return errors.New("cli_proxy auth_dir, plugin_dir, and policy_state_file must use protected canonical paths")
	}
	if err := absoluteCleanPath("cli_proxy.auth_dir", c.AuthDirectory); err != nil {
		return err
	}
	if err := absoluteCleanPath("cli_proxy.plugin_dir", c.PluginDirectory); err != nil {
		return err
	}
	if err := absoluteCleanPath("cli_proxy.policy_state_file", c.PolicyStateFile); err != nil {
		return err
	}
	return absoluteCleanPath("cli_proxy.management_credential_file", c.ManagementCredentialFile)
}

func (c CLIProxy) Validate() error { return c.validate() }

func (c CLIProxy) Configured() bool {
	return c.APIBaseURL != "" || c.ManagementURL != "" || c.ManagementCredentialFile != "" || c.CoreVersion != "" || c.CorePatch != "" || c.PluginID != "" || c.PluginVersion != "" || c.AuthDirectory != "" || c.PluginDirectory != "" || c.PolicyStateFile != "" || c.AllowRemote != nil
}

func (c CLIProxy) HealthURL() string {
	parsed, err := url.Parse(c.APIBaseURL)
	if err != nil {
		return ""
	}
	parsed.Path = "/healthz"
	return parsed.String()
}

func (l Listener) validate() error {
	if l.Network != "tcp" && l.Network != "unix" {
		return errors.New("listener.network must be tcp or unix")
	}
	if l.Network == "tcp" {
		host, portText, err := net.SplitHostPort(l.Address)
		if err != nil {
			return fmt.Errorf("listener.address: %w", err)
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.IsLoopback() {
			return errors.New("TCP listener must use a numeric loopback address")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1024 || port > 65535 {
			return errors.New("TCP listener port must be between 1024 and 65535")
		}
	} else if err := absoluteCleanPath("listener.address", l.Address); err != nil {
		return err
	}
	origin, err := url.Parse(l.PublicOrigin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("listener.public_origin must be an origin without credentials, path, query, or fragment")
	}
	if origin.Scheme != "https" {
		if !l.AllowInsecureLoopback || origin.Scheme != "http" || !originIsLoopback(origin) {
			return errors.New("listener.public_origin must use HTTPS")
		}
	}
	if len(l.TrustedProxyCIDRs) == 0 {
		return errors.New("listener.trusted_proxy_cidrs must not be empty")
	}
	for _, value := range l.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q", value)
		}
	}
	if (l.TLSCertificateFile == "") != (l.TLSPrivateKeyFile == "") {
		return errors.New("both TLS certificate and private key files are required together")
	}
	if l.TLSCertificateFile != "" {
		if err := absoluteCleanPath("listener.tls_certificate_file", l.TLSCertificateFile); err != nil {
			return err
		}
		if err := absoluteCleanPath("listener.tls_private_key_file", l.TLSPrivateKeyFile); err != nil {
			return err
		}
	}
	return nil
}

func (s SessionPolicy) validate() error {
	if !strings.HasPrefix(s.CookieName, "__Host-") || strings.ContainsAny(s.CookieName, " ;,\t\r\n") {
		return errors.New("session.cookie_name must be a valid __Host- cookie name")
	}
	if !s.Secure || !s.HTTPOnly || (!strings.EqualFold(s.SameSite, "strict") && !strings.EqualFold(s.SameSite, "lax")) {
		return errors.New("session cookies must be Secure, HttpOnly, and SameSite Strict or Lax")
	}
	if s.IdleTimeoutSeconds < 300 || s.AbsoluteTimeoutSeconds <= s.IdleTimeoutSeconds || s.AbsoluteTimeoutSeconds > 7*24*60*60 {
		return errors.New("session timeouts are outside the allowed range")
	}
	return nil
}

func (e Endpoint) validate(name string) error {
	if e.BaseURL == "" && e.CredentialFile == "" {
		return nil
	}
	if e.BaseURL == "" || e.CredentialFile == "" {
		return fmt.Errorf("%s requires both base_url and credential_file", name)
	}
	parsed, err := url.Parse(e.BaseURL)
	if err != nil || parsed.Scheme != "http" || !originIsLoopback(parsed) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s.base_url must be a loopback HTTP URL", name)
	}
	return absoluteCleanPath(name+".credential_file", e.CredentialFile)
}

func (s OptionalService) validate(name string) error {
	if !s.Enabled {
		if s.Endpoint != "" || s.CredentialFile != "" {
			return fmt.Errorf("%s is disabled but still contains endpoint configuration", name)
		}
		return nil
	}
	if s.Endpoint == "" || s.CredentialFile == "" {
		return fmt.Errorf("%s requires an endpoint and credential_file", name)
	}
	parsed, err := url.Parse(s.Endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && originIsLoopback(parsed))) {
		return fmt.Errorf("%s.endpoint must use HTTPS or loopback HTTP", name)
	}
	return absoluteCleanPath(name+".credential_file", s.CredentialFile)
}

func (t Tenant) Validate() error {
	if runtime.GOOS != "linux" {
		return errors.New("WorkAgent2 is supported on Linux only")
	}
	if t.SchemaVersion != TenantSchemaVersion {
		return fmt.Errorf("schema_version must be %d", TenantSchemaVersion)
	}
	id, err := uuid.Parse(t.TenantID)
	if err != nil || id.String() != t.TenantID {
		return errors.New("tenant_id must be a canonical UUID")
	}
	if !tenantRuntimeUserPattern.MatchString(t.RuntimeUser) {
		return errors.New("runtime_user is not a valid locked Linux account name")
	}
	for name, value := range map[string]string{
		"data_root": t.DataRoot, "socket_path": t.SocketPath, "release.releases_root": t.Release.ReleasesRoot,
		"release.pointer_file": t.Release.PointerFile,
		"backend.working_directory": t.Backend.WorkingDirectory, "capacity.slot_directory": t.Capacity.SlotDirectory,
	} {
		if err := absoluteCleanPath(name, value); err != nil {
			return err
		}
	}
	if filepath.Ext(t.SocketPath) != ".sock" {
		return errors.New("socket_path must end in .sock")
	}
	if filepath.Base(t.SocketPath) != t.TenantID+".sock" {
		return errors.New("socket_path filename must be derived from tenant_id")
	}
	if !t.SocketActivation {
		return errors.New("systemd socket activation is required")
	}
	if t.PortalUID == 0 {
		return errors.New("portal_uid must be a non-root UID")
	}
	portalOrigin, err := url.Parse(t.PortalOrigin)
	if err != nil || portalOrigin.Scheme != "https" || portalOrigin.Host == "" || portalOrigin.User != nil || portalOrigin.RawQuery != "" || portalOrigin.Fragment != "" || (portalOrigin.Path != "" && portalOrigin.Path != "/") {
		return errors.New("portal_origin must be an HTTPS origin")
	}
	if t.IdleReapSeconds < 60 || t.IdleReapSeconds > 86400 {
		return errors.New("idle_reap_seconds must be between 60 and 86400")
	}
	if t.Capacity.MaxInstances < 1 || t.Capacity.MaxInstances > 1000 {
		return errors.New("capacity.max_instances must be between 1 and 1000")
	}
	if err := validateOutboundProxyURL(t.OutboundProxyURL); err != nil {
		return err
	}
	if (t.Capacity.ProjectID == 0) != (t.Capacity.DiskHardLimitBytes == 0) {
		return errors.New("capacity project_id and disk_hard_limit_bytes must be configured together")
	}
	if err := t.Limits.Validate(); err != nil {
		return err
	}
	if t.Capacity.ProjectID != 0 && (t.Capacity.ProjectID < 1000 || t.Capacity.DiskHardLimitBytes < 1024*1024*1024 || t.Capacity.DiskHardLimitBytes > 100*1024*1024*1024*1024 || t.Capacity.DiskHardLimitBytes%512 != 0) {
		return errors.New("capacity project quota is outside the supported range")
	}
	if t.Release.PointerFile != filepath.Join(filepath.Dir(t.Release.ReleasesRoot), "current.json") {
		return errors.New("release.pointer_file must be current.json beside releases_root")
	}
	if t.Release.Scope != "runtime" && t.Release.Scope != "combined" {
		return errors.New("release.scope must be runtime or combined for a tenant runtime")
	}
	if err := cleanRelativePath("backend.executable", t.Backend.Executable); err != nil {
		return err
	}
	if !pathWithin(t.DataRoot, t.Backend.WorkingDirectory) {
		return errors.New("backend.working_directory must remain beneath data_root")
	}
	if t.Backend.HealthPath == "" || !strings.HasPrefix(t.Backend.HealthPath, "/") || strings.ContainsAny(t.Backend.HealthPath, "?#") {
		return errors.New("backend.health_path must be an absolute URL path")
	}
	switch t.Backend.ActivityProbe {
	case "aionui":
		if t.Backend.ActivityPath != "" {
			return errors.New("backend.activity_path is only valid for the aggregate test probe")
		}
	case "aggregate":
		if t.Backend.ActivityPath == "" || !strings.HasPrefix(t.Backend.ActivityPath, "/") || strings.ContainsAny(t.Backend.ActivityPath, "?#") || t.Backend.ActivityPath == t.Backend.HealthPath {
			return errors.New("backend.activity_path must be a distinct absolute URL path for the aggregate test probe")
		}
	default:
		return errors.New("backend.activity_probe must be aionui or aggregate")
	}
	if t.Backend.StartupTimeoutSeconds < 1 || t.Backend.StartupTimeoutSeconds > 300 {
		return errors.New("backend.startup_timeout_seconds must be between 1 and 300")
	}
	if t.Backend.RequireModelBootstrap && (t.Backend.ModelBootstrapTimeoutSeconds < 30 || t.Backend.ModelBootstrapTimeoutSeconds > 600) {
		return errors.New("backend.model_bootstrap_timeout_seconds must be between 30 and 600 when model bootstrap is required")
	}
	if !t.Backend.RequireModelBootstrap && t.Backend.ModelBootstrapTimeoutSeconds != 0 {
		return errors.New("backend.model_bootstrap_timeout_seconds requires model bootstrap")
	}
	if len(t.Backend.Arguments) > 64 || len(t.Backend.RequiredReleaseFiles) > 64 || len(t.Backend.Environment) > 64 {
		return errors.New("backend command configuration is too large")
	}
	for _, argument := range t.Backend.Arguments {
		if strings.ContainsRune(argument, 0) || len(argument) > 4096 {
			return errors.New("backend argument is invalid")
		}
	}
	for _, required := range t.Backend.RequiredReleaseFiles {
		if err := cleanRelativePath("backend.required_release_files", required); err != nil {
			return err
		}
	}
	if t.Backend.ActivityProbe == "aionui" {
		if !t.Backend.Migration.Enabled {
			return errors.New("AionUi backend requires the managed AionCore migration phase")
		}
		expectedArguments := []string{"start", "--port", "{listen_port}", "--data-dir", "{data_root}/data", "--work-dir", "{data_root}/workspace", "--log-dir", "{data_root}/logs", "--static-dir", "{release_root}/static", "--backend-bin", "{release_root}/bin/aioncore", "--no-open"}
		expectedMigrationArguments := []string{"--port", "{listen_port}", "--data-dir", "{data_root}/data", "--work-dir", "{data_root}/workspace", "--log-dir", "{data_root}/logs", "--managed-resources-mode", "bundled"}
		if t.Backend.Executable != "bin/aionui-web" || !equalStrings(t.Backend.Arguments, expectedArguments) || t.Backend.WorkingDirectory != filepath.Join(t.DataRoot, "workspace") || t.Backend.HealthPath != "/healthz" || !t.Backend.RequireModelBootstrap || t.Backend.Migration.Executable != "bin/aioncore" || !equalStrings(t.Backend.Migration.Arguments, expectedMigrationArguments) || t.Backend.Migration.WorkingDirectory != filepath.Join(t.DataRoot, "workspace") || t.Backend.Migration.HealthPath != "/health" || !t.Backend.InternalAuth.Enabled || t.Backend.InternalAuth.DatabasePath != filepath.Join(t.DataRoot, "data", "aionui-backend.db") {
			return errors.New("AionUi backend does not match the managed production launch contract")
		}
		required := map[string]bool{}
		for _, path := range t.Backend.RequiredReleaseFiles {
			required[filepath.ToSlash(path)] = true
		}
		for _, path := range []string{"static/index.html", "workagent-builtin-assistants/assistants.json", "workagent-builtin-assistants/rules/aionui-assistant.en-US.md", "workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md", "workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md"} {
			if !required[path] {
				return fmt.Errorf("backend.required_release_files must include %s for AionUi", path)
			}
		}
	}
	for key, value := range t.Backend.Environment {
		if !validEnvironmentName(key) || len(value) > 4096 || strings.ContainsRune(value, 0) || looksSecretName(key) || reservedRuntimeEnvironment(key) {
			return fmt.Errorf("backend environment variable %q is not allowed", key)
		}
	}
	if err := t.Backend.AgentCLI.validate(t.Backend.ActivityProbe == "aionui"); err != nil {
		return err
	}
	if t.Backend.Migration.Enabled {
		if err := cleanRelativePath("backend.migration.executable", t.Backend.Migration.Executable); err != nil {
			return err
		}
		for name, value := range map[string]string{"backend.migration.working_directory": t.Backend.Migration.WorkingDirectory} {
			if err := absoluteCleanPath(name, value); err != nil {
				return err
			}
		}
		if !pathWithin(t.DataRoot, t.Backend.Migration.WorkingDirectory) {
			return errors.New("backend migration working directory escapes its protected root")
		}
		if t.Backend.Migration.HealthPath == "" || !strings.HasPrefix(t.Backend.Migration.HealthPath, "/") || strings.ContainsAny(t.Backend.Migration.HealthPath, "?#") {
			return errors.New("backend.migration.health_path must be an absolute URL path")
		}
		if t.Backend.Migration.StartupTimeoutSeconds < 1 || t.Backend.Migration.StartupTimeoutSeconds > 300 || t.Backend.Migration.ShutdownTimeoutSeconds < 1 || t.Backend.Migration.ShutdownTimeoutSeconds > 60 {
			return errors.New("backend migration timeout is outside the allowed range")
		}
		if len(t.Backend.Migration.Arguments) > 64 {
			return errors.New("backend migration has too many arguments")
		}
		for _, argument := range t.Backend.Migration.Arguments {
			if strings.ContainsRune(argument, 0) || len(argument) > 4096 {
				return errors.New("backend migration argument is invalid")
			}
		}
	} else if t.Backend.Migration.Executable != "" || len(t.Backend.Migration.Arguments) != 0 || t.Backend.Migration.WorkingDirectory != "" || t.Backend.Migration.HealthPath != "" || t.Backend.Migration.StartupTimeoutSeconds != 0 || t.Backend.Migration.ShutdownTimeoutSeconds != 0 {
		return errors.New("disabled backend migration contains configuration")
	}
	if t.Backend.InternalAuth.Enabled {
		if err := absoluteCleanPath("backend.internal_auth.database_path", t.Backend.InternalAuth.DatabasePath); err != nil {
			return err
		}
		if !pathWithin(t.DataRoot, t.Backend.InternalAuth.DatabasePath) {
			return errors.New("backend internal authentication database must remain beneath data_root")
		}
		if !t.Backend.Migration.Enabled {
			return errors.New("backend internal authentication requires the migration phase")
		}
	} else if t.Backend.InternalAuth.DatabasePath != "" {
		return errors.New("disabled backend internal authentication contains a database path")
	}
	return nil
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (a AgentCLI) validate(required bool) error {
	configured := a.BinDirectory != "" || a.CodexExecutable != "" || a.KimiExecutable != "" || a.PythonExecutable != "" || a.ProbeTimeoutSeconds != 0
	if !configured {
		if required {
			return errors.New("backend.agent_cli is required for the AionUi production probe")
		}
		return nil
	}
	for name, value := range map[string]string{
		"backend.agent_cli.bin_directory":     a.BinDirectory,
		"backend.agent_cli.codex_executable":  a.CodexExecutable,
		"backend.agent_cli.kimi_executable":   a.KimiExecutable,
		"backend.agent_cli.python_executable": a.PythonExecutable,
	} {
		if err := cleanRelativePath(name, value); err != nil {
			return err
		}
	}
	for _, executable := range []string{a.CodexExecutable, a.KimiExecutable, a.PythonExecutable} {
		relative, err := filepath.Rel(filepath.FromSlash(a.BinDirectory), filepath.FromSlash(executable))
		if err != nil || relative == "." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("backend.agent_cli executables must remain beneath bin_directory")
		}
	}
	if a.ProbeTimeoutSeconds < 1 || a.ProbeTimeoutSeconds > 60 {
		return errors.New("backend.agent_cli.probe_timeout_seconds must be between 1 and 60")
	}
	return nil
}

func absoluteCleanPath(name, value string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return fmt.Errorf("%s must be a clean absolute path", name)
	}
	return nil
}

func cleanRelativePath(name, value string) error {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) || strings.Contains(value, `\`) {
		return fmt.Errorf("%s must be a clean relative path", name)
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	return fsutil.PathWithin(root, candidate)
}

func originIsLoopback(value *url.URL) bool {
	host := value.Hostname()
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func validateOutboundProxyURL(value string) error {
	if value == "" {
		return nil
	}
	proxy, err := url.Parse(value)
	if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Hostname() == "" || proxy.User != nil || proxy.Opaque != "" || (proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.Fragment != "" {
		return errors.New("outbound_proxy_url must be an absolute HTTP or HTTPS proxy URL without credentials, path, query, or fragment")
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || character == '_' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func looksSecretName(value string) bool {
	upper := strings.ToUpper(value)
	for _, fragment := range []string{"SECRET", "TOKEN", "PASSWORD", "API_KEY", "PRIVATE_KEY", "CREDENTIAL"} {
		if strings.Contains(upper, fragment) {
			return true
		}
	}
	return false
}

func reservedRuntimeEnvironment(value string) bool {
	upper := strings.ToUpper(value)
	if upper == "HOME" || upper == "PATH" || upper == "LANG" || upper == "TMPDIR" || upper == "CODEX_HOME" || upper == "PYTHONDONTWRITEBYTECODE" || upper == "KIMI_CODE_NO_AUTO_UPDATE" || upper == "HTTP_PROXY" || upper == "HTTPS_PROXY" || upper == "ALL_PROXY" || upper == "NO_PROXY" {
		return true
	}
	for _, prefix := range []string{"XDG_", "WORKAGENT_", "AIONUI_", "CODEX_", "KIMI_", "PYTHON"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func (p Portal) DatabasePath() string { return filepath.Join(p.Paths.PortalState, "portal.db") }
func (p Portal) AuditPath() string    { return filepath.Join(p.Paths.PortalState, "audit.jsonl") }
func (p Portal) IdleTimeout() time.Duration {
	return time.Duration(p.Session.IdleTimeoutSeconds) * time.Second
}
func (p Portal) AbsoluteTimeout() time.Duration {
	return time.Duration(p.Session.AbsoluteTimeoutSeconds) * time.Second
}
