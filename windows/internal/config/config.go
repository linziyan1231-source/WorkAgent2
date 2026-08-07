package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ProductionListenAddress = "0.0.0.0:25808"
	DefaultUserProfilesRoot = `C:\Users`
	UserDataDirectoryName   = "AionUiPortal"
	DefaultCLIProxyRoot     = `C:\ProgramData\CLIProxyAPI`
	DefaultPortalDataRoot   = `C:\ProgramData\AionUiPortal`
)

type Portal struct {
	Mode                    string   `json:"mode"`
	ListenAddress           string   `json:"listen_address"`
	PublicBaseURL           string   `json:"public_base_url"`
	BrowserOrigins          []string `json:"additional_browser_origins,omitempty"`
	TLSCertificateFile      string   `json:"tls_certificate_file"`
	TLSPrivateKeyFile       string   `json:"tls_private_key_file"`
	DatabasePath            string   `json:"database_path"`
	AuditLogPath            string   `json:"audit_log_path"`
	PortalLogPath           string   `json:"portal_log_path"`
	ReleasesRoot            string   `json:"releases_root"`
	CurrentReleaseFile      string   `json:"current_release_file"`
	UserConfigRoot          string   `json:"user_config_root"`
	UserProfilesRoot        string   `json:"user_profiles_root"`
	UserDataRoot            string   `json:"user_data_root,omitempty"`
	UserHostExecutable      string   `json:"user_host_executable"`
	PortalServiceSID        string   `json:"portal_service_sid"`
	SessionTTLSeconds       int      `json:"session_ttl_seconds"`
	SessionIdleSeconds      int      `json:"session_idle_seconds"`
	InstanceStartupSeconds  int      `json:"instance_startup_seconds"`
	IdleReapSeconds         int      `json:"idle_reap_seconds"`
	MaxRunningInstances     int      `json:"max_running_instances"`
	LoginWindowSeconds      int      `json:"login_window_seconds"`
	LoginBlockSeconds       int      `json:"login_block_seconds"`
	LoginAccountFailures    int      `json:"login_account_failures"`
	LoginIPFailures         int      `json:"login_ip_failures"`
	AdminMasterHashFile     string   `json:"admin_master_password_hash_file,omitempty"`
	UsageManagementURL      string   `json:"usage_management_url"`
	UsageManagementKeyFile  string   `json:"usage_management_key_file"`
	UsageQueryTimeoutSecs   int      `json:"usage_query_timeout_seconds"`
	UsageCacheSeconds       int      `json:"usage_cache_seconds"`
	ChatForwardURL          string   `json:"chatforward_url"`
	ChatForwardSecretFile   string   `json:"chatforward_secret_file"`
	ChatGPTProModels        []string `json:"chatgpt_pro_models"`
	NotificationSourceURL   string   `json:"notification_source_url,omitempty"`
	OutboundProxyURL        string   `json:"outbound_proxy_url,omitempty"`
	KimiDatasourceBrokerURL string   `json:"kimi_datasource_broker_url,omitempty"`
	SupportedAionCore       []string `json:"supported_aioncore_versions"`
}

func DefaultPortal() Portal {
	return Portal{
		Mode:                    "production",
		ListenAddress:           ProductionListenAddress,
		UserProfilesRoot:        DefaultUserProfilesRoot,
		SessionTTLSeconds:       12 * 60 * 60,
		SessionIdleSeconds:      60 * 60,
		InstanceStartupSeconds:  90,
		IdleReapSeconds:         30 * 60,
		MaxRunningInstances:     20,
		LoginWindowSeconds:      15 * 60,
		LoginBlockSeconds:       15 * 60,
		LoginAccountFailures:    5,
		LoginIPFailures:         20,
		UsageQueryTimeoutSecs:   25,
		UsageCacheSeconds:       30,
		ChatForwardURL:          "http://127.0.0.1:3210",
		ChatForwardSecretFile:   filepath.Join(DefaultPortalDataRoot, "chatforward.key"),
		ChatGPTProModels:        []string{"gpt-5-4-pro", "gpt-5-5-pro", "gpt-5-6-pro"},
		NotificationSourceURL:   "http://203.0.113.79:25888/notification",
		KimiDatasourceBrokerURL: "http://127.0.0.1:3211/mcp",
		SupportedAionCore:       []string{"v0.1.42"},
	}
}

func LoadPortal(path string) (Portal, error) {
	var cfg Portal
	if !filepath.IsAbs(path) {
		return cfg, fmt.Errorf("portal config path must be absolute: %q", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read portal config: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode portal config: %w", err)
	}
	if err := rejectTrailingJSON(dec); err != nil {
		return cfg, fmt.Errorf("decode portal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Portal) Validate() error {
	if c.Mode != "production" && c.Mode != "test" {
		return fmt.Errorf("mode must be production or test, got %q", c.Mode)
	}
	if c.Mode == "production" && c.ListenAddress != ProductionListenAddress {
		return fmt.Errorf("production listen_address must be %s", ProductionListenAddress)
	}
	host, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("invalid listen_address %q", c.ListenAddress)
	}
	base, err := url.Parse(c.PublicBaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" || base.User != nil || base.Opaque != "" || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("public_base_url must be an absolute HTTP or HTTPS URL without query or fragment")
	}
	if base.Path != "" && base.Path != "/" {
		return errors.New("public_base_url must not contain a path")
	}
	if c.Mode == "production" && base.Port() != "25808" && !(base.Scheme == "http" && (base.Port() == "" || base.Port() == "80")) {
		return errors.New("production public_base_url must use port 25808 or standard HTTP port 80")
	}
	browserOrigins := map[string]struct{}{strings.ToLower(base.Scheme + "://" + base.Host): {}}
	for _, value := range c.BrowserOrigins {
		origin, err := url.Parse(value)
		if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Hostname() == "" || origin.User != nil || origin.Opaque != "" ||
			origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" {
			return fmt.Errorf("additional_browser_origins contains invalid origin %q", value)
		}
		key := strings.ToLower(origin.Scheme + "://" + origin.Host)
		if _, exists := browserOrigins[key]; exists {
			return fmt.Errorf("additional_browser_origins contains duplicate origin %q", value)
		}
		browserOrigins[key] = struct{}{}
	}
	if c.UsesTLS() {
		if !filepath.IsAbs(c.TLSCertificateFile) || !filepath.IsAbs(c.TLSPrivateKeyFile) {
			return errors.New("tls_certificate_file and tls_private_key_file must be absolute paths for HTTPS")
		}
	} else if c.TLSCertificateFile != "" || c.TLSPrivateKeyFile != "" {
		return errors.New("TLS file paths must be empty when public_base_url uses HTTP")
	}
	if c.Mode == "production" && !strings.EqualFold(filepath.Clean(c.UserProfilesRoot), filepath.Clean(DefaultUserProfilesRoot)) {
		return fmt.Errorf("production user_profiles_root must be %s", DefaultUserProfilesRoot)
	}
	for name, p := range map[string]string{
		"database_path":        c.DatabasePath,
		"audit_log_path":       c.AuditLogPath,
		"portal_log_path":      c.PortalLogPath,
		"releases_root":        c.ReleasesRoot,
		"current_release_file": c.CurrentReleaseFile,
		"user_config_root":     c.UserConfigRoot,
		"user_profiles_root":   c.UserProfilesRoot,
		"user_host_executable": c.UserHostExecutable,
	} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if c.UserDataRoot != "" {
		if !filepath.IsAbs(c.UserDataRoot) || filepath.Dir(filepath.Clean(c.UserDataRoot)) == filepath.Clean(c.UserDataRoot) {
			return errors.New("user_data_root must be an absolute non-volume-root path when configured")
		}
	}
	if err := validateReleaseLayout(c.ReleasesRoot, c.CurrentReleaseFile); err != nil {
		return err
	}
	if c.Mode == "production" && strings.TrimSpace(c.PortalServiceSID) == "" {
		return errors.New("portal_service_sid is required in production")
	}
	if c.SessionTTLSeconds < 300 || c.SessionTTLSeconds > int((7*24*time.Hour).Seconds()) {
		return errors.New("session_ttl_seconds must be between 300 and 604800")
	}
	if c.SessionIdleSeconds < 60 || c.SessionIdleSeconds > c.SessionTTLSeconds {
		return errors.New("session_idle_seconds must be between 60 and session_ttl_seconds")
	}
	if c.InstanceStartupSeconds < 10 || c.InstanceStartupSeconds > 300 {
		return errors.New("instance_startup_seconds must be between 10 and 300")
	}
	if c.IdleReapSeconds < 60 || c.IdleReapSeconds > int((24*time.Hour).Seconds()) {
		return errors.New("idle_reap_seconds must be between 60 and 86400")
	}
	if c.MaxRunningInstances < 1 || c.MaxRunningInstances > 1000 {
		return errors.New("max_running_instances must be between 1 and 1000")
	}
	if c.LoginWindowSeconds < 60 || c.LoginBlockSeconds < 60 || c.LoginAccountFailures < 1 || c.LoginIPFailures < c.LoginAccountFailures {
		return errors.New("invalid login rate-limit settings")
	}
	if c.AdminMasterHashFile != "" {
		if !filepath.IsAbs(c.AdminMasterHashFile) {
			return errors.New("admin_master_password_hash_file must be absolute when configured")
		}
		if c.Mode == "production" && !strings.EqualFold(filepath.Dir(filepath.Clean(c.AdminMasterHashFile)), filepath.Clean(DefaultPortalDataRoot)) {
			return fmt.Errorf("admin_master_password_hash_file must be a direct child of %s", DefaultPortalDataRoot)
		}
	}
	if c.Mode == "production" {
		management, err := url.Parse(c.UsageManagementURL)
		if err != nil || management.Scheme != "http" || management.Hostname() != "127.0.0.1" || management.Port() == "" || management.User != nil ||
			management.Path != "/v0/management/plugins/cpa-key-policy" || management.RawQuery != "" || management.Fragment != "" {
			return errors.New("usage_management_url must be the exact local cpa-key-policy Management API URL")
		}
		if !filepath.IsAbs(c.UsageManagementKeyFile) || !strings.EqualFold(filepath.Dir(filepath.Clean(c.UsageManagementKeyFile)), filepath.Clean(DefaultCLIProxyRoot)) {
			return fmt.Errorf("usage_management_key_file must be a direct child of %s", DefaultCLIProxyRoot)
		}
	}
	if c.UsageQueryTimeoutSecs < 5 || c.UsageQueryTimeoutSecs > 60 {
		return errors.New("usage_query_timeout_seconds must be between 5 and 60")
	}
	if c.UsageCacheSeconds < 1 || c.UsageCacheSeconds > 60 {
		return errors.New("usage_cache_seconds must be between 1 and 60")
	}
	if err := c.validateChatForward(); err != nil {
		return err
	}
	if err := validateNotificationSourceURL(c.NotificationSourceURL); err != nil {
		return err
	}
	if err := validateOutboundProxyURL(c.OutboundProxyURL); err != nil {
		return err
	}
	if err := validateKimiDatasourceBrokerURL(c.KimiDatasourceBrokerURL); err != nil {
		return err
	}
	if len(c.SupportedAionCore) == 0 {
		return errors.New("supported_aioncore_versions must not be empty")
	}
	for _, version := range c.SupportedAionCore {
		if strings.TrimSpace(version) == "" {
			return errors.New("supported_aioncore_versions contains an empty version")
		}
	}
	return nil
}

func validateNotificationSourceURL(value string) error {
	if value == "" {
		return nil
	}
	source, err := url.Parse(value)
	if err != nil || (source.Scheme != "http" && source.Scheme != "https") || source.Hostname() == "" || source.User != nil || source.Opaque != "" ||
		source.Path != "/notification" || source.RawQuery != "" || source.Fragment != "" {
		return errors.New("notification_source_url must be an absolute HTTP or HTTPS /notification URL without credentials, query, or fragment")
	}
	return nil
}

func (c Portal) validateChatForward() error {
	if c.ChatForwardURL == "" {
		if c.Mode == "production" {
			return errors.New("chatforward_url is required in production")
		}
		return nil
	}
	bridge, err := url.Parse(c.ChatForwardURL)
	if err != nil || bridge.Scheme != "http" || bridge.Hostname() != "127.0.0.1" || bridge.Port() == "" || bridge.User != nil ||
		bridge.Opaque != "" || (bridge.Path != "" && bridge.Path != "/") || bridge.RawQuery != "" || bridge.Fragment != "" {
		return errors.New("chatforward_url must be an exact 127.0.0.1 HTTP origin")
	}
	if !filepath.IsAbs(c.ChatForwardSecretFile) {
		return errors.New("chatforward_secret_file must be absolute")
	}
	if c.Mode == "production" && !strings.EqualFold(filepath.Dir(filepath.Clean(c.ChatForwardSecretFile)), filepath.Clean(DefaultPortalDataRoot)) {
		return fmt.Errorf("chatforward_secret_file must be a direct child of %s", DefaultPortalDataRoot)
	}
	if len(c.ChatGPTProModels) == 0 {
		return errors.New("chatgpt_pro_models must not be empty")
	}
	seen := make(map[string]struct{}, len(c.ChatGPTProModels))
	for _, model := range c.ChatGPTProModels {
		model = strings.ToLower(strings.TrimSpace(model))
		if !strings.HasPrefix(model, "gpt-") || !strings.HasSuffix(model, "-pro") {
			return fmt.Errorf("chatgpt_pro_models contains invalid model %q", model)
		}
		if _, duplicate := seen[model]; duplicate {
			return fmt.Errorf("chatgpt_pro_models contains duplicate model %q", model)
		}
		seen[model] = struct{}{}
	}
	return nil
}

func (c Portal) UsesTLS() bool {
	base, err := url.Parse(c.PublicBaseURL)
	return err == nil && strings.EqualFold(base.Scheme, "https")
}

type ResourceLimits struct {
	MemoryBytes     uint64 `json:"memory_bytes"`
	CPUPercent      uint32 `json:"cpu_percent"`
	ActiveProcesses uint32 `json:"active_processes"`
}

type UserHost struct {
	ConfigVersion      int                   `json:"config_version"`
	WindowsSID         string                `json:"windows_sid"`
	WindowsUsername    string                `json:"windows_username"`
	WindowsProfile     string                `json:"windows_profile"`
	DataRoot           string                `json:"data_root"`
	DataRootBase       string                `json:"data_root_base,omitempty"`
	ReleasesRoot       string                `json:"releases_root"`
	CurrentReleaseFile string                `json:"current_release_file"`
	PortalServiceSID   string                `json:"portal_service_sid"`
	PipeName           string                `json:"pipe_name"`
	WebPort            int                   `json:"web_port"`
	WebPortTries       int                   `json:"web_port_tries"`
	MigrationPortStart int                   `json:"migration_port_start"`
	MigrationPortTries int                   `json:"migration_port_tries"`
	StartupSeconds     int                   `json:"startup_seconds"`
	ShutdownSeconds    int                   `json:"shutdown_seconds"`
	OutboundProxyURL   string                `json:"outbound_proxy_url,omitempty"`
	KimiDatasource     *KimiDatasourceAccess `json:"kimi_datasource,omitempty"`
	SupportedAionCore  []string              `json:"supported_aioncore_versions"`
	Limits             ResourceLimits        `json:"limits"`
}

func LoadUserHost(path string) (UserHost, error) {
	var cfg UserHost
	if !filepath.IsAbs(path) {
		return cfg, fmt.Errorf("user host config path must be absolute: %q", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read user host config: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode user host config: %w", err)
	}
	if err := rejectTrailingJSON(dec); err != nil {
		return cfg, fmt.Errorf("decode user host config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c UserHost) Validate() error {
	if c.ConfigVersion != 1 && c.ConfigVersion != 2 {
		return fmt.Errorf("unsupported user host config_version %d", c.ConfigVersion)
	}
	if !validSID(c.WindowsSID) || strings.TrimSpace(c.WindowsUsername) == "" {
		return errors.New("windows_sid and windows_username are required")
	}
	for name, p := range map[string]string{
		"windows_profile": c.WindowsProfile, "data_root": c.DataRoot, "releases_root": c.ReleasesRoot, "current_release_file": c.CurrentReleaseFile,
	} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	if c.ConfigVersion == 1 {
		if c.DataRootBase != "" || !strings.EqualFold(filepath.Clean(c.DataRoot), filepath.Join(filepath.Clean(c.WindowsProfile), UserDataDirectoryName)) {
			return fmt.Errorf("version 1 data_root must be %s directly below windows_profile", UserDataDirectoryName)
		}
	} else {
		if !filepath.IsAbs(c.DataRootBase) || filepath.Dir(filepath.Clean(c.DataRootBase)) == filepath.Clean(c.DataRootBase) {
			return errors.New("version 2 data_root_base must be an absolute non-volume-root path")
		}
		expected := filepath.Join(filepath.Clean(c.DataRootBase), c.WindowsSID)
		if !strings.EqualFold(filepath.Clean(c.DataRoot), expected) {
			return fmt.Errorf("version 2 data_root must be the Windows SID directly below data_root_base")
		}
	}
	if err := validateReleaseLayout(c.ReleasesRoot, c.CurrentReleaseFile); err != nil {
		return err
	}
	if c.PipeName != PipeNameForSID(c.WindowsSID) {
		return errors.New("pipe_name does not match windows_sid")
	}
	if c.WebPort < 1024 || c.WebPort > 65535 || c.MigrationPortStart < 1024 || c.MigrationPortStart > 65535 {
		return errors.New("invalid internal port")
	}
	if c.WebPortTries < 1 || c.WebPortTries > 64 || c.MigrationPortTries < 1 || c.MigrationPortTries > 64 {
		return errors.New("web_port_tries and migration_port_tries must be between 1 and 64")
	}
	if c.StartupSeconds < 10 || c.StartupSeconds > 300 || c.ShutdownSeconds < 5 || c.ShutdownSeconds > 120 {
		return errors.New("invalid startup or shutdown timeout")
	}
	if err := validateOutboundProxyURL(c.OutboundProxyURL); err != nil {
		return err
	}
	if c.KimiDatasource != nil {
		if err := c.KimiDatasource.Validate(); err != nil {
			return err
		}
	}
	if len(c.SupportedAionCore) == 0 {
		return errors.New("supported_aioncore_versions must not be empty")
	}
	if c.Limits.MemoryBytes < 256*1024*1024 || c.Limits.CPUPercent < 1 || c.Limits.CPUPercent > 100 || c.Limits.ActiveProcesses < 3 {
		return errors.New("invalid resource limits")
	}
	return nil
}

const DefaultKimiDatasourceBrokerURL = "http://127.0.0.1:3211/mcp"

type KimiDatasourceAccess struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

func (a KimiDatasourceAccess) Validate() error {
	if err := validateKimiDatasourceBrokerURL(a.Endpoint); err != nil {
		return err
	}
	if len(a.Token) < 32 || len(a.Token) > 512 || strings.ContainsAny(a.Token, " \t\r\n") {
		return errors.New("Kimi datasource access token must contain 32 to 512 non-whitespace characters")
	}
	return nil
}

func validateKimiDatasourceBrokerURL(value string) error {
	if value == "" {
		return nil
	}
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.User != nil ||
		endpoint.Opaque != "" || endpoint.Path != "/mcp" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("kimi_datasource_broker_url must be an exact 127.0.0.1 HTTP /mcp URL")
	}
	return nil
}

func (c Portal) EffectiveKimiDatasourceBrokerURL() string {
	if c.KimiDatasourceBrokerURL == "" {
		return DefaultKimiDatasourceBrokerURL
	}
	return c.KimiDatasourceBrokerURL
}

func validateOutboundProxyURL(value string) error {
	if value == "" {
		return nil
	}
	proxy, err := url.Parse(value)
	if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Hostname() == "" || proxy.User != nil ||
		proxy.Opaque != "" || (proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.Fragment != "" {
		return errors.New("outbound_proxy_url must be an absolute HTTP or HTTPS proxy URL without credentials, path, query, or fragment")
	}
	return nil
}

func PipeNameForSID(sid string) string {
	return `\\.\pipe\AionUiWeb-` + sid
}

func validSID(s string) bool {
	if !strings.HasPrefix(s, "S-1-") || len(s) > 184 {
		return false
	}
	for _, r := range s[4:] {
		if (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func validateReleaseLayout(releasesRoot, currentReleaseFile string) error {
	sharedRoot := filepath.Dir(filepath.Clean(releasesRoot))
	current := filepath.Clean(currentReleaseFile)
	if !strings.EqualFold(filepath.Base(filepath.Clean(releasesRoot)), "releases") ||
		!strings.EqualFold(filepath.Dir(current), sharedRoot) || !strings.EqualFold(filepath.Base(current), "current.json") {
		return errors.New("releases_root must be a releases directory and current_release_file must be its sibling current.json")
	}
	return nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
