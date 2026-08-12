package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validPortal(t *testing.T) Portal {
	t.Helper()
	root := filepath.Clean(`C:\ProgramData\AionUiPortal`)
	c := DefaultPortal()
	c.PublicBaseURL = "https://portal.example.test:25808"
	c.TLSCertificateFile = filepath.Join(root, "tls", "cert.pem")
	c.TLSPrivateKeyFile = filepath.Join(root, "tls", "key.pem")
	c.DatabasePath = filepath.Join(root, "portal.db")
	c.AuditLogPath = filepath.Join(root, "logs", "audit.jsonl")
	c.PortalLogPath = filepath.Join(root, "logs", "portal.log")
	c.ReleasesRoot = filepath.Clean(`C:\Program Files\AionUiWebShared\releases`)
	c.CurrentReleaseFile = filepath.Clean(`C:\Program Files\AionUiWebShared\current.json`)
	c.UserConfigRoot = filepath.Join(root, "users")
	c.UserHostExecutable = filepath.Clean(`C:\Program Files\AionUiPortal\AionUiUserHost.exe`)
	c.PortalServiceSID = "S-1-5-80-123"
	c.UsageManagementURL = "http://127.0.0.1:8317/v0/management/plugins/cpa-key-policy"
	c.UsageManagementKeyFile = filepath.Join(DefaultCLIProxyRoot, ".management-key")
	return c
}

func TestProductionConfigAcceptsExplicitHTTPAndRejectsUnsafeOrigins(t *testing.T) {
	c := validPortal(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	c.PublicBaseURL = "http://portal.example.test:25808"
	c.TLSCertificateFile = ""
	c.TLSPrivateKeyFile = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("explicit HTTP config rejected: %v", err)
	}
	c.PublicBaseURL = "http://portal.example.test"
	if err := c.Validate(); err != nil {
		t.Fatalf("standard HTTP origin rejected: %v", err)
	}
	c.TLSCertificateFile = filepath.Join(`C:\ProgramData\AionUiPortal`, "tls", "unused.pem")
	if err := c.Validate(); err == nil {
		t.Fatal("HTTP config accepted an unused TLS path")
	}
	c = validPortal(t)
	c.PublicBaseURL = "http://portal.example.test:8080"
	c.TLSCertificateFile = ""
	c.TLSPrivateKeyFile = ""
	if err := c.Validate(); err == nil {
		t.Fatal("alternate HTTP public port accepted")
	}
	c = validPortal(t)
	c.PublicBaseURL = "https://portal.example.test:443"
	if err := c.Validate(); err == nil {
		t.Fatal("alternate production public port accepted")
	}
	c = validPortal(t)
	c.PublicBaseURL = "https://user@portal.example.test:25808"
	if err := c.Validate(); err == nil {
		t.Fatal("public URL userinfo accepted")
	}
	c = validPortal(t)
	c.ListenAddress = "127.0.0.1:25808"
	if err := c.Validate(); err == nil {
		t.Fatal("alternate production listener accepted")
	}
}

func TestProductionConfigAcceptsOnlyExactAdditionalBrowserOrigins(t *testing.T) {
	c := validPortal(t)
	c.PublicBaseURL = "http://portal.example.test"
	c.TLSCertificateFile = ""
	c.TLSPrivateKeyFile = ""
	c.BrowserOrigins = []string{"http://134.175.110.121:25808", "http://127.0.0.1:25808"}
	if err := c.Validate(); err != nil {
		t.Fatalf("exact additional browser origins rejected: %v", err)
	}
	for _, invalid := range []string{
		"http://portal.example.test",
		"http://127.0.0.1:25808/",
		"http://127.0.0.1:25808/path",
		"http://127.0.0.1:25808?query",
		"http://user@127.0.0.1:25808",
		"ws://127.0.0.1:25808",
	} {
		candidate := c
		candidate.BrowserOrigins = []string{invalid}
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid additional browser origin accepted: %q", invalid)
		}
	}
}

func TestOutboundProxyURLIsOptionalAndStrictlyValidated(t *testing.T) {
	portal := validPortal(t)
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

	sid := "S-1-5-21-1-2-3-1001"
	profile := filepath.Join(`C:\Users`, "worker")
	userHost := UserHost{ConfigVersion: 1, WindowsSID: sid, WindowsUsername: `SERVER\worker`, WindowsProfile: profile,
		DataRoot: filepath.Join(profile, UserDataDirectoryName), ReleasesRoot: `C:\Program Files\AionUiWebShared\releases`,
		CurrentReleaseFile: `C:\Program Files\AionUiWebShared\current.json`, PortalServiceSID: "S-1-5-80-123", PipeName: PipeNameForSID(sid),
		WebPort: 35001, WebPortTries: 16, MigrationPortStart: 40000, MigrationPortTries: 16, StartupSeconds: 90, ShutdownSeconds: 20,
		OutboundProxyURL: "https://proxy.example.test:8443", SupportedAionCore: []string{"v0.1.42"},
		Limits: ResourceLimits{MemoryBytes: 1024 * 1024 * 1024, CPUPercent: 50, ActiveProcesses: 20}}
	if err := userHost.Validate(); err != nil {
		t.Fatalf("valid UserHost proxy rejected: %v", err)
	}
}

func TestPortalUsageManagementConfigRejectsNonLocalOrBroadPaths(t *testing.T) {
	for name, mutate := range map[string]func(*Portal){
		"remote URL": func(c *Portal) {
			c.UsageManagementURL = "http://43.134.118.158:8317/v0/management/plugins/cpa-key-policy"
		},
		"wrong route":      func(c *Portal) { c.UsageManagementURL = "http://127.0.0.1:8317/v0/management" },
		"key outside root": func(c *Portal) { c.UsageManagementKeyFile = `C:\Users\Administrator\management.key` },
		"long timeout":     func(c *Portal) { c.UsageQueryTimeoutSecs = 61 },
		"long cache":       func(c *Portal) { c.UsageCacheSeconds = 61 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validPortal(t)
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe usage Management API configuration was accepted")
			}
		})
	}
}

func TestChatForwardConfigRequiresLoopbackSecretAndProModels(t *testing.T) {
	valid := validPortal(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid ChatForward config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Portal){
		"remote bridge": func(c *Portal) { c.ChatForwardURL = "http://192.0.2.10:3210" },
		"bridge path":   func(c *Portal) { c.ChatForwardURL = "http://127.0.0.1:3210/chatgpt" },
		"secret outside Portal root": func(c *Portal) {
			c.ChatForwardSecretFile = `C:\Users\Administrator\chatforward.key`
		},
		"invalid model":   func(c *Portal) { c.ChatGPTProModels = []string{"gpt-5-6-thinking"} },
		"duplicate model": func(c *Portal) { c.ChatGPTProModels = []string{"gpt-5-6-pro", "GPT-5-6-PRO"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe ChatForward configuration was accepted")
			}
		})
	}
}

func TestNotificationSourceRequiresExactBoundedURL(t *testing.T) {
	valid := validPortal(t)
	valid.NotificationSourceURL = "http://134.175.110.121:25888/notification"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid notification source rejected: %v", err)
	}
	for _, invalid := range []string{
		"ftp://134.175.110.121:25888/notification",
		"http://user@134.175.110.121:25888/notification",
		"http://134.175.110.121:25888/",
		"http://134.175.110.121:25888/notification?user=test1",
	} {
		candidate := valid
		candidate.NotificationSourceURL = invalid
		if err := candidate.Validate(); err == nil {
			t.Fatalf("unsafe notification source accepted: %q", invalid)
		}
	}
}

func TestAdminMasterPasswordHashFileIsOptionalAndConfinedToPortalData(t *testing.T) {
	valid := validPortal(t)
	valid.AdminMasterHashFile = filepath.Join(DefaultPortalDataRoot, "admin-master-password.argon2id")
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid admin master password hash path rejected: %v", err)
	}
	for _, invalid := range []string{"relative.argon2id", `C:\Users\Administrator\admin-master-password.argon2id`} {
		candidate := valid
		candidate.AdminMasterHashFile = invalid
		if err := candidate.Validate(); err == nil {
			t.Fatalf("unsafe admin master password hash path accepted: %q", invalid)
		}
	}
}

func TestPortalConfigRejectsTrailingJSONValue(t *testing.T) {
	cfg := validPortal(t)
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "portal.json")
	if err := os.WriteFile(path, append(b, []byte("\n{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPortal(path); err == nil {
		t.Fatal("multiple JSON values were accepted")
	}
}

func TestVerifyReleaseIntegrityDefaultsOffAndParses(t *testing.T) {
	cfg := validPortal(t)
	if cfg.VerifyReleaseIntegrity {
		t.Fatal("verify_release_integrity defaulted to on")
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "portal.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPortal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.VerifyReleaseIntegrity {
		t.Fatal("verify_release_integrity loaded as on when omitted")
	}
	cfg.VerifyReleaseIntegrity = true
	b, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadPortal(path)
	if err != nil || !loaded.VerifyReleaseIntegrity {
		t.Fatalf("verify_release_integrity did not round-trip: %+v %v", loaded, err)
	}
}

func TestConfigPinsReleasePointerAndWindowsProfileDataLayouts(t *testing.T) {
	c := validPortal(t)
	c.CurrentReleaseFile = filepath.Clean(`C:\ProgramData\AionUiPortal\current.json`)
	if err := c.Validate(); err == nil {
		t.Fatal("release pointer outside the shared release root was accepted")
	}

	sid := "S-1-5-21-1-2-3-1001"
	profile := filepath.Join(`C:\Users`, "worker")
	userHost := UserHost{
		ConfigVersion: 1, WindowsSID: sid, WindowsUsername: `SERVER\worker`, WindowsProfile: profile,
		DataRoot:     filepath.Join(`C:\Users`, "other", UserDataDirectoryName),
		ReleasesRoot: `C:\Program Files\AionUiWebShared\releases`, CurrentReleaseFile: `C:\Program Files\AionUiWebShared\current.json`,
		PortalServiceSID: "S-1-5-80-123", PipeName: PipeNameForSID(sid), WebPort: 35001, WebPortTries: 16,
		MigrationPortStart: 40000, MigrationPortTries: 16, StartupSeconds: 90, ShutdownSeconds: 20,
		SupportedAionCore: []string{"v0.1.42"}, Limits: ResourceLimits{MemoryBytes: 1024 * 1024 * 1024, CPUPercent: 50, ActiveProcesses: 20},
	}
	if err := userHost.Validate(); err == nil {
		t.Fatal("UserHost data root outside its fixed Windows profile was accepted")
	}
	c = validPortal(t)
	c.UserProfilesRoot = `C:\Profiles`
	if err := c.Validate(); err == nil {
		t.Fatal("alternate production Windows profiles root was accepted")
	}
}

func TestUserHostSIDControlsPipeAndDataRoot(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	profile := filepath.Join(`C:\Users`, "worker")
	c := UserHost{
		ConfigVersion: 1, WindowsSID: sid, WindowsUsername: `SERVER\worker`,
		WindowsProfile: profile, DataRoot: filepath.Join(profile, UserDataDirectoryName), ReleasesRoot: `C:\Program Files\AionUiWebShared\releases`,
		CurrentReleaseFile: `C:\Program Files\AionUiWebShared\current.json`, PortalServiceSID: "S-1-5-80-123",
		PipeName: PipeNameForSID(sid), WebPort: 35001, WebPortTries: 16, MigrationPortStart: 40000, MigrationPortTries: 16,
		StartupSeconds: 90, ShutdownSeconds: 20, SupportedAionCore: []string{"v0.1.42"},
		Limits: ResourceLimits{MemoryBytes: 1024 * 1024 * 1024, CPUPercent: 50, ActiveProcesses: 20},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid user host config rejected: %v", err)
	}
	c.PipeName = `\\.\pipe\AionUiWeb-S-1-5-21-attacker`
	if err := c.Validate(); err == nil {
		t.Fatal("SID-mismatched pipe accepted")
	}
}
