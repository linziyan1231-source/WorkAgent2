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
	c.UsageSSHTarget = "root@203.0.113.52"
	c.UsageSSHHelperPath = "/root/cliproxyapi/cpa-key-policy-admin.py"
	c.UsageSSHIdentityFile = filepath.Join(DefaultUsageSSHRoot, "usage_ed25519")
	c.UsageSSHKnownHostsFile = filepath.Join(DefaultUsageSSHRoot, "known_hosts")
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
	c.PublicBaseURL = "https://contact@example.invalid:25808"
	if err := c.Validate(); err == nil {
		t.Fatal("public URL userinfo accepted")
	}
	c = validPortal(t)
	c.ListenAddress = "127.0.0.1:25808"
	if err := c.Validate(); err == nil {
		t.Fatal("alternate production listener accepted")
	}
}

func TestPortalUsageSSHConfigRejectsBroadOrAmbiguousPaths(t *testing.T) {
	for name, mutate := range map[string]func(*Portal){
		"target":                func(c *Portal) { c.UsageSSHTarget = "root@host;command" },
		"helper":                func(c *Portal) { c.UsageSSHHelperPath = "/root/../bin/sh" },
		"identity outside root": func(c *Portal) { c.UsageSSHIdentityFile = `C:\Users\user-4194d170\.ssh\id_ed25519` },
		"same file":             func(c *Portal) { c.UsageSSHKnownHostsFile = c.UsageSSHIdentityFile },
		"long timeout":          func(c *Portal) { c.UsageQueryTimeoutSecs = 61 },
		"long cache":            func(c *Portal) { c.UsageCacheSeconds = 61 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validPortal(t)
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe usage SSH configuration was accepted")
			}
		})
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

func TestConfigPinsReleasePointerAndWindowsProfileDataLayouts(t *testing.T) {
	c := validPortal(t)
	c.CurrentReleaseFile = filepath.Clean(`C:\ProgramData\AionUiPortal\current.json`)
	if err := c.Validate(); err == nil {
		t.Fatal("release pointer outside the shared release root was accepted")
	}

	sid := "S-1-5-21-1244944357-1781978532-1838913594-2042"
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
	sid := "S-1-5-21-1244944357-1781978532-1838913594-2042"
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
