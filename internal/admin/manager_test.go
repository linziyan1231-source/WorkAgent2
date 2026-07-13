package admin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/config"
	"aionuiportal/internal/release"
	"aionuiportal/internal/winutil"
)

func TestApplyAndVerifyIncludesConfigAndReleaseControlACLs(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "program")
	data := filepath.Join(root, "program-data")
	shared := filepath.Join(root, "shared")
	releases := filepath.Join(shared, "releases")
	packed := filepath.Join(root, "packed")
	for name, body := range map[string]string{
		"aionui-web.exe": "web", "package.json": `{"version":"test"}`, "static/index.html": "renderer",
		"bundled-aioncore/win32-x64/aioncore.exe": "core",
	} {
		path := filepath.Join(packed, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installed, err := release.Install(packed, releases, "test", "v0.1.42", []string{"v0.1.42"})
	if err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(shared, "current.json")
	if err := release.Activate(installed, current, filepath.Join(shared, "previous.json")); err != nil {
		t.Fatal(err)
	}
	agentRoot := agentcli.RootFromAionReleases(releases)
	agentReleaseID := "codex-0.142.5_kimi-1.38.0_python-3.13.13"
	agentRelease := filepath.Join(agentRoot, "releases", agentReleaseID)
	for name, body := range map[string]string{agentcli.CodexRelativePath: "codex", agentcli.KimiRelativePath: "python", agentcli.KimiModuleRelativePath: "kimi"} {
		path := filepath.Join(agentRelease, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agentManifest, err := agentcli.BuildManifest(agentRelease, agentReleaseID, "0.142.5", "1.38.0", "3.13.13")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentcli.WriteManifest(agentRelease, agentManifest); err != nil {
		t.Fatal(err)
	}
	if _, err := agentcli.Activate(agentRoot, agentReleaseID); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(program, 0o700); err != nil {
		t.Fatal(err)
	}
	userHost := filepath.Join(program, "AionUiUserHost.exe")
	if err := os.WriteFile(userHost, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := winutil.CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultPortal()
	cfg.Mode = "test"
	cfg.ListenAddress = "127.0.0.1:25808"
	cfg.PublicBaseURL = "http://portal.example.test:25808"
	cfg.DatabasePath = filepath.Join(data, "portal.db")
	cfg.AuditLogPath = filepath.Join(data, "logs", "audit.jsonl")
	cfg.PortalLogPath = filepath.Join(data, "logs", "portal.log")
	cfg.ReleasesRoot = releases
	cfg.CurrentReleaseFile = current
	cfg.UserConfigRoot = filepath.Join(data, "users")
	cfg.UserProfilesRoot = filepath.Join(root, "profiles")
	cfg.UserHostExecutable = userHost
	cfg.PortalServiceSID = identity.SID
	configPath := filepath.Join(data, "portal.json")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := Open(configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if failures := manager.ApplyACLs(context.Background()); len(failures) != 0 {
		t.Fatalf("ACL application failures: %v", failures)
	}
	if failures := manager.VerifyACLs(context.Background()); len(failures) != 0 {
		t.Fatalf("ACL verification failures: %v", failures)
	}
	for _, path := range []string{configPath, shared, releases, current, agentRoot, agentRelease} {
		policy := winutil.SharedReadOnlyPolicy()
		if path == configPath {
			policy = winutil.ServicePrivatePolicy(identity.SID)
		}
		if err := winutil.VerifyACL(path, policy); err != nil {
			t.Fatalf("protected ACL missing on %s: %v", path, err)
		}
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if failures := manager.VerifyACLs(context.Background()); len(failures) == 0 {
		t.Fatal("missing Portal configuration was not reported")
	}
}

func TestValidateUserHostLayoutRequiresExactFixedIdentityAndPaths(t *testing.T) {
	const sid = "S-1-5-21-1417176286-1839503707-1020375065-6067"
	const profile = `C:\Users\user-87eba76e`
	manager := Manager{Config: config.Portal{
		UserProfilesRoot:   `C:\Users`,
		ReleasesRoot:       `C:\Program Files\AionUiPortal\shared\releases`,
		CurrentReleaseFile: `C:\Program Files\AionUiPortal\shared\current.json`,
		PortalServiceSID:   "S-1-5-80-1234",
	}, ProfileDirectory: func(requestedSID string) (string, error) {
		if requestedSID != sid {
			return `C:\Users\user-d9298a10`, nil
		}
		return profile, nil
	}}
	valid := config.UserHost{
		WindowsSID:         sid,
		WindowsProfile:     profile,
		DataRoot:           profile + `\AionUiPortal`,
		ReleasesRoot:       manager.Config.ReleasesRoot,
		CurrentReleaseFile: manager.Config.CurrentReleaseFile,
		PortalServiceSID:   manager.Config.PortalServiceSID,
	}
	if err := manager.validateUserHostLayout(valid, sid); err != nil {
		t.Fatalf("exact fixed layout rejected: %v", err)
	}

	tests := []struct {
		name   string
		change func(*config.UserHost)
	}{
		{"SID", func(cfg *config.UserHost) { cfg.WindowsSID = "S-1-5-21-1032064966-1535641275-1296334407-6542" }},
		{"Windows profile", func(cfg *config.UserHost) { cfg.WindowsProfile = `C:\Users\user-d9298a10` }},
		{"data root", func(cfg *config.UserHost) { cfg.DataRoot = `C:\Users\user-d9298a10\AionUiPortal` }},
		{"release root", func(cfg *config.UserHost) { cfg.ReleasesRoot = `C:\untrusted\releases` }},
		{"current pointer", func(cfg *config.UserHost) { cfg.CurrentReleaseFile = `C:\untrusted\current.json` }},
		{"service SID", func(cfg *config.UserHost) { cfg.PortalServiceSID = "S-1-5-80-9999" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.change(&candidate)
			if err := manager.validateUserHostLayout(candidate, sid); err == nil {
				t.Fatal("mismatched recovered config was accepted")
			}
		})
	}
}

func TestProvisionUserFilesUsesResolvedWindowsProfileChild(t *testing.T) {
	root := t.TempDir()
	profilesRoot := filepath.Join(root, "profiles")
	profile := filepath.Join(profilesRoot, "worker")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := winutil.CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	manager := Manager{Config: config.Portal{
		UserProfilesRoot:       profilesRoot,
		UserConfigRoot:         filepath.Join(root, "program-data", "users"),
		ReleasesRoot:           filepath.Join(root, "shared", "releases"),
		CurrentReleaseFile:     filepath.Join(root, "shared", "current.json"),
		PortalServiceSID:       identity.SID,
		InstanceStartupSeconds: 90,
		SupportedAionCore:      []string{"v0.1.42"},
	}, ProfileDirectory: func(requestedSID string) (string, error) {
		if requestedSID != identity.SID {
			t.Fatalf("unexpected profile lookup for %s", requestedSID)
		}
		return profile, nil
	}}
	got, err := manager.provisionUserFiles(identity.SID, `SERVER\worker`)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(profile, config.UserDataDirectoryName)
	if !filepath.IsAbs(got.DataRoot) || !equalPath(got.WindowsProfile, profile) || !equalPath(got.DataRoot, want) {
		t.Fatalf("wrong profile layout: profile=%s data=%s want=%s", got.WindowsProfile, got.DataRoot, want)
	}
	if err := winutil.VerifyTreeACL(want, winutil.PrivateTreePolicy(identity.SID)); err != nil {
		t.Fatalf("private product subtree ACL: %v", err)
	}
	if _, err := os.Stat(filepath.Join(profile, config.UserDataDirectoryName, "data")); err != nil {
		t.Fatalf("private data directory missing: %v", err)
	}
}

func TestRealCProfileProductRoots(t *testing.T) {
	if os.Getenv("AIONUI_REAL_PROFILE_TEST") != "1" {
		t.Skip("set AIONUI_REAL_PROFILE_TEST=1 for the destructive-then-cleaned real profile ACL test")
	}
	serviceIdentity, err := winutil.CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"test1", "test2"} {
		t.Run(account, func(t *testing.T) {
			sid, canonical, err := winutil.ValidateStandardAccount(account)
			if err != nil {
				t.Fatal(err)
			}
			profile, err := winutil.ProfileDirectoryForSID(sid)
			if err != nil {
				t.Fatal(err)
			}
			dataRoot := filepath.Join(profile, config.UserDataDirectoryName)
			if _, err := os.Lstat(dataRoot); !os.IsNotExist(err) {
				t.Fatalf("refusing to replace an existing real user data root %s (stat error: %v)", dataRoot, err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(dataRoot); err != nil {
					t.Errorf("clean real profile test root %s: %v", dataRoot, err)
				}
			})
			root := t.TempDir()
			manager := Manager{Config: config.Portal{
				UserProfilesRoot:       config.DefaultUserProfilesRoot,
				UserConfigRoot:         filepath.Join(root, "users"),
				ReleasesRoot:           filepath.Join(root, "shared", "releases"),
				CurrentReleaseFile:     filepath.Join(root, "shared", "current.json"),
				PortalServiceSID:       serviceIdentity.SID,
				InstanceStartupSeconds: 90,
				SupportedAionCore:      []string{"v0.1.42"},
			}, ProfileDirectory: winutil.ProfileDirectoryForSID}
			got, err := manager.provisionUserFiles(sid, canonical)
			if err != nil {
				t.Fatal(err)
			}
			if !equalPath(got.WindowsProfile, profile) || !equalPath(got.DataRoot, dataRoot) {
				t.Fatalf("real profile layout mismatch: %+v", got)
			}
			if err := winutil.VerifyTreeACL(dataRoot, winutil.PrivateTreePolicy(sid)); err != nil {
				t.Fatalf("real profile product ACL: %v", err)
			}
		})
	}
}

func equalPath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}
