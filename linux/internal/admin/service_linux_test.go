package admin

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestSystemdWordSetsRejectPrivilegeAndPathExpansion(t *testing.T) {
	if !sameWords("AF_INET6 AF_UNIX AF_INET", []string{"AF_UNIX", "AF_INET", "AF_INET6"}) {
		t.Fatal("equivalent systemd set ordering was rejected")
	}
	for _, value := range []string{"workagent-slots wheel", "workagent-slots workagent-slots", ""} {
		if sameWords(value, []string{"workagent-slots"}) {
			t.Fatalf("expanded or malformed supplementary group set was accepted: %q", value)
		}
	}
}

type staticSystemdProperties map[string]string

func (s staticSystemdProperties) Properties(_ context.Context, _ string, names ...string) (map[string]string, error) {
	result := make(map[string]string, len(names))
	for _, name := range names {
		result[name] = s[name]
	}
	return result, nil
}

func (staticSystemdProperties) Action(context.Context, ...string) error { return nil }

func TestPortalServiceSandboxVerificationRejectsWritablePathExpansion(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	portal, err := config.LoadPortal(filepath.Join(repositoryRoot, "config", "portal.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	properties := staticSystemdProperties{
		"LoadState": "loaded", "User": "workagent", "Group": "workagent", "SupplementaryGroups": "",
		"MemoryHigh": "1610612736", "MemoryMax": "2147483648", "CPUQuotaPerSecUSec": "2s", "TasksMax": "512",
		"NoNewPrivileges": "yes", "UMask": "0077", "KillMode": "control-group", "PrivateDevices": "yes", "PrivateTmp": "yes", "ProtectClock": "yes",
		"ProtectControlGroups": "yes", "ProtectHome": "yes", "ProtectHostname": "yes", "ProtectKernelLogs": "yes", "ProtectKernelModules": "yes",
		"ProtectKernelTunables": "yes", "ProtectSystem": "strict", "RestrictRealtime": "yes",
		"LockPersonality": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "SystemCallArchitectures": "native",
		"RestrictNamespaces": "yes", "MemoryDenyWriteExecute": "yes", "RestrictSUIDSGID": "yes",
		"RestrictAddressFamilies": "AF_INET6 AF_UNIX AF_INET", "ReadWritePaths": "/run/workagent /var/lib/workagent/portal", "ReadOnlyPaths": "/srv/workagent/users",
	}
	if err := VerifyPortalService(context.Background(), portal, properties); err != nil {
		t.Fatalf("production Portal sandbox was rejected: %v", err)
	}
	properties["ReadWritePaths"] += " /srv/workagent/users"
	if err := VerifyPortalService(context.Background(), portal, properties); err == nil {
		t.Fatal("expanded Portal writable paths were accepted")
	}
}

func TestTenantServiceRejectsSharedKeyringOrCoreDumps(t *testing.T) {
	properties := map[string]string{"KeyringMode": "private", "LimitCORE": "0"}
	if err := validateTenantSecretIsolation(properties); err != nil {
		t.Fatalf("production tenant secret-isolation policy was rejected: %v", err)
	}
	properties["KeyringMode"] = "shared"
	if err := validateTenantSecretIsolation(properties); err == nil {
		t.Fatal("shared tenant service keyring was accepted")
	}
	properties["KeyringMode"] = "private"
	properties["LimitCORE"] = "infinity"
	if err := validateTenantSecretIsolation(properties); err == nil {
		t.Fatal("tenant service core dumps were accepted")
	}
}
