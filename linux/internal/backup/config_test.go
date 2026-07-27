package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validTestConfig() Config {
	return Config{
		SchemaVersion: ConfigSchemaVersion, LocalDirectory: "/var/lib/workagent-backup/local",
		OffHostDirectory: "/mnt/workagent-backup/off-host", RequireRemoteFilesystem: true,
		EncryptionKey:  "/etc/workagent-backup/encryption.key",
		MetricsFile:    "/var/lib/node_exporter/textfile_collector/workagent_backup.prom",
		RetentionCount: 14,
	}
}

func TestLoadConfigRequiresExactRootOwnedMode0600(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production backup configuration ownership requires root")
	}
	payload, err := json.Marshal(validTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "backup.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("canonical backup configuration was rejected: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("world-readable backup configuration was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("non-root-owned backup configuration was accepted")
	}
}

func TestBackupRejectsHostBoundCredentialMaterial(t *testing.T) {
	for _, source := range []Source{
		{Name: "credential-parent", Path: "/etc"},
		{Name: "credential-store", Path: "/etc/credstore.encrypted/workagent"},
		{Name: "systemd-state", Path: "/var/lib/systemd"},
		{Name: "systemd-host-key", Path: "/var/lib/systemd/credential.secret"},
	} {
		configuration := validTestConfig()
		configuration.AdditionalSources = []Source{source}
		err := configuration.Validate()
		if err == nil || !strings.Contains(err.Error(), "host-bound systemd credentials") {
			t.Fatalf("host-bound credential source was accepted: %+v err=%v", source, err)
		}
		if eligibleForBlankHostInstall(source, map[string]string{"configuration": "/etc/workagent"}) {
			t.Fatalf("host-bound credential source was eligible for blank-host installation: %+v", source)
		}
	}
}

func TestBackupRejectsChatForwardHostBoundProfiles(t *testing.T) {
	for _, source := range []Source{
		{Name: "chatforward-state", Path: "/var/lib/workagent/chatforward"},
		{Name: "chatforward-profile", Path: "/var/lib/workagent/chatforward/chromium"},
		{Name: "chatforward-cache-profile", Path: "/var/cache/workagent/chatforward/chromium/Default"},
	} {
		configuration := validTestConfig()
		configuration.AdditionalSources = []Source{source}
		err := configuration.Validate()
		if err == nil || !strings.Contains(err.Error(), "browser profile") {
			t.Fatalf("ChatForward host-bound profile source was accepted: %+v err=%v", source, err)
		}
	}
}

func TestBackupRejectsCLIProxyOAuthMaterial(t *testing.T) {
	for _, source := range []Source{
		{Name: "all-cliproxy-state", Path: "/var/lib/cliproxyapi"},
		{Name: "oauth-directory", Path: "/var/lib/cliproxyapi/auth"},
		{Name: "oauth-child", Path: "/var/lib/cliproxyapi/auth/provider.json"},
	} {
		configuration := validTestConfig()
		configuration.AdditionalSources = []Source{source}
		err := configuration.Validate()
		if err == nil || !strings.Contains(err.Error(), "OAuth material") {
			t.Fatalf("CLIProxy OAuth source was accepted: %+v err=%v", source, err)
		}
	}
	configuration := validTestConfig()
	configuration.AdditionalSources = []Source{{Name: "policy-evidence", Path: "/var/lib/cliproxyapi/policy/evidence.json"}}
	if err := configuration.Validate(); err != nil {
		t.Fatalf("non-OAuth CLIProxy policy evidence was rejected: %v", err)
	}
}

func TestBackupRejectsEncryptionKeyPathOverlap(t *testing.T) {
	for _, source := range []Source{
		{Name: "key-parent", Path: "/etc/workagent-backup"},
		{Name: "key-file", Path: "/etc/workagent-backup/encryption.key"},
		{Name: "key-child", Path: "/etc/workagent-backup/encryption.key/child"},
	} {
		configuration := validTestConfig()
		configuration.AdditionalSources = []Source{source}
		err := configuration.Validate()
		if err == nil || !strings.Contains(err.Error(), "encryption key") {
			t.Fatalf("backup encryption-key overlap was accepted: %+v err=%v", source, err)
		}
	}
}
