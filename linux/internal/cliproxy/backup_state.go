package cliproxy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

// AcquireProductionMigrationLock takes the same exclusive lock used by the
// offline migration importer. CLIProxy holds the corresponding shared lock for
// its whole process lifetime, so callers may safely copy or replace policy
// state until the returned closer is closed.
func AcquireProductionMigrationLock() (io.Closer, error) {
	return acquireCLIProxyMigrationLock()
}

// AcquireProductionMigrationSharedLock holds the production migration inode
// read-only and shared. Live migration staging and verification use it to
// exclude the offline state importer without excluding CLIProxy itself.
func AcquireProductionMigrationSharedLock() (io.Closer, error) {
	return acquireCLIProxyMigrationSharedLock()
}

// VerifyProductionPolicyState verifies the protected on-host policy file and
// its dedicated runtime ownership before it is admitted to an encrypted
// application backup. Provider OAuth material lives in a separate directory
// and is deliberately outside this contract.
func VerifyProductionPolicyState(path string, expectedUID, expectedGID uint32) error {
	if path != config.CLIProxyPolicyStateFile || expectedUID == 0 || expectedGID == 0 {
		return errors.New("CLIProxy policy-state identity is invalid")
	}
	payload, stat, err := readProtectedMigrationFile(path, maxCLIProxyPolicyStateBytes, false)
	if err != nil {
		return err
	}
	defer clear(payload)
	if err := verifyBackupPolicyStateIdentity(path, stat); err != nil {
		return err
	}
	if stat.Uid != expectedUID || stat.Gid != expectedGID {
		return errors.New("CLIProxy policy state is not owned by its dedicated identity")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 {
		return errors.New("CLIProxy policy-state directory is unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != expectedUID || parentStat.Gid != expectedGID {
		return errors.New("CLIProxy policy-state directory ownership is invalid")
	}
	return ValidatePolicyStatePayload(payload)
}

// ValidatePolicyStatePayload performs a bounded semantic validation of a v1
// cpa-key-policy state document. Unknown top-level and per-key fields are
// retained by the plugin and are therefore intentionally accepted.
func ValidatePolicyStatePayload(payload []byte) error {
	if len(payload) == 0 || len(payload) > maxCLIProxyPolicyStateBytes || bytes.IndexByte(payload, 0) >= 0 {
		return errors.New("CLIProxy policy-state payload is empty or oversized")
	}
	document, err := decodeMutablePolicyState(payload)
	if err != nil {
		return err
	}
	if len(document.usage) > 100_000 {
		return errors.New("CLIProxy policy state contains too many usage entries")
	}
	seen := make(map[string]bool, len(document.keys))
	for _, key := range document.keys {
		var id, hash, preview string
		var enabled bool
		if decodeStrictJSON(key["id"], &id) != nil || !policyKeyIDPattern.MatchString(id) || seen[id] ||
			decodeStrictJSON(key["key_hash"], &hash) != nil || !stateKeyHashPattern.MatchString(hash) ||
			decodeStrictJSON(key["key_preview"], &preview) != nil || !validStateKeyPreview(preview) ||
			decodeStrictJSON(key["enabled"], &enabled) != nil {
			return errors.New("CLIProxy policy state contains an invalid or duplicate key")
		}
		seen[id] = true
	}
	for keyID, raw := range document.usage {
		if keyID == "" || len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("CLIProxy policy state contains an invalid usage entry")
		}
		if _, err := decodeUsageState(raw); err != nil {
			return errors.New("CLIProxy policy state contains invalid usage")
		}
	}
	return nil
}

func verifyBackupPolicyStateIdentity(path string, before syscall.Stat_t) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("CLIProxy policy state changed while it was read")
	}
	after, ok := info.Sys().(*syscall.Stat_t)
	if !ok || after.Dev != before.Dev || after.Ino != before.Ino || after.Nlink != before.Nlink || after.Mode != before.Mode ||
		after.Uid != before.Uid || after.Gid != before.Gid || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return errors.New("CLIProxy policy state changed while it was read")
	}
	return nil
}
