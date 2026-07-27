package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"

	"golang.org/x/sys/unix"
)

const (
	maxCLIProxyPolicyStateBytes = 64 * 1024 * 1024
	CLIProxyMigrationLockPath   = "/run/workagent/cliproxy-migration.lock"
	CLIProxyMigrationBackupDir  = "/var/lib/workagent/migration/backups/cliproxy"
)

var lookupCLIProxyMigrationGroup = osuser.LookupGroup

type ApplyMigrationPlanOptions struct {
	ReportPath         string
	PlanPath           string
	PortalDatabasePath string
	StatePath          string
	Systemd            systemdctl.Controller
}

type ApplyMigrationPlanResult struct {
	Overrides     int  `json:"overrides"`
	Changed       bool `json:"changed"`
	BackupCreated bool `json:"backup_created"`
}

type mutablePolicyState struct {
	top   map[string]json.RawMessage
	keys  []map[string]json.RawMessage
	usage map[string]json.RawMessage
}

// ApplyMigrationPlan is the only offline importer for the archived Windows
// quota/usage plan. It requires an inactive CLIProxy systemd unit and changes
// only the two quota fields plus the usage entry of each deterministic key.
// Key hashes, previews, routing, aliases, and every unrelated state field are
// preserved semantically through their RawMessage values; the containing JSON
// document is intentionally re-encoded in canonical indented form.
func ApplyMigrationPlan(ctx context.Context, options ApplyMigrationPlanOptions) (ApplyMigrationPlanResult, error) {
	if options.StatePath != config.CLIProxyPolicyStateFile {
		return ApplyMigrationPlanResult{}, errors.New("CLIProxy migration state path is not the production policy path")
	}
	cutoverLock, err := acquireCLIProxyMigrationLock()
	if err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	defer func() {
		_ = unix.Flock(int(cutoverLock.Fd()), unix.LOCK_UN)
		_ = cutoverLock.Close()
	}()
	artifacts, err := loadMigrationArtifacts(ctx, options.ReportPath, options.PlanPath, options.PortalDatabasePath)
	if err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	controller := options.Systemd
	if controller == nil {
		value := systemdctl.Default()
		controller = value
	}
	if err := requireCLIProxyStopped(ctx, controller); err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	statePayload, stateInfo, err := readProtectedMigrationFile(options.StatePath, maxCLIProxyPolicyStateBytes, false)
	if err != nil {
		return ApplyMigrationPlanResult{}, fmt.Errorf("CLIProxy policy state: %w", err)
	}
	defer clear(statePayload)
	if stateInfo.Uid == 0 || stateInfo.Gid == 0 {
		return ApplyMigrationPlanResult{}, errors.New("CLIProxy policy state must be owned by its dedicated non-root identity")
	}
	document, err := decodeMutablePolicyState(statePayload)
	if err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	changed, err := patchMigrationPolicyState(document, artifacts.plan)
	if err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	result := ApplyMigrationPlanResult{Overrides: len(artifacts.plan.Overrides), Changed: changed}
	backupPath := migrationStateBackupPath(artifacts.plan.SourceFingerprint)
	if !changed {
		backupCreated, err := ensureConvergentMigrationStateBackup(backupPath, statePayload, artifacts.plan)
		if err != nil {
			return ApplyMigrationPlanResult{}, err
		}
		result.BackupCreated = backupCreated
		return result, nil
	}
	if err := requireCLIProxyStopped(ctx, controller); err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	backupCreated, err := ensureMigrationStateBackup(backupPath, statePayload)
	if err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	result.BackupCreated = backupCreated
	updated, err := encodeMutablePolicyState(document)
	if err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	defer clear(updated)
	if err := verifyMigrationFileIdentity(options.StatePath, stateInfo); err != nil {
		return ApplyMigrationPlanResult{}, errors.New("CLIProxy policy state changed before offline activation")
	}
	if err := requireCLIProxyStopped(ctx, controller); err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	if err := atomicReplaceMigrationState(options.StatePath, updated, stateInfo); err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	if err := requireCLIProxyStopped(ctx, controller); err != nil {
		return ApplyMigrationPlanResult{}, errors.New("CLIProxy did not remain stopped through offline state activation")
	}
	readback, _, err := readProtectedMigrationFile(options.StatePath, maxCLIProxyPolicyStateBytes, false)
	if err != nil {
		return ApplyMigrationPlanResult{}, errors.New("read back activated CLIProxy policy state")
	}
	defer clear(readback)
	verified, err := decodeMutablePolicyState(readback)
	if err != nil {
		return ApplyMigrationPlanResult{}, errors.New("activated CLIProxy policy state is invalid")
	}
	if changedAgain, err := patchMigrationPolicyState(verified, artifacts.plan); err != nil || changedAgain {
		return ApplyMigrationPlanResult{}, errors.New("activated CLIProxy policy state did not pass exact readback")
	}
	if err := verifyMigrationStateBackupConvergence(backupPath, readback, artifacts.plan); err != nil {
		return ApplyMigrationPlanResult{}, err
	}
	return result, nil
}

func acquireCLIProxyMigrationLock() (*os.File, error) {
	if effectiveUID() != 0 {
		return nil, errors.New("CLIProxy migration cutover lock must be acquired by root")
	}
	group, err := lookupCLIProxyMigrationGroup("cliproxyapi")
	if err != nil {
		return nil, errors.New("CLIProxy dedicated group is unavailable")
	}
	gid, err := parsePositiveUint32(group.Gid)
	if err != nil {
		return nil, errors.New("CLIProxy dedicated group identity is invalid")
	}
	return acquireValidatedCLIProxyMigrationLock(CLIProxyMigrationLockPath, gid)
}

func acquireValidatedCLIProxyMigrationLock(path string, expectedGID uint32) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedGID == 0 {
		return nil, errors.New("CLIProxy migration cutover lock path or group is invalid")
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, errors.New("CLIProxy migration cutover lock path is unsafe")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o755 {
		return nil, errors.New("CLIProxy migration cutover lock parent is unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return nil, errors.New("CLIProxy migration cutover lock parent must be root-owned")
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("CLIProxy migration cutover lock is missing or unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
		file.Close()
		return nil, errors.New("CLIProxy migration cutover lock must be a regular file with mode 0640")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != expectedGID {
		file.Close()
		return nil, errors.New("CLIProxy migration cutover lock ownership is invalid")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("CLIProxy is starting or running; exclusive migration cutover lock is unavailable")
		}
		return nil, errors.New("CLIProxy migration cutover lock could not be acquired")
	}
	return file, nil
}

func requireCLIProxyStopped(ctx context.Context, controller systemdctl.Controller) error {
	if controller == nil {
		return errors.New("systemd controller is required for offline CLIProxy migration")
	}
	properties, err := controller.Properties(ctx, "cliproxyapi.service", "ActiveState", "SubState", "MainPID", "ControlPID")
	if err != nil {
		return fmt.Errorf("prove CLIProxy is stopped: %w", err)
	}
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 64)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 64)
	if properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" || mainErr != nil || controlErr != nil || mainPID != 0 || controlPID != 0 {
		return errors.New("CLIProxy must be explicitly stopped and inactive before offline migration")
	}
	return nil
}

func decodeMutablePolicyState(payload []byte) (*mutablePolicyState, error) {
	var top map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&top); err != nil || decoder.Decode(&struct{}{}) != io.EOF || top == nil {
		return nil, errors.New("CLIProxy policy state JSON is invalid")
	}
	var version int
	if err := decodeStrictJSON(top["version"], &version); err != nil || version != 1 {
		return nil, errors.New("CLIProxy policy state schema is not v1")
	}
	var keys []map[string]json.RawMessage
	if err := decodeStrictJSON(top["keys"], &keys); err != nil || len(keys) == 0 || len(keys) > 100_000 {
		return nil, errors.New("CLIProxy policy state keys are invalid")
	}
	usage := make(map[string]json.RawMessage)
	if raw, ok := top["usage"]; ok && len(bytes.TrimSpace(raw)) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if err := decodeStrictJSON(raw, &usage); err != nil {
			return nil, errors.New("CLIProxy policy state usage map is invalid")
		}
	}
	return &mutablePolicyState{top: top, keys: keys, usage: usage}, nil
}

func patchMigrationPolicyState(document *mutablePolicyState, plan migrationQuotaPlan) (bool, error) {
	if document == nil || document.top == nil || len(document.keys) == 0 {
		return false, errors.New("CLIProxy policy state document is missing")
	}
	overrides := make(map[string]migrationQuotaOverride, len(plan.Overrides))
	for _, override := range plan.Overrides {
		overrides[override.NewKeyID] = override
	}
	found := make(map[string]bool, len(overrides))
	changed := false
	seen := make(map[string]bool, len(document.keys))
	for _, key := range document.keys {
		var id string
		if err := decodeStrictJSON(key["id"], &id); err != nil || id == "" || seen[id] {
			return false, errors.New("CLIProxy policy state contains an invalid or duplicate key id")
		}
		seen[id] = true
		override, targeted := overrides[id]
		if !targeted {
			continue
		}
		var hash, preview string
		var enabled bool
		if err := decodeStrictJSON(key["key_hash"], &hash); err != nil || !stateKeyHashPattern.MatchString(hash) ||
			decodeStrictJSON(key["key_preview"], &preview) != nil || !validStateKeyPreview(preview) ||
			decodeStrictJSON(key["enabled"], &enabled) != nil || !enabled {
			return false, errors.New("deterministic migration key is missing a valid new hash, preview, or enabled state")
		}
		if !rawNumberEqual(key["daily_limit_usd"], override.DailyLimitUSD) {
			key["daily_limit_usd"] = json.RawMessage(override.DailyLimitUSD)
			changed = true
		}
		if !rawNumberEqual(key["weekly_limit_usd"], override.WeeklyLimitUSD) {
			key["weekly_limit_usd"] = json.RawMessage(override.WeeklyLimitUSD)
			changed = true
		}
		currentUsage := usageState{ByAlias: map[string]aliasUsageWindows{}}
		if raw, exists := document.usage[id]; exists && len(bytes.TrimSpace(raw)) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			var err error
			currentUsage, err = decodeUsageState(raw)
			if err != nil {
				return false, errors.New("deterministic migration key has invalid existing usage")
			}
		}
		if !usageStateEqual(currentUsage, override.usage) {
			if !usageIsZero(currentUsage) {
				return false, errors.New("deterministic migration key already has conflicting non-zero usage")
			}
			document.usage[id] = append(json.RawMessage(nil), override.LegacyUsage...)
			changed = true
		}
		found[id] = true
	}
	if len(found) != len(overrides) {
		return false, errors.New("CLIProxy policy state is missing a provisioned deterministic migration key")
	}
	encodedKeys, err := json.Marshal(document.keys)
	if err != nil {
		return false, errors.New("encode migrated CLIProxy policy keys")
	}
	encodedUsage, err := json.Marshal(document.usage)
	if err != nil {
		return false, errors.New("encode migrated CLIProxy policy usage")
	}
	document.top["keys"] = encodedKeys
	document.top["usage"] = encodedUsage
	return changed, nil
}

func encodeMutablePolicyState(document *mutablePolicyState) ([]byte, error) {
	if document == nil || document.top == nil {
		return nil, errors.New("CLIProxy policy state document is missing")
	}
	payload, err := json.MarshalIndent(document.top, "", "  ")
	if err != nil {
		return nil, errors.New("encode migrated CLIProxy policy state")
	}
	return append(payload, '\n'), nil
}

func rawNumberEqual(raw json.RawMessage, expected string) bool {
	if len(raw) == 0 {
		return false
	}
	var number json.Number
	if err := decodeStrictJSON(raw, &number); err != nil {
		return false
	}
	left, leftOK := new(big.Rat).SetString(number.String())
	right, rightOK := new(big.Rat).SetString(expected)
	return leftOK && rightOK && left.Cmp(right) == 0
}

func validStateKeyPreview(value string) bool {
	return strings.HasPrefix(value, "cpa_") && len(value) >= 15 && len(value) <= 32 && strings.Contains(value, "...") && !strings.ContainsAny(value, "\r\n\x00")
}

func migrationStateBackupPath(fingerprint string) string {
	return filepath.Join(CLIProxyMigrationBackupDir, "cpa-key-policy-state.pre-windows-migration."+fingerprint+".json")
}

func ensureConvergentMigrationStateBackup(path string, current []byte, plan migrationQuotaPlan) (bool, error) {
	if err := validateMigrationBackupDirectory(filepath.Dir(path)); err != nil {
		return false, err
	}
	created := false
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		rootOwner := syscall.Stat_t{Uid: 0, Gid: 0}
		if err := writeMigrationFileNoReplace(path, current, rootOwner); err != nil {
			return false, err
		}
		created = true
	} else if err != nil {
		return false, errors.New("inspect CLIProxy migration backup")
	}
	if err := verifyMigrationStateBackupConvergence(path, current, plan); err != nil {
		return false, err
	}
	return created, nil
}

func ensureMigrationStateBackup(path string, payload []byte) (bool, error) {
	if err := validateMigrationBackupDirectory(filepath.Dir(path)); err != nil {
		return false, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("existing CLIProxy migration backup is unsafe")
		}
		existing, _, readErr := readProtectedMigrationFile(path, maxCLIProxyPolicyStateBytes, true)
		if readErr != nil || !bytes.Equal(existing, payload) {
			clear(existing)
			return false, errors.New("existing CLIProxy migration backup does not match the interrupted pre-state")
		}
		clear(existing)
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("inspect CLIProxy migration backup")
	}
	rootOwner := syscall.Stat_t{Uid: 0, Gid: 0}
	if err := writeMigrationFileNoReplace(path, payload, rootOwner); err != nil {
		return false, err
	}
	return true, nil
}

func validateMigrationBackupDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return errors.New("CLIProxy migration backup directory path is invalid")
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("CLIProxy migration backup directory or ancestor is missing or unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 {
			return errors.New("CLIProxy migration backup directory and ancestors must be root-owned")
		}
		if current == path {
			if info.Mode().Perm() != 0o700 {
				return errors.New("CLIProxy migration backup directory must have mode 0700")
			}
		} else if info.Mode().Perm()&0o022 != 0 {
			return errors.New("CLIProxy migration backup ancestor is writable outside root")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func verifyMigrationStateBackupConvergence(path string, current []byte, plan migrationQuotaPlan) error {
	if err := validateMigrationBackupDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	backup, _, err := readProtectedMigrationFile(path, maxCLIProxyPolicyStateBytes, true)
	if err != nil {
		return errors.New("root-owned CLIProxy migration backup is missing or unsafe")
	}
	defer clear(backup)
	converged, err := migrationPolicyStateAfterPlan(backup, plan)
	if err != nil {
		return errors.New("CLIProxy migration backup cannot be validated against the plan")
	}
	defer clear(converged)
	canonicalCurrent, err := migrationPolicyStateAfterPlan(current, plan)
	if err != nil {
		return errors.New("current CLIProxy policy state cannot be validated against the plan")
	}
	defer clear(canonicalCurrent)
	currentDocument, err := decodeMutablePolicyState(current)
	if err != nil {
		return errors.New("current CLIProxy policy state is invalid")
	}
	if changed, err := patchMigrationPolicyState(currentDocument, plan); err != nil || changed {
		return errors.New("current CLIProxy policy state has not fully applied the migration plan")
	}
	if !bytes.Equal(converged, canonicalCurrent) {
		return errors.New("CLIProxy migration backup is not bound to the current state and plan")
	}
	return nil
}

func migrationPolicyStateAfterPlan(payload []byte, plan migrationQuotaPlan) ([]byte, error) {
	document, err := decodeMutablePolicyState(payload)
	if err != nil {
		return nil, err
	}
	if _, err := patchMigrationPolicyState(document, plan); err != nil {
		return nil, err
	}
	return encodeMutablePolicyState(document)
}

func writeMigrationFileNoReplace(path string, payload []byte, owner syscall.Stat_t) error {
	parent := filepath.Dir(path)
	file, err := os.CreateTemp(parent, ".cliproxy-migration-backup-*")
	if err != nil {
		return errors.New("create CLIProxy migration backup")
	}
	temporary := file.Name()
	remove := true
	defer func() {
		file.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chown(int(owner.Uid), int(owner.Gid)); err != nil || file.Chmod(0o600) != nil {
		return errors.New("protect CLIProxy migration backup")
	}
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("write and sync CLIProxy migration backup")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("activate CLIProxy migration backup without replacement")
	}
	remove = false
	return syncMigrationDirectory(parent)
}

func atomicReplaceMigrationState(path string, payload []byte, owner syscall.Stat_t) error {
	parent := filepath.Dir(path)
	file, err := os.CreateTemp(parent, ".cpa-key-policy-state.migration-*")
	if err != nil {
		return errors.New("create migrated CLIProxy policy state")
	}
	temporary := file.Name()
	remove := true
	defer func() {
		file.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chown(int(owner.Uid), int(owner.Gid)); err != nil || file.Chmod(0o600) != nil {
		return errors.New("protect migrated CLIProxy policy state")
	}
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("write and sync migrated CLIProxy policy state")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("atomically activate migrated CLIProxy policy state")
	}
	remove = false
	return syncMigrationDirectory(parent)
}

func syncMigrationDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("open migration state directory for sync")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync migration state directory")
	}
	return nil
}
