package cliproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/jsonutil"

	"golang.org/x/sys/unix"
)

const (
	maxCLIProxyPolicyStateBytes = 64 * 1024 * 1024
	CLIProxyMigrationLockPath   = "/run/workagent/cliproxy-migration.lock"
)

var (
	lookupCLIProxyMigrationGroup = osuser.LookupGroup
	effectiveUID                 = os.Geteuid
	stateKeyHashPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	stateAliasPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type mutablePolicyState struct {
	top   map[string]json.RawMessage
	keys  []map[string]json.RawMessage
	usage map[string]json.RawMessage
}

type usageState struct {
	Daily   usageWindow
	Weekly  usageWindow
	ByAlias map[string]aliasUsageWindows
}

type aliasUsageWindows struct {
	Daily  usageWindow `json:"daily"`
	Weekly usageWindow `json:"weekly"`
}

type usageWindow struct {
	TotalUSD        float64   `json:"total_usd"`
	WindowStart     time.Time `json:"window_start,omitempty"`
	CacheReadTokens int64     `json:"cache_read_tokens,omitempty"`
	CacheCostUSD    float64   `json:"cache_cost_usd,omitempty"`
	InputTokens     int64     `json:"input_tokens,omitempty"`
	OutputTokens    int64     `json:"output_tokens,omitempty"`
	CallCount       int64     `json:"call_count,omitempty"`
}

func acquireCLIProxyMigrationLock() (*os.File, error) {
	return acquireCLIProxyMigrationLockOperation(unix.LOCK_EX)
}

func acquireCLIProxyMigrationSharedLock() (*os.File, error) {
	return acquireCLIProxyMigrationLockOperation(unix.LOCK_SH)
}

func acquireCLIProxyMigrationLockOperation(operation int) (*os.File, error) {
	if effectiveUID() != 0 {
		return nil, errors.New("CLIProxy migration lock must be acquired by root")
	}
	if operation != unix.LOCK_SH && operation != unix.LOCK_EX {
		return nil, errors.New("CLIProxy migration lock operation is invalid")
	}
	group, err := lookupCLIProxyMigrationGroup("cliproxyapi")
	if err != nil {
		return nil, errors.New("CLIProxy dedicated group is unavailable")
	}
	gid, err := parsePositiveUint32(group.Gid)
	if err != nil {
		return nil, errors.New("CLIProxy dedicated group identity is invalid")
	}
	return acquireValidatedCLIProxyMigrationLockOperation(CLIProxyMigrationLockPath, gid, operation)
}

func acquireValidatedCLIProxyMigrationLockOperation(path string, expectedGID uint32, operation int) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedGID == 0 {
		return nil, errors.New("CLIProxy migration lock path or group is invalid")
	}
	if operation != unix.LOCK_SH && operation != unix.LOCK_EX {
		return nil, errors.New("CLIProxy migration lock operation is invalid")
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, errors.New("CLIProxy migration lock path is unsafe")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o755 {
		return nil, errors.New("CLIProxy migration lock parent is unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return nil, errors.New("CLIProxy migration lock parent must be root-owned")
	}
	openMode := unix.O_RDONLY
	readOnly := true
	if operation == unix.LOCK_EX {
		openMode = unix.O_RDWR
		readOnly = false
	}
	fd, err := unix.Open(path, openMode|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("CLIProxy migration lock is missing or unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("CLIProxy migration lock descriptor is unavailable")
	}
	if err := validateCLIProxyMigrationLockFD(fd, path, expectedGID, readOnly); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(fd, operation|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			if operation == unix.LOCK_EX {
				return nil, errors.New("CLIProxy is starting or running; exclusive policy-state lock is unavailable")
			}
			return nil, errors.New("offline CLIProxy policy-state maintenance is active; shared lock is unavailable")
		}
		return nil, errors.New("CLIProxy migration lock could not be acquired")
	}
	if err := validateCLIProxyMigrationLockFD(fd, path, expectedGID, readOnly); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateCLIProxyMigrationLockFD(fd int, path string, expectedGID uint32, readOnly bool) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return errors.New("inspect CLIProxy migration lock descriptor access mode")
	}
	expectedAccess := unix.O_RDWR
	if readOnly {
		expectedAccess = unix.O_RDONLY
	}
	if flags&unix.O_ACCMODE != expectedAccess {
		return errors.New("CLIProxy migration lock descriptor access mode is unsafe")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return errors.New("inspect CLIProxy migration lock descriptor")
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Mode&0o7777 != 0o640 || opened.Uid != 0 || opened.Gid != expectedGID || opened.Nlink != 1 || opened.Size != 0 {
		return errors.New("CLIProxy migration lock descriptor metadata is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("CLIProxy migration lock pathname is missing or unsafe")
	}
	named, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(named.Dev) != opened.Dev || named.Ino != opened.Ino || uint32(named.Mode) != opened.Mode || named.Uid != opened.Uid || named.Gid != opened.Gid || named.Nlink != opened.Nlink || named.Size != opened.Size {
		return errors.New("CLIProxy migration lock pathname does not identify the opened inode")
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

func validStateKeyPreview(value string) bool {
	return strings.HasPrefix(value, "cpa_") && len(value) >= 15 && len(value) <= 32 && strings.Contains(value, "...") && !strings.ContainsAny(value, "\r\n\x00")
}

func decodeUsageState(raw json.RawMessage) (usageState, error) {
	if len(raw) == 0 {
		return usageState{}, errors.New("usage state is missing")
	}
	var envelope struct {
		Daily   json.RawMessage            `json:"daily"`
		Weekly  json.RawMessage            `json:"weekly"`
		ByAlias map[string]json.RawMessage `json:"by_alias,omitempty"`
	}
	if err := decodeStrictJSON(raw, &envelope); err != nil {
		return usageState{}, errors.New("usage object has an invalid shape")
	}
	result := usageState{ByAlias: make(map[string]aliasUsageWindows, len(envelope.ByAlias))}
	var err error
	if len(envelope.Daily) > 0 {
		result.Daily, err = decodeUsageWindow(envelope.Daily)
		if err != nil {
			return usageState{}, err
		}
	}
	if len(envelope.Weekly) > 0 {
		result.Weekly, err = decodeUsageWindow(envelope.Weekly)
		if err != nil {
			return usageState{}, err
		}
	}
	for alias, entry := range envelope.ByAlias {
		if !stateAliasPattern.MatchString(alias) {
			return usageState{}, errors.New("usage contains an invalid alias")
		}
		var dual struct {
			Daily  json.RawMessage `json:"daily"`
			Weekly json.RawMessage `json:"weekly"`
		}
		if err := decodeStrictJSON(entry, &dual); err == nil && (len(dual.Daily) > 0 || len(dual.Weekly) > 0) {
			windows := aliasUsageWindows{}
			if len(dual.Daily) > 0 {
				windows.Daily, err = decodeUsageWindow(dual.Daily)
				if err != nil {
					return usageState{}, err
				}
			}
			if len(dual.Weekly) > 0 {
				windows.Weekly, err = decodeUsageWindow(dual.Weekly)
				if err != nil {
					return usageState{}, err
				}
			}
			result.ByAlias[alias] = windows
			continue
		}
		window, windowErr := decodeUsageWindow(entry)
		if windowErr != nil {
			return usageState{}, errors.New("usage alias entry has an invalid shape")
		}
		result.ByAlias[alias] = aliasUsageWindows{Daily: window}
	}
	return result, nil
}

func decodeUsageWindow(raw json.RawMessage) (usageWindow, error) {
	var window usageWindow
	if err := decodeStrictJSON(raw, &window); err != nil {
		return usageWindow{}, errors.New("usage window has an invalid shape")
	}
	if !finiteNonnegative(window.TotalUSD) || !finiteNonnegative(window.CacheCostUSD) || window.TotalUSD > 1_000_000_000 || window.CacheCostUSD > 1_000_000_000 ||
		window.CacheReadTokens < 0 || window.InputTokens < 0 || window.OutputTokens < 0 || window.CallCount < 0 {
		return usageWindow{}, errors.New("usage window contains a negative, non-finite, or oversized value")
	}
	if !window.WindowStart.IsZero() && (window.WindowStart.Year() < 2000 || window.WindowStart.Year() > 2200) {
		return usageWindow{}, errors.New("usage window timestamp is outside the supported range")
	}
	if !window.WindowStart.IsZero() && window.WindowStart.After(time.Now().UTC().Add(5*time.Minute)) {
		return usageWindow{}, errors.New("usage window timestamp is unexpectedly in the future")
	}
	if usageWindowHasMeasurements(window) && window.WindowStart.IsZero() {
		return usageWindow{}, errors.New("non-zero usage window is missing its window_start")
	}
	return window, nil
}

func usageWindowHasMeasurements(value usageWindow) bool {
	return value.TotalUSD != 0 || value.CacheReadTokens != 0 || value.CacheCostUSD != 0 || value.InputTokens != 0 || value.OutputTokens != 0 || value.CallCount != 0
}

func finiteNonnegative(value float64) bool {
	return value >= 0 && !math.IsInf(value, 0) && !math.IsNaN(value)
}

func readProtectedMigrationFile(path string, maximum int64, rootOwned bool) ([]byte, syscall.Stat_t, error) {
	file, stat, err := openProtectedMigrationFile(path, maximum, rootOwned)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		clear(payload)
		return nil, syscall.Stat_t{}, errors.New("protected file could not be read safely")
	}
	return payload, stat, nil
}

func openProtectedMigrationFile(path string, maximum int64, rootOwned bool) (*os.File, syscall.Stat_t, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || maximum < 1 {
		return nil, syscall.Stat_t{}, errors.New("path must be clean, absolute, and bounded")
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, syscall.Stat_t{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, errors.New("protected file could not be opened")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximum {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file is missing, oversized, or has unsafe mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (rootOwned && stat.Uid != 0) {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file ownership is invalid")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file parent is unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != stat.Uid {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("protected file parent ownership does not match")
	}
	return file, *stat, nil
}

func rejectSymlinkAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("protected path component is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("protected path must not contain a symbolic link")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func decodeStrictJSON(payload []byte, destination any) error {
	err := jsonutil.DecodeStrict(payload, destination, true)
	if errors.Is(err, jsonutil.ErrTrailingData) {
		return errors.New("JSON contains trailing data")
	}
	return err
}

func parsePositiveUint32(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, errors.New("runtime account identity is invalid")
	}
	return uint32(parsed), nil
}
