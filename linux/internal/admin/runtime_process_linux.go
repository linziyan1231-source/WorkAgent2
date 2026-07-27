package admin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	// Leave enough bounded retries for a busy host while still fitting well
	// inside the tenant unit's 60-second startup deadline.
	runtimeProcessAuditScans        = 16
	runtimeProcessAuditCleanScans   = 2
	runtimeProcessAuditMaxPIDs      = 131072
	runtimeProcessAuditMaxFileBytes = 64 * 1024
)

type runtimeProcessAuditSource interface {
	processIDs() ([]int, error)
	processFile(pid int, name string) ([]byte, error)
}

type procRuntimeProcessAuditSource struct{ root string }

// VerifyRuntimeUIDQuiescent is the root-only ExecStartPre boundary ensuring a
// dedicated tenant UID has no process from a previous activation. systemd
// starts UserHost immediately after this succeeds and KillMode=control-group
// is independently pinned by tenant service verification.
func VerifyRuntimeUIDQuiescent(runtimeUID uint32) error {
	return verifyRuntimeUIDQuiescent(runtimeUID, uint32(os.Geteuid()), procRuntimeProcessAuditSource{root: "/proc"}, runtimeProcessAuditScans, runtimeProcessAuditMaxPIDs)
}

func verifyRuntimeUIDQuiescent(runtimeUID, effectiveUID uint32, source runtimeProcessAuditSource, scans, maximumPIDs int) error {
	if effectiveUID != 0 {
		return errors.New("tenant runtime process audit requires root")
	}
	if runtimeUID == 0 {
		return errors.New("tenant runtime process audit rejects UID 0")
	}
	if source == nil || scans < runtimeProcessAuditCleanScans || maximumPIDs < 1 {
		return errors.New("tenant runtime process audit configuration is invalid")
	}
	consecutiveClean := 0
	for attempt := 0; attempt < scans; attempt++ {
		stable, err := scanRuntimeUIDProcesses(runtimeUID, source, maximumPIDs)
		if err != nil {
			return err
		}
		if stable {
			consecutiveClean++
			if consecutiveClean == runtimeProcessAuditCleanScans {
				return nil
			}
		} else {
			consecutiveClean = 0
		}
	}
	return errors.New("tenant runtime process audit could not obtain a stable process-table view")
}

func scanRuntimeUIDProcesses(runtimeUID uint32, source runtimeProcessAuditSource, maximumPIDs int) (bool, error) {
	pids, err := source.processIDs()
	if err != nil {
		return false, errors.New("tenant runtime process audit cannot enumerate the process table")
	}
	if len(pids) > maximumPIDs {
		return false, errors.New("tenant runtime process audit process limit exceeded")
	}
	stable := true
	for _, pid := range pids {
		if pid < 1 {
			return false, errors.New("tenant runtime process audit found an invalid process identifier")
		}
		before, err := source.processFile(pid, "stat")
		if processDisappeared(err) {
			stable = false
			continue
		}
		if err != nil {
			return false, errors.New("tenant runtime process audit cannot read process identity")
		}
		beforeStart, err := parseRuntimeProcessStartTime(before)
		clear(before)
		if err != nil {
			return false, err
		}

		status, err := source.processFile(pid, "status")
		if processDisappeared(err) {
			stable = false
			continue
		}
		if err != nil {
			return false, errors.New("tenant runtime process audit cannot read process credentials")
		}
		uids, err := parseRuntimeProcessUIDs(status)
		clear(status)
		if err != nil {
			return false, err
		}

		after, err := source.processFile(pid, "stat")
		if processDisappeared(err) {
			stable = false
			continue
		}
		if err != nil {
			return false, errors.New("tenant runtime process audit cannot re-read process identity")
		}
		afterStart, err := parseRuntimeProcessStartTime(after)
		clear(after)
		if err != nil {
			return false, err
		}
		if beforeStart != afterStart {
			stable = false
			continue
		}
		for _, uid := range uids {
			if uid == runtimeUID {
				return false, errors.New("tenant runtime UID already owns a residual process")
			}
		}
	}
	return stable, nil
}

func parseRuntimeProcessStartTime(content []byte) (uint64, error) {
	closing := strings.LastIndexByte(string(content), ')')
	if closing < 1 || closing+2 >= len(content) || content[closing+1] != ' ' {
		return 0, errors.New("tenant runtime process audit found malformed process identity")
	}
	fields := strings.Fields(string(content[closing+2:]))
	// The slice begins at proc stat field 3; starttime is field 22.
	if len(fields) < 20 {
		return 0, errors.New("tenant runtime process audit found incomplete process identity")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, errors.New("tenant runtime process audit found invalid process start time")
	}
	return startTime, nil
}

func parseRuntimeProcessUIDs(content []byte) ([4]uint32, error) {
	var result [4]uint32
	found := false
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		if found {
			return result, errors.New("tenant runtime process audit found duplicate process credentials")
		}
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "Uid:" {
			return result, errors.New("tenant runtime process audit found malformed process credentials")
		}
		for index := range result {
			value, err := strconv.ParseUint(fields[index+1], 10, 32)
			if err != nil {
				return result, errors.New("tenant runtime process audit found invalid process credentials")
			}
			result[index] = uint32(value)
		}
		found = true
	}
	if !found {
		return result, errors.New("tenant runtime process audit found missing process credentials")
	}
	return result, nil
}

func processDisappeared(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func (p procRuntimeProcessAuditSource) processIDs() ([]int, error) {
	entries, err := os.ReadDir(p.root)
	if err != nil {
		return nil, err
	}
	result := make([]int, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || strings.IndexFunc(name, func(character rune) bool { return character < '0' || character > '9' }) >= 0 {
			continue
		}
		pid, err := strconv.ParseInt(name, 10, 32)
		if err != nil || pid < 1 {
			return nil, errors.New("tenant runtime process audit found an invalid process-table entry")
		}
		result = append(result, int(pid))
		if len(result) > runtimeProcessAuditMaxPIDs {
			return nil, errors.New("tenant runtime process audit process limit exceeded")
		}
	}
	return result, nil
}

func (p procRuntimeProcessAuditSource) processFile(pid int, name string) ([]byte, error) {
	file, err := os.Open(filepath.Join(p.root, strconv.Itoa(pid), name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, runtimeProcessAuditMaxFileBytes+1))
	if err != nil {
		clear(content)
		return nil, err
	}
	if len(content) > runtimeProcessAuditMaxFileBytes {
		clear(content)
		return nil, fmt.Errorf("tenant runtime process audit %s file limit exceeded", name)
	}
	return content, nil
}
