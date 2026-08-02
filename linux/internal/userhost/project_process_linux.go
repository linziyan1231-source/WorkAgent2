package userhost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type projectFileUser struct {
	pid       int
	startTime string
}

func (h *Host) projectFileUsers(source string, legacyRoot bool) ([]projectFileUser, error) {
	cgroup, err := processCgroup(os.Getpid())
	if err != nil || cgroup == "" {
		return nil, errors.New("cannot identify the UserHost cgroup")
	}
	excluded := map[int]bool{os.Getpid(): true}
	h.mu.RLock()
	if h.backend != nil && h.backend.Process != nil {
		excluded[h.backend.Process.Pid] = true
	}
	h.mu.RUnlock()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	users := make([]projectFileUser, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 2 || excluded[pid] {
			continue
		}
		uid, err := processEffectiveUID(pid)
		if err != nil || uid != h.uid {
			continue
		}
		candidateCgroup, err := processCgroup(pid)
		if err != nil || candidateCgroup != cgroup {
			continue
		}
		uses, err := processUsesPath(pid, source, legacyRoot)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("inspect process %d project references: %w", pid, err)
		}
		if !uses {
			continue
		}
		start, err := processStartTime(pid)
		if err != nil {
			continue
		}
		users = append(users, projectFileUser{pid: pid, startTime: start})
		if len(users) > 256 {
			return nil, errors.New("too many processes are using the project")
		}
	}
	return users, nil
}

func (h *Host) stopProjectFileUsers(ctx context.Context, source string, legacyRoot bool, users []projectFileUser) error {
	for _, user := range users {
		if processStillMatches(user) {
			if err := syscall.Kill(user.pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("stop project process %d: %w", user.pid, err)
			}
		}
	}
	if err := waitProjectProcesses(ctx, users, 2*time.Second); err != nil {
		for _, user := range users {
			if processStillMatches(user) {
				if killErr := syscall.Kill(user.pid, syscall.SIGKILL); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
					return fmt.Errorf("terminate project process %d: %w", user.pid, killErr)
				}
			}
		}
		if err := waitProjectProcesses(ctx, users, 2*time.Second); err != nil {
			return errors.New("project processes did not stop")
		}
	}
	remaining, err := h.projectFileUsers(source, legacyRoot)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("new project file users appeared while stopping the project")
	}
	return nil
}

func waitProjectProcesses(ctx context.Context, users []projectFileUser, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining := false
		for _, user := range users {
			if processStillMatches(user) {
				remaining = true
				break
			}
		}
		if !remaining {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("project processes are still running")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func processStillMatches(user projectFileUser) bool {
	start, err := processStartTime(user.pid)
	return err == nil && start == user.startTime
}

func processEffectiveUID(pid int) (uint32, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[0] == "Uid:" {
			value, err := strconv.ParseUint(fields[2], 10, 32)
			return uint32(value), err
		}
	}
	return 0, errors.New("process effective UID is unavailable")
}

func processCgroup(pid int) (string, error) {
	payload, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	var result string
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.HasPrefix(line, "0::/") || line == "0::/" {
			if result != "" {
				return "", errors.New("multiple unified cgroups")
			}
			result = line
		}
	}
	if result == "" {
		return "", errors.New("unified cgroup is unavailable")
	}
	return result, nil
}

func cgroupProcessIDs(pid int) ([]int, error) {
	cgroup, err := processCgroup(pid)
	if err != nil {
		return nil, err
	}
	relative := strings.TrimPrefix(cgroup, "0::/")
	if relative == cgroup || relative == "" || filepath.Clean(relative) != relative || filepath.IsAbs(relative) || strings.HasPrefix(relative, "..") {
		return nil, errors.New("process is not in a dedicated unified cgroup")
	}
	file, err := os.Open(filepath.Join("/sys/fs/cgroup", relative, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	pids := make([]int, 0, 4)
	seen := make(map[int]bool)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		candidate, err := strconv.Atoi(value)
		if err != nil || candidate < 2 || seen[candidate] {
			return nil, errors.New("cgroup contains an invalid process ID")
		}
		seen[candidate] = true
		pids = append(pids, candidate)
		if len(pids) > 4096 {
			return nil, errors.New("cgroup process count exceeds the configured limit")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(pids) == 0 {
		return nil, errors.New("cgroup contains no processes")
	}
	return pids, nil
}

func processStartTime(pid int) (string, error) {
	payload, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	closing := strings.LastIndexByte(string(payload), ')')
	if closing < 0 {
		return "", errors.New("process stat is invalid")
	}
	fields := strings.Fields(string(payload[closing+1:]))
	// fields starts at proc(5) field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return "", errors.New("process stat is incomplete")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}

func processUsesPath(pid int, source string, descendantsOnly bool) (bool, error) {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	for _, name := range []string{"cwd", "exe"} {
		target, err := os.Readlink(filepath.Join(root, name))
		if err == nil && projectReferenceMatches(target, source, descendantsOnly) {
			return true, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return false, err
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil {
		return false, err
	}
	if len(entries) > 8192 {
		return false, errors.New("process has too many open file descriptors")
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(root, "fd", entry.Name()))
		if err == nil && projectReferenceMatches(target, source, descendantsOnly) {
			return true, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return false, err
		}
	}
	return false, nil
}

func projectReferenceMatches(target, source string, descendantsOnly bool) bool {
	target = strings.TrimSuffix(target, " (deleted)")
	if !filepath.IsAbs(target) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(source), filepath.Clean(target))
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	return !descendantsOnly || relative != "."
}
