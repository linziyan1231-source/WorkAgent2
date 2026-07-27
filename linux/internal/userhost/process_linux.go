package userhost

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func checkAionCoreHealth(ctx context.Context, port uint16, expectedVersions []string, runtimeToken []byte) error {
	if port == 0 || len(expectedVersions) == 0 {
		return errors.New("AionCore health contract is incomplete")
	}
	requestContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(int(port))+"/health", nil)
	if err != nil {
		return err
	}
	setWorkAgentRuntimeHeader(request, runtimeToken)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("AionCore health endpoint is unreachable")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(payload) > 64*1024 {
		return errors.New("AionCore health response exceeded its limit")
	}
	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if response.StatusCode != http.StatusOK || decoder.Decode(&health) != nil || decoder.Decode(&struct{}{}) != io.EOF || health.Status != "ok" {
		return fmt.Errorf("AionCore health response is invalid (HTTP %d)", response.StatusCode)
	}
	for _, expected := range expectedVersions {
		if health.Version == expected {
			return nil
		}
	}
	return fmt.Errorf("AionCore health version %q does not match the signed release", health.Version)
}

func verifyAionCoreProcess(rootPID int, expectedExecutable string) (int, uint16, error) {
	if expectedExecutable == "" {
		return 0, 0, errors.New("AionCore executable is not configured")
	}
	expected, err := os.Stat(expectedExecutable)
	if err != nil {
		return 0, 0, fmt.Errorf("inspect AionCore executable: %w", err)
	}
	pids, err := processTree(rootPID)
	if err != nil {
		return 0, 0, err
	}
	corePID := 0
	for _, pid := range pids {
		if pid == rootPID {
			continue
		}
		actual, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
		if err != nil || !os.SameFile(expected, actual) {
			continue
		}
		if corePID != 0 {
			return 0, 0, errors.New("multiple verified AionCore processes are running")
		}
		corePID = pid
	}
	if corePID == 0 {
		return 0, 0, errors.New("verified AionCore child process was not found")
	}
	inodes, err := processSocketInodes(corePID)
	if err != nil {
		return 0, 0, err
	}
	port := uint16(0)
	listeners := 0
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(table)
		if err != nil {
			return 0, 0, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" || !inodes[fields[9]] {
				continue
			}
			address := strings.Split(fields[1], ":")
			if len(address) != 2 || !procAddressIsLoopback(address[0]) {
				file.Close()
				return 0, 0, errors.New("AionCore has a non-loopback TCP listener")
			}
			value, err := strconv.ParseUint(address[1], 16, 16)
			if err != nil || value == 0 {
				file.Close()
				return 0, 0, errors.New("AionCore listener port is invalid")
			}
			listeners++
			port = uint16(value)
		}
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return 0, 0, scanErr
		}
	}
	if listeners != 1 {
		return 0, 0, fmt.Errorf("AionCore must own exactly one loopback TCP listener, found %d", listeners)
	}
	return corePID, port, nil
}

func processSocketInodes(pid int) (map[string]bool, error) {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			result[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	return result, nil
}

func procAddressIsLoopback(value string) bool {
	raw, err := hex.DecodeString(value)
	if err != nil || (len(raw) != net.IPv4len && len(raw) != net.IPv6len) {
		return false
	}
	for offset := 0; offset < len(raw); offset += 4 {
		raw[offset], raw[offset+3] = raw[offset+3], raw[offset]
		raw[offset+1], raw[offset+2] = raw[offset+2], raw[offset+1]
	}
	return net.IP(raw).IsLoopback()
}

func verifyBackendProcess(address string, rootPID int, expectedExecutable string) error {
	if err := verifyBackendExecutable(rootPID, expectedExecutable); err != nil {
		return err
	}
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("backend address is invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("backend port is invalid")
	}
	inodes, err := listeningSocketInodes(uint16(port))
	if err != nil || len(inodes) == 0 {
		return errors.New("backend has no verified listening socket")
	}
	pids, err := processTree(rootPID)
	if err != nil {
		return err
	}
	for _, pid := range pids {
		entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			if inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] {
				return nil
			}
		}
	}
	return errors.New("backend listener is not owned by the supervised process tree")
}

func verifyBackendExecutable(pid int, expectedExecutable string) error {
	if pid < 2 {
		return errors.New("backend PID is invalid")
	}
	expected, err := os.Stat(expectedExecutable)
	if err != nil {
		return fmt.Errorf("inspect backend executable: %w", err)
	}
	actual, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil || !os.SameFile(expected, actual) {
		return errors.New("backend process executable does not match the verified release")
	}
	return nil
}

func listeningSocketInodes(port uint16) (map[string]bool, error) {
	result := make(map[string]bool)
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(table)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			value, err := strconv.ParseUint(parts[1], 16, 16)
			if err == nil && uint16(value) == port {
				result[fields[9]] = true
			}
		}
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return nil, scanErr
		}
	}
	return result, nil
}

func processTree(root int) ([]int, error) {
	result := []int{root}
	seen := map[int]bool{root: true}
	for index := 0; index < len(result); index++ {
		if len(result) > 1024 {
			return nil, errors.New("backend process tree is unexpectedly large")
		}
		pid := result[index]
		payload, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid), "children"))
		if err != nil {
			if pid == root {
				return nil, errors.New("cannot inspect backend process tree")
			}
			continue
		}
		for _, field := range strings.Fields(string(payload)) {
			child, err := strconv.Atoi(field)
			if err == nil && child > 1 && !seen[child] {
				seen[child] = true
				result = append(result, child)
			}
		}
	}
	return result, nil
}
