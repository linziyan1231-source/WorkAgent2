package admin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type runtimeProcessRead struct {
	content []byte
	err     error
}

type scriptedRuntimeProcessSource struct {
	scans     [][]int
	scanError error
	scanIndex int
	files     map[string][]runtimeProcessRead
}

func (s *scriptedRuntimeProcessSource) processIDs() ([]int, error) {
	if s.scanError != nil {
		return nil, s.scanError
	}
	if len(s.scans) == 0 {
		return nil, nil
	}
	index := s.scanIndex
	if index >= len(s.scans) {
		index = len(s.scans) - 1
	}
	s.scanIndex++
	return append([]int(nil), s.scans[index]...), nil
}

func (s *scriptedRuntimeProcessSource) processFile(pid int, name string) ([]byte, error) {
	key := fmt.Sprintf("%d/%s", pid, name)
	reads := s.files[key]
	if len(reads) == 0 {
		return nil, errors.New("unexpected process read")
	}
	read := reads[0]
	if len(reads) > 1 {
		s.files[key] = reads[1:]
	}
	return append([]byte(nil), read.content...), read.err
}

func runtimeProcessStat(pid int, startTime uint64) []byte {
	fields := make([]string, 20)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "S"
	fields[19] = strconv.FormatUint(startTime, 10)
	return []byte(fmt.Sprintf("%d (worker ) name) %s\n", pid, strings.Join(fields, " ")))
}

func runtimeProcessStatus(uids [4]uint32) []byte {
	return []byte(fmt.Sprintf("Name:\tworker\nUid:\t%d\t%d\t%d\t%d\n", uids[0], uids[1], uids[2], uids[3]))
}

func stableRuntimeProcessSource(uids [4]uint32) *scriptedRuntimeProcessSource {
	return &scriptedRuntimeProcessSource{
		scans: [][]int{{101}, {101}},
		files: map[string][]runtimeProcessRead{
			"101/stat":   {{content: runtimeProcessStat(101, 500)}},
			"101/status": {{content: runtimeProcessStatus(uids)}},
		},
	}
}

func TestRuntimeUIDProcessAuditRequiresRootAndNonRootTarget(t *testing.T) {
	empty := &scriptedRuntimeProcessSource{scans: [][]int{{}, {}}}
	if err := verifyRuntimeUIDQuiescent(2001, 1000, empty, 4, 10); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("non-root process audit result=%v", err)
	}
	if err := verifyRuntimeUIDQuiescent(0, 0, empty, 4, 10); err == nil || !strings.Contains(err.Error(), "UID 0") {
		t.Fatalf("root target process audit result=%v", err)
	}
}

func TestRuntimeUIDProcessAuditRequiresTwoCleanFullScans(t *testing.T) {
	source := stableRuntimeProcessSource([4]uint32{1000, 1000, 1000, 1000})
	if err := verifyRuntimeUIDQuiescent(2001, 0, source, 4, 10); err != nil {
		t.Fatal(err)
	}
	if source.scanIndex != 2 {
		t.Fatalf("clean scan count=%d want 2", source.scanIndex)
	}

	appeared := stableRuntimeProcessSource([4]uint32{2001, 2001, 2001, 2001})
	appeared.scans = [][]int{{}, {101}}
	if err := verifyRuntimeUIDQuiescent(2001, 0, appeared, 4, 10); err == nil || !strings.Contains(err.Error(), "residual process") {
		t.Fatalf("process appearing between full scans result=%v", err)
	}
}

func TestRuntimeUIDProcessAuditRejectsEveryKernelUIDSlot(t *testing.T) {
	for slot := 0; slot < 4; slot++ {
		t.Run(strconv.Itoa(slot), func(t *testing.T) {
			uids := [4]uint32{1000, 1000, 1000, 1000}
			uids[slot] = 2001
			if err := verifyRuntimeUIDQuiescent(2001, 0, stableRuntimeProcessSource(uids), 4, 10); err == nil || !strings.Contains(err.Error(), "residual process") {
				t.Fatalf("UID slot %d result=%v", slot, err)
			}
		})
	}
}

func TestRuntimeUIDProcessAuditRescansTransientPIDDisappearanceAndReuse(t *testing.T) {
	disappeared := &scriptedRuntimeProcessSource{
		scans: [][]int{{101}, {}, {}},
		files: map[string][]runtimeProcessRead{"101/stat": {{err: os.ErrNotExist}}},
	}
	if err := verifyRuntimeUIDQuiescent(2001, 0, disappeared, 4, 10); err != nil {
		t.Fatalf("ordinary disappearing process caused permanent failure: %v", err)
	}

	reused := &scriptedRuntimeProcessSource{
		scans: [][]int{{101}, {}, {}},
		files: map[string][]runtimeProcessRead{
			"101/stat": {
				{content: runtimeProcessStat(101, 500)},
				{content: runtimeProcessStat(101, 501)},
			},
			"101/status": {{content: runtimeProcessStatus([4]uint32{1000, 1000, 1000, 1000})}},
		},
	}
	if err := verifyRuntimeUIDQuiescent(2001, 0, reused, 4, 10); err != nil {
		t.Fatalf("PID reuse did not trigger a successful bounded full rescan: %v", err)
	}
}

func TestRuntimeUIDProcessAuditFailsClosedOnUnstableOrUnexplainedEvidence(t *testing.T) {
	unstable := &scriptedRuntimeProcessSource{
		scans: [][]int{{101}, {101}, {101}, {101}},
		files: map[string][]runtimeProcessRead{"101/stat": {{err: syscall.ENOENT}}},
	}
	if err := verifyRuntimeUIDQuiescent(2001, 0, unstable, 4, 10); err == nil || !strings.Contains(err.Error(), "stable process-table") {
		t.Fatalf("persistent process churn result=%v", err)
	}

	permission := &scriptedRuntimeProcessSource{
		scans: [][]int{{101}},
		files: map[string][]runtimeProcessRead{"101/stat": {{err: syscall.EACCES}}},
	}
	if err := verifyRuntimeUIDQuiescent(2001, 0, permission, 4, 10); err == nil || !strings.Contains(err.Error(), "cannot read process identity") {
		t.Fatalf("unreadable process evidence result=%v", err)
	}

	enumeration := &scriptedRuntimeProcessSource{scanError: syscall.EACCES}
	if err := verifyRuntimeUIDQuiescent(2001, 0, enumeration, 4, 10); err == nil || !strings.Contains(err.Error(), "cannot enumerate") {
		t.Fatalf("unreadable process table result=%v", err)
	}

	overLimit := &scriptedRuntimeProcessSource{scans: [][]int{{101, 102}}}
	if err := verifyRuntimeUIDQuiescent(2001, 0, overLimit, 4, 1); err == nil || !strings.Contains(err.Error(), "limit exceeded") {
		t.Fatalf("process limit result=%v", err)
	}
}

func TestRuntimeUIDProcessAuditRejectsMalformedEvidenceWithoutEchoingIt(t *testing.T) {
	secret := "SECRET-COMMAND-AND-ENVIRONMENT"
	malformed := &scriptedRuntimeProcessSource{
		scans: [][]int{{101}},
		files: map[string][]runtimeProcessRead{
			"101/stat":   {{content: runtimeProcessStat(101, 500)}},
			"101/status": {{content: []byte(secret)}},
		},
	}
	err := verifyRuntimeUIDQuiescent(2001, 0, malformed, 4, 10)
	if err == nil || !strings.Contains(err.Error(), "missing process credentials") {
		t.Fatalf("malformed process evidence result=%v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("process evidence leaked into the audit error")
	}
}

func TestRuntimeUIDProcessAuditLiveRejectsAnUnprivilegedResidualProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("live runtime UID process audit requires root")
	}
	var runtimeUID uint32
	for candidate := uint32(65520); candidate < 65532; candidate++ {
		if VerifyRuntimeUIDQuiescent(candidate) == nil {
			runtimeUID = candidate
			break
		}
	}
	if runtimeUID == 0 {
		t.Skip("no unused unprivileged runtime UID was available")
	}
	process := exec.Command("/usr/bin/sleep", "30")
	process.Env = []string{"PATH=/usr/bin:/bin"}
	process.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: runtimeUID, Gid: runtimeUID, NoSetGroups: true},
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if process.Process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	}()
	if err := VerifyRuntimeUIDQuiescent(runtimeUID); err == nil || !strings.Contains(err.Error(), "residual process") {
		t.Fatalf("live unprivileged residual process result=%v", err)
	}
	if err := process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err == nil {
		t.Fatal("killed runtime process unexpectedly exited successfully")
	}
	process.Process = nil
	if err := VerifyRuntimeUIDQuiescent(runtimeUID); err != nil {
		t.Fatalf("stopped runtime UID remained non-quiescent: %v", err)
	}
}
