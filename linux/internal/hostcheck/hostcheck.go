package hostcheck

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

type Report struct {
	Ready            bool     `json:"ready"`
	CgroupV2         bool     `json:"cgroup_v2"`
	Systemd          bool     `json:"systemd"`
	PtraceScope      int      `json:"ptrace_scope"`
	Filesystem       string   `json:"tenant_data_filesystem"`
	MountPoint       string   `json:"tenant_data_mount_point"`
	ProjectQuota     bool     `json:"project_quota"`
	BlockingFindings []string `json:"blocking_findings"`
}

type mount struct {
	point      string
	source     string
	filesystem string
	options    map[string]struct{}
}

func Inspect(portal config.Portal) (Report, error) {
	payload, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return Report{}, err
	}
	mounts, err := parseMountInfo(string(payload))
	if err != nil {
		return Report{}, err
	}
	selected, ok := mountForPath(mounts, portal.Paths.TenantData)
	if !ok {
		return Report{}, errors.New("cannot identify the tenant-data filesystem")
	}
	_, cgroupErr := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	_, systemdErr := os.Stat("/run/systemd/system")
	ptracePayload, ptraceReadErr := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	ptraceScope, ptraceParseErr := parsePtraceScope(string(ptracePayload))
	if ptraceReadErr != nil || ptraceParseErr != nil {
		ptraceScope = -1
	}
	_, projectQuota := selected.options["prjquota"]
	if !projectQuota {
		_, projectQuota = selected.options["pquota"]
	}
	report := Report{CgroupV2: cgroupErr == nil, Systemd: systemdErr == nil, PtraceScope: ptraceScope, Filesystem: selected.filesystem, MountPoint: selected.point, ProjectQuota: projectQuota}
	if !report.CgroupV2 {
		report.BlockingFindings = append(report.BlockingFindings, "cgroup v2 is unavailable")
	}
	if !report.Systemd {
		report.BlockingFindings = append(report.BlockingFindings, "systemd is unavailable")
	}
	if report.PtraceScope < 2 {
		report.BlockingFindings = append(report.BlockingFindings, "kernel.yama.ptrace_scope must be at least 2")
	}
	if selected.filesystem != "xfs" {
		report.BlockingFindings = append(report.BlockingFindings, "tenant data is not on XFS")
	}
	if portal.Runtime.RequireProjectQuota && !projectQuota {
		report.BlockingFindings = append(report.BlockingFindings, "XFS project quota is required but not enabled")
	}
	report.Ready = len(report.BlockingFindings) == 0
	return report, nil
}

func parsePtraceScope(payload string) (int, error) {
	value := strings.TrimSpace(payload)
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return 0, errors.New("invalid ptrace scope")
	}
	scope, err := strconv.Atoi(value)
	if err != nil || scope < 0 || scope > 3 {
		return 0, errors.New("invalid ptrace scope")
	}
	return scope, nil
}

func parseMountInfo(payload string) ([]mount, error) {
	var result []mount
	scanner := bufio.NewScanner(strings.NewReader(payload))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, value := range fields {
			if value == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			return nil, errors.New("invalid mountinfo record")
		}
		point := unescapeMount(fields[4])
		options := make(map[string]struct{})
		for _, group := range []string{fields[5], fields[separator+3]} {
			for _, value := range strings.Split(group, ",") {
				options[value] = struct{}{}
			}
		}
		result = append(result, mount{point: point, source: unescapeMount(fields[separator+2]), filesystem: fields[separator+1], options: options})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func mountForPath(mounts []mount, target string) (mount, bool) {
	target = filepath.Clean(target)
	var selected mount
	matched := false
	for _, candidate := range mounts {
		relative, err := filepath.Rel(candidate.point, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if !matched || len(candidate.point) > len(selected.point) {
			selected, matched = candidate, true
		}
	}
	return selected, matched
}

func unescapeMount(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}

func (r Report) Error() error {
	if r.Ready {
		return nil
	}
	return fmt.Errorf("host readiness blocked: %s", strings.Join(r.BlockingFindings, "; "))
}
