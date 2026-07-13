package winutil

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobObjectCPUEnable  = 0x1
	jobObjectCPUHardCap = 0x4
)

type JobLimits struct {
	MemoryBytes     uint64
	CPUPercent      uint32
	ActiveProcesses uint32
}

type Job struct {
	handle windows.Handle
	once   sync.Once
}

type ProcessInfo struct {
	PID       uint32
	ImagePath string
	ImageName string
}

type JobStats struct {
	ProcessCount   uint32
	MemoryBytes    uint64
	CPUTime100ns   uint64
	TotalProcesses uint32
}

type jobCPUInfo struct {
	ControlFlags uint32
	CPURate      uint32
}

type jobBasicAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob       = kernel32.NewProc("IsProcessInJob")
	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

func NewJob(name string, limits JobLimits) (*Job, error) {
	if limits.MemoryBytes < 256*1024*1024 || limits.CPUPercent < 1 || limits.CPUPercent > 100 || limits.ActiveProcesses < 3 {
		return nil, errors.New("invalid Job Object limits")
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateJobObject(nil, namePtr)
	if err != nil {
		return nil, fmt.Errorf("create Job Object: %w", err)
	}
	job := &Job{handle: handle}
	runtime.SetFinalizer(job, func(j *Job) { j.Close() })
	var extended windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	extended.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
		windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	extended.BasicLimitInformation.ActiveProcessLimit = limits.ActiveProcesses
	extended.JobMemoryLimit = uintptr(limits.MemoryBytes)
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&extended)), uint32(unsafe.Sizeof(extended))); err != nil {
		job.Close()
		return nil, fmt.Errorf("set Job Object memory/process limits: %w", err)
	}
	cpu := jobCPUInfo{ControlFlags: jobObjectCPUEnable | jobObjectCPUHardCap, CPURate: limits.CPUPercent * 100}
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
		job.Close()
		return nil, fmt.Errorf("set Job Object CPU limit: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
		windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS}
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		job.Close()
		return nil, fmt.Errorf("set Job Object UI restrictions: %w", err)
	}
	return job, nil
}

func (j *Job) AssignCurrentProcess() error {
	if err := windows.AssignProcessToJobObject(j.handle, windows.CurrentProcess()); err != nil {
		return fmt.Errorf("assign UserHost to Job Object: %w", err)
	}
	inside, err := processInJob(windows.CurrentProcess(), j.handle)
	if err != nil {
		return err
	}
	if !inside {
		return errors.New("UserHost was not placed in its Job Object")
	}
	return nil
}

func (j *Job) AssignPID(pid uint32) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open PID %d for Job Object assignment: %w", pid, err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(j.handle, process); err != nil {
		return fmt.Errorf("assign PID %d to Job Object: %w", pid, err)
	}
	inside, err := processInJob(process, j.handle)
	if err != nil {
		return err
	}
	if !inside {
		return fmt.Errorf("PID %d was not placed in the Job Object", pid)
	}
	return nil
}

func (j *Job) ContainsPID(pid uint32) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	return processInJob(h, j.handle)
}

func processInJob(process, job windows.Handle) (bool, error) {
	var result int32
	r1, _, e := procIsProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&result)))
	if r1 == 0 {
		return false, fmt.Errorf("IsProcessInJob: %w", e)
	}
	return result != 0, nil
}

func (j *Job) Processes() ([]ProcessInfo, error) {
	for capacity := 16; capacity <= 4096; capacity *= 2 {
		headerSize := unsafe.Sizeof(uint32(0)) * 2
		buf := make([]byte, int(headerSize)+capacity*int(unsafe.Sizeof(uintptr(0))))
		err := windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buf[0])), uint32(len(buf)), nil)
		assigned := *(*uint32)(unsafe.Pointer(&buf[0]))
		listed := *(*uint32)(unsafe.Pointer(&buf[4]))
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("query Job Object process list: %w", err)
		}
		if int(assigned) > capacity || int(listed) > capacity {
			continue
		}
		processes := make([]ProcessInfo, 0, listed)
		base := uintptr(unsafe.Pointer(&buf[0])) + headerSize
		for i := uint32(0); i < listed; i++ {
			pid := uint32(*(*uintptr)(unsafe.Pointer(base + uintptr(i)*unsafe.Sizeof(uintptr(0)))))
			path := processPath(pid)
			processes = append(processes, ProcessInfo{PID: pid, ImagePath: path, ImageName: filepath.Base(path)})
		}
		sort.Slice(processes, func(a, b int) bool { return processes[a].PID < processes[b].PID })
		return processes, nil
	}
	return nil, errors.New("Job Object process list exceeded safety limit")
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func (j *Job) Stats() (JobStats, error) {
	var accounting jobBasicAccounting
	if err := windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
		return JobStats{}, fmt.Errorf("query Job Object accounting: %w", err)
	}
	processes, err := j.Processes()
	if err != nil {
		return JobStats{}, err
	}
	var memory uint64
	for _, process := range processes {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, process.PID)
		if err != nil {
			continue
		}
		var counters processMemoryCounters
		counters.CB = uint32(unsafe.Sizeof(counters))
		r1, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&counters)), uintptr(counters.CB))
		windows.CloseHandle(h)
		if r1 != 0 {
			memory += uint64(counters.WorkingSetSize)
		}
	}
	return JobStats{ProcessCount: accounting.ActiveProcesses, MemoryBytes: memory,
		CPUTime100ns: uint64(accounting.TotalUserTime + accounting.TotalKernelTime), TotalProcesses: accounting.TotalProcesses}, nil
}

func CPUPercent(previous, current JobStats, elapsed time.Duration) float64 {
	if elapsed <= 0 || current.CPUTime100ns < previous.CPUTime100ns {
		return 0
	}
	cpuDuration := time.Duration(current.CPUTime100ns-previous.CPUTime100ns) * 100
	percent := float64(cpuDuration) / float64(elapsed) * 100
	if percent < 0 {
		return 0
	}
	return percent
}

func (j *Job) Terminate(exitCode uint32) error {
	if err := windows.TerminateJobObject(j.handle, exitCode); err != nil {
		return fmt.Errorf("terminate Job Object: %w", err)
	}
	return nil
}

func (j *Job) Close() error {
	var err error
	j.once.Do(func() {
		runtime.SetFinalizer(j, nil)
		err = windows.CloseHandle(j.handle)
	})
	return err
}
