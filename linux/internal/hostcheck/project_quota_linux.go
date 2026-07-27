package hostcheck

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fsIOCFSGetXAttr    = 0x801c581f
	fsIOCFSSetXAttr    = 0x401c5820
	fsXFlagProjInherit = 0x00000200
	xqmProjectQuota    = 2
	xqmGetQuota        = (('X' << 8) + 3)
	xqmSetQuotaLimit   = (('X' << 8) + 4)
	fsProjectQuotaFlag = 1 << 1
	fsDQBlockHard      = 1 << 3
)

type fsXAttr struct {
	XFlags     uint32
	ExtSize    uint32
	Nextents   uint32
	ProjectID  uint32
	CowExtSize uint32
	Pad        [8]byte
}

func AssignTenantQuota(path string, expectedProjectID uint32, expectedHardLimit uint64) (ProjectQuotaStatus, error) {
	if os.Geteuid() != 0 {
		return ProjectQuotaStatus{}, errors.New("assigning an XFS project quota requires root")
	}
	if expectedProjectID < 1000 || expectedHardLimit < 1024*1024*1024 || expectedHardLimit%512 != 0 {
		return ProjectQuotaStatus{}, errors.New("expected project quota is invalid")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	if len(entries) != 0 {
		return ProjectQuotaStatus{}, errors.New("project quota must be assigned before the tenant root receives data")
	}
	payload, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	mounts, err := parseMountInfo(string(payload))
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	selected, ok := mountForPath(mounts, path)
	if !ok || selected.filesystem != "xfs" {
		return ProjectQuotaStatus{}, errors.New("tenant root is not on XFS")
	}
	_, quotaEnabled := selected.options["prjquota"]
	if !quotaEnabled {
		_, quotaEnabled = selected.options["pquota"]
	}
	if !quotaEnabled {
		return ProjectQuotaStatus{}, errors.New("XFS project quota accounting is not enabled")
	}
	file, err := os.Open(path)
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	defer file.Close()
	var original fsXAttr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), fsIOCFSGetXAttr, uintptr(unsafe.Pointer(&original)))
	if errno != 0 {
		return ProjectQuotaStatus{}, fmt.Errorf("read XFS project attribute: %w", errno)
	}
	if original.ProjectID != 0 && original.ProjectID != expectedProjectID {
		return ProjectQuotaStatus{}, errors.New("tenant root already belongs to another XFS project")
	}
	desired := original
	desired.ProjectID = expectedProjectID
	desired.XFlags |= fsXFlagProjInherit
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, file.Fd(), fsIOCFSSetXAttr, uintptr(unsafe.Pointer(&desired)))
	if errno != 0 {
		return ProjectQuotaStatus{}, fmt.Errorf("assign XFS project attribute: %w", errno)
	}
	revert := func() {
		_, _, _ = unix.Syscall(unix.SYS_IOCTL, file.Fd(), fsIOCFSSetXAttr, uintptr(unsafe.Pointer(&original)))
	}
	special, err := unix.BytePtrFromString(selected.point)
	if err != nil {
		revert()
		return ProjectQuotaStatus{}, err
	}
	quota := xfsDiskQuota{Version: 1, Flags: fsProjectQuotaFlag, FieldMask: fsDQBlockHard, ID: expectedProjectID, BlockHard: expectedHardLimit / 512}
	command := uintptr((xqmSetQuotaLimit << 8) | xqmProjectQuota)
	_, _, errno = unix.Syscall6(unix.SYS_QUOTACTL, command, uintptr(unsafe.Pointer(special)), uintptr(expectedProjectID), uintptr(unsafe.Pointer(&quota)), 0, 0)
	if errno != 0 {
		revert()
		return ProjectQuotaStatus{}, fmt.Errorf("set XFS project quota: %w", errno)
	}
	status, err := VerifyProjectQuota(path, selected.point, expectedProjectID, expectedHardLimit)
	if err != nil {
		return ProjectQuotaStatus{}, fmt.Errorf("verify assigned XFS project quota: %w", err)
	}
	return status, nil
}

type xfsDiskQuota struct {
	Version       int8
	Flags         int8
	FieldMask     uint16
	ID            uint32
	BlockHard     uint64
	BlockSoft     uint64
	InodeHard     uint64
	InodeSoft     uint64
	BlockCount    uint64
	InodeCount    uint64
	InodeTimer    int32
	BlockTimer    int32
	InodeWarnings uint16
	BlockWarnings uint16
	InodeTimerHi  int8
	BlockTimerHi  int8
	RTTimerHi     int8
	Padding2      int8
	RTBlockHard   uint64
	RTBlockSoft   uint64
	RTBlockCount  uint64
	RTBlockTimer  int32
	RTWarnings    uint16
	Padding3      int16
	Padding4      [8]byte
}

type ProjectQuotaStatus struct {
	ProjectID      uint32 `json:"project_id"`
	HardLimitBytes uint64 `json:"hard_limit_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	Inherit        bool   `json:"inherit"`
}

func VerifyProjectQuota(path, mountPoint string, expectedProjectID uint32, expectedHardLimit uint64) (ProjectQuotaStatus, error) {
	if expectedProjectID < 1000 || expectedHardLimit < 1024*1024*1024 || expectedHardLimit%512 != 0 {
		return ProjectQuotaStatus{}, errors.New("expected project quota is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	defer file.Close()
	var attr fsXAttr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), fsIOCFSGetXAttr, uintptr(unsafe.Pointer(&attr)))
	if errno != 0 {
		return ProjectQuotaStatus{}, fmt.Errorf("read XFS project attribute: %w", errno)
	}
	if attr.ProjectID != expectedProjectID || attr.XFlags&fsXFlagProjInherit == 0 {
		return ProjectQuotaStatus{}, errors.New("tenant root project ID or inheritance flag does not match configuration")
	}
	special, err := unix.BytePtrFromString(mountPoint)
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	var quota xfsDiskQuota
	command := uintptr((xqmGetQuota << 8) | xqmProjectQuota)
	_, _, errno = unix.Syscall6(unix.SYS_QUOTACTL, command, uintptr(unsafe.Pointer(special)), uintptr(expectedProjectID), uintptr(unsafe.Pointer(&quota)), 0, 0)
	if errno != 0 {
		return ProjectQuotaStatus{}, fmt.Errorf("read XFS project quota: %w", errno)
	}
	if quota.Version != 1 || quota.ID != expectedProjectID || quota.BlockHard > ^uint64(0)/512 || quota.BlockCount > ^uint64(0)/512 {
		return ProjectQuotaStatus{}, errors.New("XFS project quota response is invalid")
	}
	status := ProjectQuotaStatus{ProjectID: quota.ID, HardLimitBytes: quota.BlockHard * 512, UsedBytes: quota.BlockCount * 512, Inherit: true}
	if status.HardLimitBytes != expectedHardLimit || status.HardLimitBytes == 0 || status.UsedBytes > status.HardLimitBytes {
		return ProjectQuotaStatus{}, errors.New("XFS project hard limit does not match configuration")
	}
	return status, nil
}

func VerifyTenantQuota(path string, expectedProjectID uint32, expectedHardLimit uint64) (ProjectQuotaStatus, error) {
	payload, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	mounts, err := parseMountInfo(string(payload))
	if err != nil {
		return ProjectQuotaStatus{}, err
	}
	selected, ok := mountForPath(mounts, path)
	if !ok || selected.filesystem != "xfs" {
		return ProjectQuotaStatus{}, errors.New("tenant root is not on XFS")
	}
	_, projectQuota := selected.options["prjquota"]
	if !projectQuota {
		_, projectQuota = selected.options["pquota"]
	}
	if !projectQuota {
		return ProjectQuotaStatus{}, errors.New("XFS project quota accounting is not enabled")
	}
	return VerifyProjectQuota(path, selected.point, expectedProjectID, expectedHardLimit)
}
