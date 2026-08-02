package winutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxRestartManagerFiles = 10000

var (
	restartManagerDLL   = windows.NewLazySystemDLL("rstrtmgr.dll")
	rmStartSession      = restartManagerDLL.NewProc("RmStartSession")
	rmRegisterResources = restartManagerDLL.NewProc("RmRegisterResources")
	rmGetList           = restartManagerDLL.NewProc("RmGetList")
	rmEndSession        = restartManagerDLL.NewProc("RmEndSession")
)

type rmUniqueProcess struct {
	ProcessID        uint32
	ProcessStartTime windows.Filetime
}

type rmProcessInfo struct {
	Process          rmUniqueProcess
	AppName          [256]uint16
	ServiceShortName [64]uint16
	ApplicationType  uint32
	AppStatus        uint32
	SessionID        uint32
	Restartable      int32
}

func TerminateFileUsers(root, expectedSID string, excluded map[uint32]bool) ([]uint32, error) {
	files, err := restartManagerFiles(root)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("project contains no files that Windows Restart Manager can inspect")
	}
	processes, err := lockingProcesses(files)
	if err != nil {
		return nil, err
	}
	if len(processes) == 0 {
		return nil, errors.New("Windows did not identify the process holding the project")
	}
	terminated := make([]uint32, 0, len(processes))
	for _, process := range processes {
		if process.ProcessID == 0 || excluded[process.ProcessID] {
			return terminated, fmt.Errorf("protected AionUi process %d is using the project", process.ProcessID)
		}
		if err := terminateOwnedProcess(process, expectedSID); err != nil {
			return terminated, err
		}
		terminated = append(terminated, process.ProcessID)
	}
	return terminated, nil
}

func restartManagerFiles(root string) ([]string, error) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return nil, errors.New("project path must be absolute")
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root {
			reparse, err := isReparsePoint(path)
			if err != nil {
				return err
			}
			if reparse {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		files = append(files, path)
		if len(files) > maxRestartManagerFiles {
			return fmt.Errorf("project exceeds the %d-file force-stop inspection limit", maxRestartManagerFiles)
		}
		return nil
	})
	return files, err
}

func lockingProcesses(files []string) ([]rmUniqueProcess, error) {
	var handle uint32
	key := make([]uint16, 33)
	if code, _, _ := rmStartSession.Call(uintptr(unsafe.Pointer(&handle)), 0, uintptr(unsafe.Pointer(&key[0]))); code != 0 {
		return nil, syscall.Errno(code)
	}
	defer rmEndSession.Call(uintptr(handle))
	pointers := make([]*uint16, len(files))
	for index, path := range files {
		pointer, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		pointers[index] = pointer
	}
	if code, _, _ := rmRegisterResources.Call(uintptr(handle), uintptr(len(pointers)), uintptr(unsafe.Pointer(&pointers[0])), 0, 0, 0, 0); code != 0 {
		return nil, syscall.Errno(code)
	}
	var needed, count, rebootReasons uint32
	code, _, _ := rmGetList.Call(uintptr(handle), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)), 0, uintptr(unsafe.Pointer(&rebootReasons)))
	if code == 0 && needed == 0 {
		return nil, nil
	}
	if code != uintptr(windows.ERROR_MORE_DATA) {
		return nil, syscall.Errno(code)
	}
	items := make([]rmProcessInfo, needed)
	count = needed
	code, _, _ = rmGetList.Call(uintptr(handle), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&items[0])), uintptr(unsafe.Pointer(&rebootReasons)))
	if code != 0 {
		return nil, syscall.Errno(code)
	}
	result := make([]rmUniqueProcess, 0, count)
	seen := make(map[uint32]bool)
	for _, item := range items[:count] {
		if !seen[item.Process.ProcessID] {
			seen[item.Process.ProcessID] = true
			result = append(result, item.Process)
		}
	}
	return result, nil
}

func terminateOwnedProcess(process rmUniqueProcess, expectedSID string) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, process.ProcessID)
	if err != nil {
		return fmt.Errorf("open process %d using project: %w", process.ProcessID, err)
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return fmt.Errorf("verify process %d start time: %w", process.ProcessID, err)
	}
	if creation != process.ProcessStartTime {
		return fmt.Errorf("process %d changed before force stop", process.ProcessID)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("inspect process %d owner: %w", process.ProcessID, err)
	}
	defer token.Close()
	owner, err := token.GetTokenUser()
	if err != nil || owner.User.Sid == nil || !strings.EqualFold(owner.User.Sid.String(), expectedSID) {
		return fmt.Errorf("process %d is not owned by the current Portal user", process.ProcessID)
	}
	if err := windows.TerminateProcess(handle, 3); err != nil {
		return fmt.Errorf("terminate process %d using project: %w", process.ProcessID, err)
	}
	if status, err := windows.WaitForSingleObject(handle, 5000); err != nil || status != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process %d did not exit after force stop", process.ProcessID)
	}
	return nil
}
