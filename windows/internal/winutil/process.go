package winutil

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func SignalProcessGroup(pid uint32) error {
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid); err != nil {
		return fmt.Errorf("send CTRL_BREAK to process group %d: %w", pid, err)
	}
	return nil
}
