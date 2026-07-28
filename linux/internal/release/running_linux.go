//go:build linux

package release

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// VerifyRunningExecutable proves the running process image is the installed
// control executable by exact inode identity and frozen metadata.
func VerifyRunningExecutable(controlRoot, binary string) error {
	running, err := unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open running %s executable: %w", binary, err)
	}
	defer unix.Close(running)
	current, err := unix.Open(filepath.Join(controlRoot, "bin", binary), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open current signed %s executable: %w", binary, err)
	}
	defer unix.Close(current)
	var runningStat unix.Stat_t
	var currentStat unix.Stat_t
	if err := unix.Fstat(running, &runningStat); err != nil {
		return fmt.Errorf("inspect running %s executable: %w", binary, err)
	}
	if err := unix.Fstat(current, &currentStat); err != nil {
		return fmt.Errorf("inspect current signed %s executable: %w", binary, err)
	}
	if runningStat.Dev != currentStat.Dev || runningStat.Ino != currentStat.Ino || currentStat.Mode&unix.S_IFMT != unix.S_IFREG || currentStat.Mode&0o7777 != 0o555 || currentStat.Uid != 0 || currentStat.Gid != 0 || currentStat.Nlink != 1 {
		return fmt.Errorf("running %s is not the current signed control executable", binary)
	}
	return nil
}
