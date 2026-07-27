package sdnotify

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func Notify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if strings.HasPrefix(path, "@") {
		path = "\x00" + strings.TrimPrefix(path, "@")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	_, err = connection.Write([]byte(state))
	return err
}

func Watchdog(ctx context.Context) {
	if ctx == nil || os.Getenv("NOTIFY_SOCKET") == "" {
		return
	}
	if configuredPID := strings.TrimSpace(os.Getenv("WATCHDOG_PID")); configuredPID != "" {
		pid, err := strconv.Atoi(configuredPID)
		if err != nil || pid != os.Getpid() {
			return
		}
	}
	microseconds, err := strconv.ParseUint(strings.TrimSpace(os.Getenv("WATCHDOG_USEC")), 10, 64)
	if err != nil || microseconds < uint64((2*time.Second)/time.Microsecond) || microseconds > uint64((24*time.Hour)/time.Microsecond) {
		return
	}
	interval := time.Duration(microseconds) * time.Microsecond / 3
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = Notify("WATCHDOG=1")
		}
	}
}
