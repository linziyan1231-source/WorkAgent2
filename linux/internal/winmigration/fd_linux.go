//go:build linux

package winmigration

import "golang.org/x/sys/unix"

func unixClose(fd int) error { return unix.Close(fd) }
