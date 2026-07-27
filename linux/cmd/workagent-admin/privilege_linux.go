package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// dropToPortalRuntime permanently removes root before SQLite can create the
// Portal database, WAL/SHM sidecars, audit sink or .runtime.lock.  This keeps a
// root-invoked administrative command from leaving state that the Portal
// service cannot subsequently open.
func dropToPortalRuntime(runtimeUser string) error {
	account, err := user.Lookup(runtimeUser)
	if err != nil {
		return fmt.Errorf("lookup Portal runtime identity: %w", err)
	}
	uid64, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid64, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid64 == 0 || gid64 == 0 {
		return errors.New("Portal runtime identity is invalid")
	}
	uid, gid := int(uid64), int(gid64)
	switch os.Geteuid() {
	case 0:
		if err := syscall.Setgroups([]int{}); err != nil {
			return fmt.Errorf("clear administrator supplementary groups: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("assume Portal runtime group: %w", err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("assume Portal runtime user: %w", err)
		}
	case uid:
		// A deliberately unprivileged invocation is accepted only if it already
		// has the exact Portal primary identity and no foreign group access.
	default:
		return errors.New("Portal identity updates must run as root or the Portal runtime user")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("inspect Portal runtime groups: %w", err)
	}
	if err := validatePortalRuntimeIdentity(uid, gid, os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups); err != nil {
		return err
	}
	return nil
}

func validatePortalRuntimeIdentity(wantUID, wantGID, realUID, effectiveUID, realGID, effectiveGID int, groups []int) error {
	if wantUID <= 0 || wantGID <= 0 || realUID != wantUID || effectiveUID != wantUID || realGID != wantGID || effectiveGID != wantGID {
		return errors.New("Portal runtime privilege drop did not reach the configured identity")
	}
	for _, group := range groups {
		if group != wantGID {
			return errors.New("Portal runtime privilege drop retained a supplementary group")
		}
	}
	return nil
}
