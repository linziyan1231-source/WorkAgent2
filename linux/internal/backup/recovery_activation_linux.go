//go:build linux

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	recoveryInstallLockPath = "/run/workagent-backup/recovery-install.lock"
	// The activation journal must survive a host reboot. A /run journal would
	// disappear precisely when recovery needs to undo a power-loss-interrupted
	// systemd enable/start sequence.
	recoveryActivationJournalPath = "/var/lib/workagent-backup/recovery-activation.json"
	maxRecoveryActivationJournal  = 256 * 1024
)

type recoveryActivationJournal struct {
	SchemaVersion int      `json:"schema_version"`
	Units         []string `json:"units"`
}

func acquireRecoveryInstallLock(path string) (io.Closer, error) {
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	base := filepath.Base(path)
	if base != filepath.Base(recoveryInstallLockPath) {
		return nil, errors.New("blank-host recovery lock name is invalid")
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(parentFD, base, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parentFD, base, flags, 0)
	}
	if err != nil {
		return nil, errors.New("open blank-host recovery lock")
	}
	file := os.NewFile(uintptr(fd), path)
	if created {
		if err := unix.Fchown(fd, 0, 0); err != nil || unix.Fchmod(fd, 0o600) != nil || unix.Fsync(fd) != nil || unix.Fsync(parentFD) != nil {
			file.Close()
			_ = unix.Unlinkat(parentFD, base, 0)
			_ = unix.Fsync(parentFD)
			return nil, errors.New("initialize blank-host recovery lock")
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 {
		file.Close()
		return nil, errors.New("blank-host recovery lock is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, base, stat); err != nil {
		file.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another blank-host recovery is already running")
		}
		return nil, errors.New("acquire blank-host recovery lock")
	}
	return file, nil
}

func openRecoveryControlParent(path string) (int, error) {
	if !cleanAbsolute(path) || (path != recoveryInstallLockPath && path != recoveryActivationJournalPath) {
		return -1, errors.New("blank-host recovery control path is invalid")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, errors.New("open blank-host recovery control directory")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(stat.Mode).Perm() != 0o700 || stat.Uid != 0 || stat.Gid != 0 {
		unix.Close(fd)
		return -1, errors.New("blank-host recovery control directory is unsafe")
	}
	return fd, nil
}

func validateRecoveryActivationJournal(value recoveryActivationJournal) error {
	if value.SchemaVersion != 1 || len(value.Units) < 5 || len(value.Units) > 2005 ||
		value.Units[0] != "cliproxyapi.service" || value.Units[1] != "workagent-notification.service" ||
		value.Units[2] != "workagent-chatforward.service" ||
		value.Units[len(value.Units)-2] != "workagent-chatforward-browser.service" ||
		value.Units[len(value.Units)-1] != "workagent-portal.service" {
		return errors.New("blank-host recovery activation journal metadata is invalid")
	}
	middle := value.Units[3 : len(value.Units)-2]
	if len(middle)%2 != 0 {
		return errors.New("blank-host recovery activation journal tenant-unit set is incomplete")
	}
	tenantCount := len(middle) / 2
	seen := make(map[string]bool, len(value.Units))
	for index, unit := range value.Units {
		valid := (index == 0 && unit == "cliproxyapi.service") ||
			(index == 1 && unit == "workagent-notification.service") ||
			(index == 2 && unit == "workagent-chatforward.service") ||
			(index == len(value.Units)-2 && unit == "workagent-chatforward-browser.service") ||
			(index == len(value.Units)-1 && unit == "workagent-portal.service")
		if index >= 3 && index < 3+tenantCount {
			valid = validRecoveryTenantActivationUnit(unit, ".service")
			if index > 3 {
				valid = valid && value.Units[index-1] < unit
			}
		}
		if index >= 3+tenantCount && index < len(value.Units)-2 {
			valid = validRecoveryTenantActivationUnit(unit, ".socket")
			service := value.Units[3+index-(3+tenantCount)]
			valid = valid && strings.TrimSuffix(service, ".service") == strings.TrimSuffix(unit, ".socket")
		}
		if !valid || seen[unit] {
			return errors.New("blank-host recovery activation journal contains an invalid, duplicate, or unsorted unit")
		}
		seen[unit] = true
	}
	return nil
}

func validRecoveryTenantActivationUnit(unit, suffix string) bool {
	if !strings.HasPrefix(unit, "workagent-userhost@") || !strings.HasSuffix(unit, suffix) {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(unit, "workagent-userhost@"), suffix)
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}

func writeRecoveryActivationJournal(path string, value recoveryActivationJournal) error {
	if filepath.Base(path) != filepath.Base(recoveryActivationJournalPath) {
		return errors.New("blank-host recovery activation journal name is invalid")
	}
	if err := validateRecoveryActivationJournal(value); err != nil {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	base := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return errors.New("blank-host recovery activation journal already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return errors.New("inspect blank-host recovery activation journal")
	}
	fd, err := unix.Openat(parentFD, ".", unix.O_WRONLY|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create unnamed blank-host recovery activation journal: %w", err)
	}
	file := os.NewFile(uintptr(fd), "recovery-activation-journal")
	defer file.Close()
	if err := unix.Fchown(fd, 0, 0); err != nil || unix.Fchmod(fd, 0o600) != nil {
		return errors.New("initialize blank-host recovery activation journal")
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := unix.Linkat(fd, "", parentFD, base, unix.AT_EMPTY_PATH); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("blank-host recovery activation journal appeared concurrently")
		}
		return fmt.Errorf("publish blank-host recovery activation journal: %w", err)
	}
	return unix.Fsync(parentFD)
}

func loadRecoveryActivationJournal(path string) (recoveryActivationJournal, bool, error) {
	if filepath.Base(path) != filepath.Base(recoveryActivationJournalPath) {
		return recoveryActivationJournal{}, false, errors.New("blank-host recovery activation journal name is invalid")
	}
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return recoveryActivationJournal{}, false, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return recoveryActivationJournal{}, false, nil
	}
	if err != nil {
		return recoveryActivationJournal{}, false, errors.New("open blank-host recovery activation journal")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != 0o600 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Size <= 0 || stat.Size > maxRecoveryActivationJournal {
		return recoveryActivationJournal{}, false, errors.New("blank-host recovery activation journal is unsafe")
	}
	if err := verifyRecoveryDestinationName(parentFD, filepath.Base(path), stat); err != nil {
		return recoveryActivationJournal{}, false, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxRecoveryActivationJournal+1))
	if err != nil || len(payload) > maxRecoveryActivationJournal {
		return recoveryActivationJournal{}, false, errors.New("read blank-host recovery activation journal")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var value recoveryActivationJournal
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return recoveryActivationJournal{}, false, errors.New("blank-host recovery activation journal is invalid")
	}
	if err := validateRecoveryActivationJournal(value); err != nil {
		return recoveryActivationJournal{}, false, err
	}
	return value, true, nil
}

func removeRecoveryActivationJournal(path string) error {
	parentFD, err := openRecoveryControlParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Unlinkat(parentFD, filepath.Base(path), 0); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func rollbackRecoveryActivation(controller systemdctl.Controller, path string) error {
	value, found, err := loadRecoveryActivationJournal(path)
	if err != nil || !found {
		return err
	}
	if err := stopRecoveryActivationUnits(controller, value); err != nil {
		return err
	}
	return removeRecoveryActivationJournal(path)
}

func rollbackKnownRecoveryActivation(controller systemdctl.Controller, value recoveryActivationJournal, path string) error {
	return rollbackKnownRecoveryActivationWithIO(controller, value, path, loadRecoveryActivationJournal, removeRecoveryActivationJournal)
}

func rollbackKnownRecoveryActivationWithIO(
	controller systemdctl.Controller,
	value recoveryActivationJournal,
	path string,
	load func(string) (recoveryActivationJournal, bool, error),
	remove func(string) error,
) error {
	// Never discard the durable retry evidence when disable, stop, or the
	// stopped-state proof fails. The next recovery invocation must see the
	// journal and repeat the rollback before it is allowed to mutate anything.
	if err := stopRecoveryActivationUnits(controller, value); err != nil {
		return err
	}
	_, found, err := load(path)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("blank-host recovery activation journal disappeared during rollback")
	}
	return remove(path)
}

func stopRecoveryActivationUnits(controller systemdctl.Controller, value recoveryActivationJournal) error {
	if err := validateRecoveryActivationJournal(value); err != nil {
		return err
	}
	if controller == nil {
		return errors.New("blank-host recovery activation rollback has no systemd controller")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var failures []error
	if err := recoverySystemdActionUnits(ctx, controller, "disable", recoveryActivationEnableUnits(value)); err != nil {
		failures = append(failures, fmt.Errorf("disable partially activated recovery units: %w", err))
	}
	for index := len(value.Units) - 1; index >= 0; index-- {
		if err := controller.Action(ctx, "stop", value.Units[index]); err != nil {
			failures = append(failures, fmt.Errorf("stop partially activated unit %s: %w", value.Units[index], err))
		}
	}
	if err := requireRecoveryUnitsStopped(ctx, controller, value.Units); err != nil {
		failures = append(failures, err)
	}
	if err := requireRecoveryUnitFileState(ctx, controller, recoveryActivationEnableUnits(value), "disabled"); err != nil {
		failures = append(failures, fmt.Errorf("prove partially activated recovery units are disabled: %w", err))
	}
	staticUnits := make([]string, 0, len(value.Units))
	for _, unit := range value.Units {
		if strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service") {
			staticUnits = append(staticUnits, unit)
		}
	}
	if len(staticUnits) != 0 {
		if err := requireRecoveryUnitFileState(ctx, controller, staticUnits, "static"); err != nil {
			failures = append(failures, fmt.Errorf("prove recovery tenant services remain static: %w", err))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return nil
}

func recoverySystemdActionUnits(ctx context.Context, controller systemdctl.Controller, action string, units []string) error {
	if controller == nil || (action != "enable" && action != "disable") || len(units) == 0 {
		return errors.New("blank-host recovery bulk systemd action is invalid")
	}
	// systemdctl deliberately caps one invocation at 64 arguments. Keep the
	// action plus at most 63 units per call while the persistent journal makes
	// a partially completed multi-call enable fully rollback-safe.
	for offset := 0; offset < len(units); offset += 63 {
		end := offset + 63
		if end > len(units) {
			end = len(units)
		}
		arguments := append([]string{action}, units[offset:end]...)
		if err := controller.Action(ctx, arguments...); err != nil {
			return err
		}
	}
	return nil
}

func activationJournalForUnits(units []string) (recoveryActivationJournal, error) {
	if len(units) < 5 || units[0] != "cliproxyapi.service" || units[1] != "workagent-notification.service" ||
		units[2] != "workagent-chatforward.service" || units[len(units)-2] != "workagent-chatforward-browser.service" ||
		units[len(units)-1] != "workagent-portal.service" {
		return recoveryActivationJournal{}, errors.New("blank-host recovery activation input is invalid")
	}
	sockets := append([]string(nil), units[3:len(units)-2]...)
	sort.Strings(sockets)
	services := make([]string, len(sockets))
	for index, socket := range sockets {
		if !validRecoveryTenantActivationUnit(socket, ".socket") {
			return recoveryActivationJournal{}, errors.New("blank-host recovery activation input contains an invalid tenant socket")
		}
		services[index] = strings.TrimSuffix(socket, ".socket") + ".service"
	}
	managed := append([]string(nil), units[:3]...)
	managed = append(managed, services...)
	managed = append(managed, sockets...)
	managed = append(managed, units[len(units)-2:]...)
	value := recoveryActivationJournal{SchemaVersion: 1, Units: managed}
	return value, validateRecoveryActivationJournal(value)
}

func recoveryActivationEnableUnits(value recoveryActivationJournal) []string {
	result := make([]string, 0, len(value.Units))
	for _, unit := range value.Units {
		if strings.HasPrefix(unit, "workagent-userhost@") && strings.HasSuffix(unit, ".service") {
			continue
		}
		result = append(result, unit)
	}
	return result
}
