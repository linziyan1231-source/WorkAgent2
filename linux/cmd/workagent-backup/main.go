package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

const (
	quiesceJournalPath     = "/run/workagent-backup/quiesce.json"
	maxQuiesceJournalBytes = 256 * 1024
)

type quiesceJournal struct {
	SchemaVersion int      `json:"schema_version"`
	Units         []string `json:"units"`
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: workagent-backup <keygen|create|verify|restore|resume> [options]")
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "create":
		err = create(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "restore":
		err = restore(os.Args[2:])
	case "resume":
		err = resume(os.Args[2:])
	default:
		err = errors.New("unknown backup command")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func flagsFor(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func keygen(arguments []string) error {
	flags := flagsFor("keygen")
	path := flags.String("key-file", "", "absolute backup encryption-key path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := backup.GenerateKey(*path); err != nil {
		return err
	}
	return output(map[string]any{"created": true, "key_file": *path})
}

func create(arguments []string) (returnErr error) {
	flags := flagsFor("create")
	portalPath := flags.String("portal-config", "/etc/workagent/portal.json", "Portal configuration path")
	backupPath := flags.String("config", "/etc/workagent/backup.json", "backup configuration path")
	quiesceSystemd := flags.Bool("quiesce-systemd", false, "stop and restore active WorkAgent services around the snapshot")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	configuration, key, err := load(*backupPath)
	if err != nil {
		return err
	}
	defer clear(key)
	if err := backup.VerifyEnvironment(configuration, true); err != nil {
		return fmt.Errorf("backup environment verification failed: %w", err)
	}
	var resume func() error
	if *quiesceSystemd {
		if err := resumeQuiescedServices(); err != nil {
			return fmt.Errorf("recover interrupted backup quiescence: %w", err)
		}
		resume, err = quiesce(*portalPath)
		if err != nil {
			return err
		}
		defer func() {
			if resume != nil {
				if err := resume(); err != nil {
					returnErr = errors.Join(returnErr, fmt.Errorf("resume services after backup attempt: %w", err))
				}
			}
		}()
	}
	snapshot, err := backup.DiscoverSnapshot(*portalPath, configuration)
	if err != nil {
		return err
	}
	snapshotOpen := true
	defer func() {
		if snapshotOpen {
			_ = snapshot.Close()
		}
	}()
	created, err := backup.Create(snapshot, configuration, key, time.Now().UTC())
	if err != nil {
		return err
	}
	// Release every Portal, tenant, and CLIProxy lifetime lock before asking
	// systemd to restart the services that acquire those locks at startup.
	if err := snapshot.Close(); err != nil {
		return fmt.Errorf("backup succeeded but snapshot locks could not be released: %w", err)
	}
	snapshotOpen = false
	if resume != nil {
		if err := resume(); err != nil {
			return fmt.Errorf("backup succeeded but service restart failed: %w", err)
		}
		resume = nil
	}
	return output(map[string]any{"created": true, "backup_id": created.Manifest.BackupID, "local_archive": created.LocalArchive, "off_host_archive": created.OffHostArchive, "receipt": created.LocalReceipt})
}

func resume(arguments []string) error {
	flags := flagsFor("resume")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("resume does not accept arguments")
	}
	return resumeQuiescedServices()
}

func verify(arguments []string) error {
	flags := flagsFor("verify")
	backupPath := flags.String("config", "/etc/workagent/backup.json", "backup configuration path")
	archive := flags.String("archive", "", "encrypted backup archive")
	receipt := flags.String("receipt", "", "backup receipt")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	_, key, err := load(*backupPath)
	if err != nil {
		return err
	}
	defer clear(key)
	manifest, err := backup.VerifyFiles(*archive, *receipt, key, true)
	if err != nil {
		return err
	}
	return output(map[string]any{"verified": true, "backup_id": manifest.BackupID, "created_at": manifest.CreatedAt, "entries": len(manifest.Entries)})
}

func restore(arguments []string) error {
	flags := flagsFor("restore")
	backupPath := flags.String("config", "/etc/workagent/backup.json", "backup configuration path")
	archive := flags.String("archive", "", "encrypted backup archive")
	receipt := flags.String("receipt", "", "backup receipt")
	target := flags.String("target", "", "new blank-host staging root")
	install := flags.Bool("install", false, "install the verified tree onto a blank package-prepared host")
	confirmation := flags.String("confirm", "", "required blank-host installation confirmation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	_, key, err := load(*backupPath)
	if err != nil {
		return err
	}
	defer clear(key)
	var manifest backup.Manifest
	if info, statErr := os.Lstat(*target); *install && statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("existing install-resume target is unsafe")
		}
		manifest, err = backup.VerifyFiles(*archive, *receipt, key, true)
		if err == nil {
			err = backup.VerifyRestoredFiles(*target, manifest, true)
		}
	} else {
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		manifest, err = backup.RestoreFiles(*archive, *receipt, key, *target, true)
	}
	if err != nil {
		return err
	}
	if err := backup.ValidateRestoredTree(*target, manifest); err != nil {
		return fmt.Errorf("restored tree failed application validation: %w", err)
	}
	var installed any
	if *install {
		result, err := backup.InstallRestoredTree(context.Background(), *target, manifest, backup.InstallOptions{Confirmation: *confirmation})
		if err != nil {
			return fmt.Errorf("blank-host installation failed: %w", err)
		}
		installed = result
	} else if *confirmation != "" {
		return errors.New("--confirm is only valid with --install")
	}
	return output(map[string]any{"restored": true, "backup_id": manifest.BackupID, "target": *target, "entries": len(manifest.Entries), "installed": installed})
}

func load(path string) (backup.Config, []byte, error) {
	configuration, err := backup.LoadConfig(path)
	if err != nil {
		return backup.Config{}, nil, err
	}
	key, err := backup.LoadKey(configuration.EncryptionKey, true)
	if err != nil {
		return backup.Config{}, nil, err
	}
	return configuration, key, nil
}

func output(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }

func quiesce(portalConfigPath string) (func() error, error) {
	portal, err := config.LoadPortal(portalConfigPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return nil, err
	}
	var tenantIDs []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		tenant, err := config.LoadTenant(filepath.Join(portal.Paths.TenantConfigs, entry.Name()))
		if err != nil || entry.Name() != tenant.TenantID+".json" {
			return nil, errors.New("cannot safely enumerate tenant services for backup")
		}
		tenantIDs = append(tenantIDs, tenant.TenantID)
	}
	if len(tenantIDs) == 0 {
		return nil, errors.New("no tenant service is configured")
	}
	sort.Strings(tenantIDs)
	units := []string{"workagent-portal.service"}
	// Stop activation sockets before their services. The reverse resume order
	// starts CLIProxy, then services (which require their sockets), then the
	// explicitly restored sockets and finally Portal.
	for _, tenantID := range tenantIDs {
		units = append(units, "workagent-userhost@"+tenantID+".socket")
	}
	for _, tenantID := range tenantIDs {
		units = append(units, "workagent-userhost@"+tenantID+".service")
	}
	// Stop CLIProxy last so Portal and UserHost can no longer mutate policy
	// state; resume walks this list backwards and therefore brings CLIProxy
	// back before its dependants.
	units = append(units, "cliproxyapi.service")
	var active []string
	for _, unit := range units {
		isActive, err := quiesceUnitActive(unit)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", unit, err)
		}
		if isActive {
			active = append(active, unit)
		}
	}
	if len(active) == 0 {
		return func() error { return nil }, nil
	}
	if err := writeQuiesceJournal(quiesceJournal{SchemaVersion: 1, Units: active}); err != nil {
		return nil, fmt.Errorf("record backup quiescence recovery: %w", err)
	}
	for _, unit := range active {
		if _, err := systemctl("stop", unit); err != nil {
			restoreErr := resumeQuiescedServices()
			return nil, fmt.Errorf("stop %s for backup: %w", unit, errors.Join(err, restoreErr))
		}
		stillActive, err := quiesceUnitActive(unit)
		if err != nil || stillActive {
			proofErr := err
			if proofErr == nil {
				proofErr = errors.New("unit remained active after systemctl stop")
			}
			restoreErr := resumeQuiescedServices()
			return nil, fmt.Errorf("prove %s stopped for backup: %w", unit, errors.Join(proofErr, restoreErr))
		}
	}
	return resumeQuiescedServices, nil
}

func writeQuiesceJournal(value quiesceJournal) error {
	if os.Geteuid() != 0 {
		return errors.New("backup quiescence recovery requires root")
	}
	if err := validateQuiesceJournal(value); err != nil {
		return err
	}
	parent := filepath.Dir(quiesceJournalPath)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("backup quiescence journal directory is unsafe")
	}
	if _, err := os.Lstat(quiesceJournalPath); err == nil {
		return errors.New("backup quiescence journal already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload)+1 > maxQuiesceJournalBytes {
		return errors.New("backup quiescence journal is oversized")
	}
	temporary, err := os.CreateTemp(parent, ".quiesce-*.partial")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(payload, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, quiesceJournalPath, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("backup quiescence journal appeared concurrently")
		}
		return err
	}
	return syncJournalDirectory(parent)
}

func resumeQuiescedServices() error {
	value, found, err := loadQuiesceJournal()
	if err != nil || !found {
		return err
	}
	for index := len(value.Units) - 1; index >= 0; index-- {
		if _, err := systemctl("start", value.Units[index]); err != nil {
			return fmt.Errorf("start %s: %w", value.Units[index], err)
		}
		active, err := quiesceUnitActive(value.Units[index])
		if err != nil || !active {
			if err == nil {
				err = errors.New("unit did not become active after systemctl start")
			}
			return fmt.Errorf("prove %s resumed: %w", value.Units[index], err)
		}
	}
	// Recheck the complete original active set before committing away the
	// journal. A service that exits while later dependants are starting must
	// leave durable retry evidence rather than be reported as resumed.
	for _, unit := range value.Units {
		active, err := quiesceUnitActive(unit)
		if err != nil || !active {
			if err == nil {
				err = errors.New("unit stopped again before quiescence commit")
			}
			return fmt.Errorf("recheck resumed unit %s: %w", unit, err)
		}
	}
	if err := os.Remove(quiesceJournalPath); err != nil {
		return err
	}
	return syncJournalDirectory(filepath.Dir(quiesceJournalPath))
}

func loadQuiesceJournal() (quiesceJournal, bool, error) {
	info, err := os.Lstat(quiesceJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return quiesceJournal{}, false, nil
	}
	if err != nil {
		return quiesceJournal{}, false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxQuiesceJournalBytes {
		return quiesceJournal{}, false, errors.New("backup quiescence journal is unsafe")
	}
	payload, err := os.ReadFile(quiesceJournalPath)
	if err != nil {
		return quiesceJournal{}, false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var value quiesceJournal
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return quiesceJournal{}, false, errors.New("backup quiescence journal is invalid")
	}
	if err := validateQuiesceJournal(value); err != nil {
		return quiesceJournal{}, false, err
	}
	return value, true, nil
}

func validateQuiesceJournal(value quiesceJournal) error {
	if value.SchemaVersion != 1 || len(value.Units) == 0 || len(value.Units) > 2002 {
		return errors.New("backup quiescence journal metadata is invalid")
	}
	seen := make(map[string]bool, len(value.Units))
	for _, unit := range value.Units {
		valid := unit == "workagent-portal.service" || unit == "cliproxyapi.service"
		if !valid && strings.HasPrefix(unit, "workagent-userhost@") && (strings.HasSuffix(unit, ".service") || strings.HasSuffix(unit, ".socket")) {
			suffix := ".service"
			if strings.HasSuffix(unit, ".socket") {
				suffix = ".socket"
			}
			id := strings.TrimSuffix(strings.TrimPrefix(unit, "workagent-userhost@"), suffix)
			parsed, err := uuid.Parse(id)
			valid = err == nil && parsed.String() == id
		}
		if !valid || seen[unit] {
			return errors.New("backup quiescence journal contains an invalid or duplicate unit")
		}
		seen[unit] = true
	}
	return nil
}

func quiesceUnitActive(unit string) (bool, error) {
	output, err := systemctl("show", "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=ControlPID", unit)
	if err != nil {
		return false, err
	}
	return parseQuiesceUnitState(unit, output)
}

func parseQuiesceUnitState(unit, output string) (bool, error) {
	properties := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && key != "" {
			properties[key] = value
		}
	}
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 64)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 64)
	if properties["LoadState"] != "loaded" || mainErr != nil || controlErr != nil {
		return false, errors.New("unit state evidence is unavailable")
	}
	switch properties["ActiveState"] {
	case "active":
		if properties["SubState"] == "" || controlPID != 0 {
			return false, errors.New("active unit has unsafe process state")
		}
		if strings.HasSuffix(unit, ".service") && mainPID == 0 {
			return false, errors.New("active service has no main process")
		}
		if strings.HasSuffix(unit, ".socket") && mainPID != 0 {
			return false, errors.New("active socket has an unexpected main process")
		}
		return true, nil
	case "inactive":
		if properties["SubState"] != "dead" || mainPID != 0 || controlPID != 0 {
			return false, errors.New("inactive unit has unsafe residual state")
		}
		return false, nil
	default:
		return false, fmt.Errorf("unit is in transitional or failed state %s/%s", properties["ActiveState"], properties["SubState"])
	}
}

func syncJournalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func systemctl(arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "workagent-backup:", message)
	os.Exit(1)
}
