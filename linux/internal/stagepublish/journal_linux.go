//go:build linux

package stagepublish

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

type journal struct {
	SchemaVersion       int             `json:"schema_version"`
	Status              string          `json:"status"`
	StagePath           string          `json:"stage_path"`
	SourceFingerprint   string          `json:"source_fingerprint"`
	OutputFingerprint   string          `json:"output_fingerprint"`
	PortalSHA256        string          `json:"portal_sha256"`
	PortalTemporary     string          `json:"portal_temporary"`
	PortalState         string          `json:"portal_state"`
	Tenants             []journalTenant `json:"tenants"`
	RollbackDestination string          `json:"rollback_destination"`
	UpdatedAt           string          `json:"updated_at"`
}

type journalTenant struct {
	TenantID       string                              `json:"tenant_id"`
	RuntimeUser    string                              `json:"runtime_user"`
	UID            uint32                              `json:"uid,omitempty"`
	GID            uint32                              `json:"gid,omitempty"`
	ProjectID      uint32                              `json:"project_id"`
	HardLimitBytes uint64                              `json:"hard_limit_bytes"`
	Temporary      string                              `json:"temporary"`
	State          string                              `json:"state"`
	Payload        winmigration.PublicationTreeSummary `json:"payload"`
}

func newJournal(options Options, verified winmigration.PublicationStage, paths layout, now time.Time) journal {
	prefix := verified.Report.OutputFingerprint[:16]
	value := journal{
		SchemaVersion: JournalSchema, Status: "prepared", StagePath: options.Stage,
		SourceFingerprint: verified.Report.SourceFingerprint, OutputFingerprint: verified.Report.OutputFingerprint,
		PortalSHA256: verified.PortalSHA256, PortalTemporary: ".portal.db.import-" + prefix + ".partial", PortalState: "pending",
		RollbackDestination: filepath.Join(paths.rollbackRoot, verified.Report.SourceFingerprint), UpdatedAt: now.UTC().Format(time.RFC3339Nano),
	}
	for _, report := range verified.Report.Tenants {
		value.Tenants = append(value.Tenants, journalTenant{
			TenantID: report.TenantID, RuntimeUser: report.RuntimeUser, ProjectID: report.ProjectID, HardLimitBytes: report.DiskHardLimitBytes,
			Temporary: "." + report.TenantID + ".import-" + prefix + ".partial", State: "pending", Payload: verified.Tenants[report.TenantID].Payload,
		})
	}
	sort.Slice(value.Tenants, func(i, k int) bool { return value.Tenants[i].TenantID < value.Tenants[k].TenantID })
	return value
}

func (j journal) validateAgainst(options Options, verified winmigration.PublicationStage, paths layout) error {
	if j.SchemaVersion != JournalSchema || (j.Status != "prepared" && j.Status != "provisioned" && j.Status != "publishing" && j.Status != "complete") ||
		j.StagePath != options.Stage || j.SourceFingerprint != verified.Report.SourceFingerprint || j.OutputFingerprint != verified.Report.OutputFingerprint || j.PortalSHA256 != verified.PortalSHA256 ||
		j.PortalTemporary != ".portal.db.import-"+verified.Report.OutputFingerprint[:16]+".partial" || (j.PortalState != "pending" && j.PortalState != "published") ||
		j.RollbackDestination != filepath.Join(paths.rollbackRoot, verified.Report.SourceFingerprint) || len(j.Tenants) != len(verified.Report.Tenants) {
		return errors.New("existing publication journal conflicts with the requested stage")
	}
	reports := make(map[string]winmigration.TenantReport, len(verified.Report.Tenants))
	for _, report := range verified.Report.Tenants {
		reports[report.TenantID] = report
	}
	seen := make(map[string]bool, len(j.Tenants))
	for _, tenant := range j.Tenants {
		report, ok := reports[tenant.TenantID]
		payload := verified.Tenants[tenant.TenantID].Payload
		if !ok || seen[tenant.TenantID] || tenant.RuntimeUser != report.RuntimeUser || tenant.ProjectID != report.ProjectID || tenant.HardLimitBytes != report.DiskHardLimitBytes ||
			tenant.Temporary != "."+tenant.TenantID+".import-"+verified.Report.OutputFingerprint[:16]+".partial" || (tenant.State != "pending" && tenant.State != "ready" && tenant.State != "published") || tenant.Payload != payload {
			return errors.New("existing publication journal tenant state is invalid")
		}
		if (tenant.UID == 0) != (tenant.GID == 0) {
			return errors.New("existing publication journal tenant ownership is incomplete")
		}
		seen[tenant.TenantID] = true
	}
	if j.Status == "complete" {
		if j.PortalState != "published" {
			return errors.New("completed publication journal has an incomplete Portal state")
		}
		for _, tenant := range j.Tenants {
			if tenant.State != "published" || tenant.UID == 0 || tenant.GID == 0 {
				return errors.New("completed publication journal has an incomplete tenant state")
			}
		}
	}
	return nil
}

func ensureProtectedDirectory(path string, expectedUID uint32, apply bool) (bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false, errors.New("protected directory path is invalid")
	}
	components := splitAbsolute(path)
	currentFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(currentFD) }()
	createdAll := true
	for index, component := range components {
		var stat unix.Stat_t
		err := unix.Fstatat(currentFD, component, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			createdAll = false
			if !apply {
				return false, nil
			}
			mode := uint32(0o700)
			if err := unix.Mkdirat(currentFD, component, mode); err != nil {
				return false, fmt.Errorf("create protected migration directory: %w", err)
			}
			if err := unix.Fsync(currentFD); err != nil {
				return false, err
			}
		} else if err != nil {
			return false, err
		}
		next, err := unix.Openat2(currentFD, component, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return false, errors.New("protected migration directory ancestor is unsafe")
		}
		if err := unix.Fstat(next, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != expectedUID || stat.Gid != expectedUID || os.FileMode(stat.Mode).Perm()&0o022 != 0 {
			unix.Close(next)
			return false, errors.New("protected migration directory ownership or mode is unsafe")
		}
		// Every directory at and below /var/lib/workagent/migration is private;
		// general system ancestors retain their normal non-writable modes.
		if index >= migrationPathPrivateIndex(components) && os.FileMode(stat.Mode).Perm() != 0o700 {
			unix.Close(next)
			return false, errors.New("protected migration directory is not mode 0700")
		}
		_ = unix.Close(currentFD)
		currentFD = next
	}
	return createdAll, nil
}

func migrationPathPrivateIndex(components []string) int {
	for index := range components {
		if index >= 3 && components[index-3] == "var" && components[index-2] == "lib" && components[index-1] == "workagent" && components[index] == "migration" {
			return index
		}
	}
	return len(components)
}

func splitAbsolute(value string) []string {
	clean := filepath.Clean(value)
	var result []string
	for clean != string(filepath.Separator) {
		result = append([]string{filepath.Base(clean)}, result...)
		clean = filepath.Dir(clean)
	}
	return result
}

func loadJournal(path string, expectedUID uint32) (journal, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal{}, false, nil
	}
	stat, ok := fileStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 1024*1024 || stat.Uid != expectedUID || stat.Gid != expectedUID {
		return journal{}, false, errors.New("publication journal is not a protected regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return journal{}, false, err
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(payload) > 1024*1024 {
		clear(payload)
		return journal{}, false, errors.New("publication journal read failed")
	}
	defer clear(payload)
	var value journal
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return journal{}, false, errors.New("publication journal JSON is invalid")
	}
	return value, true, nil
}

func writeJournal(path string, value *journal, expectedUID uint32, now time.Time) error {
	if value == nil {
		return errors.New("publication journal value is missing")
	}
	value.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	defer clear(payload)
	parent := filepath.Dir(path)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil || parentStat.Uid != expectedUID || parentStat.Gid != expectedUID || os.FileMode(parentStat.Mode).Perm() != 0o700 {
		return errors.New("publication journal directory is unsafe")
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	base := filepath.Base(path)
	temporary := "." + base + ".tmp-" + hex.EncodeToString(random)
	fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if err := file.Chown(int(expectedUID), int(expectedUID)); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, base); err != nil {
		return err
	}
	remove = false
	return unix.Fsync(parentFD)
}
