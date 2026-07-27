package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	PreflightSchemaVersion   = 2
	MaintenanceNoticeMessage = "系统正在升级，正在进行的任务可能会中断"
)

var requiredPreflightChecks = []string{"active_tenants", "backup_destination", "host", "portal_config", "portal_readiness", "target_release"}

type MaintenanceNotice struct {
	ID          string    `json:"id"`
	Message     string    `json:"message"`
	PublishedAt time.Time `json:"published_at"`
	ObservedAt  time.Time `json:"observed_at"`
}

type PreflightReport struct {
	SchemaVersion        int                `json:"schema_version"`
	TargetReleaseID      string             `json:"target_release_id"`
	CurrentReleaseID     string             `json:"current_release_id,omitempty"`
	Scope                string             `json:"scope"`
	PointerFile          string             `json:"pointer_file"`
	CreatedAt            time.Time          `json:"created_at"`
	ExpiresAt            time.Time          `json:"expires_at"`
	TargetManifestSHA256 string             `json:"target_manifest_sha256"`
	PortalConfigSHA256   string             `json:"portal_config_sha256"`
	TenantConfigSHA256   map[string]string  `json:"tenant_config_sha256"`
	MaintenanceNotice    *MaintenanceNotice `json:"maintenance_notice,omitempty"`
	Checks               []PreflightCheck   `json:"checks"`
}

type PreflightCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

func NewPreflightReport(targetReleaseID, currentReleaseID, scope, pointerFile, targetManifestPath, portalConfigPath string, tenantConfigs map[string]string, notice *MaintenanceNotice, now time.Time) (PreflightReport, error) {
	manifestHash, err := ProtectedFileSHA256(targetManifestPath, true)
	if err != nil {
		return PreflightReport{}, err
	}
	portalHash, err := ProtectedFileSHA256(portalConfigPath, true)
	if err != nil {
		return PreflightReport{}, err
	}
	report := PreflightReport{
		SchemaVersion: PreflightSchemaVersion, TargetReleaseID: targetReleaseID, CurrentReleaseID: currentReleaseID, Scope: scope, PointerFile: pointerFile,
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(30 * time.Minute), TargetManifestSHA256: manifestHash, PortalConfigSHA256: portalHash,
		TenantConfigSHA256: make(map[string]string, len(tenantConfigs)),
	}
	for tenantID, path := range tenantConfigs {
		hash, err := ProtectedFileSHA256(path, true)
		if err != nil {
			return PreflightReport{}, err
		}
		report.TenantConfigSHA256[tenantID] = hash
	}
	for _, name := range requiredPreflightChecks {
		report.Checks = append(report.Checks, PreflightCheck{Name: name, Passed: true})
	}
	if currentReleaseID != "" {
		if notice == nil {
			return PreflightReport{}, errors.New("release preflight requires authenticated maintenance-notice evidence")
		}
		copy := *notice
		report.MaintenanceNotice = &copy
		report.Checks = append(report.Checks, PreflightCheck{Name: "maintenance_notice", Passed: true})
	} else if notice != nil {
		return PreflightReport{}, errors.New("initial release preflight must not contain upgrade-notice evidence")
	}
	if err := report.Validate(); err != nil {
		return PreflightReport{}, err
	}
	return report, nil
}

func (r PreflightReport) Validate() error {
	if r.SchemaVersion != PreflightSchemaVersion || !validIdentifier(r.TargetReleaseID) || (r.CurrentReleaseID != "" && !validIdentifier(r.CurrentReleaseID)) || !cleanAbsolute(r.PointerFile) || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.Sub(r.CreatedAt) > time.Hour {
		return errors.New("release preflight metadata is invalid")
	}
	if r.Scope != ScopePortal && r.Scope != ScopeRuntime && r.Scope != ScopeShared && r.Scope != ScopeCombined {
		return errors.New("release preflight scope is invalid")
	}
	for _, value := range []string{r.TargetManifestSHA256, r.PortalConfigSHA256} {
		if !validSHA256(value) {
			return errors.New("release preflight contains an invalid hash")
		}
	}
	if len(r.TenantConfigSHA256) == 0 || len(r.TenantConfigSHA256) > 10000 {
		return errors.New("release preflight tenant evidence is missing or too large")
	}
	for tenantID, hash := range r.TenantConfigSHA256 {
		if !validIdentifier(tenantID) || !validSHA256(hash) {
			return errors.New("release preflight tenant evidence is invalid")
		}
	}
	checks := make(map[string]bool)
	for _, check := range r.Checks {
		if check.Name == "" || checks[check.Name] || !check.Passed {
			return errors.New("release preflight contains a failed or duplicate check")
		}
		checks[check.Name] = true
	}
	for _, required := range requiredPreflightChecks {
		if !checks[required] {
			return fmt.Errorf("release preflight omits check %s", required)
		}
	}
	if r.CurrentReleaseID == "" {
		if r.MaintenanceNotice != nil || checks["maintenance_notice"] {
			return errors.New("initial release preflight contains an unexpected maintenance notice")
		}
	} else {
		if r.MaintenanceNotice == nil || !checks["maintenance_notice"] {
			return errors.New("release preflight omits authenticated maintenance-notice evidence")
		}
		if err := r.MaintenanceNotice.Validate(r.TargetReleaseID, r.CreatedAt); err != nil {
			return err
		}
		if r.MaintenanceNotice.ObservedAt.Before(r.CreatedAt.Add(-5*time.Minute)) || r.MaintenanceNotice.ObservedAt.After(r.CreatedAt.Add(5*time.Minute)) {
			return errors.New("maintenance notice was not observed during this preflight")
		}
	}
	return nil
}

func ExpectedMaintenanceNoticeID(targetReleaseID string) string {
	return "workagent-upgrade-" + targetReleaseID
}

func (n MaintenanceNotice) Validate(targetReleaseID string, now time.Time) error {
	if !validIdentifier(targetReleaseID) || n.ID != ExpectedMaintenanceNoticeID(targetReleaseID) || n.Message != MaintenanceNoticeMessage || n.PublishedAt.IsZero() || n.ObservedAt.IsZero() {
		return errors.New("maintenance notice identity or content is invalid")
	}
	now = now.UTC()
	published, observed := n.PublishedAt.UTC(), n.ObservedAt.UTC()
	if observed.After(now.Add(5*time.Minute)) || observed.Before(now.Add(-time.Hour)) || published.After(observed.Add(-time.Minute)) || published.Before(observed.Add(-24*time.Hour)) {
		return errors.New("maintenance notice was not freshly observed at least 60 seconds after publication")
	}
	return nil
}

func WritePreflight(path string, report PreflightReport) error {
	if !cleanAbsolute(path) {
		return errors.New("release preflight path must be clean and absolute")
	}
	if err := report.Validate(); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(payload, '\n'), 0o400)
}

func LoadPreflight(path string, requireRootOwner bool) (PreflightReport, error) {
	payload, err := readProtectedBoundedFile(path, 4*1024*1024, requireRootOwner, false)
	if err != nil {
		return PreflightReport{}, fmt.Errorf("read release preflight: %w", err)
	}
	var report PreflightReport
	if err := decodeStrictJSON(payload, &report); err != nil {
		return PreflightReport{}, errors.New("release preflight is invalid")
	}
	if err := report.Validate(); err != nil {
		return PreflightReport{}, err
	}
	return report, nil
}

func VerifyPreflight(path, targetReleaseID, currentReleaseID, scope, pointerFile, targetManifestPath, portalConfigPath string, tenantConfigs map[string]string, now time.Time, requireRootOwner bool) error {
	report, err := LoadPreflight(path, requireRootOwner)
	if err != nil {
		return err
	}
	if report.TargetReleaseID != targetReleaseID || report.CurrentReleaseID != currentReleaseID || report.Scope != scope || report.PointerFile != pointerFile || now.UTC().Before(report.CreatedAt.Add(-5*time.Minute)) || !now.UTC().Before(report.ExpiresAt) {
		return errors.New("release preflight does not match this activation or has expired")
	}
	if report.MaintenanceNotice != nil {
		if err := report.MaintenanceNotice.Validate(targetReleaseID, now); err != nil {
			return err
		}
	}
	manifestHash, err := ProtectedFileSHA256(targetManifestPath, requireRootOwner)
	if err != nil || manifestHash != report.TargetManifestSHA256 {
		return errors.New("target manifest changed after release preflight")
	}
	portalHash, err := ProtectedFileSHA256(portalConfigPath, requireRootOwner)
	if err != nil || portalHash != report.PortalConfigSHA256 {
		return errors.New("Portal configuration changed after release preflight")
	}
	if len(tenantConfigs) != len(report.TenantConfigSHA256) {
		return errors.New("tenant configuration set changed after release preflight")
	}
	for tenantID, configPath := range tenantConfigs {
		hash, err := ProtectedFileSHA256(configPath, requireRootOwner)
		if err != nil || report.TenantConfigSHA256[tenantID] != hash {
			return fmt.Errorf("tenant %s configuration changed after release preflight", tenantID)
		}
	}
	return nil
}

func ProtectedFileSHA256(path string, requireRootOwner bool) (string, error) {
	if !cleanAbsolute(path) {
		return "", errors.New("protected file path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 64*1024*1024 || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("protected file is missing or unsafe")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", errors.New("protected file is not root-owned")
		}
	}
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 64*1024*1024+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
