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
	"reflect"
	"strings"
	"syscall"
	"time"
)

const (
	PreflightSchemaVersion   = 4
	MaintenanceNoticeMessage = "系统正在升级，正在进行的任务可能会中断"
)

var requiredPreflightChecks = []string{"backup_destination", "host", "portal_config", "target_release", "tenants"}

type MaintenanceNotice struct {
	ID          string    `json:"id"`
	Message     string    `json:"message"`
	PublishedAt time.Time `json:"published_at"`
	ObservedAt  time.Time `json:"observed_at"`
}

type PreflightInputs struct {
	TargetManifestPath  string
	TargetSignaturePath string
	PublicKeyPath       string
	PortalConfigPath    string
	TenantConfigPaths   map[string]string
	BackupConfigPath    string
	BackupKeyPath       string
	BrandID             string
	BrandConfigPath     string
	BrandAssetPaths     map[string]string
	PolicyID            string
	PolicyConfigPath    string
}

type ProtectedFileEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type PreflightEvidence struct {
	TargetManifest  ProtectedFileEvidence            `json:"target_manifest"`
	TargetSignature ProtectedFileEvidence            `json:"target_signature"`
	PublicKey       ProtectedFileEvidence            `json:"public_key"`
	PortalConfig    ProtectedFileEvidence            `json:"portal_config"`
	TenantConfigs   map[string]ProtectedFileEvidence `json:"tenant_configs"`
	BackupConfig    ProtectedFileEvidence            `json:"backup_config"`
	BackupKey       ProtectedFileEvidence            `json:"backup_key"`
	BrandID         string                           `json:"brand_id"`
	BrandConfig     ProtectedFileEvidence            `json:"brand_config"`
	BrandAssets     map[string]ProtectedFileEvidence `json:"brand_assets"`
	PolicyID        string                           `json:"policy_id"`
	PolicyConfig    ProtectedFileEvidence            `json:"policy_config"`
}

type PreflightReport struct {
	SchemaVersion     int                `json:"schema_version"`
	TargetReleaseID   string             `json:"target_release_id"`
	CurrentReleaseID  string             `json:"current_release_id,omitempty"`
	Scope             string             `json:"scope"`
	PointerFile       string             `json:"pointer_file"`
	CreatedAt         time.Time          `json:"created_at"`
	ExpiresAt         time.Time          `json:"expires_at"`
	Evidence          PreflightEvidence  `json:"evidence"`
	ConsumerContract  ConsumerContract   `json:"consumer_contract"`
	MaintenanceNotice *MaintenanceNotice `json:"maintenance_notice,omitempty"`
	Checks            []PreflightCheck   `json:"checks"`
}

type PreflightCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

var requiredBrandAssetNames = []string{"app-icon", "favicon", "logo", "logo-dark"}

func (i PreflightInputs) Validate() error {
	for label, path := range map[string]string{
		"target manifest": i.TargetManifestPath, "target signature": i.TargetSignaturePath,
		"public key": i.PublicKeyPath, "Portal config": i.PortalConfigPath,
		"backup config": i.BackupConfigPath, "backup key": i.BackupKeyPath,
		"brand config": i.BrandConfigPath, "policy config": i.PolicyConfigPath,
	} {
		if !cleanAbsolute(path) {
			return fmt.Errorf("preflight %s path is invalid", label)
		}
	}
	if filepath.Base(i.TargetManifestPath) != "manifest.json" || i.TargetSignaturePath != filepath.Join(filepath.Dir(i.TargetManifestPath), "manifest.sig") {
		return errors.New("preflight target manifest and signature paths are not canonical")
	}
	if !validIdentifier(i.BrandID) || !validIdentifier(i.PolicyID) {
		return errors.New("preflight product identity is invalid")
	}
	if len(i.TenantConfigPaths) == 0 || len(i.TenantConfigPaths) > 10000 {
		return errors.New("preflight tenant input set is missing or too large")
	}
	for tenantID, path := range i.TenantConfigPaths {
		if !validIdentifier(tenantID) || !cleanAbsolute(path) {
			return errors.New("preflight tenant input is invalid")
		}
	}
	if len(i.BrandAssetPaths) != len(requiredBrandAssetNames) {
		return errors.New("preflight brand asset input set is incomplete")
	}
	for _, name := range requiredBrandAssetNames {
		if !cleanAbsolute(i.BrandAssetPaths[name]) {
			return fmt.Errorf("preflight brand asset %s path is invalid", name)
		}
	}
	return nil
}

func (e ProtectedFileEvidence) Validate() error {
	if !cleanAbsolute(e.Path) || !validSHA256(e.SHA256) {
		return errors.New("protected preflight file evidence is invalid")
	}
	return nil
}

func (e PreflightEvidence) Validate() error {
	if !validIdentifier(e.BrandID) || !validIdentifier(e.PolicyID) {
		return errors.New("release preflight product identity evidence is invalid")
	}
	for _, file := range []ProtectedFileEvidence{
		e.TargetManifest, e.TargetSignature, e.PublicKey, e.PortalConfig,
		e.BackupConfig, e.BackupKey, e.BrandConfig, e.PolicyConfig,
	} {
		if err := file.Validate(); err != nil {
			return err
		}
	}
	if len(e.TenantConfigs) == 0 || len(e.TenantConfigs) > 10000 {
		return errors.New("release preflight tenant evidence is missing or too large")
	}
	for tenantID, file := range e.TenantConfigs {
		if !validIdentifier(tenantID) || file.Validate() != nil {
			return errors.New("release preflight tenant evidence is invalid")
		}
	}
	if len(e.BrandAssets) != len(requiredBrandAssetNames) {
		return errors.New("release preflight brand asset evidence is incomplete")
	}
	for _, name := range requiredBrandAssetNames {
		if err := e.BrandAssets[name].Validate(); err != nil {
			return fmt.Errorf("release preflight brand asset %s evidence is invalid", name)
		}
	}
	return nil
}

func capturePreflightEvidence(inputs PreflightInputs, requireRootOwner bool) (PreflightEvidence, error) {
	if err := inputs.Validate(); err != nil {
		return PreflightEvidence{}, err
	}
	capture := func(label, path string) (ProtectedFileEvidence, error) {
		hash, err := ProtectedFileSHA256(path, requireRootOwner)
		if err != nil {
			return ProtectedFileEvidence{}, fmt.Errorf("hash preflight %s: %w", label, err)
		}
		return ProtectedFileEvidence{Path: path, SHA256: hash}, nil
	}
	evidence := PreflightEvidence{
		BrandID: inputs.BrandID, PolicyID: inputs.PolicyID,
		TenantConfigs: make(map[string]ProtectedFileEvidence, len(inputs.TenantConfigPaths)),
		BrandAssets:   make(map[string]ProtectedFileEvidence, len(inputs.BrandAssetPaths)),
	}
	files := []struct {
		label string
		path  string
		set   func(ProtectedFileEvidence)
	}{
		{"target manifest", inputs.TargetManifestPath, func(value ProtectedFileEvidence) { evidence.TargetManifest = value }},
		{"target signature", inputs.TargetSignaturePath, func(value ProtectedFileEvidence) { evidence.TargetSignature = value }},
		{"public key", inputs.PublicKeyPath, func(value ProtectedFileEvidence) { evidence.PublicKey = value }},
		{"Portal config", inputs.PortalConfigPath, func(value ProtectedFileEvidence) { evidence.PortalConfig = value }},
		{"backup config", inputs.BackupConfigPath, func(value ProtectedFileEvidence) { evidence.BackupConfig = value }},
		{"backup key", inputs.BackupKeyPath, func(value ProtectedFileEvidence) { evidence.BackupKey = value }},
		{"brand config", inputs.BrandConfigPath, func(value ProtectedFileEvidence) { evidence.BrandConfig = value }},
		{"policy config", inputs.PolicyConfigPath, func(value ProtectedFileEvidence) { evidence.PolicyConfig = value }},
	}
	for _, file := range files {
		value, err := capture(file.label, file.path)
		if err != nil {
			return PreflightEvidence{}, err
		}
		file.set(value)
	}
	for tenantID, path := range inputs.TenantConfigPaths {
		value, err := capture("tenant "+tenantID+" config", path)
		if err != nil {
			return PreflightEvidence{}, err
		}
		evidence.TenantConfigs[tenantID] = value
	}
	for name, path := range inputs.BrandAssetPaths {
		value, err := capture("brand asset "+name, path)
		if err != nil {
			return PreflightEvidence{}, err
		}
		evidence.BrandAssets[name] = value
	}
	if err := evidence.Validate(); err != nil {
		return PreflightEvidence{}, err
	}
	return evidence, nil
}

func NewPreflightReport(targetReleaseID, currentReleaseID, scope, pointerFile string, inputs PreflightInputs, contract ConsumerContract, notice *MaintenanceNotice, now time.Time) (PreflightReport, error) {
	evidence, err := capturePreflightEvidence(inputs, true)
	if err != nil {
		return PreflightReport{}, err
	}
	report := PreflightReport{
		SchemaVersion: PreflightSchemaVersion, TargetReleaseID: targetReleaseID, CurrentReleaseID: currentReleaseID, Scope: scope, PointerFile: pointerFile,
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(30 * time.Minute), Evidence: evidence, ConsumerContract: contract,
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
		report.Checks = append(report.Checks, PreflightCheck{Name: "portal_readiness", Passed: true})
		report.Checks = append(report.Checks, PreflightCheck{Name: "maintenance_notice", Passed: true})
	} else if notice != nil {
		return PreflightReport{}, errors.New("initial release preflight must not contain upgrade-notice evidence")
	} else {
		report.Checks = append(report.Checks, PreflightCheck{Name: "portal_bootstrap", Passed: true})
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
	if err := r.ConsumerContract.Validate(); err != nil {
		return fmt.Errorf("release preflight consumer contract is invalid: %w", err)
	}
	if err := r.Evidence.Validate(); err != nil {
		return err
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
		if r.MaintenanceNotice != nil || checks["maintenance_notice"] || checks["portal_readiness"] || !checks["portal_bootstrap"] {
			return errors.New("initial release preflight contains an unexpected maintenance notice")
		}
	} else {
		if r.MaintenanceNotice == nil || !checks["maintenance_notice"] || !checks["portal_readiness"] || checks["portal_bootstrap"] {
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
	return atomicWriteExclusive(path, append(payload, '\n'), 0o400)
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

func VerifyPreflight(path, targetReleaseID, currentReleaseID, scope, pointerFile string, inputs PreflightInputs, contract ConsumerContract, now time.Time, requireRootOwner bool) error {
	if err := contract.Validate(); err != nil {
		return err
	}
	currentEvidence, err := capturePreflightEvidence(inputs, requireRootOwner)
	if err != nil {
		return err
	}
	report, err := LoadPreflight(path, requireRootOwner)
	if err != nil {
		return err
	}
	if report.TargetReleaseID != targetReleaseID || report.CurrentReleaseID != currentReleaseID || report.Scope != scope || report.PointerFile != pointerFile || !report.ConsumerContract.Equal(contract) || !reflect.DeepEqual(report.Evidence, currentEvidence) || now.UTC().Before(report.CreatedAt.Add(-5*time.Minute)) || !now.UTC().Before(report.ExpiresAt) {
		return errors.New("release preflight does not match this activation or has expired")
	}
	if report.MaintenanceNotice != nil {
		if err := report.MaintenanceNotice.Validate(targetReleaseID, now); err != nil {
			return err
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
