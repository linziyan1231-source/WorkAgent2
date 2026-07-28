//go:build linux

package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const (
	MigrationLiveVerificationReceiptPath = "/var/lib/workagent/migration/cutover/cliproxy-live-verification.json"

	migrationLiveReceiptName              = "cliproxy-live-verification.json"
	migrationLiveReceiptStageName         = ".cliproxy-live-verification.json.workagent-stage"
	migrationLiveReceiptSchema            = 2
	migrationLiveReceiptMaximum           = 8 * 1024 * 1024
	migrationLiveReceiptTTL               = 5 * time.Minute
	migrationLiveReceiptClockSkew         = 5 * time.Second
	migrationLiveReceiptMaxTenants        = 10000
	migrationLiveReceiptService           = "cliproxyapi.service"
	migrationLiveReceiptFragment          = "/etc/systemd/system/cliproxyapi.service"
	migrationLiveReceiptVendorFragment    = "/usr/lib/systemd/system/cliproxyapi.service"
	migrationLiveReceiptReferenceFragment = "/opt/workagent/control/share/deploy/systemd/cliproxyapi.service"
	migrationLiveReceiptFragmentMaximum   = 1024 * 1024
)

// migrationReceiptEvidence is the evidence field list shared by the issued
// live-verification receipt and the bound evidence re-collected at activation
// time. It is embedded in both so the fields exist exactly once.
type migrationReceiptEvidence struct {
	Report         migrationReceiptReport      `json:"report"`
	Plan           migrationReceiptPlan        `json:"plan"`
	Portal         migrationReceiptPortal      `json:"portal"`
	PendingBundles []migrationReceiptPending   `json:"pending_bundles"`
	PolicyState    migrationReceiptPolicyState `json:"policy_state"`
}

type migrationLiveVerificationReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	ReceiptPath   string `json:"receipt_path"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	migrationReceiptEvidence
	CLIProxy       migrationReceiptCLIProxyProof `json:"cliproxy_verified_contract"`
	EvidenceSHA256 string                        `json:"evidence_sha256"`
}

type migrationReceiptReport struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	SourceFingerprint string `json:"source_fingerprint"`
	OutputFingerprint string `json:"output_fingerprint"`
}

type migrationReceiptPlan struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type migrationReceiptPortal struct {
	DatabasePath          string `json:"database_path"`
	Users                 int    `json:"users"`
	IdentityCatalogSHA256 string `json:"identity_catalog_sha256"`
}

type migrationReceiptPending struct {
	TenantID      string `json:"tenant_id"`
	Path          string `json:"path"`
	BundleSHA256  string `json:"bundle_sha256"`
	StateSHA256   string `json:"state_sha256"`
	BundleVersion int    `json:"bundle_version"`
}

type migrationReceiptPolicyState struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type migrationReceiptCLIProxyProof struct {
	InputContractSHA256 string                            `json:"input_contract_sha256"`
	LiveCatalogSHA256   string                            `json:"live_catalog_sha256"`
	LiveKeysSHA256      string                            `json:"live_keys_sha256"`
	ServiceGeneration   migrationReceiptServiceGeneration `json:"service_generation"`
}

type migrationReceiptServiceGeneration struct {
	Unit                          string `json:"unit"`
	LoadState                     string `json:"load_state"`
	ActiveState                   string `json:"active_state"`
	SubState                      string `json:"sub_state"`
	User                          string `json:"user"`
	Group                         string `json:"group"`
	MainPID                       uint32 `json:"main_pid"`
	ControlPID                    uint32 `json:"control_pid"`
	Result                        string `json:"result"`
	InvocationID                  string `json:"invocation_id"`
	ActiveEnterTimestampMonotonic uint64 `json:"active_enter_timestamp_monotonic"`
	FragmentPath                  string `json:"fragment_path"`
	FragmentSHA256                string `json:"fragment_sha256"`
	DropInPaths                   string `json:"drop_in_paths"`
	NeedDaemonReload              string `json:"need_daemon_reload"`
}

type migrationReceiptBoundEvidence struct {
	migrationReceiptEvidence
	InputContract     string
	LiveCatalog       string
	LiveKeys          string
	ServiceGeneration migrationReceiptServiceGeneration
}

// LiveVerificationReceiptValidationOptions are the exact protected inputs
// that a later tenant-catalog activation must re-read. The caller must already
// hold A_EX followed by the control fixed-consumer guards (C_SH + control SH).
// ValidateMigrationLiveVerificationReceipt takes migration SH itself, then
// locks every tenant in canonical order before inspecting pending bundles.
type LiveVerificationReceiptValidationOptions struct {
	ReportPath         string
	PlanPath           string
	PortalDatabasePath string
	CLIProxy           config.CLIProxy
	Policy             productconfig.Policy
}

type LiveVerificationReceiptValidation struct {
	IssuedAt                time.Time
	ExpiresAt               time.Time
	Users                   int
	PendingBundles          int
	ReceiptSHA256           string
	ServiceGenerationSHA256 string
}

type migrationReceiptFaultHook func(string) error

type migrationReceiptEvidenceCollector func(context.Context, LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error)

type migrationReceiptLockAcquire func() (io.Closer, error)

type migrationReceiptFragmentDigest func(string) (string, error)

// ValidateMigrationLiveVerificationReceipt validates the fixed production
// receipt while holding the CLIProxy migration lock shared. It deliberately
// does not reacquire catalog/control locks: callers must enter with A_EX then
// lifecyclelock.AcquireFixedConsumer("/opt/workagent/control") so the complete
// order remains A_EX -> C_SH -> control SH -> migration SH -> tenant locks.
func ValidateMigrationLiveVerificationReceipt(ctx context.Context, options LiveVerificationReceiptValidationOptions) (LiveVerificationReceiptValidation, error) {
	return validateMigrationLiveVerificationReceiptWithLock(
		ctx, MigrationLiveVerificationReceiptPath, time.Now().UTC(), options,
		AcquireProductionMigrationSharedLock, collectMigrationReceiptBoundEvidence,
	)
}

func validateMigrationLiveVerificationReceiptWithLock(
	ctx context.Context,
	receiptPath string,
	now time.Time,
	options LiveVerificationReceiptValidationOptions,
	acquire migrationReceiptLockAcquire,
	collector migrationReceiptEvidenceCollector,
) (result LiveVerificationReceiptValidation, resultErr error) {
	if ctx == nil || acquire == nil || collector == nil {
		return LiveVerificationReceiptValidation{}, errors.New("CLIProxy live-verification receipt validator is unavailable")
	}
	guard, err := acquire()
	if err != nil {
		return LiveVerificationReceiptValidation{}, fmt.Errorf("acquire CLIProxy migration shared lock for receipt validation: %w", err)
	}
	if receiptCloserMissing(guard) {
		return LiveVerificationReceiptValidation{}, errors.New("CLIProxy migration shared lock returned no guard")
	}
	defer func() { resultErr = errors.Join(resultErr, guard.Close()) }()
	return validateMigrationLiveVerificationReceiptAt(ctx, receiptPath, now, options, collector)
}

func validateMigrationLiveVerificationReceiptAt(
	ctx context.Context,
	receiptPath string,
	now time.Time,
	options LiveVerificationReceiptValidationOptions,
	collector migrationReceiptEvidenceCollector,
) (LiveVerificationReceiptValidation, error) {
	validationBegan := time.Now()
	if effectiveUID() != 0 {
		return LiveVerificationReceiptValidation{}, errors.New("CLIProxy live-verification receipt validation requires root")
	}
	if ctx == nil || collector == nil || !validMigrationLiveReceiptPath(receiptPath) {
		return LiveVerificationReceiptValidation{}, errors.New("CLIProxy live-verification receipt validation input is invalid")
	}
	if err := ctx.Err(); err != nil {
		return LiveVerificationReceiptValidation{}, err
	}
	handle, receipt, payload, err := openMigrationLiveReceipt(receiptPath, true)
	if err != nil {
		return LiveVerificationReceiptValidation{}, err
	}
	defer handle.close()
	defer clear(payload)
	issued, expires, err := validateMigrationLiveReceipt(receiptPath, receipt)
	if err != nil {
		return LiveVerificationReceiptValidation{}, err
	}
	now = now.UTC()
	if now.Before(issued.Add(-migrationLiveReceiptClockSkew)) || !now.Before(expires) {
		return LiveVerificationReceiptValidation{}, errors.New("CLIProxy live-verification receipt is not currently valid")
	}
	evidence, err := collector(ctx, options)
	if err != nil {
		return LiveVerificationReceiptValidation{}, fmt.Errorf("re-read CLIProxy live-verification receipt inputs: %w", err)
	}
	if err := compareMigrationReceiptEvidence(receipt, evidence); err != nil {
		return LiveVerificationReceiptValidation{}, err
	}
	if err := handle.revalidate(); err != nil {
		return LiveVerificationReceiptValidation{}, err
	}
	finalNow := now.Add(time.Since(validationBegan))
	if finalNow.Before(issued.Add(-migrationLiveReceiptClockSkew)) || !finalNow.Before(expires) {
		return LiveVerificationReceiptValidation{}, errors.New("CLIProxy live-verification receipt expired during input validation")
	}
	serviceGenerationSHA256, err := migrationReceiptJSONSHA256(receipt.CLIProxy.ServiceGeneration)
	if err != nil {
		return LiveVerificationReceiptValidation{}, errors.New("encode CLIProxy receipt service generation")
	}
	return LiveVerificationReceiptValidation{
		IssuedAt: issued, ExpiresAt: expires, Users: receipt.Portal.Users,
		PendingBundles: len(receipt.PendingBundles), ReceiptSHA256: sha256Hex(payload),
		ServiceGenerationSHA256: serviceGenerationSHA256,
	}, nil
}

// ValidateMigrationLiveVerificationServiceGeneration re-proves that the
// receipt-bound CLIProxy process is still the exact active production
// invocation. Tenant-catalog activation calls it immediately before reporting
// success, after sockets have been started and while A_EX is still held.
func ValidateMigrationLiveVerificationServiceGeneration(ctx context.Context, expectedSHA256 string) error {
	if effectiveUID() != 0 {
		return errors.New("CLIProxy service-generation validation requires root")
	}
	return validateMigrationReceiptServiceGenerationWithController(ctx, expectedSHA256, systemdctl.Default())
}

func validateMigrationReceiptServiceGenerationWithController(ctx context.Context, expectedSHA256 string, controller systemdctl.Controller) error {
	return validateMigrationReceiptServiceGenerationWithControllerAndFragment(
		ctx, expectedSHA256, controller, summarizeProductionMigrationReceiptServiceFragment,
	)
}

func validateMigrationReceiptServiceGenerationWithControllerAndFragment(
	ctx context.Context,
	expectedSHA256 string,
	controller systemdctl.Controller,
	fragmentDigest migrationReceiptFragmentDigest,
) error {
	if ctx == nil || !fingerprintPattern.MatchString(expectedSHA256) {
		return errors.New("CLIProxy service-generation validation input is invalid")
	}
	generation, err := summarizeMigrationReceiptServiceGenerationWithFragment(ctx, controller, fragmentDigest)
	if err != nil {
		return err
	}
	actual, err := migrationReceiptJSONSHA256(generation)
	if err != nil || actual != expectedSHA256 {
		return errors.New("CLIProxy service generation changed after receipt validation")
	}
	return nil
}

func receiptCloserMissing(closer io.Closer) bool {
	if closer == nil {
		return true
	}
	// The production acquisition returns a concrete pointer. A typed-nil
	// pointer is rejected by invoking no methods on it through a tiny JSON-free
	// reflection helper kept local to this package.
	value := reflectValueOf(closer)
	return value
}

// reflectValueOf is split out so receiptCloserMissing remains easy to audit;
// it is implemented without exposing reflection in the public API.
func reflectValueOf(value io.Closer) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type migrationReceiptPortalIdentity struct {
	Username     string `json:"username"`
	UsernameNorm string `json:"username_norm"`
	TenantID     string `json:"tenant_id"`
	RuntimeUser  string `json:"runtime_user"`
	DataRoot     string `json:"data_root"`
	Enabled      bool   `json:"enabled"`
}

type migrationReceiptInputContract struct {
	CLIProxy config.CLIProxy      `json:"cliproxy"`
	Policy   productconfig.Policy `json:"policy"`
}

type migrationReceiptCatalogEntry struct {
	Key   string       `json:"key"`
	Alias catalogAlias `json:"alias"`
}

type migrationReceiptStableKey struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Enabled             bool              `json:"enabled"`
	KeyPreview          string            `json:"key_preview"`
	RPM                 int               `json:"rpm"`
	Models              []json.RawMessage `json:"models"`
	Aliases             []json.RawMessage `json:"aliases"`
	DailyLimitUSD       json.Number       `json:"daily_limit_usd"`
	WeeklyLimitUSD      json.Number       `json:"weekly_limit_usd"`
	AllowModelsEndpoint bool              `json:"allow_models_endpoint"`
}

func collectMigrationReceiptBoundEvidence(ctx context.Context, options LiveVerificationReceiptValidationOptions) (migrationReceiptBoundEvidence, error) {
	if ctx == nil {
		return migrationReceiptBoundEvidence{}, errors.New("CLIProxy live-verification evidence context is unavailable")
	}
	if err := options.CLIProxy.Validate(); err != nil {
		return migrationReceiptBoundEvidence{}, fmt.Errorf("CLIProxy contract: %w", err)
	}
	if err := options.Policy.Validate(); err != nil {
		return migrationReceiptBoundEvidence{}, fmt.Errorf("CLIProxy policy: %w", err)
	}
	serviceGeneration, err := summarizeProductionMigrationReceiptServiceGeneration(ctx)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	artifacts, err := loadMigrationArtifacts(ctx, options.ReportPath, options.PlanPath, options.PortalDatabasePath)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	tenants, err := lockMigrationTenants(artifacts.users)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	defer closeMigrationTenants(tenants)
	evidence, err := collectMigrationReceiptBoundEvidenceLocked(ctx, options, artifacts, tenants)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	serviceGenerationAfterInputs, err := summarizeProductionMigrationReceiptServiceGeneration(ctx)
	if err != nil || !reflect.DeepEqual(serviceGeneration, serviceGenerationAfterInputs) {
		return migrationReceiptBoundEvidence{}, errors.New("CLIProxy service generation changed while receipt inputs were re-read")
	}
	evidence.ServiceGeneration = serviceGeneration
	return evidence, nil
}

func summarizeProductionMigrationReceiptServiceGeneration(ctx context.Context) (migrationReceiptServiceGeneration, error) {
	return summarizeMigrationReceiptServiceGeneration(ctx, systemdctl.Default())
}

func summarizeMigrationReceiptServiceGeneration(ctx context.Context, controller systemdctl.Controller) (migrationReceiptServiceGeneration, error) {
	return summarizeMigrationReceiptServiceGenerationWithFragment(
		ctx, controller, summarizeProductionMigrationReceiptServiceFragment,
	)
}

func summarizeMigrationReceiptServiceGenerationWithFragment(
	ctx context.Context,
	controller systemdctl.Controller,
	fragmentDigest migrationReceiptFragmentDigest,
) (migrationReceiptServiceGeneration, error) {
	if ctx == nil || controller == nil || fragmentDigest == nil {
		return migrationReceiptServiceGeneration{}, errors.New("CLIProxy service-generation proof is unavailable")
	}
	generation, err := readMigrationReceiptServiceGenerationProperties(ctx, controller)
	if err != nil {
		return migrationReceiptServiceGeneration{}, err
	}
	fragmentSHA256, err := fragmentDigest(generation.FragmentPath)
	if err != nil {
		return migrationReceiptServiceGeneration{}, fmt.Errorf("prove CLIProxy service unit source: %w", err)
	}
	generationAfterFragment, err := readMigrationReceiptServiceGenerationProperties(ctx, controller)
	if err != nil || !reflect.DeepEqual(generation, generationAfterFragment) {
		return migrationReceiptServiceGeneration{}, errors.New("CLIProxy service generation changed while its signed unit source was authenticated")
	}
	generation.FragmentSHA256 = fragmentSHA256
	if validateMigrationReceiptServiceGeneration(generation) != nil {
		return migrationReceiptServiceGeneration{}, errors.New("CLIProxy service is not one exact loaded, active, running production generation")
	}
	return generation, nil
}

func readMigrationReceiptServiceGenerationProperties(ctx context.Context, controller systemdctl.Controller) (migrationReceiptServiceGeneration, error) {
	propertyNames := []string{
		"LoadState", "ActiveState", "SubState", "User", "Group", "MainPID", "ControlPID", "Result",
		"InvocationID", "ActiveEnterTimestampMonotonic", "FragmentPath", "DropInPaths", "NeedDaemonReload",
	}
	properties, err := controller.Properties(ctx, migrationLiveReceiptService, propertyNames...)
	if err != nil {
		return migrationReceiptServiceGeneration{}, fmt.Errorf("read CLIProxy service generation: %w", err)
	}
	if len(properties) != len(propertyNames) {
		return migrationReceiptServiceGeneration{}, errors.New("CLIProxy service-generation properties are incomplete")
	}
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 32)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 32)
	activeEnter, activeErr := strconv.ParseUint(properties["ActiveEnterTimestampMonotonic"], 10, 64)
	generation := migrationReceiptServiceGeneration{
		Unit:      migrationLiveReceiptService,
		LoadState: properties["LoadState"], ActiveState: properties["ActiveState"], SubState: properties["SubState"],
		User: properties["User"], Group: properties["Group"],
		MainPID: uint32(mainPID), ControlPID: uint32(controlPID), Result: properties["Result"],
		InvocationID: properties["InvocationID"], ActiveEnterTimestampMonotonic: activeEnter,
		FragmentPath: properties["FragmentPath"], DropInPaths: properties["DropInPaths"], NeedDaemonReload: properties["NeedDaemonReload"],
	}
	if mainErr != nil || controlErr != nil || activeErr != nil || validateMigrationReceiptServiceGenerationProperties(generation) != nil {
		return migrationReceiptServiceGeneration{}, errors.New("CLIProxy service is not one exact loaded, active, running production generation")
	}
	return generation, nil
}

func validateMigrationReceiptServiceGenerationProperties(generation migrationReceiptServiceGeneration) error {
	parsed, err := uuid.Parse(generation.InvocationID)
	canonicalInvocation := ""
	if err == nil {
		canonicalInvocation = strings.ReplaceAll(parsed.String(), "-", "")
	}
	if generation.Unit != migrationLiveReceiptService || generation.LoadState != "loaded" || generation.ActiveState != "active" ||
		generation.SubState != "running" || generation.User != "cliproxyapi" || generation.Group != "cliproxyapi" ||
		generation.MainPID == 0 || generation.ControlPID != 0 || generation.Result != "success" ||
		len(generation.InvocationID) != 32 || parsed == uuid.Nil || canonicalInvocation != generation.InvocationID || generation.ActiveEnterTimestampMonotonic == 0 ||
		!migrationReceiptTrustedFragmentPath(generation.FragmentPath) || generation.DropInPaths != "" || generation.NeedDaemonReload != "no" {
		return errors.New("CLIProxy service-generation proof is invalid")
	}
	return nil
}

func validateMigrationReceiptServiceGeneration(generation migrationReceiptServiceGeneration) error {
	if validateMigrationReceiptServiceGenerationProperties(generation) != nil || !fingerprintPattern.MatchString(generation.FragmentSHA256) {
		return errors.New("CLIProxy service-generation proof is invalid")
	}
	return nil
}

func migrationReceiptTrustedFragmentPath(path string) bool {
	return path == migrationLiveReceiptFragment || path == migrationLiveReceiptVendorFragment
}

func summarizeProductionMigrationReceiptServiceFragment(installedPath string) (string, error) {
	if !migrationReceiptTrustedFragmentPath(installedPath) {
		return "", errors.New("CLIProxy service unit path is not a trusted production fragment")
	}
	return summarizeMigrationReceiptServiceFragmentAt(installedPath, migrationLiveReceiptReferenceFragment)
}

func summarizeMigrationReceiptServiceFragmentAt(installedPath, referencePath string) (string, error) {
	installedSHA256, err := readProtectedMigrationReceiptServiceFragmentAt(installedPath, 0o644, nil)
	if err != nil {
		return "", fmt.Errorf("read installed CLIProxy service unit: %w", err)
	}
	referenceSHA256, err := readProtectedMigrationReceiptServiceFragmentAt(referencePath, 0o444, nil)
	if err != nil {
		return "", fmt.Errorf("read signed CLIProxy service unit asset: %w", err)
	}
	if installedSHA256 != referenceSHA256 {
		return "", errors.New("installed CLIProxy service unit differs from the signed control release asset")
	}
	return installedSHA256, nil
}

func readProtectedMigrationReceiptServiceFragmentAt(path string, expectedMode uint32, hook migrationReceiptFaultHook) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || (expectedMode != 0o644 && expectedMode != 0o444) {
		return "", errors.New("CLIProxy service unit source contract is invalid")
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open filesystem root for CLIProxy service unit: %w", err)
	}
	defer unix.Close(rootFD)
	open := func() (int, error) {
		fd, openErr := unix.Openat2(rootFD, strings.TrimPrefix(path, string(filepath.Separator)), &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
		if openErr != nil {
			return -1, errors.New("open CLIProxy service unit without following links")
		}
		return fd, nil
	}
	fd, err := open()
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || unsafeMigrationReceiptServiceFragment(before, expectedMode) {
		return "", errors.New("CLIProxy service unit metadata is unsafe")
	}
	if acl, aclErr := migrationReceiptReadACL(fd); aclErr != nil || len(acl) != 0 {
		return "", errors.New("CLIProxy service unit ACL is unsafe")
	}
	payload := make([]byte, int(before.Size))
	for offset := 0; offset < len(payload); {
		read, readErr := unix.Pread(fd, payload[offset:], int64(offset))
		if readErr != nil || read <= 0 {
			return "", errors.New("read CLIProxy service unit safely")
		}
		offset += read
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameMigrationReceiptServiceFragmentStat(before, after) ||
		unsafeMigrationReceiptServiceFragment(after, expectedMode) {
		return "", errors.New("CLIProxy service unit changed while it was read")
	}
	if acl, aclErr := migrationReceiptReadACL(fd); aclErr != nil || len(acl) != 0 {
		return "", errors.New("CLIProxy service unit ACL changed while it was read")
	}
	if err := migrationReceiptHook(hook, "service-fragment-before-path-recheck"); err != nil {
		return "", err
	}
	probeFD, err := open()
	if err != nil {
		return "", errors.New("CLIProxy service unit pathname changed while it was read")
	}
	defer unix.Close(probeFD)
	var named unix.Stat_t
	if err := unix.Fstat(probeFD, &named); err != nil || !sameMigrationReceiptServiceFragmentStat(after, named) ||
		unsafeMigrationReceiptServiceFragment(named, expectedMode) {
		return "", errors.New("CLIProxy service unit pathname changed while it was read")
	}
	if acl, aclErr := migrationReceiptReadACL(probeFD); aclErr != nil || len(acl) != 0 {
		return "", errors.New("CLIProxy service unit pathname ACL changed while it was read")
	}
	return sha256Hex(payload), nil
}

func unsafeMigrationReceiptServiceFragment(stat unix.Stat_t, expectedMode uint32) bool {
	return stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != expectedMode || stat.Nlink != 1 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Size < 1 || stat.Size > migrationLiveReceiptFragmentMaximum
}

func sameMigrationReceiptServiceFragmentStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Nlink == right.Nlink &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size &&
		left.Mtim.Sec == right.Mtim.Sec && left.Mtim.Nsec == right.Mtim.Nsec &&
		left.Ctim.Sec == right.Ctim.Sec && left.Ctim.Nsec == right.Ctim.Nsec
}

func collectMigrationReceiptBoundEvidenceLocked(
	ctx context.Context,
	options LiveVerificationReceiptValidationOptions,
	artifacts migrationArtifacts,
	tenants []stagedMigrationTenant,
) (migrationReceiptBoundEvidence, error) {
	if ctx == nil {
		return migrationReceiptBoundEvidence{}, errors.New("CLIProxy live-verification evidence context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	portal, err := summarizeMigrationReceiptPortal(options.PortalDatabasePath, artifacts.users)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	contract, err := migrationReceiptJSONSHA256(migrationReceiptInputContract{CLIProxy: options.CLIProxy, Policy: options.Policy})
	if err != nil {
		return migrationReceiptBoundEvidence{}, errors.New("encode CLIProxy live-verification input contract")
	}
	pending, err := summarizeMigrationReceiptPending(ctx, options, tenants)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	policyState, err := summarizeMigrationReceiptPolicyState(options.CLIProxy.PolicyStateFile)
	if err != nil {
		return migrationReceiptBoundEvidence{}, err
	}
	return migrationReceiptBoundEvidence{
		migrationReceiptEvidence: migrationReceiptEvidence{
			Report: migrationReceiptReport{
				Path: options.ReportPath, SHA256: artifacts.reportSHA256,
				SourceFingerprint: artifacts.report.SourceFingerprint,
				OutputFingerprint: artifacts.report.OutputFingerprint,
			},
			Plan:   migrationReceiptPlan{Path: options.PlanPath, SHA256: artifacts.planSHA256},
			Portal: portal, PendingBundles: pending, PolicyState: policyState,
		},
		InputContract: contract,
	}, nil
}

func summarizeMigrationReceiptPortal(path string, users []portalMigrationUser) (migrationReceiptPortal, error) {
	if !validMigrationReceiptInputPath(path) || len(users) < 1 || len(users) > migrationLiveReceiptMaxTenants {
		return migrationReceiptPortal{}, errors.New("migrated Portal receipt catalog is invalid")
	}
	identities := make([]migrationReceiptPortalIdentity, len(users))
	for index, user := range users {
		identities[index] = migrationReceiptPortalIdentity{
			Username: user.Username, UsernameNorm: user.UsernameNorm, TenantID: user.TenantID,
			RuntimeUser: user.RuntimeUser, DataRoot: user.DataRoot, Enabled: user.Enabled,
		}
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].TenantID == identities[j].TenantID {
			return identities[i].UsernameNorm < identities[j].UsernameNorm
		}
		return identities[i].TenantID < identities[j].TenantID
	})
	for index, identity := range identities {
		parsed, err := uuid.Parse(identity.TenantID)
		if err != nil || parsed.String() != identity.TenantID || !migrationUsernamePattern.MatchString(identity.Username) ||
			identity.UsernameNorm == "" || !migrationRuntimePattern.MatchString(identity.RuntimeUser) ||
			!validMigrationReceiptInputPath(identity.DataRoot) || filepath.Base(identity.DataRoot) != identity.TenantID ||
			(index > 0 && identities[index-1].TenantID >= identity.TenantID) {
			return migrationReceiptPortal{}, errors.New("migrated Portal receipt identity is invalid")
		}
	}
	digest, err := migrationReceiptJSONSHA256(identities)
	if err != nil {
		return migrationReceiptPortal{}, err
	}
	return migrationReceiptPortal{DatabasePath: path, Users: len(identities), IdentityCatalogSHA256: digest}, nil
}

func summarizeMigrationReceiptPending(ctx context.Context, options LiveVerificationReceiptValidationOptions, tenants []stagedMigrationTenant) ([]migrationReceiptPending, error) {
	if len(tenants) < 1 || len(tenants) > migrationLiveReceiptMaxTenants {
		return nil, errors.New("CLIProxy live-verification pending tenant catalog is invalid")
	}
	result := make([]migrationReceiptPending, 0, len(tenants))
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if tenant.root == nil || tenant.user.TenantID == "" || filepath.Base(tenant.user.DataRoot) != tenant.user.TenantID {
			return nil, errors.New("CLIProxy live-verification pending tenant is invalid")
		}
		if err := rejectAppliedMigrationMarker(tenant.root); err != nil {
			return nil, err
		}
		payload, bundle, err := readMigrationReceiptPending(tenant)
		if err != nil {
			return nil, err
		}
		expected, expectedErr := modelbootstrap.StateFromPolicy(options.Policy, options.CLIProxy.APIBaseURL, tenant.user.TenantID)
		if expectedErr != nil || !bundle.State.Equal(expected) {
			bundle.Zero()
			clear(payload)
			return nil, errors.New("tenant migration bundle policy does not match live-verification receipt")
		}
		stateHash, hashErr := migrationReceiptJSONSHA256(bundle.State)
		entry := migrationReceiptPending{
			TenantID:     tenant.user.TenantID,
			Path:         filepath.Join(tenant.user.DataRoot, filepath.FromSlash(migrationPendingPath)),
			BundleSHA256: sha256Hex(payload), StateSHA256: stateHash, BundleVersion: bundle.State.FormatVersion,
		}
		bundle.Zero()
		clear(payload)
		if hashErr != nil {
			return nil, hashErr
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TenantID < result[j].TenantID })
	for index := range result {
		if index > 0 && result[index-1].TenantID >= result[index].TenantID {
			return nil, errors.New("CLIProxy live-verification pending tenant catalog is duplicated")
		}
	}
	return result, nil
}

func readMigrationReceiptPending(tenant stagedMigrationTenant) ([]byte, modelbootstrap.Bundle, error) {
	file, err := tenant.root.Open(migrationPendingPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle is unavailable for live-verification receipt")
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSyscallStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxPendingBytes ||
		stat.Nlink != 1 || stat.Uid != tenant.uid || stat.Gid != tenant.gid {
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle metadata is unsafe for live-verification receipt")
	}
	if acl, aclErr := migrationReceiptReadACL(int(file.Fd())); aclErr != nil || len(acl) != 0 {
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle ACL is unsafe for live-verification receipt")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxPendingBytes+1))
	if err != nil || len(payload) < 1 || len(payload) > maxPendingBytes || int64(len(payload)) != stat.Size {
		clear(payload)
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle changed while building live-verification receipt")
	}
	afterInfo, afterErr := file.Stat()
	after, afterOK := infoSyscallStat(afterInfo)
	if afterErr != nil || !afterOK || !sameMigrationReceiptStat(stat, after) {
		clear(payload)
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle changed while building live-verification receipt")
	}
	probe, probeErr := tenant.root.Open(migrationPendingPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if probeErr != nil {
		clear(payload)
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle pathname changed while building live-verification receipt")
	}
	probeInfo, probeStatErr := probe.Stat()
	probeStat, probeOK := infoSyscallStat(probeInfo)
	probeCloseErr := probe.Close()
	if probeStatErr != nil || probeCloseErr != nil || !probeOK || !sameMigrationReceiptStat(after, probeStat) {
		clear(payload)
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle pathname changed while building live-verification receipt")
	}
	var bundle modelbootstrap.Bundle
	if decodeStrictJSON(payload, &bundle) != nil || bundle.ValidateManagedForTenant(tenant.user.TenantID) != nil {
		bundle.Zero()
		clear(payload)
		return nil, modelbootstrap.Bundle{}, errors.New("tenant migration bundle is invalid for live-verification receipt")
	}
	return payload, bundle, nil
}

func summarizeMigrationReceiptPolicyState(path string) (migrationReceiptPolicyState, error) {
	file, before, err := openProtectedMigrationFile(path, maxCLIProxyPolicyStateBytes, false)
	if err != nil {
		return migrationReceiptPolicyState{}, fmt.Errorf("CLIProxy policy state for live-verification receipt: %w", err)
	}
	defer file.Close()
	if before.Nlink != 1 || before.Uid == 0 || before.Gid == 0 {
		return migrationReceiptPolicyState{}, errors.New("CLIProxy policy-state identity is unsafe for live-verification receipt")
	}
	if acl, aclErr := migrationReceiptReadACL(int(file.Fd())); aclErr != nil || len(acl) != 0 {
		return migrationReceiptPolicyState{}, errors.New("CLIProxy policy-state ACL is unsafe for live-verification receipt")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxCLIProxyPolicyStateBytes+1))
	if err != nil || len(payload) < 1 || len(payload) > maxCLIProxyPolicyStateBytes || int64(len(payload)) != before.Size {
		clear(payload)
		return migrationReceiptPolicyState{}, errors.New("CLIProxy policy state changed while building live-verification receipt")
	}
	defer clear(payload)
	afterInfo, afterErr := file.Stat()
	after, afterOK := infoSyscallStat(afterInfo)
	if afterErr != nil || !afterOK || !sameMigrationReceiptStat(unixStatFromSyscall(before), after) ||
		verifyBackupPolicyStateIdentity(path, before) != nil || ValidatePolicyStatePayload(payload) != nil {
		return migrationReceiptPolicyState{}, errors.New("CLIProxy policy state is invalid or changed while building live-verification receipt")
	}
	return migrationReceiptPolicyState{Path: path, SHA256: sha256Hex(payload), Size: before.Size, UID: before.Uid, GID: before.Gid}, nil
}

func infoSyscallStat(info os.FileInfo) (unix.Stat_t, bool) {
	if info == nil {
		return unix.Stat_t{}, false
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return unix.Stat_t{}, false
	}
	return unixStatFromSyscall(*value), true
}

func unixStatFromSyscall(value syscall.Stat_t) unix.Stat_t {
	return unix.Stat_t{
		Dev: value.Dev, Ino: value.Ino, Nlink: value.Nlink, Mode: value.Mode,
		Uid: value.Uid, Gid: value.Gid, Size: value.Size,
		Atim: unix.Timespec{Sec: value.Atim.Sec, Nsec: value.Atim.Nsec},
		Mtim: unix.Timespec{Sec: value.Mtim.Sec, Nsec: value.Mtim.Nsec},
		Ctim: unix.Timespec{Sec: value.Ctim.Sec, Nsec: value.Ctim.Nsec},
	}
}

func canonicalLiveCatalogDigest(catalog map[string]catalogAlias) (string, error) {
	if len(catalog) == 0 || len(catalog) > 100_000 {
		return "", errors.New("CLIProxy live catalog is empty or oversized")
	}
	entries := make([]migrationReceiptCatalogEntry, 0, len(catalog))
	for key, alias := range catalog {
		if key == "" || key != strings.ToLower(alias.Alias) || len(alias.Targets) == 0 {
			return "", errors.New("CLIProxy live catalog contains an invalid identity")
		}
		entries = append(entries, migrationReceiptCatalogEntry{Key: key, Alias: alias})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return migrationReceiptJSONSHA256(entries)
}

func canonicalLiveKeysDigest(keys []listedKey) (string, error) {
	if len(keys) == 0 || len(keys) > 100_000 {
		return "", errors.New("CLIProxy live key catalog is empty or oversized")
	}
	stable := make([]migrationReceiptStableKey, 0, len(keys))
	for _, key := range keys {
		if key.ID == "" {
			return "", errors.New("CLIProxy live key catalog contains an invalid identity")
		}
		models, err := canonicalMigrationReceiptRawList(key.Models)
		if err != nil {
			return "", errors.New("CLIProxy live key model contract is invalid")
		}
		aliases, err := canonicalMigrationReceiptRawList(key.Aliases)
		if err != nil {
			return "", errors.New("CLIProxy live key alias contract is invalid")
		}
		stable = append(stable, migrationReceiptStableKey{
			ID: key.ID, Name: key.Name, Enabled: key.Enabled, KeyPreview: key.KeyPreview, RPM: key.RPM,
			Models: models, Aliases: aliases, DailyLimitUSD: key.DailyLimitUSD, WeeklyLimitUSD: key.WeeklyLimitUSD,
			AllowModelsEndpoint: key.AllowModelsEndpoint,
		})
	}
	sort.Slice(stable, func(i, j int) bool { return stable[i].ID < stable[j].ID })
	for index := 1; index < len(stable); index++ {
		if stable[index-1].ID >= stable[index].ID {
			return "", errors.New("CLIProxy live key catalog contains duplicate identities")
		}
	}
	return migrationReceiptJSONSHA256(stable)
}

func canonicalMigrationReceiptRawList(values []json.RawMessage) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, len(values))
	for index, raw := range values {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, errors.New("JSON contains trailing data")
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		result[index] = canonical
	}
	return result, nil
}

func migrationReceiptJSONSHA256(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(payload), nil
}

func buildMigrationLiveVerificationReceipt(
	receiptPath string,
	now time.Time,
	evidence migrationReceiptBoundEvidence,
) (migrationLiveVerificationReceipt, time.Time, error) {
	now = now.UTC()
	now = time.Unix(0, now.UnixNano()).UTC()
	expires := now.Add(migrationLiveReceiptTTL)
	receiptEvidence := evidence.migrationReceiptEvidence
	receiptEvidence.PendingBundles = append([]migrationReceiptPending(nil), evidence.PendingBundles...)
	receipt := migrationLiveVerificationReceipt{
		SchemaVersion: migrationLiveReceiptSchema, ReceiptPath: receiptPath,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano),
		migrationReceiptEvidence: receiptEvidence,
		CLIProxy: migrationReceiptCLIProxyProof{
			InputContractSHA256: evidence.InputContract,
			LiveCatalogSHA256:   evidence.LiveCatalog,
			LiveKeysSHA256:      evidence.LiveKeys,
			ServiceGeneration:   evidence.ServiceGeneration,
		},
	}
	var err error
	receipt.EvidenceSHA256, err = migrationReceiptEvidenceSHA256(receipt)
	if err != nil {
		return migrationLiveVerificationReceipt{}, time.Time{}, errors.New("encode CLIProxy live-verification receipt evidence")
	}
	if _, _, err := validateMigrationLiveReceipt(receiptPath, receipt); err != nil {
		return migrationLiveVerificationReceipt{}, time.Time{}, err
	}
	return receipt, expires, nil
}

func validateMigrationLiveReceipt(receiptPath string, receipt migrationLiveVerificationReceipt) (time.Time, time.Time, error) {
	invalid := func() (time.Time, time.Time, error) {
		return time.Time{}, time.Time{}, errors.New("CLIProxy live-verification receipt is structurally invalid")
	}
	if !validMigrationLiveReceiptPath(receiptPath) || receipt.SchemaVersion != migrationLiveReceiptSchema || receipt.ReceiptPath != receiptPath ||
		!validMigrationReceiptInputPath(receipt.Report.Path) || !fingerprintPattern.MatchString(receipt.Report.SHA256) ||
		!fingerprintPattern.MatchString(receipt.Report.SourceFingerprint) || !fingerprintPattern.MatchString(receipt.Report.OutputFingerprint) ||
		!validMigrationReceiptInputPath(receipt.Plan.Path) || !fingerprintPattern.MatchString(receipt.Plan.SHA256) ||
		!validMigrationReceiptInputPath(receipt.Portal.DatabasePath) || receipt.Portal.Users < 1 || receipt.Portal.Users > migrationLiveReceiptMaxTenants ||
		!fingerprintPattern.MatchString(receipt.Portal.IdentityCatalogSHA256) || len(receipt.PendingBundles) != receipt.Portal.Users ||
		!validMigrationReceiptInputPath(receipt.PolicyState.Path) || !fingerprintPattern.MatchString(receipt.PolicyState.SHA256) ||
		receipt.PolicyState.Size < 1 || receipt.PolicyState.Size > maxCLIProxyPolicyStateBytes || receipt.PolicyState.UID == 0 || receipt.PolicyState.GID == 0 ||
		!fingerprintPattern.MatchString(receipt.CLIProxy.InputContractSHA256) || !fingerprintPattern.MatchString(receipt.CLIProxy.LiveCatalogSHA256) ||
		!fingerprintPattern.MatchString(receipt.CLIProxy.LiveKeysSHA256) || validateMigrationReceiptServiceGeneration(receipt.CLIProxy.ServiceGeneration) != nil ||
		!fingerprintPattern.MatchString(receipt.EvidenceSHA256) {
		return invalid()
	}
	evidenceSHA256, evidenceErr := migrationReceiptEvidenceSHA256(receipt)
	if evidenceErr != nil || evidenceSHA256 != receipt.EvidenceSHA256 {
		return invalid()
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, receipt.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || issued.Location() != time.UTC || expires.Location() != time.UTC ||
		issued.Format(time.RFC3339Nano) != receipt.IssuedAt || expires.Format(time.RFC3339Nano) != receipt.ExpiresAt ||
		expires.Sub(issued) != migrationLiveReceiptTTL {
		return invalid()
	}
	for index, pending := range receipt.PendingBundles {
		parsed, err := uuid.Parse(pending.TenantID)
		pathSuffix := string(filepath.Separator) + pending.TenantID + string(filepath.Separator) + filepath.FromSlash(migrationPendingPath)
		if err != nil || parsed.String() != pending.TenantID || !validMigrationReceiptInputPath(pending.Path) ||
			!strings.HasSuffix(pending.Path, pathSuffix) || !fingerprintPattern.MatchString(pending.BundleSHA256) ||
			!fingerprintPattern.MatchString(pending.StateSHA256) || pending.BundleVersion != modelbootstrap.FormatVersion ||
			(index > 0 && receipt.PendingBundles[index-1].TenantID >= pending.TenantID) {
			return invalid()
		}
	}
	return issued, expires, nil
}

func compareMigrationReceiptEvidence(receipt migrationLiveVerificationReceipt, evidence migrationReceiptBoundEvidence) error {
	if !reflect.DeepEqual(receipt.Report, evidence.Report) || !reflect.DeepEqual(receipt.Plan, evidence.Plan) ||
		!reflect.DeepEqual(receipt.Portal, evidence.Portal) || !reflect.DeepEqual(receipt.PendingBundles, evidence.PendingBundles) ||
		!reflect.DeepEqual(receipt.PolicyState, evidence.PolicyState) || receipt.CLIProxy.InputContractSHA256 != evidence.InputContract ||
		!reflect.DeepEqual(receipt.CLIProxy.ServiceGeneration, evidence.ServiceGeneration) {
		return errors.New("CLIProxy live-verification receipt inputs have drifted")
	}
	return nil
}

func migrationReceiptEvidenceSHA256(receipt migrationLiveVerificationReceipt) (string, error) {
	receipt.EvidenceSHA256 = ""
	return migrationReceiptJSONSHA256(receipt)
}

func encodeMigrationLiveReceipt(receipt migrationLiveVerificationReceipt) ([]byte, error) {
	payload, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) < 2 || len(payload) > migrationLiveReceiptMaximum {
		return nil, errors.New("CLIProxy live-verification receipt exceeds its size bound")
	}
	return payload, nil
}

func decodeMigrationLiveReceipt(receiptPath string, payload []byte) (migrationLiveVerificationReceipt, error) {
	if len(payload) < 2 || len(payload) > migrationLiveReceiptMaximum {
		return migrationLiveVerificationReceipt{}, errors.New("CLIProxy live-verification receipt size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt migrationLiveVerificationReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return migrationLiveVerificationReceipt{}, errors.New("CLIProxy live-verification receipt JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return migrationLiveVerificationReceipt{}, errors.New("CLIProxy live-verification receipt contains trailing JSON")
	}
	if _, _, err := validateMigrationLiveReceipt(receiptPath, receipt); err != nil {
		return migrationLiveVerificationReceipt{}, err
	}
	canonical, err := encodeMigrationLiveReceipt(receipt)
	if err != nil || !bytes.Equal(payload, canonical) {
		return migrationLiveVerificationReceipt{}, errors.New("CLIProxy live-verification receipt is not canonical JSON")
	}
	return receipt, nil
}

func validMigrationLiveReceiptPath(path string) bool {
	return validMigrationReceiptInputPath(path) && filepath.Base(path) == migrationLiveReceiptName
}

func validMigrationReceiptInputPath(path string) bool {
	return path != "" && len(path) <= 4096 && utf8.ValidString(path) && !strings.ContainsRune(path, 0) &&
		filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

type migrationReceiptOpenedFile struct {
	file    *os.File
	stat    unix.Stat_t
	payload []byte
	receipt migrationLiveVerificationReceipt
}

func (opened *migrationReceiptOpenedFile) close() error {
	if opened == nil || opened.file == nil {
		return nil
	}
	err := opened.file.Close()
	opened.file = nil
	clear(opened.payload)
	opened.payload = nil
	return err
}

type migrationLiveReceiptHandle struct {
	path       string
	parentPath string
	parentFD   int
	parentStat unix.Stat_t
	opened     *migrationReceiptOpenedFile
}

func (handle *migrationLiveReceiptHandle) close() error {
	if handle == nil {
		return nil
	}
	var result error
	if handle.opened != nil {
		result = errors.Join(result, handle.opened.close())
		handle.opened = nil
	}
	if handle.parentFD >= 0 {
		result = errors.Join(result, unix.Close(handle.parentFD))
		handle.parentFD = -1
	}
	return result
}

func (handle *migrationLiveReceiptHandle) revalidate() error {
	if handle == nil || handle.parentFD < 0 || handle.opened == nil {
		return errors.New("CLIProxy live-verification receipt handle is unavailable")
	}
	if err := revalidateMigrationReceiptNamed(handle.parentFD, migrationLiveReceiptName, handle.opened); err != nil {
		return fmt.Errorf("CLIProxy live-verification receipt changed during validation: %w", err)
	}
	if exists, err := migrationReceiptNameExists(handle.parentFD, migrationLiveReceiptStageName); err != nil {
		return err
	} else if exists {
		return errors.New("CLIProxy live-verification receipt has an unfinished staged refresh")
	}
	return revalidateMigrationReceiptParent(handle.parentFD, handle.parentPath, handle.parentStat)
}

func openMigrationLiveReceipt(receiptPath string, rejectStage bool) (*migrationLiveReceiptHandle, migrationLiveVerificationReceipt, []byte, error) {
	parentFD, parentStat, err := openMigrationReceiptParent(receiptPath)
	if err != nil {
		return nil, migrationLiveVerificationReceipt{}, nil, err
	}
	handle := &migrationLiveReceiptHandle{
		path: receiptPath, parentPath: filepath.Dir(receiptPath), parentFD: parentFD, parentStat: parentStat,
	}
	fail := func(err error) (*migrationLiveReceiptHandle, migrationLiveVerificationReceipt, []byte, error) {
		_ = handle.close()
		return nil, migrationLiveVerificationReceipt{}, nil, err
	}
	if rejectStage {
		if exists, inspectErr := migrationReceiptNameExists(parentFD, migrationLiveReceiptStageName); inspectErr != nil {
			return fail(inspectErr)
		} else if exists {
			return fail(errors.New("CLIProxy live-verification receipt has an unfinished staged refresh"))
		}
	}
	opened, err := openMigrationReceiptNamed(parentFD, migrationLiveReceiptName, receiptPath)
	if err != nil {
		return fail(err)
	}
	handle.opened = opened
	if rejectStage {
		if exists, inspectErr := migrationReceiptNameExists(parentFD, migrationLiveReceiptStageName); inspectErr != nil {
			return fail(inspectErr)
		} else if exists {
			return fail(errors.New("CLIProxy live-verification receipt staged refresh appeared concurrently"))
		}
	}
	if err := handle.revalidate(); err != nil {
		return fail(err)
	}
	payload := append([]byte(nil), opened.payload...)
	return handle, opened.receipt, payload, nil
}

func openMigrationReceiptParent(receiptPath string) (int, unix.Stat_t, error) {
	if !validMigrationLiveReceiptPath(receiptPath) {
		return -1, unix.Stat_t{}, errors.New("CLIProxy live-verification receipt path is invalid")
	}
	parentPath := filepath.Dir(receiptPath)
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, fmt.Errorf("open filesystem root for CLIProxy live-verification receipt: %w", err)
	}
	defer unix.Close(rootFD)
	relative := strings.TrimPrefix(parentPath, string(filepath.Separator))
	if relative == "" || relative == "." {
		return -1, unix.Stat_t{}, errors.New("CLIProxy live-verification receipt parent is invalid")
	}
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("open CLIProxy live-verification receipt parent without following links")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || unsafeMigrationReceiptParent(stat) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("CLIProxy live-verification receipt parent must be root:root mode 0700")
	}
	return fd, stat, nil
}

func unsafeMigrationReceiptParent(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != 0 || stat.Gid != 0
}

func revalidateMigrationReceiptParent(parentFD int, parentPath string, expected unix.Stat_t) error {
	var opened unix.Stat_t
	if err := unix.Fstat(parentFD, &opened); err != nil || unsafeMigrationReceiptParent(opened) ||
		opened.Dev != expected.Dev || opened.Ino != expected.Ino || opened.Mode != expected.Mode || opened.Uid != expected.Uid || opened.Gid != expected.Gid {
		return errors.New("CLIProxy live-verification receipt parent descriptor changed")
	}
	probePath := filepath.Join(parentPath, migrationLiveReceiptName)
	probeFD, probeStat, err := openMigrationReceiptParent(probePath)
	if err != nil {
		return err
	}
	_ = unix.Close(probeFD)
	if probeStat.Dev != opened.Dev || probeStat.Ino != opened.Ino || probeStat.Mode != opened.Mode || probeStat.Uid != opened.Uid || probeStat.Gid != opened.Gid {
		return errors.New("CLIProxy live-verification receipt parent pathname changed")
	}
	return nil
}

func migrationReceiptNameExists(parentFD int, name string) (bool, error) {
	if name != migrationLiveReceiptName && name != migrationLiveReceiptStageName {
		return false, errors.New("CLIProxy live-verification receipt filename is invalid")
	}
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect CLIProxy live-verification receipt pathname: %w", err)
	}
	return true, nil
}

func openMigrationReceiptNamed(parentFD int, name, receiptPath string) (*migrationReceiptOpenedFile, error) {
	if (name != migrationLiveReceiptName && name != migrationLiveReceiptStageName) || !validMigrationLiveReceiptPath(receiptPath) {
		return nil, errors.New("CLIProxy live-verification receipt filename is invalid")
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, errors.New("open CLIProxy live-verification receipt without following links")
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt CLIProxy live-verification receipt")
	}
	fail := func(err error) (*migrationReceiptOpenedFile, error) {
		_ = file.Close()
		return nil, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || unsafeMigrationReceiptFile(opened) {
		return fail(errors.New("CLIProxy live-verification receipt metadata is unsafe"))
	}
	if acl, aclErr := migrationReceiptReadACL(fd); aclErr != nil || len(acl) != 0 {
		return fail(errors.New("CLIProxy live-verification receipt ACL is unsafe"))
	}
	payload := make([]byte, int(opened.Size))
	for offset := 0; offset < len(payload); {
		read, readErr := unix.Pread(fd, payload[offset:], int64(offset))
		if readErr != nil || read <= 0 {
			clear(payload)
			return fail(errors.New("read CLIProxy live-verification receipt safely"))
		}
		offset += read
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameMigrationReceiptStat(opened, after) {
		clear(payload)
		return fail(errors.New("CLIProxy live-verification receipt changed while it was read"))
	}
	var named unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameMigrationReceiptStat(after, named) {
		clear(payload)
		return fail(errors.New("CLIProxy live-verification receipt pathname changed while it was read"))
	}
	receipt, err := decodeMigrationLiveReceipt(receiptPath, payload)
	if err != nil {
		clear(payload)
		return fail(err)
	}
	return &migrationReceiptOpenedFile{file: file, stat: opened, payload: payload, receipt: receipt}, nil
}

func unsafeMigrationReceiptFile(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Size < 1 || stat.Size > migrationLiveReceiptMaximum
}

func sameMigrationReceiptStat(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Nlink == right.Nlink &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size &&
		left.Mtim.Sec == right.Mtim.Sec && left.Mtim.Nsec == right.Mtim.Nsec &&
		left.Ctim.Sec == right.Ctim.Sec && left.Ctim.Nsec == right.Ctim.Nsec
}

func revalidateMigrationReceiptNamed(parentFD int, name string, opened *migrationReceiptOpenedFile) error {
	if opened == nil || opened.file == nil {
		return errors.New("CLIProxy live-verification receipt descriptor is unavailable")
	}
	var descriptor, named unix.Stat_t
	if err := unix.Fstat(int(opened.file.Fd()), &descriptor); err != nil || !sameMigrationReceiptStat(opened.stat, descriptor) || unsafeMigrationReceiptFile(descriptor) {
		return errors.New("CLIProxy live-verification receipt descriptor changed")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameMigrationReceiptStat(descriptor, named) {
		return errors.New("CLIProxy live-verification receipt pathname changed")
	}
	if acl, aclErr := migrationReceiptReadACL(int(opened.file.Fd())); aclErr != nil || len(acl) != 0 {
		return errors.New("CLIProxy live-verification receipt ACL changed")
	}
	return nil
}

func migrationReceiptReadACL(fd int) ([]byte, error) {
	size, err := unix.Fgetxattr(fd, "system.posix_acl_access", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if size <= 0 || size > 64*1024 {
		return nil, errors.New("POSIX ACL is oversized")
	}
	payload := make([]byte, size)
	read, err := unix.Fgetxattr(fd, "system.posix_acl_access", payload)
	if err != nil || read != size {
		return nil, errors.New("POSIX ACL changed while it was read")
	}
	return payload, nil
}

func clearMigrationReceiptACL(fd int) error {
	err := unix.Fremovexattr(fd, "system.posix_acl_access")
	if err == nil || errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return fmt.Errorf("clear CLIProxy live-verification receipt ACL: %w", err)
}

func migrationReceiptHook(hook migrationReceiptFaultHook, point string) error {
	if hook == nil {
		return nil
	}
	if err := hook(point); err != nil {
		return fmt.Errorf("CLIProxy live-verification receipt fault at %s: %w", point, err)
	}
	return nil
}

func writeMigrationLiveVerificationReceiptAt(receiptPath string, receipt migrationLiveVerificationReceipt, hook migrationReceiptFaultHook) error {
	if effectiveUID() != 0 {
		return errors.New("CLIProxy live-verification receipt publication requires root")
	}
	if _, _, err := validateMigrationLiveReceipt(receiptPath, receipt); err != nil {
		return err
	}
	payload, err := encodeMigrationLiveReceipt(receipt)
	if err != nil {
		return err
	}
	defer clear(payload)
	parentFD, parentStat, err := openMigrationReceiptParent(receiptPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	parentPath := filepath.Dir(receiptPath)

	finalExists, err := migrationReceiptNameExists(parentFD, migrationLiveReceiptName)
	if err != nil {
		return err
	}
	var final *migrationReceiptOpenedFile
	if finalExists {
		final, err = openMigrationReceiptNamed(parentFD, migrationLiveReceiptName, receiptPath)
		if err != nil {
			return fmt.Errorf("refuse unsafe existing CLIProxy live-verification receipt: %w", err)
		}
		defer final.close()
	}
	stageExists, err := migrationReceiptNameExists(parentFD, migrationLiveReceiptStageName)
	if err != nil {
		return err
	}
	if stageExists {
		stage, openErr := openMigrationReceiptNamed(parentFD, migrationLiveReceiptStageName, receiptPath)
		if openErr != nil {
			return fmt.Errorf("refuse unsafe staged CLIProxy live-verification receipt: %w", openErr)
		}
		if final != nil {
			openErr = revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptName, final)
		}
		if openErr == nil {
			openErr = revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptStageName, stage)
		}
		if openErr == nil {
			openErr = revalidateMigrationReceiptParent(parentFD, parentPath, parentStat)
		}
		if openErr == nil {
			openErr = unix.Unlinkat(parentFD, migrationLiveReceiptStageName, 0)
		}
		closeErr := stage.close()
		if openErr == nil {
			openErr = unix.Fsync(parentFD)
		}
		if err := errors.Join(openErr, closeErr); err != nil {
			return fmt.Errorf("recover canonical CLIProxy live-verification receipt stage: %w", err)
		}
	}
	if final != nil {
		if err := revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptName, final); err != nil {
			return err
		}
	}
	if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
		return err
	}

	anonymous, err := prepareAnonymousMigrationReceipt(parentFD, payload)
	if err != nil {
		return err
	}
	defer anonymous.close()
	anonFD := int(anonymous.file.Fd())
	if final == nil {
		if err := unix.Linkat(anonFD, "", parentFD, migrationLiveReceiptName, unix.AT_EMPTY_PATH); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return errors.New("CLIProxy live-verification receipt appeared concurrently")
			}
			return fmt.Errorf("publish CLIProxy live-verification receipt without replacement: %w", err)
		}
		if err := refreshMigrationReceiptNamed(parentFD, migrationLiveReceiptName, anonymous); err != nil {
			return err
		}
		if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
			return err
		}
		if err := migrationReceiptHook(hook, "receipt-linked"); err != nil {
			return err
		}
		if err := unix.Fsync(parentFD); err != nil {
			return fmt.Errorf("synchronize CLIProxy live-verification receipt publication: %w", err)
		}
		if err := revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptName, anonymous); err != nil {
			return err
		}
		if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
			return err
		}
		return nil
	}

	if exists, err := migrationReceiptNameExists(parentFD, migrationLiveReceiptStageName); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("CLIProxy live-verification receipt stage appeared concurrently")
	}
	if err := unix.Linkat(anonFD, "", parentFD, migrationLiveReceiptStageName, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("stage CLIProxy live-verification receipt refresh: %w", err)
	}
	if err := refreshMigrationReceiptNamed(parentFD, migrationLiveReceiptStageName, anonymous); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptName, final); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
		return err
	}
	if err := migrationReceiptHook(hook, "stage-linked"); err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, migrationLiveReceiptStageName, parentFD, migrationLiveReceiptName, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("atomically refresh CLIProxy live-verification receipt: %w", err)
	}
	if err := migrationReceiptHook(hook, "exchanged"); err != nil {
		return err
	}
	if err := refreshMigrationReceiptNamed(parentFD, migrationLiveReceiptName, anonymous); err != nil {
		return err
	}
	if err := refreshMigrationReceiptNamed(parentFD, migrationLiveReceiptStageName, final); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
		return err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("synchronize CLIProxy live-verification receipt refresh: %w", err)
	}
	if err := migrationReceiptHook(hook, "exchange-durable"); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptName, anonymous); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptStageName, final); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, migrationLiveReceiptStageName, 0); err != nil {
		return fmt.Errorf("remove displaced CLIProxy live-verification receipt: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("synchronize displaced CLIProxy live-verification receipt removal: %w", err)
	}
	if err := revalidateMigrationReceiptNamed(parentFD, migrationLiveReceiptName, anonymous); err != nil {
		return err
	}
	if err := revalidateMigrationReceiptParent(parentFD, parentPath, parentStat); err != nil {
		return err
	}
	// There is deliberately no fallible hook after the durable cleanup. Every
	// injected refresh failure therefore leaves a canonical stage for recovery.
	return nil
}

func refreshMigrationReceiptNamed(parentFD int, name string, opened *migrationReceiptOpenedFile) error {
	if opened == nil || opened.file == nil {
		return errors.New("CLIProxy live-verification receipt descriptor is unavailable")
	}
	var descriptor, named unix.Stat_t
	if err := unix.Fstat(int(opened.file.Fd()), &descriptor); err != nil || unsafeMigrationReceiptFile(descriptor) {
		return errors.New("CLIProxy live-verification receipt descriptor is unsafe after publication")
	}
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameMigrationReceiptStat(descriptor, named) {
		return errors.New("CLIProxy live-verification receipt pathname differs after publication")
	}
	if acl, aclErr := migrationReceiptReadACL(int(opened.file.Fd())); aclErr != nil || len(acl) != 0 {
		return errors.New("CLIProxy live-verification receipt ACL is unsafe after publication")
	}
	opened.stat = descriptor
	return nil
}

func prepareAnonymousMigrationReceipt(parentFD int, payload []byte) (*migrationReceiptOpenedFile, error) {
	fd, err := unix.Openat(parentFD, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create anonymous CLIProxy live-verification receipt: %w", err)
	}
	file := os.NewFile(uintptr(fd), "anonymous-cliproxy-live-verification-receipt")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt anonymous CLIProxy live-verification receipt")
	}
	fail := func(err error) (*migrationReceiptOpenedFile, error) {
		_ = file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := file.Chown(0, 0); err != nil {
		return fail(err)
	}
	if err := clearMigrationReceiptACL(fd); err != nil {
		return fail(err)
	}
	for offset := 0; offset < len(payload); {
		written, writeErr := file.Write(payload[offset:])
		if writeErr != nil || written <= 0 {
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			return fail(writeErr)
		}
		offset += written
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 ||
		stat.Nlink != 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Size != int64(len(payload)) {
		return fail(errors.New("anonymous CLIProxy live-verification receipt metadata is unsafe"))
	}
	if acl, aclErr := migrationReceiptReadACL(fd); aclErr != nil || len(acl) != 0 {
		return fail(errors.New("anonymous CLIProxy live-verification receipt ACL is unsafe"))
	}
	readback := make([]byte, len(payload))
	for offset := 0; offset < len(readback); {
		read, readErr := unix.Pread(fd, readback[offset:], int64(offset))
		if readErr != nil || read <= 0 {
			clear(readback)
			return fail(errors.New("read anonymous CLIProxy live-verification receipt"))
		}
		offset += read
	}
	if !bytes.Equal(readback, payload) {
		clear(readback)
		return fail(errors.New("anonymous CLIProxy live-verification receipt readback differs"))
	}
	clear(readback)
	return &migrationReceiptOpenedFile{file: file, stat: stat, payload: append([]byte(nil), payload...)}, nil
}
