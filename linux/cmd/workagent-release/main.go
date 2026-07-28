package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fixedroot"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/lifecyclelock"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

type repeatedFlag []string

var trustedExecutingSourceRevision = currentExecutableSourceRevision

func (values *repeatedFlag) String() string { return fmt.Sprint([]string(*values)) }
func (values *repeatedFlag) Set(value string) error {
	if value == "" {
		return errors.New("flag value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: workagent-release <provenance|validate-layout|manifest|verify|preflight|activate|rollback|fixed-install|fixed-rollback|fixed-reconcile> [options]")
	}
	var err error
	switch os.Args[1] {
	case "provenance":
		err = provenance(os.Args[2:])
	case "validate-layout":
		err = validateLayout(os.Args[2:])
	case "manifest":
		err = manifest(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "preflight":
		err = preflight(os.Args[2:])
	case "activate":
		err = activate(os.Args[2:])
	case "rollback":
		err = rollback(os.Args[2:])
	case "fixed-install":
		err = fixedInstall(os.Args[2:])
	case "fixed-rollback":
		err = fixedRollback(os.Args[2:])
	case "fixed-reconcile":
		err = fixedReconcile(os.Args[2:])
	default:
		fatal("unknown release command")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func validateLayout(arguments []string) error {
	flags := commandFlags("validate-layout")
	root := flags.String("root", "", "immutable artifact root")
	profile := flags.String("profile", "", "public or root-only mode profile")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !cleanAbsolute(*root) {
		return errors.New("validate-layout requires a clean absolute --root and no positional arguments")
	}
	if err := release.ValidateFrozenTree(*root, *profile, false); err != nil {
		return err
	}
	return output(map[string]any{"profile": *profile, "root": *root, "validated": true})
}

func provenance(arguments []string) error {
	flags := commandFlags("provenance")
	releaseID := flags.String("release-id", "", "release identifier")
	revision := flags.String("source-revision", "", "clean committed source revision")
	sourceURI := flags.String("source-uri", "", "source material URI")
	builderID := flags.String("builder-id", "", "approved builder identity")
	buildType := flags.String("build-type", "", "approved build recipe identity")
	invocationID := flags.String("invocation-id", "", "unique build invocation identifier")
	componentsPath := flags.String("components", "", "JSON component-list path")
	outputPath := flags.String("output", "", "absolute provenance output path")
	reproducible := flags.Bool("reproducible", false, "attest that independent builds matched")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !cleanAbsolute(*outputPath) {
		return errors.New("provenance requires a clean absolute --output and no positional arguments")
	}
	components, err := release.LoadComponents(*componentsPath, false)
	if err != nil {
		return err
	}
	value, err := release.NewProvenance(*releaseID, *revision, *sourceURI, *builderID, *buildType, *invocationID, *reproducible, components)
	if err != nil {
		return err
	}
	if err := release.WriteProvenance(*outputPath, value); err != nil {
		return err
	}
	return output(map[string]any{"created": true, "reproducible": true, "release_id": value.ReleaseID, "materials": len(value.Materials), "provenance": *outputPath})
}

func commandFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func currentExecutableSourceRevision() (string, error) {
	build, ok := debug.ReadBuildInfo()
	return sourceRevisionFromBuildInfo(build, ok)
}

func sourceRevisionFromBuildInfo(build *debug.BuildInfo, ok bool) (string, error) {
	if !ok || build == nil {
		return "", errors.New("trusted admission executable has no Go build information")
	}
	if build.Path != "github.com/linziyan1231-source/WorkAgent2/linux/cmd/workagent-release" {
		return "", errors.New("trusted admission executable has an unexpected Go main package")
	}
	settings := make(map[string]string)
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs", "vcs.revision", "vcs.modified":
			if _, duplicate := settings[setting.Key]; duplicate {
				return "", fmt.Errorf("trusted admission executable has duplicate %s build evidence", setting.Key)
			}
			settings[setting.Key] = setting.Value
		}
	}
	revision := settings["vcs.revision"]
	if settings["vcs"] != "git" || settings["vcs.modified"] != "false" || len(revision) != 40 {
		return "", errors.New("trusted admission executable is not a clean 40-hex Git build")
	}
	for _, character := range revision {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", errors.New("trusted admission executable Git revision is invalid")
		}
	}
	return revision, nil
}

func manifest(arguments []string) error {
	flags := commandFlags("manifest")
	root := flags.String("root", "", "immutable release root")
	releaseID := flags.String("release-id", "", "release identifier")
	revision := flags.String("source-revision", "", "approved source revision")
	branding := flags.String("branding-version", "", "branding package version")
	policy := flags.String("policy-version", "", "policy package version")
	scope := flags.String("scope", "", "portal, runtime, shared, or combined")
	dataSchema := flags.Int("data-schema-version", 0, "latest data schema written by this release")
	minimumReadableDataSchema := flags.Int("minimum-readable-data-schema", 0, "oldest data schema readable by this release")
	maximumReadableDataSchema := flags.Int("maximum-readable-data-schema", 0, "newest data schema readable by this release")
	componentsPath := flags.String("components", "", "protected JSON component-list path")
	var required repeatedFlag
	flags.Var(&required, "required", "required canonical non-executable consumer file; repeat as needed")
	var requiredExecutable repeatedFlag
	flags.Var(&requiredExecutable, "required-executable", "required canonical executable consumer file; repeat as needed")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !cleanAbsolute(*root) {
		return errors.New("--root must be a clean absolute path")
	}
	executableRevision, err := trustedExecutingSourceRevision()
	if err != nil {
		return fmt.Errorf("manifest admission executable: %w", err)
	}
	if *revision != executableRevision {
		return errors.New("manifest --source-revision does not match the trusted admission executable")
	}
	if err := release.ValidateSignReadyTree(*root, true); err != nil {
		return fmt.Errorf("release tree is not sign-ready: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(*root, "manifest.json")); err == nil {
		return errors.New("release manifest output manifest.json already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	consumerContract, err := release.NewConsumerContract(required, requiredExecutable)
	if err != nil {
		return fmt.Errorf("manifest consumer contract: %w", err)
	}
	components, err := release.LoadComponents(*componentsPath, true)
	if err != nil {
		return err
	}
	if err := release.ValidateAdmissionComponentBaseline(*scope, executableRevision, components); err != nil {
		return fmt.Errorf("manifest component baseline: %w", err)
	}
	value, err := release.BuildManifest(*root, release.Manifest{
		ReleaseID: *releaseID, SourceRevision: *revision, BuiltAt: time.Now().UTC(), BrandingVersion: *branding, PolicyVersion: *policy,
		ComponentScope: *scope, DataSchemaVersion: *dataSchema, MinimumReadableDataSchema: *minimumReadableDataSchema, MaximumReadableDataSchema: *maximumReadableDataSchema,
		Components: components,
	})
	if err != nil {
		return err
	}
	if err := release.ValidateManifestConsumerContract(value, consumerContract); err != nil {
		return err
	}
	manifestPath := filepath.Join(*root, "manifest.json")
	if err := release.WriteManifest(manifestPath, value); err != nil {
		return err
	}
	verified, err := release.Verify(*root, manifestPath, release.VerifyOptions{
		ExpectedReleaseID: *releaseID, ExpectedSourceRevision: executableRevision, RequireRootOwner: true,
		AllowedScopes: []string{*scope}, RequireAdmissionBaseline: true,
		RequiredPaths: consumerContract.RequiredPaths, RequiredExecutablePaths: consumerContract.RequiredExecutablePaths,
	})
	if err != nil {
		return err
	}
	return output(map[string]any{"created": true, "release_id": verified.Manifest.ReleaseID, "scope": verified.Manifest.ComponentScope, "files": len(verified.Manifest.Files)})
}

type verificationFlags struct {
	root               *string
	releaseID          *string
	scope              *string
	required           repeatedFlag
	requiredExecutable repeatedFlag
	releases           *string
	pointer            *string
	manifest           string
	signature          string
	components         map[string]string
}

func addVerificationFlags(flags *flag.FlagSet, includeRoot bool) verificationFlags {
	values := verificationFlags{}
	if includeRoot {
		values.root = flags.String("root", "", "immutable release root")
	}
	values.releaseID = flags.String("release-id", "", "expected release identifier")
	values.scope = flags.String("scope", "", "expected component scope")
	flags.Var(&values.required, "required", "required relative release file; repeat as needed")
	flags.Var(&values.requiredExecutable, "required-executable", "required canonically executable release file; repeat as needed")
	return values
}

func verify(arguments []string) error {
	flags := commandFlags("verify")
	values := addVerificationFlags(flags, true)
	admissionBaseline := flags.Bool("admission-baseline", false, "require the current exact component baseline for a new candidate")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !cleanAbsolute(*values.root) {
		return errors.New("--root must be a clean absolute path")
	}
	verified, err := verifyRelease(*values.root, *values.releaseID, *values.scope, values.required, values.requiredExecutable, *admissionBaseline)
	if err != nil {
		return err
	}
	return output(map[string]any{"verified": true, "release_id": verified.Manifest.ReleaseID, "scope": verified.Manifest.ComponentScope, "files": len(verified.Manifest.Files)})
}

type fixedRootSpec struct {
	scope    string
	contract release.ConsumerContract
}

func productionFixedRootSpec(destination string) (fixedRootSpec, error) {
	var required []string
	var requiredExecutable []string
	var scope string
	switch destination {
	case fixedroot.ControlPath:
		scope = release.ScopePortal
		required = []string{
			"share/deploy/caddy/Caddyfile",
			"share/deploy/systemd/caddy.service",
			"share/deploy/systemd/caddy.service.d/workagent.conf",
			"share/deploy/systemd/cliproxyapi.service",
			"share/deploy/systemd/srv-workagent-users.mount",
			"share/deploy/systemd/workagent-backup.service",
			"share/deploy/systemd/workagent-backup.timer",
			"share/deploy/systemd/workagent-chatforward-browser.service",
			"share/deploy/systemd/workagent-chatforward.service",
			"share/deploy/systemd/workagent-healthcheck.service",
			"share/deploy/systemd/workagent-healthcheck.timer",
			"share/deploy/systemd/workagent-notification.service",
			"share/deploy/systemd/workagent-portal.service",
			"share/deploy/systemd/workagent-portal.service.d/chatforward.conf",
			"share/deploy/systemd/workagent-portal.service.d/credentials.conf.example",
			"share/deploy/systemd/workagent-tenant-catalog-ready.target",
			"share/deploy/systemd/workagent-tenant-config-reconcile.service",
			"share/deploy/systemd/workagent-userhost@.service",
			"share/deploy/systemd/workagent-userhost@.socket",
		}
		requiredExecutable = []string{
			"admin/install-core-activation-admission-v1",
			"admin/install-edge-publication-admission-v1",
			"admin/install-fixed-root-exec-v1",
			"admin/install-recovery-activation-admission-v1",
			"admin/production-host-prepare",
			"admin/production-preflight",
			"admin/smoke-chatforward-browser-sandbox",
			"admin/verify-host-rpms",
			"bin/workagent-admin",
			"bin/workagent-backup",
			"bin/workagent-cliproxy",
			"bin/workagent-healthcheck",
			"bin/workagent-notification",
			"bin/workagent-portal",
			"bin/workagent-provision",
			"bin/workagent-release",
			"bin/workagent-secret",
			"bin/workagent-userhost",
			"share/deploy/libexec/workagent-core-activation-admission-v1",
			"share/deploy/libexec/workagent-edge-publication-admission-v1",
			"share/deploy/libexec/workagent-fixed-root-exec-v1",
			"share/deploy/libexec/workagent-recovery-activation-admission-v1",
		}
	case fixedroot.SharedPath:
		scope = release.ScopeShared
		required = []string{
			"chatforward/app/extension/manifest.json",
			"chatforward/app/src/server.js",
		}
		requiredExecutable = []string{
			"chatforward/integration/login.sh",
			"chatforward/integration/readiness.mjs",
			"chatforward/integration/run-browser.sh",
			"chatforward/integration/run-server.sh",
			"chatforward/node/bin/node",
			"cliproxyapi/bin/cli-proxy-api",
			"cliproxyapi/plugins/cpa-key-policy-v0.4.5.so",
		}
	default:
		return fixedRootSpec{}, errors.New("--destination must be exactly /opt/workagent/control or /opt/workagent/shared")
	}
	contract, err := release.NewConsumerContract(required, requiredExecutable)
	if err != nil {
		return fixedRootSpec{}, fmt.Errorf("fixed-root production consumer contract: %w", err)
	}
	return fixedRootSpec{scope: scope, contract: contract}, nil
}

func fixedInstall(arguments []string) error {
	flags := commandFlags("fixed-install")
	destination := flags.String("destination", "", "exact fixed-root destination")
	stagedRoot := flags.String("staged-root", "", "complete verified sibling stage")
	expectedCurrent := flags.String("expected-current-release", "", "exact current release ID; omit only for first install")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "protected Portal configuration path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("fixed-install does not accept positional arguments")
	}
	verify, drain, err := fixedRootCallbacks(*destination, *portalConfig, *expectedCurrent == "", systemdctl.Default())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	activation, err := acquireCleanReleaseMutation(ctx)
	if err != nil {
		return fmt.Errorf("fixed-root install activation boundary: %w", err)
	}
	defer activation.Close()
	result, err := fixedroot.Install(ctx, fixedroot.InstallOptions{
		Destination: *destination, StagedRoot: *stagedRoot, ExpectedCurrentRelease: *expectedCurrent,
	}, verify, drain)
	if err != nil {
		return err
	}
	return output(result)
}

func fixedRollback(arguments []string) error {
	flags := commandFlags("fixed-rollback")
	destination := flags.String("destination", "", "exact fixed-root destination")
	expectedCurrent := flags.String("expected-current-release", "", "exact current release ID")
	expectedPrevious := flags.String("expected-previous-release", "", "exact previous release ID")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "protected Portal configuration path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("fixed-rollback does not accept positional arguments")
	}
	verify, drain, err := fixedRootCallbacks(*destination, *portalConfig, false, systemdctl.Default())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	activation, err := acquireCleanReleaseMutation(ctx)
	if err != nil {
		return fmt.Errorf("fixed-root rollback activation boundary: %w", err)
	}
	defer activation.Close()
	result, err := fixedroot.Rollback(ctx, fixedroot.RollbackOptions{
		Destination: *destination, ExpectedCurrentRelease: *expectedCurrent, ExpectedPreviousRelease: *expectedPrevious,
	}, verify, drain)
	if err != nil {
		return err
	}
	return output(result)
}

func fixedReconcile(arguments []string) error {
	flags := commandFlags("fixed-reconcile")
	destination := flags.String("destination", "", "exact fixed-root destination")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "protected Portal configuration path")
	initial := flags.Bool("initial", false, "recover only a pending first control-root install before tenant configuration exists")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("fixed-reconcile does not accept positional arguments")
	}
	if *initial && *destination != fixedroot.ControlPath {
		return errors.New("fixed-reconcile --initial is restricted to /opt/workagent/control")
	}
	verify, drain, err := fixedRootCallbacks(*destination, *portalConfig, *initial, systemdctl.Default())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	activation, err := acquireCleanReleaseMutation(ctx)
	if err != nil {
		return fmt.Errorf("fixed-root reconciliation activation boundary: %w", err)
	}
	defer activation.Close()
	var result fixedroot.Result
	if *initial {
		result, err = fixedroot.ReconcileInitial(ctx, *destination, verify, drain)
	} else {
		result, err = fixedroot.Reconcile(ctx, *destination, verify, drain)
	}
	if err != nil {
		return err
	}
	return output(result)
}

func fixedRootCallbacks(destination, portalConfigPath string, initialFleet bool, controller systemdctl.Controller) (fixedroot.VerifyFunc, fixedroot.DrainFunc, error) {
	spec, err := productionFixedRootSpec(destination)
	if err != nil {
		return nil, nil, err
	}
	if controller == nil {
		return nil, nil, errors.New("fixed-root operations require a systemd controller")
	}
	if destination == fixedroot.ControlPath && !initialFleet && !cleanAbsolute(portalConfigPath) {
		return nil, nil, errors.New("control fixed-root operations require a clean absolute --portal-config")
	}
	verify := func(ctx context.Context, root string, candidate bool) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		verified, err := verifyRelease(root, "", spec.scope, spec.contract.RequiredPaths, spec.contract.RequiredExecutablePaths, candidate)
		if err != nil {
			return "", err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return verified.Manifest.ReleaseID, nil
	}
	drain := func(ctx context.Context, callbackDestination string) error {
		if callbackDestination != destination {
			return errors.New("fixed-root drain destination changed")
		}
		tenantConfigs := map[string]string{}
		if destination == fixedroot.ControlPath && !initialFleet {
			_, loaded, err := tenantEvidence(portalConfigPath)
			if err != nil {
				return fmt.Errorf("load protected tenant fleet for fixed-root drain: %w", err)
			}
			tenantConfigs = loaded
		}
		return ensureFixedRootFleetStopped(ctx, destination, tenantConfigs, controller)
	}
	return verify, drain, nil
}

func preflight(arguments []string) error {
	flags := commandFlags("preflight")
	pointerPath := flags.String("pointer", "", "absolute current pointer path")
	releasesRoot := flags.String("releases-root", "", "root containing immutable releases")
	portalConfigPath := flags.String("portal-config", "/etc/workagent/portal.json", "Portal configuration path")
	backupConfigPath := flags.String("backup-config", "/etc/workagent/backup.json", "backup configuration path")
	maintenanceSessionFile := flags.String("maintenance-session-file", "", "protected file containing an authenticated Portal session cookie value")
	outputPath := flags.String("output", "", "protected preflight report path")
	values := addVerificationFlags(flags, false)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateChannelPaths(*releasesRoot, *pointerPath); err != nil {
		return err
	}
	if err := release.ValidateReleaseID(*values.releaseID); err != nil {
		return fmt.Errorf("preflight requires an explicit valid --release-id: %w", err)
	}
	catalog, err := acquireReleaseCatalog(false)
	if err != nil {
		return fmt.Errorf("preflight lifecycle gate: %w", err)
	}
	defer catalog.Close()
	portal, tenantConfigs, err := tenantEvidence(*portalConfigPath)
	if err != nil {
		return err
	}
	consumerContract, err := deriveChannelConsumerContract(portal, tenantConfigs, *releasesRoot, *pointerPath, *values.scope)
	if err != nil {
		return err
	}
	if err := requireSuppliedContractMatch(consumerContract, values.required, values.requiredExecutable); err != nil {
		return err
	}
	brand, err := productconfig.LoadBrand(portal.BrandFile)
	if err != nil {
		return fmt.Errorf("preflight brand check: %w", err)
	}
	policy, err := productconfig.LoadPolicy(portal.PolicyFile)
	if err != nil {
		return fmt.Errorf("preflight policy check: %w", err)
	}
	host, err := hostcheck.Inspect(portal)
	if err != nil || host.Error() != nil {
		return fmt.Errorf("preflight host check: %w", errors.Join(err, host.Error()))
	}
	targetRoot := filepath.Join(*releasesRoot, *values.releaseID)
	target, err := verifyRelease(targetRoot, *values.releaseID, *values.scope, consumerContract.RequiredPaths, consumerContract.RequiredExecutablePaths, true)
	if err != nil {
		return fmt.Errorf("preflight target release check: %w", err)
	}
	if target.Manifest.BrandingVersion != brand.BrandID || target.Manifest.PolicyVersion != policy.PolicyID {
		return errors.New("preflight target release product identities do not match the protected brand and policy")
	}
	currentRelease := ""
	pointer, err := release.LoadProtectedPointer(*pointerPath, true)
	if err == nil {
		if pointer.Scope != *values.scope {
			return errors.New("preflight pointer scope mismatch")
		}
		currentRelease = pointer.Current
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return fmt.Errorf("preflight Portal database check: %w", err)
	}
	users, listErr := data.ListUsers(context.Background())
	closeErr := data.Close()
	if listErr != nil || closeErr != nil {
		return fmt.Errorf("preflight Portal identity check: %w", errors.Join(listErr, closeErr))
	}
	if err := validatePreflightUserSet(users); err != nil {
		return err
	}
	for _, userValue := range users {
		if !userValue.Enabled {
			continue
		}
		path, ok := tenantConfigs[userValue.TenantID]
		if !ok {
			return fmt.Errorf("enabled tenant %s has no configuration", userValue.TenantID)
		}
		tenant, err := config.LoadTenant(path)
		if err != nil || tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
			return fmt.Errorf("preflight tenant %s identity check failed", userValue.TenantID)
		}
		var hostErr error
		if currentRelease == "" {
			_, hostErr = admin.VerifyTenantInfrastructure(portal, tenant)
		} else {
			_, hostErr = admin.VerifyTenantHost(portal, tenant)
		}
		if hostErr != nil {
			return fmt.Errorf("preflight tenant %s host check: %w", userValue.TenantID, hostErr)
		}
	}
	backupConfiguration, err := backup.LoadConfig(*backupConfigPath)
	if err != nil {
		return err
	}
	if err := backup.VerifyEnvironment(backupConfiguration, true); err != nil {
		return fmt.Errorf("preflight backup destination check: %w", err)
	}
	inputs, err := newPreflightInputs(portal, *portalConfigPath, tenantConfigs, *backupConfigPath, backupConfiguration, targetRoot, brand, policy)
	if err != nil {
		return err
	}
	if err := validatePreflightOutputPath(*outputPath, *pointerPath, *maintenanceSessionFile, inputs); err != nil {
		return err
	}
	if currentRelease != "" {
		if err := checkPortalReadiness(portal); err != nil {
			return fmt.Errorf("preflight Portal readiness check: %w", err)
		}
	}
	var maintenanceNotice *release.MaintenanceNotice
	if currentRelease != "" {
		observedAt := time.Now().UTC()
		maintenanceNotice, err = checkMaintenanceNotice(context.Background(), portal, *maintenanceSessionFile, *values.releaseID, observedAt)
		if err != nil {
			return fmt.Errorf("preflight maintenance-notice check: %w", err)
		}
	} else if *maintenanceSessionFile != "" {
		return errors.New("--maintenance-session-file is only valid when upgrading an active release")
	}
	report, err := release.NewPreflightReport(*values.releaseID, currentRelease, *values.scope, *pointerPath, inputs, consumerContract, maintenanceNotice, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := release.WritePreflight(*outputPath, report); err != nil {
		return err
	}
	return output(map[string]any{"passed": true, "target_release_id": report.TargetReleaseID, "current_release_id": report.CurrentReleaseID, "scope": report.Scope, "expires_at": report.ExpiresAt, "report": *outputPath})
}

func validatePreflightUserSet(users []store.User) error {
	enabled, enabledAdmins := 0, 0
	for _, userValue := range users {
		if !userValue.Enabled {
			continue
		}
		enabled++
		if userValue.Admin {
			enabledAdmins++
		}
	}
	if enabled == 0 {
		return errors.New("preflight found no enabled tenant")
	}
	if enabledAdmins == 0 {
		return errors.New("preflight found no enabled administrator")
	}
	return nil
}

func activate(arguments []string) error {
	flags := commandFlags("activate")
	pointer := flags.String("pointer", "", "absolute current pointer path")
	releasesRoot := flags.String("releases-root", "", "root containing immutable releases")
	values := addVerificationFlags(flags, false)
	preflightPath := flags.String("preflight", "", "protected preflight report")
	portalConfigPath := flags.String("portal-config", "/etc/workagent/portal.json", "Portal configuration path")
	backupConfigPath := flags.String("backup-config", "/etc/workagent/backup.json", "backup configuration path")
	backupArchive := flags.String("backup-archive", "", "verified pre-upgrade backup archive")
	backupReceipt := flags.String("backup-receipt", "", "verified pre-upgrade backup receipt")
	initial := flags.Bool("initial", false, "confirm this is the first activation with no prior release")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateChannelPaths(*releasesRoot, *pointer); err != nil {
		return err
	}
	if err := release.ValidateReleaseID(*values.releaseID); err != nil {
		return fmt.Errorf("activation requires an explicit valid --release-id: %w", err)
	}
	activation, err := acquireCleanReleaseMutationWithTimeout()
	if err != nil {
		return fmt.Errorf("activation global lifecycle gate: %w", err)
	}
	defer activation.Close()
	catalog, err := acquireReleaseCatalog(true)
	if err != nil {
		return fmt.Errorf("activation lifecycle gate: %w", err)
	}
	defer catalog.Close()
	currentRelease := ""
	currentPointer, pointerErr := release.LoadProtectedPointer(*pointer, true)
	if pointerErr == nil {
		if *initial {
			return errors.New("--initial cannot be used when an active release already exists")
		}
		if currentPointer.Scope != *values.scope {
			return errors.New("active release scope does not match the activation request")
		}
		currentRelease = currentPointer.Current
	} else if errors.Is(pointerErr, os.ErrNotExist) {
		if !*initial {
			return errors.New("first activation requires --initial")
		}
	} else {
		return pointerErr
	}
	portal, tenantConfigs, err := tenantEvidence(*portalConfigPath)
	if err != nil {
		return err
	}
	consumerContract, err := deriveChannelConsumerContract(portal, tenantConfigs, *releasesRoot, *pointer, *values.scope)
	if err != nil {
		return err
	}
	if err := requireSuppliedContractMatch(consumerContract, values.required, values.requiredExecutable); err != nil {
		return err
	}
	brand, err := productconfig.LoadBrand(portal.BrandFile)
	if err != nil {
		return err
	}
	policy, err := productconfig.LoadPolicy(portal.PolicyFile)
	if err != nil {
		return err
	}
	backupConfiguration, err := backup.LoadConfig(*backupConfigPath)
	if err != nil {
		return err
	}
	if err := backup.VerifyEnvironment(backupConfiguration, true); err != nil {
		return fmt.Errorf("activation backup destination check: %w", err)
	}
	targetRoot := filepath.Join(*releasesRoot, *values.releaseID)
	inputs, err := newPreflightInputs(portal, *portalConfigPath, tenantConfigs, *backupConfigPath, backupConfiguration, targetRoot, brand, policy)
	if err != nil {
		return err
	}
	if err := release.VerifyPreflight(*preflightPath, *values.releaseID, currentRelease, *values.scope, *pointer, inputs, consumerContract, time.Now().UTC(), true); err != nil {
		return fmt.Errorf("activation preflight gate failed: %w", err)
	}
	if currentRelease != "" {
		key, err := backup.LoadKey(backupConfiguration.EncryptionKey, true)
		if err != nil {
			return err
		}
		backupManifest, verifyErr := backup.VerifyFiles(*backupArchive, *backupReceipt, key, true)
		clear(key)
		if verifyErr != nil {
			return fmt.Errorf("activation backup gate failed: %w", verifyErr)
		}
		now := time.Now().UTC()
		if backupManifest.CreatedAt.Before(now.Add(-4*time.Hour)) || backupManifest.CreatedAt.After(now.Add(5*time.Minute)) || !backupContainsPointer(backupManifest, *pointer, *values.scope, currentRelease) {
			return errors.New("activation backup is stale or does not capture the current release")
		}
		backupContract, err := backup.BuildActivationBackupContract(*portalConfigPath, backupConfiguration)
		if err != nil {
			return fmt.Errorf("derive activation backup recovery contract: %w", err)
		}
		if err := backup.ValidateActivationBackupManifest(backupManifest, backupContract); err != nil {
			return fmt.Errorf("activation backup is not a complete recovery point: %w", err)
		}
	}
	_ = portal
	if err := ensureReleaseFleetStopped(context.Background(), portal, tenantConfigs, *values.scope, systemdctl.Default()); err != nil {
		return fmt.Errorf("activation drain gate failed: %w", err)
	}
	executableRevision, err := trustedExecutingSourceRevision()
	if err != nil {
		return fmt.Errorf("activation admission executable: %w", err)
	}
	verified, err := release.ActivateVerified(*releasesRoot, *pointer, *values.releaseID, release.ResolveOptions{
		Scope: *values.scope, ExpectedSourceRevision: executableRevision, RequiredPaths: consumerContract.RequiredPaths, RequiredExecutablePaths: consumerContract.RequiredExecutablePaths, RequireRootOwner: true, RequireAdmissionBaseline: true, RequireCurrentMatch: true, ExpectedCurrentRelease: currentRelease,
	}, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("refuse to activate unverified release: %w", err)
	}
	return output(map[string]any{"activated": true, "release_id": verified.Manifest.ReleaseID, "scope": *values.scope})
}

func rollback(arguments []string) error {
	flags := commandFlags("rollback")
	pointerPath := flags.String("pointer", "", "absolute current pointer path")
	releasesRoot := flags.String("releases-root", "", "root containing immutable releases")
	scope := flags.String("scope", "", "expected component scope")
	portalConfigPath := flags.String("portal-config", "/etc/workagent/portal.json", "Portal configuration path")
	var required repeatedFlag
	flags.Var(&required, "required", "required relative release file; repeat as needed")
	var requiredExecutable repeatedFlag
	flags.Var(&requiredExecutable, "required-executable", "required canonically executable release file; repeat as needed")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateChannelPaths(*releasesRoot, *pointerPath); err != nil {
		return err
	}
	activation, err := acquireCleanReleaseMutationWithTimeout()
	if err != nil {
		return fmt.Errorf("rollback global lifecycle gate: %w", err)
	}
	defer activation.Close()
	catalog, err := acquireReleaseCatalog(true)
	if err != nil {
		return fmt.Errorf("rollback lifecycle gate: %w", err)
	}
	defer catalog.Close()
	portal, tenantConfigs, err := tenantEvidence(*portalConfigPath)
	if err != nil {
		return err
	}
	consumerContract, err := deriveChannelConsumerContract(portal, tenantConfigs, *releasesRoot, *pointerPath, *scope)
	if err != nil {
		return err
	}
	if err := requireSuppliedContractMatch(consumerContract, required, requiredExecutable); err != nil {
		return err
	}
	if err := ensureReleaseFleetStopped(context.Background(), portal, tenantConfigs, *scope, systemdctl.Default()); err != nil {
		return fmt.Errorf("rollback drain gate failed: %w", err)
	}
	next, _, err := release.RollbackVerified(*releasesRoot, *pointerPath, release.ResolveOptions{
		Scope: *scope, RequiredPaths: consumerContract.RequiredPaths, RequiredExecutablePaths: consumerContract.RequiredExecutablePaths, RequireRootOwner: true,
	}, time.Now().UTC())
	if err != nil {
		return err
	}
	return output(map[string]any{"rolled_back": true, "release_id": next.Current, "previous_release_id": next.Previous, "scope": next.Scope})
}

func acquireCleanReleaseMutationWithTimeout() (io.Closer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return acquireCleanReleaseMutation(ctx)
}

// acquireCleanReleaseMutation is the outermost A_EX boundary for every
// signed-pointer or fixed-root writer. It prevents a release swap from
// crossing a tenant/recovery activation transaction whose replay semantics
// are implemented by the currently authenticated control binary.
func acquireCleanReleaseMutation(ctx context.Context) (io.Closer, error) {
	return acquireCleanReleaseMutationWith(
		ctx,
		func(ctx context.Context) (io.Closer, error) { return lifecyclelock.AcquireActivationExclusive(ctx) },
		backup.AssertNoPendingRecoveryActivation,
		admin.AssertTenantActivationClean,
	)
}

func acquireCleanReleaseMutationWith(
	ctx context.Context,
	acquire func(context.Context) (io.Closer, error),
	assertRecoveryClean func() error,
	assertTenantClean func() error,
) (io.Closer, error) {
	if ctx == nil {
		return nil, errors.New("release activation context is unavailable")
	}
	if acquire == nil || assertRecoveryClean == nil || assertTenantClean == nil {
		return nil, errors.New("release activation dependencies are unavailable")
	}
	activation, err := acquire(ctx)
	if err != nil {
		return nil, err
	}
	if activation == nil {
		return nil, errors.New("release activation lock returned no guard")
	}
	if err := assertRecoveryClean(); err != nil {
		return nil, errors.Join(err, activation.Close())
	}
	if err := assertTenantClean(); err != nil {
		return nil, errors.Join(err, activation.Close())
	}
	return activation, nil
}

func acquireReleaseCatalog(exclusive bool) (*lifecyclelock.Guard, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if exclusive {
		return lifecyclelock.AcquireCatalogExclusive(ctx)
	}
	return lifecyclelock.AcquireCatalogShared(ctx)
}

func ensureReleaseFleetStopped(ctx context.Context, portal config.Portal, tenantConfigs map[string]string, scope string, controller systemdctl.Controller) error {
	if controller == nil {
		return errors.New("systemd controller is required")
	}
	var units []string
	var tenantUnits []string
	if scope == release.ScopeRuntime || scope == release.ScopeCombined {
		tenantIDs := make([]string, 0, len(tenantConfigs))
		for tenantID := range tenantConfigs {
			tenantIDs = append(tenantIDs, tenantID)
		}
		slices.Sort(tenantIDs)
		for _, tenantID := range tenantIDs {
			tenantUnits = append(tenantUnits, "workagent-userhost@"+tenantID+".socket", "workagent-userhost@"+tenantID+".service")
		}
		units = append(units, tenantUnits...)
	}
	if scope == release.ScopePortal || scope == release.ScopeCombined || (scope == release.ScopeRuntime && portal.Renderer.Scope == release.ScopeRuntime) {
		units = append(units, "workagent-portal.service")
	}
	// ChatForward's browser owns the Chromium process and must be drained
	// before the bridge whenever the shared payload can change. Requiring both
	// units to be inactive here prevents a signed pointer from moving while
	// either process still has the old release open. The ordering is also the
	// operator-facing stop order used by the deployment procedure.
	if scope == release.ScopeShared || scope == release.ScopeCombined {
		units = append(units, "workagent-chatforward-browser.service", "workagent-chatforward.service")
	}
	if scope != release.ScopePortal && scope != release.ScopeRuntime && scope != release.ScopeShared && scope != release.ScopeCombined {
		return errors.New("release scope is invalid")
	}
	if err := ensureCleanlyStoppedUnits(ctx, units, controller); err != nil {
		return err
	}
	if len(tenantUnits) > 0 {
		return ensureExactLoadedTenantUnits(ctx, tenantUnits, controller)
	}
	return nil
}

func ensureFixedRootFleetStopped(ctx context.Context, destination string, tenantConfigs map[string]string, controller systemdctl.Controller) error {
	if controller == nil {
		return errors.New("systemd controller is required")
	}
	var units []string
	var tenantUnits []string
	switch destination {
	case fixedroot.ControlPath:
		// Browser owns Chromium and is deliberately checked before the bridge.
		// These are all persistent consumers of the immutable control root.
		units = []string{
			"caddy.service",
			"workagent-backup.timer",
			"workagent-healthcheck.timer",
			"workagent-chatforward-browser.service",
			"workagent-chatforward.service",
			"cliproxyapi.service",
			"workagent-portal.service",
			"workagent-backup.service",
			"workagent-healthcheck.service",
			"workagent-notification.service",
			"workagent-tenant-catalog-ready.target",
			"workagent-tenant-config-reconcile.service",
		}
		tenantIDs := make([]string, 0, len(tenantConfigs))
		for tenantID := range tenantConfigs {
			tenantIDs = append(tenantIDs, tenantID)
		}
		slices.Sort(tenantIDs)
		for _, tenantID := range tenantIDs {
			tenantUnits = append(tenantUnits, "workagent-userhost@"+tenantID+".socket", "workagent-userhost@"+tenantID+".service")
		}
		units = append(units, tenantUnits...)
	case fixedroot.SharedPath:
		units = []string{
			"workagent-chatforward-browser.service",
			"workagent-chatforward.service",
			"cliproxyapi.service",
		}
	default:
		return errors.New("fixed-root drain destination is invalid")
	}
	requireDisabled := map[string]bool{}
	if destination == fixedroot.ControlPath {
		requireDisabled["caddy.service"] = true
		requireDisabled["workagent-backup.timer"] = true
		requireDisabled["workagent-healthcheck.timer"] = true
	}
	if err := ensureCleanlyStoppedUnitsWithDisabled(ctx, units, requireDisabled, controller); err != nil {
		return err
	}
	if destination == fixedroot.ControlPath {
		// Enumerate even an empty first-install fleet. A loaded tenant instance
		// without protected configuration must never be hidden by an empty map.
		return ensureExactLoadedTenantUnits(ctx, tenantUnits, controller)
	}
	return nil
}

func ensureCleanlyStoppedUnits(ctx context.Context, units []string, controller systemdctl.Controller) error {
	return ensureCleanlyStoppedUnitsWithDisabled(ctx, units, nil, controller)
}

func ensureCleanlyStoppedUnitsWithDisabled(ctx context.Context, units []string, requireDisabled map[string]bool, controller systemdctl.Controller) error {
	if controller == nil {
		return errors.New("systemd controller is required")
	}
	for _, unit := range units {
		isService := strings.HasSuffix(unit, ".service")
		isTimer := strings.HasSuffix(unit, ".timer")
		propertyNames := []string{"LoadState", "ActiveState", "SubState"}
		if isService {
			propertyNames = append(propertyNames, "ControlPID", "Result", "MainPID")
		} else if isTimer {
			propertyNames = append(propertyNames, "Result")
		}
		if requireDisabled[unit] {
			propertyNames = append(propertyNames, "UnitFileState")
		}
		properties, err := controller.Properties(ctx, unit, propertyNames...)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", unit, err)
		}
		if properties["LoadState"] != "loaded" {
			return fmt.Errorf("%s is not loaded", unit)
		}
		if state := properties["ActiveState"]; state != "inactive" {
			return fmt.Errorf("%s is %s; stop affected services (ChatForward browser before bridge) before switching releases", unit, state)
		}
		if properties["SubState"] != "dead" || (isService && (properties["ControlPID"] != "0" || properties["Result"] != "success" || properties["MainPID"] != "0")) ||
			(isTimer && properties["Result"] != "success") {
			return fmt.Errorf("%s is not cleanly drained (substate=%s result=%s main_pid=%s control_pid=%s)", unit, properties["SubState"], properties["Result"], properties["MainPID"], properties["ControlPID"])
		}
		if requireDisabled[unit] && properties["UnitFileState"] != "disabled" {
			return fmt.Errorf("%s remains durably enabled; disable it before switching the signed control root", unit)
		}
	}
	return nil
}

func ensureExactLoadedTenantUnits(ctx context.Context, tenantUnits []string, controller systemdctl.Controller) error {
	lister, ok := controller.(systemdctl.UnitLister)
	if !ok {
		return errors.New("systemd controller cannot enumerate loaded tenant units")
	}
	loaded, err := lister.ListUnits(ctx, "workagent-userhost@*.service", "workagent-userhost@*.socket")
	if err != nil {
		return fmt.Errorf("enumerate loaded tenant units: %w", err)
	}
	expected := make(map[string]bool, len(tenantUnits))
	for _, unit := range tenantUnits {
		expected[unit] = true
	}
	seen := make(map[string]bool, len(loaded))
	for _, unit := range loaded {
		if !expected[unit] {
			return fmt.Errorf("loaded tenant unit %s has no protected tenant configuration", unit)
		}
		seen[unit] = true
	}
	for _, unit := range tenantUnits {
		if !seen[unit] {
			return fmt.Errorf("protected tenant unit %s is not loaded", unit)
		}
	}
	return nil
}

func verifyRelease(root, releaseID, scope string, required, requiredExecutable []string, admissionBaseline bool) (release.Verified, error) {
	if scope == "" {
		return release.Verified{}, errors.New("--scope is required")
	}
	expectedSourceRevision := ""
	if admissionBaseline {
		var err error
		expectedSourceRevision, err = trustedExecutingSourceRevision()
		if err != nil {
			return release.Verified{}, fmt.Errorf("release admission executable: %w", err)
		}
	}
	contract, err := release.NewConsumerContract(required, requiredExecutable)
	if err != nil {
		return release.Verified{}, fmt.Errorf("release verification consumer contract: %w", err)
	}
	return release.Verify(root, filepath.Join(root, "manifest.json"), release.VerifyOptions{
		ExpectedReleaseID: releaseID, ExpectedSourceRevision: expectedSourceRevision, RequiredPaths: contract.RequiredPaths, RequiredExecutablePaths: contract.RequiredExecutablePaths, RequireRootOwner: true,
		AllowedScopes: []string{scope}, RequireAdmissionBaseline: admissionBaseline,
	})
}

func deriveChannelConsumerContract(portal config.Portal, tenantConfigs map[string]string, releasesRoot, pointerPath, scope string) (release.ConsumerContract, error) {
	if err := validateChannelPaths(releasesRoot, pointerPath); err != nil {
		return release.ConsumerContract{}, err
	}
	if scope != release.ScopeRuntime {
		return release.ConsumerContract{}, errors.New("the configured mutable release pointer is restricted to runtime scope")
	}
	required := make(map[string]bool)
	requiredExecutables := make(map[string]bool)
	addRequired := func(path string) { required[filepath.ToSlash(path)] = true }
	addExecutable := func(path string) { requiredExecutables[filepath.ToSlash(path)] = true }

	if !portal.Renderer.Configured() || portal.Renderer.ReleasesRoot != releasesRoot || portal.Renderer.PointerFile != pointerPath || portal.Renderer.Scope != scope {
		return release.ConsumerContract{}, errors.New("activation channel does not exactly match the protected Portal Renderer channel")
	}
	addRequired(filepath.Join(portal.Renderer.RelativeRoot, "index.html"))
	for tenantID, path := range tenantConfigs {
		tenant, err := config.LoadTenant(path)
		if err != nil {
			return release.ConsumerContract{}, fmt.Errorf("load tenant %s consumer contract: %w", tenantID, err)
		}
		if err := admin.ValidateTenantBinding(portal, tenant); err != nil {
			return release.ConsumerContract{}, fmt.Errorf("tenant %s is not bound to the activation channel: %w", tenantID, err)
		}
		for _, value := range tenant.Backend.RequiredReleaseFiles {
			addRequired(value)
		}
		addExecutable(tenant.Backend.Executable)
		if tenant.Backend.Migration.Enabled {
			addExecutable(tenant.Backend.Migration.Executable)
		}
		if tenant.Backend.AgentCLI.BinDirectory != "" {
			addExecutable(tenant.Backend.AgentCLI.CodexExecutable)
			addExecutable(tenant.Backend.AgentCLI.KimiExecutable)
			addExecutable(tenant.Backend.AgentCLI.PythonExecutable)
		}
	}
	requiredList := make([]string, 0, len(required))
	for path := range required {
		requiredList = append(requiredList, path)
	}
	executableList := make([]string, 0, len(requiredExecutables))
	for path := range requiredExecutables {
		executableList = append(executableList, path)
	}
	contract, err := release.NewConsumerContract(requiredList, executableList)
	if err != nil {
		return release.ConsumerContract{}, fmt.Errorf("derive release consumer contract: %w", err)
	}
	return contract, nil
}

func requireSuppliedContractMatch(derived release.ConsumerContract, required, requiredExecutable []string) error {
	if len(required)+len(requiredExecutable) == 0 {
		return nil
	}
	supplied, err := release.NewConsumerContract(required, requiredExecutable)
	if err != nil {
		return err
	}
	if !supplied.Equal(derived) {
		return errors.New("supplied release consumer paths do not exactly match the protected Portal and tenant configuration")
	}
	return nil
}

func validateChannelPaths(releasesRoot, pointer string) error {
	if !cleanAbsolute(releasesRoot) || !cleanAbsolute(pointer) || pointer != filepath.Join(filepath.Dir(releasesRoot), "current.json") {
		return errors.New("release root and pointer paths are not canonical")
	}
	return nil
}

func tenantEvidence(portalConfigPath string) (config.Portal, map[string]string, error) {
	portal, err := config.LoadPortal(portalConfigPath)
	if err != nil {
		return config.Portal{}, nil, err
	}
	if err := verifyReleaseTenantCatalogAdmission(portal, portalConfigPath, admin.VerifyPortalFiles, admin.AssertTenantFileCatalogClean); err != nil {
		return config.Portal{}, nil, err
	}
	entries, err := os.ReadDir(portal.Paths.TenantConfigs)
	if err != nil {
		return config.Portal{}, nil, err
	}
	result := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(portal.Paths.TenantConfigs, entry.Name())
		tenant, err := config.LoadTenant(path)
		if err != nil || entry.Name() != tenant.TenantID+".json" {
			return config.Portal{}, nil, errors.New("tenant configuration set is invalid")
		}
		if err := admin.VerifyTenantConfigPath(portal, tenant, path); err != nil {
			return config.Portal{}, nil, fmt.Errorf("tenant configuration protection %s: %w", entry.Name(), err)
		}
		result[tenant.TenantID] = path
	}
	if len(result) == 0 {
		return config.Portal{}, nil, errors.New("tenant configuration set is empty")
	}
	return portal, result, nil
}

func verifyReleaseTenantCatalogAdmission(
	portal config.Portal,
	portalConfigPath string,
	verifyPortalFiles func(config.Portal, string) error,
	assertTenantFileCatalogClean func(config.Portal) error,
) error {
	if verifyPortalFiles == nil || assertTenantFileCatalogClean == nil {
		return errors.New("release tenant-catalog admission dependencies are unavailable")
	}
	if err := verifyPortalFiles(portal, portalConfigPath); err != nil {
		return err
	}
	if err := assertTenantFileCatalogClean(portal); err != nil {
		return fmt.Errorf("refuse release operation with an uncommitted tenant file catalog: %w", err)
	}
	return nil
}

func newPreflightInputs(portal config.Portal, portalConfigPath string, tenantConfigs map[string]string, backupConfigPath string, backupConfiguration backup.Config, targetRoot string, brand productconfig.Brand, policy productconfig.Policy) (release.PreflightInputs, error) {
	assets := make(map[string]string, 4)
	for _, name := range []string{"app-icon", "favicon", "logo", "logo-dark"} {
		path, ok := brand.AssetPath(name)
		if !ok {
			return release.PreflightInputs{}, fmt.Errorf("brand asset %s is unavailable for release preflight", name)
		}
		assets[name] = path
	}
	inputs := release.PreflightInputs{
		TargetManifestPath: filepath.Join(targetRoot, "manifest.json"),
		PortalConfigPath:   portalConfigPath,
		TenantConfigPaths:  tenantConfigs,
		BackupConfigPath:   backupConfigPath,
		BackupKeyPath:      backupConfiguration.EncryptionKey,
		BrandID:            brand.BrandID,
		BrandConfigPath:    portal.BrandFile,
		BrandAssetPaths:    assets,
		PolicyID:           policy.PolicyID,
		PolicyConfigPath:   portal.PolicyFile,
	}
	if err := inputs.Validate(); err != nil {
		return release.PreflightInputs{}, err
	}
	return inputs, nil
}

type protectedPreflightPath struct {
	label string
	path  string
}

func validatePreflightOutputPath(outputPath, pointerPath, maintenanceSessionPath string, inputs release.PreflightInputs) error {
	if !cleanAbsolute(outputPath) {
		return errors.New("preflight --output must be a clean absolute path")
	}
	if !cleanAbsolute(pointerPath) {
		return errors.New("preflight pointer path is not canonical")
	}
	if err := inputs.Validate(); err != nil {
		return err
	}

	protected := []protectedPreflightPath{
		{label: "release pointer", path: pointerPath},
		{label: "target manifest", path: inputs.TargetManifestPath},
		{label: "Portal config", path: inputs.PortalConfigPath},
		{label: "backup config", path: inputs.BackupConfigPath},
		{label: "backup encryption key", path: inputs.BackupKeyPath},
		{label: "brand config", path: inputs.BrandConfigPath},
		{label: "policy config", path: inputs.PolicyConfigPath},
	}
	for tenantID, path := range inputs.TenantConfigPaths {
		protected = append(protected, protectedPreflightPath{label: "tenant " + tenantID + " config", path: path})
	}
	for name, path := range inputs.BrandAssetPaths {
		protected = append(protected, protectedPreflightPath{label: "brand asset " + name, path: path})
	}
	if maintenanceSessionPath != "" {
		if !cleanAbsolute(maintenanceSessionPath) {
			return errors.New("preflight maintenance session path is not canonical")
		}
		protected = append(protected, protectedPreflightPath{label: "maintenance session", path: maintenanceSessionPath})
	}

	outputCanonical, err := canonicalPotentialPath(outputPath)
	if err != nil {
		return fmt.Errorf("resolve preflight --output: %w", err)
	}
	outputInfo, outputExists, err := statPotentialPath(outputPath)
	if err != nil {
		return fmt.Errorf("inspect preflight --output: %w", err)
	}
	for _, candidate := range protected {
		candidateCanonical, err := canonicalPotentialPath(candidate.path)
		if err != nil {
			return fmt.Errorf("resolve protected %s path: %w", candidate.label, err)
		}
		if outputCanonical == candidateCanonical {
			return fmt.Errorf("preflight --output aliases protected %s path", candidate.label)
		}
		if !outputExists {
			continue
		}
		candidateInfo, candidateExists, err := statPotentialPath(candidate.path)
		if err != nil {
			return fmt.Errorf("inspect protected %s path: %w", candidate.label, err)
		}
		if candidateExists && os.SameFile(outputInfo, candidateInfo) {
			return fmt.Errorf("preflight --output aliases protected %s path", candidate.label)
		}
	}
	if outputCanonical != outputPath {
		return errors.New("preflight --output must not traverse symbolic links")
	}
	if outputExists {
		return errors.New("preflight --output already exists; reports are immutable")
	}
	parentInfo, err := os.Lstat(filepath.Dir(outputPath))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("preflight --output parent is missing or unsafe")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Geteuid()) || (os.Geteuid() == 0 && parentStat.Gid != 0) {
		return errors.New("preflight --output parent must be owned by the invoking trusted identity")
	}
	return nil
}

func statPotentialPath(path string) (os.FileInfo, bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return info, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

func canonicalPotentialPath(path string) (string, error) {
	return canonicalPotentialPathDepth(path, 0)
}

func canonicalPotentialPathDepth(path string, depth int) (string, error) {
	if !cleanAbsolute(path) {
		return "", errors.New("path is not clean and absolute")
	}
	if depth > 255 {
		return "", errors.New("too many symbolic links")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}
			return canonicalPotentialPathDepth(filepath.Clean(target), depth+1)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		return filepath.Clean(resolved), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", err
	}
	resolvedParent, err := canonicalPotentialPathDepth(parent, depth+1)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), nil
}

type localPortalEndpoint struct {
	client         *http.Client
	baseURL        string
	host           string
	forwardedHTTPS bool
}

func newLocalPortalEndpoint(portal config.Portal) (localPortalEndpoint, error) {
	origin, err := url.Parse(portal.Listener.PublicOrigin)
	if err != nil {
		return localPortalEndpoint{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = nil
	scheme := "http"
	host := portal.Listener.Address
	if portal.Listener.Network == "unix" {
		host = "portal"
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", portal.Listener.Address)
		}
	}
	if portal.Listener.TLSCertificateFile != "" {
		scheme = "https"
		certificate, err := os.ReadFile(portal.Listener.TLSCertificateFile)
		if err != nil {
			return localPortalEndpoint{}, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return localPortalEndpoint{}, errors.New("Portal TLS certificate could not be trusted for preflight")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: origin.Hostname()}
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return localPortalEndpoint{client: client, baseURL: scheme + "://" + host, host: origin.Host, forwardedHTTPS: scheme == "http" && portal.Listener.RequireForwardedHTTPS}, nil
}

func (endpoint localPortalEndpoint) request(ctx context.Context, path string) (*http.Request, error) {
	if endpoint.client == nil || !strings.HasPrefix(path, "/") {
		return nil, errors.New("local Portal endpoint is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Host = endpoint.host
	if endpoint.forwardedHTTPS {
		request.Header.Set("X-Forwarded-Proto", "https")
	}
	return request, nil
}

func checkPortalReadiness(portal config.Portal) error {
	endpoint, err := newLocalPortalEndpoint(portal)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := endpoint.request(ctx, "/readyz")
	if err != nil {
		return err
	}
	response, err := endpoint.client.Do(request)
	if err != nil {
		return errors.New("Portal readiness endpoint is unreachable")
	}
	defer response.Body.Close()
	var value struct {
		Ready bool `json:"ready"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1024*1024))
	if response.StatusCode != http.StatusOK || decoder.Decode(&value) != nil || !value.Ready {
		return fmt.Errorf("Portal readiness returned HTTP %d or a not-ready report", response.StatusCode)
	}
	return nil
}

func checkMaintenanceNotice(ctx context.Context, portal config.Portal, sessionFile, targetReleaseID string, observedAt time.Time) (*release.MaintenanceNotice, error) {
	session, err := readMaintenanceSession(sessionFile)
	if err != nil {
		return nil, err
	}
	defer clear(session)
	return checkMaintenanceNoticeWithSession(ctx, portal, session, targetReleaseID, observedAt)
}

func checkMaintenanceNoticeWithSession(ctx context.Context, portal config.Portal, session []byte, targetReleaseID string, observedAt time.Time) (*release.MaintenanceNotice, error) {
	if len(session) < 20 {
		return nil, errors.New("authenticated Portal session is missing")
	}
	endpoint, err := newLocalPortalEndpoint(portal)
	if err != nil {
		return nil, err
	}
	requestContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := endpoint.request(requestContext, "/api/portal/me/notifications")
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.AddCookie(&http.Cookie{Name: portal.Session.CookieName, Value: string(session), Path: "/", Secure: true, HttpOnly: true})
	response, err := endpoint.client.Do(request)
	if err != nil {
		return nil, errors.New("authenticated Portal notification endpoint is unreachable")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(payload) > 64*1024 || response.StatusCode != http.StatusOK {
		clear(payload)
		return nil, fmt.Errorf("authenticated Portal notification endpoint returned HTTP %d or an invalid body", response.StatusCode)
	}
	defer clear(payload)
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Notifications []struct {
				ID          string `json:"id"`
				Title       string `json:"title,omitempty"`
				Message     string `json:"message"`
				PublishedAt string `json:"published_at,omitempty"`
			} `json:"notifications"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !result.Success || len(result.Data.Notifications) > 20 {
		return nil, errors.New("authenticated Portal notification response is invalid")
	}
	expectedID := release.ExpectedMaintenanceNoticeID(targetReleaseID)
	var match *release.MaintenanceNotice
	for _, item := range result.Data.Notifications {
		if item.ID != expectedID || item.Message != release.MaintenanceNoticeMessage {
			continue
		}
		publishedAt, err := time.Parse(time.RFC3339Nano, item.PublishedAt)
		if err != nil {
			return nil, errors.New("maintenance notice published_at must use RFC3339")
		}
		if match != nil {
			return nil, errors.New("authenticated Portal response duplicated the maintenance notice")
		}
		value := release.MaintenanceNotice{ID: item.ID, Message: item.Message, PublishedAt: publishedAt.UTC(), ObservedAt: observedAt.UTC()}
		match = &value
	}
	if match == nil {
		return nil, fmt.Errorf("authenticated Portal response does not contain maintenance notice %s", expectedID)
	}
	if err := match.Validate(targetReleaseID, observedAt); err != nil {
		return nil, err
	}
	return match, nil
}

func readMaintenanceSession(path string) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("--maintenance-session-file must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 20 || info.Size() > 4096 {
		return nil, errors.New("maintenance session file is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("maintenance session file must be root-owned")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("maintenance session file is unreadable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("maintenance session file could not be verified")
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != 0 || opened.Mode().Perm()&0o077 != 0 || !opened.Mode().IsRegular() || opened.Size() < 20 || opened.Size() > 4096 {
		return nil, errors.New("maintenance session file changed during verification")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(payload) > 4096 {
		clear(payload)
		return nil, errors.New("maintenance session file is unreadable or oversized")
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) < 20 || len(payload) > 4096 {
		clear(payload)
		return nil, errors.New("maintenance session value is invalid")
	}
	for _, value := range payload {
		if value < 0x21 || value > 0x7e || value == ';' || value == ',' {
			clear(payload)
			return nil, errors.New("maintenance session value is not a valid cookie value")
		}
	}
	return payload, nil
}

func backupContainsPointer(manifest backup.Manifest, path, scope, current string) bool {
	for _, pointer := range manifest.ReleasePointers {
		if pointer.Path == path && pointer.Scope == scope && pointer.Current == current {
			return true
		}
	}
	return false
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func output(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "workagent-release:", message)
	os.Exit(1)
}
