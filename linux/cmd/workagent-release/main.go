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
	"strings"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/backup"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

type repeatedFlag []string

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
		fatal("usage: workagent-release <keygen|provenance|license-template|manifest|verify|preflight|activate|rollback> [options]")
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "provenance":
		err = provenance(os.Args[2:])
	case "license-template":
		err = licenseTemplate(os.Args[2:])
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
	default:
		fatal("unknown release command")
	}
	if err != nil {
		fatal(err.Error())
	}
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

func licenseTemplate(arguments []string) error {
	flags := commandFlags("license-template")
	componentsPath := flags.String("components", "", "JSON component-list path")
	outputPath := flags.String("output", "", "absolute private review-template output path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !cleanAbsolute(*outputPath) {
		return errors.New("license-template requires a clean absolute --output and no positional arguments")
	}
	components, err := release.LoadComponents(*componentsPath, false)
	if err != nil {
		return err
	}
	value, err := release.NewLicenseReviewTemplate(components)
	if err != nil {
		return err
	}
	if err := release.WriteLicenseReviewTemplate(*outputPath, value); err != nil {
		return err
	}
	return output(map[string]any{"approved": false, "components": len(value.Entries), "created": true, "template": *outputPath})
}

func commandFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func keygen(arguments []string) error {
	flags := commandFlags("keygen")
	publicKey := flags.String("public-key", "", "absolute public verification key path")
	privateKey := flags.String("private-key", "", "absolute private signing key path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := release.GenerateSigningKey(*publicKey, *privateKey); err != nil {
		return err
	}
	return output(map[string]any{"created": true, "public_key": *publicKey, "private_key": *privateKey})
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
	sbom := flags.String("sbom", "sbom.spdx.json", "relative SBOM path")
	provenance := flags.String("provenance", "provenance.json", "relative provenance path")
	licenses := flags.String("licenses", "licenses.json", "relative approved license-report path")
	privateKey := flags.String("private-key", "", "protected private signing key path")
	publicKey := flags.String("public-key", "", "trusted public verification key path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !cleanAbsolute(*root) {
		return errors.New("--root must be a clean absolute path")
	}
	components, err := release.LoadComponents(*componentsPath, true)
	if err != nil {
		return err
	}
	value, err := release.BuildManifest(*root, release.Manifest{
		ReleaseID: *releaseID, SourceRevision: *revision, BuiltAt: time.Now().UTC(), BrandingVersion: *branding, PolicyVersion: *policy,
		ComponentScope: *scope, DataSchemaVersion: *dataSchema, MinimumReadableDataSchema: *minimumReadableDataSchema, MaximumReadableDataSchema: *maximumReadableDataSchema,
		Components: components, SBOMPath: *sbom, ProvenancePath: *provenance, LicenseReportPath: *licenses,
	})
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(*root, "manifest.json")
	signaturePath := filepath.Join(*root, "manifest.sig")
	if err := release.WriteManifest(manifestPath, value); err != nil {
		return err
	}
	if err := release.SignManifest(manifestPath, signaturePath, *privateKey, true); err != nil {
		return err
	}
	verified, err := release.Verify(*root, manifestPath, release.VerifyOptions{
		ExpectedReleaseID: *releaseID, RequireRootOwner: true, RequireSignature: true, SignaturePath: signaturePath, PublicKeyPath: *publicKey,
		AllowedScopes: []string{*scope}, RequiredComponents: release.RequiredComponentsForScope(*scope),
	})
	if err != nil {
		return err
	}
	return output(map[string]any{"created": true, "signed": true, "release_id": verified.Manifest.ReleaseID, "scope": verified.Manifest.ComponentScope, "files": len(verified.Manifest.Files)})
}

type verificationFlags struct {
	root       *string
	releaseID  *string
	publicKey  *string
	scope      *string
	required   repeatedFlag
	releases   *string
	pointer    *string
	manifest   string
	signature  string
	components map[string]string
}

func addVerificationFlags(flags *flag.FlagSet, includeRoot bool) verificationFlags {
	values := verificationFlags{}
	if includeRoot {
		values.root = flags.String("root", "", "immutable release root")
	}
	values.releaseID = flags.String("release-id", "", "expected release identifier")
	values.publicKey = flags.String("public-key", "", "trusted public verification key path")
	values.scope = flags.String("scope", "", "expected component scope")
	flags.Var(&values.required, "required", "required relative release file; repeat as needed")
	return values
}

func verify(arguments []string) error {
	flags := commandFlags("verify")
	values := addVerificationFlags(flags, true)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !cleanAbsolute(*values.root) {
		return errors.New("--root must be a clean absolute path")
	}
	verified, err := verifyRelease(*values.root, *values.releaseID, *values.publicKey, *values.scope, values.required)
	if err != nil {
		return err
	}
	return output(map[string]any{"verified": true, "release_id": verified.Manifest.ReleaseID, "scope": verified.Manifest.ComponentScope, "files": len(verified.Manifest.Files)})
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
	portal, tenantConfigs, err := tenantEvidence(*portalConfigPath)
	if err != nil {
		return err
	}
	if _, err := productconfig.LoadBrand(portal.BrandFile); err != nil {
		return fmt.Errorf("preflight brand check: %w", err)
	}
	if _, err := productconfig.LoadPolicy(portal.PolicyFile); err != nil {
		return fmt.Errorf("preflight policy check: %w", err)
	}
	host, err := hostcheck.Inspect(portal)
	if err != nil || host.Error() != nil {
		return fmt.Errorf("preflight host check: %w", errors.Join(err, host.Error()))
	}
	targetRoot := filepath.Join(*releasesRoot, *values.releaseID)
	if _, err := verifyRelease(targetRoot, *values.releaseID, *values.publicKey, *values.scope, values.required); err != nil {
		return fmt.Errorf("preflight target release check: %w", err)
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
	enabled := 0
	for _, userValue := range users {
		if !userValue.Enabled {
			continue
		}
		enabled++
		path, ok := tenantConfigs[userValue.TenantID]
		if !ok {
			return fmt.Errorf("enabled tenant %s has no configuration", userValue.TenantID)
		}
		tenant, err := config.LoadTenant(path)
		if err != nil || tenant.RuntimeUser != userValue.RuntimeUser || tenant.DataRoot != userValue.DataRoot {
			return fmt.Errorf("preflight tenant %s identity check failed", userValue.TenantID)
		}
		if _, err := admin.VerifyTenantHost(portal, tenant); err != nil {
			return fmt.Errorf("preflight tenant %s host check: %w", userValue.TenantID, err)
		}
	}
	if enabled == 0 {
		return errors.New("preflight found no enabled tenant")
	}
	backupConfiguration, err := backup.LoadConfig(*backupConfigPath)
	if err != nil {
		return err
	}
	if err := backup.VerifyEnvironment(backupConfiguration, true); err != nil {
		return fmt.Errorf("preflight backup destination check: %w", err)
	}
	if err := checkPortalReadiness(portal); err != nil {
		return fmt.Errorf("preflight Portal readiness check: %w", err)
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
	report, err := release.NewPreflightReport(*values.releaseID, currentRelease, *values.scope, *pointerPath, filepath.Join(targetRoot, "manifest.json"), *portalConfigPath, tenantConfigs, maintenanceNotice, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := release.WritePreflight(*outputPath, report); err != nil {
		return err
	}
	return output(map[string]any{"passed": true, "target_release_id": report.TargetReleaseID, "current_release_id": report.CurrentReleaseID, "scope": report.Scope, "expires_at": report.ExpiresAt, "report": *outputPath})
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
	targetManifest := filepath.Join(*releasesRoot, *values.releaseID, "manifest.json")
	if err := release.VerifyPreflight(*preflightPath, *values.releaseID, currentRelease, *values.scope, *pointer, targetManifest, *portalConfigPath, tenantConfigs, time.Now().UTC(), true); err != nil {
		return fmt.Errorf("activation preflight gate failed: %w", err)
	}
	if currentRelease != "" {
		backupConfiguration, err := backup.LoadConfig(*backupConfigPath)
		if err != nil {
			return err
		}
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
	}
	_ = portal
	if err := ensureReleaseFleetStopped(context.Background(), portal, tenantConfigs, *values.scope, systemdctl.Default()); err != nil {
		return fmt.Errorf("activation drain gate failed: %w", err)
	}
	verified, err := release.ActivateVerified(*releasesRoot, *pointer, *values.releaseID, *values.publicKey, release.ResolveOptions{
		Scope: *values.scope, RequiredPaths: values.required, RequireRootOwner: true, RequiredComponents: release.RequiredComponentsForScope(*values.scope), RequireCurrentMatch: true, ExpectedCurrentRelease: currentRelease,
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
	publicKey := flags.String("public-key", "", "trusted public verification key path")
	scope := flags.String("scope", "", "expected component scope")
	portalConfigPath := flags.String("portal-config", "/etc/workagent/portal.json", "Portal configuration path")
	var required repeatedFlag
	flags.Var(&required, "required", "required relative release file; repeat as needed")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if err := validateChannelPaths(*releasesRoot, *pointerPath); err != nil {
		return err
	}
	portal, tenantConfigs, err := tenantEvidence(*portalConfigPath)
	if err != nil {
		return err
	}
	if err := ensureReleaseFleetStopped(context.Background(), portal, tenantConfigs, *scope, systemdctl.Default()); err != nil {
		return fmt.Errorf("rollback drain gate failed: %w", err)
	}
	next, _, err := release.RollbackVerified(*releasesRoot, *pointerPath, *publicKey, release.ResolveOptions{
		Scope: *scope, RequiredPaths: required, RequireRootOwner: true, RequiredComponents: release.RequiredComponentsForScope(*scope),
	}, time.Now().UTC())
	if err != nil {
		return err
	}
	return output(map[string]any{"rolled_back": true, "release_id": next.Current, "previous_release_id": next.Previous, "scope": next.Scope})
}

func ensureReleaseFleetStopped(ctx context.Context, portal config.Portal, tenantConfigs map[string]string, scope string, controller systemdctl.Controller) error {
	if controller == nil {
		return errors.New("systemd controller is required")
	}
	var units []string
	if scope == release.ScopeRuntime || scope == release.ScopeCombined {
		for tenantID := range tenantConfigs {
			units = append(units, "workagent-userhost@"+tenantID+".socket", "workagent-userhost@"+tenantID+".service")
		}
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
	for _, unit := range units {
		properties, err := controller.Properties(ctx, unit, "LoadState", "ActiveState")
		if err != nil {
			return fmt.Errorf("inspect %s: %w", unit, err)
		}
		if properties["LoadState"] != "loaded" {
			return fmt.Errorf("%s is not loaded", unit)
		}
		if state := properties["ActiveState"]; state != "inactive" && state != "failed" {
			return fmt.Errorf("%s is %s; stop affected services (ChatForward browser before bridge) before switching releases", unit, state)
		}
	}
	return nil
}

func verifyRelease(root, releaseID, publicKey, scope string, required []string) (release.Verified, error) {
	if scope == "" || releaseID == "" || !cleanAbsolute(publicKey) {
		return release.Verified{}, errors.New("--release-id, --scope, and a clean absolute --public-key are required")
	}
	return release.Verify(root, filepath.Join(root, "manifest.json"), release.VerifyOptions{
		ExpectedReleaseID: releaseID, RequiredPaths: required, RequireRootOwner: true, RequireSignature: true,
		SignaturePath: filepath.Join(root, "manifest.sig"), PublicKeyPath: publicKey, AllowedScopes: []string{scope}, RequiredComponents: release.RequiredComponentsForScope(scope),
	})
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
	if err := admin.VerifyPortalFiles(portal, portalConfigPath); err != nil {
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
