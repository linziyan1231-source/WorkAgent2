//go:build linux

package serviceaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/edgepublication"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

// PortalEdgeGeneration is the authenticated running identity of
// workagent-portal.service at one point in time.
type PortalEdgeGeneration struct {
	MainPID                       string
	InvocationID                  string
	ActiveEnterTimestampMonotonic string
	FragmentPath                  string
	DropInPaths                   string
	ExecStart                     string
}

// PortalEdgeContentSnapshot binds the protected Portal configuration, policy,
// and brand assets admitted for one edge publication.
type PortalEdgeContentSnapshot struct {
	PortalSHA256   string
	PolicySHA256   string
	BrandSHA256    string
	LogoSHA256     string
	LogoDarkSHA256 string
	FaviconSHA256  string
	AppIconSHA256  string
	PolicyID       string
	BrandID        string
}

func PreparePortalEdgeGeneration(ctx context.Context, portal config.Portal, controller systemdctl.Controller) (PortalEdgeGeneration, error) {
	if ctx == nil || controller == nil {
		return PortalEdgeGeneration{}, errors.New("Portal edge-generation controller is unavailable")
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return PortalEdgeGeneration{}, fmt.Errorf("reload systemd manager before Portal restart: %w", err)
	}
	before, err := CapturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return PortalEdgeGeneration{}, fmt.Errorf("authenticate manager-loaded Portal definition before restart: %w", err)
	}
	if err := WithCleanup(func(cleanupContext context.Context) error {
		return disableCaddyFailClosed(cleanupContext, controller, PropertyNames(false, "caddy.service"), VerifyProductionSource)
	}); err != nil {
		return PortalEdgeGeneration{}, fmt.Errorf("durably quiesce Caddy before Portal generation replacement: %w", err)
	}
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		actionErr := controller.Action(ctx, "restart", "workagent-portal.service")
		after, proofErr := CapturePortalEdgeGeneration(ctx, portal, controller)
		if proofErr == nil && portalGenerationAdvanced(before, after) {
			return after, nil
		}
		failures = append(failures, errors.Join(actionErr, proofErr, errorUnless(portalGenerationAdvanced(before, after), "Portal restart did not enter a new invocation")))
	}
	return PortalEdgeGeneration{}, errors.Join(errors.New("Portal failed to enter a new authenticated generation while Caddy remains durably disabled"), errors.Join(failures...))
}

func portalGenerationAdvanced(before, after PortalEdgeGeneration) bool {
	beforeStamp, beforeErr := strconv.ParseUint(before.ActiveEnterTimestampMonotonic, 10, 64)
	afterStamp, afterErr := strconv.ParseUint(after.ActiveEnterTimestampMonotonic, 10, 64)
	return before.InvocationID != "" && after.InvocationID != "" && before.InvocationID != after.InvocationID && beforeErr == nil && afterErr == nil && afterStamp > beforeStamp
}

func CapturePortalEdgeContent(expected config.Portal) (PortalEdgeContentSnapshot, error) {
	current, err := config.LoadPortal("/etc/workagent/portal.json")
	if err != nil || !reflect.DeepEqual(current, expected) {
		return PortalEdgeContentSnapshot{}, errors.Join(errors.New("Portal configuration changed from the protected command snapshot"), err)
	}
	if err := current.ValidateProductionLayout("/etc/workagent/portal.json"); err != nil {
		return PortalEdgeContentSnapshot{}, err
	}
	if err := admin.VerifyPortalFiles(current, "/etc/workagent/portal.json"); err != nil {
		return PortalEdgeContentSnapshot{}, err
	}
	policy, err := productconfig.LoadPolicy(current.PolicyFile)
	if err != nil {
		return PortalEdgeContentSnapshot{}, err
	}
	brand, err := productconfig.LoadBrand(current.BrandFile)
	if err != nil {
		return PortalEdgeContentSnapshot{}, err
	}
	digests := make(map[string]string, 7)
	for label, path := range map[string]string{"portal": "/etc/workagent/portal.json", "policy": current.PolicyFile, "brand": current.BrandFile} {
		digest, err := release.ProtectedFileSHA256(path, true)
		if err != nil {
			return PortalEdgeContentSnapshot{}, fmt.Errorf("hash protected Portal %s content: %w", label, err)
		}
		digests[label] = digest
	}
	for label, asset := range map[string]string{"logo": "logo", "logo_dark": "logo-dark", "favicon": "favicon", "app_icon": "app-icon"} {
		path, ok := brand.AssetPath(asset)
		if !ok {
			return PortalEdgeContentSnapshot{}, fmt.Errorf("resolve protected Portal brand asset %s", asset)
		}
		digest, err := release.ProtectedFileSHA256(path, true)
		if err != nil {
			return PortalEdgeContentSnapshot{}, fmt.Errorf("hash protected Portal brand asset %s: %w", asset, err)
		}
		digests[label] = digest
	}
	return PortalEdgeContentSnapshot{
		PortalSHA256: digests["portal"], PolicySHA256: digests["policy"], BrandSHA256: digests["brand"], LogoSHA256: digests["logo"],
		LogoDarkSHA256: digests["logo_dark"], FaviconSHA256: digests["favicon"], AppIconSHA256: digests["app_icon"], PolicyID: policy.PolicyID, BrandID: brand.BrandID,
	}, nil
}

func VerifyPortalEdgePublicationReadiness(ctx context.Context, portal config.Portal, controller systemdctl.Controller, expectedPolicyID, expectedBrandID string, expectedGeneration *PortalEdgeGeneration, throughCaddy bool) (PortalEdgeGeneration, error) {
	if ctx == nil || controller == nil {
		return PortalEdgeGeneration{}, errors.New("Portal edge-readiness verifier is unavailable")
	}
	before, err := CapturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return PortalEdgeGeneration{}, err
	}
	if expectedGeneration != nil && before != *expectedGeneration {
		return PortalEdgeGeneration{}, errors.New("Portal service generation changed across edge publication")
	}
	if err := admin.VerifyPortalService(ctx, portal, controller); err != nil {
		return PortalEdgeGeneration{}, err
	}
	publicOrigin, err := url.Parse(portal.Listener.PublicOrigin)
	if err != nil || publicOrigin.Scheme != "https" || publicOrigin.Host == "" || publicOrigin.Path != "" || publicOrigin.RawQuery != "" || publicOrigin.Fragment != "" {
		return PortalEdgeGeneration{}, errors.New("Portal public origin is invalid for edge readiness")
	}
	endpoint := "http://" + portal.Listener.Address + "/readyz"
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext,
		DisableKeepAlives: true,
	}
	if throughCaddy {
		endpoint = strings.TrimSuffix(portal.Listener.PublicOrigin, "/") + "/readyz"
		dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
		transport.DialContext = func(dialContext context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dialContext, "tcp", "127.0.0.1:443")
		}
		transport.ForceAttemptHTTP2 = true
		transport.TLSHandshakeTimeout = 5 * time.Second
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Portal readiness redirected")
		},
	}
	probeContext := ctx
	cancelProbe := func() {}
	if throughCaddy {
		probeContext, cancelProbe = context.WithTimeout(ctx, 2*time.Minute)
	}
	report, probeErr := edgepublication.ProbeReadiness(probeContext, client, endpoint, publicOrigin.Host, !throughCaddy, throughCaddy)
	cancelProbe()
	transport.CloseIdleConnections()
	if probeErr != nil {
		return PortalEdgeGeneration{}, probeErr
	}
	if err := edgepublication.ValidateReadinessReport(report, time.Now().UTC(), expectedPolicyID, expectedBrandID); err != nil {
		return PortalEdgeGeneration{}, err
	}
	after, err := CapturePortalEdgeGeneration(ctx, portal, controller)
	if err != nil {
		return PortalEdgeGeneration{}, err
	}
	if after != before {
		return PortalEdgeGeneration{}, errors.New("Portal service generation or authenticated source changed during readiness proof")
	}
	return after, nil
}

func CapturePortalEdgeGeneration(ctx context.Context, portal config.Portal, controller systemdctl.Controller) (PortalEdgeGeneration, error) {
	// Use the same complete manager command vector as every production
	// service-action proof. A Portal restart is part of edge publication, so a
	// manager-only Exec* or privilege-flag drift must fail before the restart
	// and again on each post-restart/readiness capture even when the signed unit
	// files on disk remain unchanged.
	properties := PropertyNames(false, "workagent-portal.service")
	before, err := controller.Properties(ctx, "workagent-portal.service", properties...)
	if err != nil {
		return PortalEdgeGeneration{}, fmt.Errorf("inspect Portal generation before source authentication: %w", err)
	}
	if err := verifyPortalEdgeManagerContract(before); err != nil {
		return PortalEdgeGeneration{}, err
	}
	if err := VerifyPortalEdgeUnitSourceAt(before, portal, ProductionControlRoot, []string{"/etc/systemd/system", "/usr/lib/systemd/system"}, "/etc/systemd/system"); err != nil {
		return PortalEdgeGeneration{}, fmt.Errorf("authenticate Portal unit source: %w", err)
	}
	after, err := controller.Properties(ctx, "workagent-portal.service", properties...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return PortalEdgeGeneration{}, errors.Join(errors.New("Portal generation changed during source authentication"), err)
	}
	stamp, stampErr := strconv.ParseUint(after["ActiveEnterTimestampMonotonic"], 10, 64)
	if after["InvocationID"] == "" || stampErr != nil || stamp == 0 {
		return PortalEdgeGeneration{}, errors.New("Portal service generation identity is unavailable")
	}
	return PortalEdgeGeneration{
		MainPID: after["MainPID"], InvocationID: after["InvocationID"], ActiveEnterTimestampMonotonic: after["ActiveEnterTimestampMonotonic"],
		FragmentPath: after["FragmentPath"], DropInPaths: after["DropInPaths"], ExecStart: after["ExecStart"],
	}, nil
}

func verifyPortalEdgeManagerContract(properties map[string]string) error {
	if err := verifyServiceActionManagerContract("workagent-portal.service", properties); err != nil {
		return fmt.Errorf("Portal manager-loaded definition is not the complete signed production contract: %w", err)
	}
	if properties["UnitFileState"] != "enabled" || !ServiceRunning(properties) {
		return errors.New("Portal manager-loaded unit or running generation does not match the signed production contract")
	}
	return nil
}

func VerifyPortalEdgeUnitSourceAt(properties map[string]string, portal config.Portal, controlRoot string, systemdRoots []string, dropInRoot string) error {
	if !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || !filepath.IsAbs(dropInRoot) || filepath.Clean(dropInRoot) != dropInRoot || len(systemdRoots) == 0 {
		return errors.New("Portal source verifier layout is invalid")
	}
	fragmentAccepted := false
	for _, root := range systemdRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return errors.New("Portal systemd source root is invalid")
		}
		if properties["FragmentPath"] == filepath.Join(root, "workagent-portal.service") {
			fragmentAccepted = true
		}
	}
	if !fragmentAccepted {
		return errors.New("Portal fragment path is outside the authenticated systemd namespace")
	}
	fragment := properties["FragmentPath"]
	chatDropIn := filepath.Join(dropInRoot, "workagent-portal.service.d", "chatforward.conf")
	credentialsDropIn := filepath.Join(dropInRoot, "workagent-portal.service.d", "credentials.conf")
	dropIns := strings.Fields(properties["DropInPaths"])
	if len(dropIns) != 2 || !SameExactWords(dropIns, []string{chatDropIn, credentialsDropIn}) {
		return errors.New("Portal drop-in namespace is not exact")
	}
	for _, path := range []string{fragment, chatDropIn, credentialsDropIn} {
		if err := VerifyInstalledSystemdSourceFile(path); err != nil {
			return err
		}
	}
	checks := [][2]string{
		{fragment, filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service")},
		{chatDropIn, filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service.d/chatforward.conf")},
	}
	for _, check := range checks {
		installedDigest, err := release.ProtectedFileSHA256(check[0], true)
		if err != nil {
			return err
		}
		referenceDigest, referenceErr := release.ProtectedFileSHA256(check[1], true)
		if referenceErr != nil || installedDigest != referenceDigest {
			return errors.Join(errors.New("Portal unit source does not match the signed control release"), referenceErr)
		}
	}
	expectedCredentialsDigest, err := PortalCredentialsReferenceDigest(portal, controlRoot)
	if err != nil {
		return err
	}
	installedCredentialsDigest, err := release.ProtectedFileSHA256(credentialsDropIn, true)
	if err != nil || installedCredentialsDigest != expectedCredentialsDigest {
		return errors.Join(errors.New("Portal credential drop-in does not exactly match the signed production template"), err)
	}
	return nil
}

func PortalCredentialsReferenceDigest(portal config.Portal, controlRoot string) (string, error) {
	referencePath := filepath.Join(controlRoot, "share/deploy/systemd/workagent-portal.service.d/credentials.conf.example")
	referenceDigest, err := release.ProtectedFileSHA256(referencePath, true)
	if err != nil {
		return "", err
	}
	payload, err := os.ReadFile(referencePath)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(payload)) != referenceDigest {
		return "", errors.Join(errors.New("Portal credential reference changed while it was read"), err)
	}
	if portal.AdminMasterPasswordHashFile != "" {
		const commented = "# LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred"
		const enabled = "LoadCredentialEncrypted=admin-master-password-hash:/etc/credstore.encrypted/workagent/admin-master-password-hash.cred"
		if bytes.Count(payload, []byte(commented)) != 1 {
			return "", errors.New("Portal credential reference optional administrator line is not exact")
		}
		payload = bytes.Replace(payload, []byte(commented), []byte(enabled), 1)
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload)), nil
}

func SameExactWords(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	wanted := make(map[string]bool, len(expected))
	for _, value := range expected {
		if value == "" || wanted[value] {
			return false
		}
		wanted[value] = true
	}
	for _, value := range actual {
		if !wanted[value] {
			return false
		}
		delete(wanted, value)
	}
	return len(wanted) == 0
}

func VerifyPublishedEdge(ctx context.Context, portal config.Portal, controller systemdctl.Controller, expectedContent PortalEdgeContentSnapshot, portalGeneration PortalEdgeGeneration) (CaddyPublishingGeneration, error) {
	currentContent, err := CapturePortalEdgeContent(portal)
	if err != nil || currentContent != expectedContent {
		return CaddyPublishingGeneration{}, errors.Join(errors.New("protected Portal content changed before live edge proof"), err)
	}
	if err := admin.AssertTenantFileCatalogClean(portal); err != nil {
		return CaddyPublishingGeneration{}, err
	}
	data, err := store.Open(portal.DatabasePath(), portal.AuditPath())
	if err != nil {
		return CaddyPublishingGeneration{}, err
	}
	proofErr := errors.Join(
		admin.VerifyLiveTenantIdentityCatalog(ctx, portal, data),
		admin.VerifyLiveTenantActivationCatalog(ctx, portal, data, controller),
	)
	if err := errors.Join(proofErr, data.Close()); err != nil {
		return CaddyPublishingGeneration{}, fmt.Errorf("tenant catalog changed during edge publication: %w", err)
	}
	caddyBefore, err := captureCaddyPublishingGeneration(ctx, controller, nil)
	if err != nil {
		return CaddyPublishingGeneration{}, err
	}
	if err := VerifyCaddyLiveConfig(ctx, caddyBefore.MainPID); err != nil {
		return CaddyPublishingGeneration{}, fmt.Errorf("Caddy live configuration does not match the signed Caddyfile before TLS proof: %w", err)
	}
	if _, err := VerifyPortalEdgePublicationReadiness(ctx, portal, controller, expectedContent.PolicyID, expectedContent.BrandID, &portalGeneration, true); err != nil {
		return CaddyPublishingGeneration{}, err
	}
	if err := VerifyCaddyLiveConfig(ctx, caddyBefore.MainPID); err != nil {
		return CaddyPublishingGeneration{}, fmt.Errorf("Caddy live configuration changed during TLS proof: %w", err)
	}
	caddyAfter, err := captureCaddyPublishingGeneration(ctx, controller, &caddyBefore)
	if err != nil {
		return CaddyPublishingGeneration{}, err
	}
	if caddyAfter != caddyBefore {
		return CaddyPublishingGeneration{}, errors.New("Caddy generation changed during the live TLS edge-readiness proof")
	}
	currentContent, err = CapturePortalEdgeContent(portal)
	if err != nil || currentContent != expectedContent {
		return CaddyPublishingGeneration{}, errors.Join(errors.New("protected Portal content changed during live edge proof"), err)
	}
	return caddyAfter, nil
}
