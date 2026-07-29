//go:build linux

package serviceaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

const productionCaddyBinarySHA256 = "33cd4c300c46fef824abe017fb3c5698698c41cd7eaf9cf097126d5ac6e4cf4a"

// CaddyPublishingGeneration is the exact guarded start-post Caddy generation
// admitted for edge publication.
type CaddyPublishingGeneration struct {
	MainPID                         string
	ControlPID                      string
	InvocationID                    string
	ExecMainStartTimestampMonotonic string
	FragmentPath                    string
	DropInPaths                     string
	ExecStart                       string
	ExecStartPre                    string
	ExecStartPost                   string
}

// ExecuteCaddyEdgeCommit enables and starts Caddy into its guarded start-post
// publication state while the edge-publication evidence stays authenticated.
func ExecuteCaddyEdgeCommit(ctx context.Context, controller systemdctl.Controller, verifySource SourceVerifier, verifyEvidence EvidenceVerifier) error {
	const unit = "caddy.service"
	if verifyEvidence == nil {
		return errors.New("Caddy edge-evidence verifier is unavailable")
	}
	if err := verifyEvidence(); err != nil {
		return fmt.Errorf("authenticate edge-publication evidence before manager reload: %w", err)
	}
	if err := controller.Action(ctx, "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd manager immediately before Caddy publication: %w", err)
	}
	propertyNames := PropertyNames(false, unit)
	before, err := controller.Properties(ctx, unit, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect Caddy after manager reload: %w", err)
	}
	if err := verifyPrecondition("enable-now", false, before); err != nil {
		return err
	}
	if err := authenticateCaddyState(unit, before, verifySource); err != nil {
		return fmt.Errorf("authenticate Caddy after manager reload: %w", err)
	}
	if before["UnitFileState"] != "disabled" || !UnitStopped(false, before) {
		return errors.New("Caddy publication requires an exactly disabled, inactive, and process-free starting state")
	}
	if err := verifyEvidence(); err != nil {
		return fmt.Errorf("edge-publication evidence changed before durable Caddy enablement: %w", err)
	}
	var enableFailures []error
	var enabled map[string]string
	for attempt := 1; attempt <= 2; attempt++ {
		actionErr := controller.Action(ctx, "enable", unit)
		properties, readErr := controller.Properties(ctx, unit, propertyNames...)
		if readErr == nil {
			authErr := authenticateCaddyState(unit, properties, verifySource)
			stableSource := properties["FragmentPath"] == before["FragmentPath"] && properties["DropInPaths"] == before["DropInPaths"]
			persistedInactive := properties["UnitFileState"] == "enabled" && UnitStopped(false, properties)
			var durabilityErr error
			if authErr == nil && stableSource && persistedInactive {
				durabilityErr = syncCaddyEnablementForAction(true, properties["FragmentPath"])
			}
			if authErr == nil && stableSource && persistedInactive && durabilityErr == nil {
				enabled = properties
				break
			}
			enableFailures = append(enableFailures, errors.Join(actionErr, authErr, durabilityErr, errorUnless(stableSource, "Caddy authenticated source changed while enabling"), errorUnless(persistedInactive, "Caddy did not remain inactive while its durable enablement was committed")))
		} else {
			enableFailures = append(enableFailures, errors.Join(actionErr, readErr))
		}
	}
	if enabled == nil {
		rollbackErr := WithCleanup(func(cleanupContext context.Context) error {
			return disableCaddyFailClosed(cleanupContext, controller, propertyNames, verifySource)
		})
		if rollbackErr == nil {
			return errors.Join(errors.New("Caddy enablement failed and was durably disabled before publication"), errors.Join(enableFailures...))
		}
		return errors.Join(errors.New("Caddy enablement failed and its durable final state is ambiguous"), errors.Join(enableFailures...), rollbackErr)
	}
	if err := verifyEvidence(); err != nil {
		return failCaddyGuardedStart(controller, propertyNames, verifySource, fmt.Errorf("edge-publication evidence changed after durable Caddy enablement: %w", err))
	}
	startErr := controller.Action(ctx, "start", "--no-block", unit)
	var startFailures []error
	for attempt := 1; attempt <= 600; attempt++ {
		properties, readErr := controller.Properties(ctx, unit, propertyNames...)
		if readErr == nil {
			evidenceErr := verifyEvidence()
			authErr := authenticateCaddyState(unit, properties, verifySource)
			stableSource := properties["FragmentPath"] == enabled["FragmentPath"] && properties["DropInPaths"] == enabled["DropInPaths"] && properties["UnitFileState"] == "enabled"
			if evidenceErr != nil || authErr != nil || !stableSource {
				return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy guarded startup lost authenticated source, durable enablement, or publication authority"), startErr, evidenceErr, authErr, errorUnless(stableSource, "Caddy source or durable enablement changed during guarded startup")))
			}
			generation, generationErr := caddyPublishingGenerationFromProperties(properties)
			newInvocation := generationErr == nil && generation.InvocationID != "" && generation.InvocationID != before["InvocationID"]
			if generationErr == nil && newInvocation {
				after, stableErr := controller.Properties(ctx, unit, propertyNames...)
				finalEvidenceErr := verifyEvidence()
				if stableErr == nil && finalEvidenceErr == nil && reflect.DeepEqual(properties, after) {
					return nil
				}
				return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy guarded start-post generation or evidence changed during authentication"), startErr, stableErr, finalEvidenceErr, errorUnless(reflect.DeepEqual(properties, after), "Caddy guarded generation was unstable")))
			}
			if !caddySafePublicationTransition(properties, before, attempt) {
				return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy entered an impossible state before edge-publication commit"), startErr, generationErr, errorUnless(newInvocation, "Caddy guarded invocation identity is invalid")))
			}
			startFailures = append(startFailures, generationErr)
		} else {
			return failCaddyGuardedStart(controller, propertyNames, verifySource, errors.Join(errors.New("Caddy manager state became unreadable after guarded start mutation"), startErr, readErr))
		}
		if attempt < 600 {
			select {
			case <-ctx.Done():
				attempt = 600
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	rollbackErr := WithCleanup(func(cleanupContext context.Context) error {
		return disableCaddyFailClosed(cleanupContext, controller, propertyNames, verifySource)
	})
	if rollbackErr == nil {
		return errors.Join(errors.New("Caddy failed to enter a new authenticated guarded start-post generation and was durably disabled"), startErr, errors.Join(startFailures...))
	}
	return errors.Join(errors.New("Caddy guarded startup failed and its durable final state is ambiguous"), startErr, errors.Join(startFailures...), rollbackErr)
}

func caddySafePublicationTransition(properties, before map[string]string, attempt int) bool {
	if properties["LoadState"] != "loaded" || properties["UnitFileState"] != "enabled" || properties["Result"] != "success" {
		return false
	}
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 31)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 31)
	if mainErr != nil || controlErr != nil {
		return false
	}
	if properties["ActiveState"] == "inactive" && properties["SubState"] == "dead" {
		return attempt <= 20 && mainPID == 0 && controlPID == 0 && properties["InvocationID"] == before["InvocationID"]
	}
	if properties["ActiveState"] != "activating" || properties["InvocationID"] == "" || properties["InvocationID"] == before["InvocationID"] {
		return false
	}
	switch properties["SubState"] {
	case "start-pre":
		return mainPID == 0 && controlPID > 0
	case "start":
		return mainPID > 0
	default:
		return false
	}
}

func failCaddyGuardedStart(controller systemdctl.Controller, propertyNames []string, verifySource SourceVerifier, cause error) error {
	rollbackErr := WithCleanup(func(cleanupContext context.Context) error {
		return disableCaddyFailClosed(cleanupContext, controller, propertyNames, verifySource)
	})
	if rollbackErr == nil {
		return errors.Join(errors.New("Caddy guarded startup was rejected and durably disabled"), cause)
	}
	return errors.Join(errors.New("Caddy guarded startup was rejected and its final state is ambiguous"), cause, rollbackErr)
}

// RollbackPublishedCaddyFailClosed durably disables Caddy under its currently
// authenticated manager contract.
func RollbackPublishedCaddyFailClosed(ctx context.Context, controller systemdctl.Controller) error {
	properties := PropertyNames(false, "caddy.service")
	return disableCaddyFailClosed(ctx, controller, properties, VerifyProductionSource)
}

func disableCaddyFailClosed(ctx context.Context, controller systemdctl.Controller, propertyNames []string, verifySource SourceVerifier) error {
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		before, beforeErr := controller.Properties(ctx, "caddy.service", propertyNames...)
		var beforeAuthErr error
		if beforeErr == nil {
			beforeAuthErr = authenticateCaddyState("caddy.service", before, verifySource)
		}
		actionErr := controller.Action(ctx, "disable", "--now", "caddy.service")
		properties, readErr := controller.Properties(ctx, "caddy.service", propertyNames...)
		if readErr == nil {
			authErr := authenticateCaddyState("caddy.service", properties, verifySource)
			stableSource := beforeErr == nil && before["FragmentPath"] == properties["FragmentPath"] && before["DropInPaths"] == properties["DropInPaths"]
			var durabilityErr error
			if authErr == nil && properties["UnitFileState"] == "disabled" {
				durabilityErr = syncCaddyEnablementForAction(false, properties["FragmentPath"])
			}
			if beforeErr == nil && beforeAuthErr == nil && authErr == nil && stableSource && durabilityErr == nil && properties["UnitFileState"] == "disabled" && UnitStopped(false, properties) {
				after, stableErr := controller.Properties(ctx, "caddy.service", propertyNames...)
				if stableErr == nil && reflect.DeepEqual(properties, after) {
					return nil
				}
				failures = append(failures, errors.Join(actionErr, errors.New("cleanly stopped Caddy changed during fail-closed authentication"), stableErr))
				continue
			}
			if beforeErr == nil && beforeAuthErr == nil && authErr == nil && stableSource && durabilityErr == nil && properties["UnitFileState"] == "disabled" && caddyTerminalProcessFree(properties) {
				resetErr := controller.Action(ctx, "reset-failed", "caddy.service")
				settled, settleErr := controller.Properties(ctx, "caddy.service", propertyNames...)
				settledAuthErr := authenticateCaddyState("caddy.service", settled, verifySource)
				if resetErr == nil && settleErr == nil && settledAuthErr == nil && settled["UnitFileState"] == "disabled" && UnitStopped(false, settled) {
					after, stableErr := controller.Properties(ctx, "caddy.service", propertyNames...)
					if stableErr == nil && reflect.DeepEqual(settled, after) {
						return nil
					}
					failures = append(failures, errors.Join(actionErr, resetErr, errors.New("reset Caddy failure state changed during final authentication"), stableErr))
					continue
				}
				failures = append(failures, errors.Join(actionErr, resetErr, settleErr, settledAuthErr, errors.New("Caddy failure state did not reset to disabled, inactive, and process-free")))
				continue
			}
			failures = append(failures, errors.Join(beforeErr, beforeAuthErr, actionErr, authErr, durabilityErr, errorUnless(stableSource, "Caddy manager source changed during fail-closed disable"), errors.New("Caddy did not read back as authenticated, durably disabled, and inactive")))
		} else {
			failures = append(failures, errors.Join(beforeErr, beforeAuthErr, actionErr, readErr))
		}
	}
	return errors.Join(failures...)
}

func caddyTerminalProcessFree(properties map[string]string) bool {
	if properties["MainPID"] != "0" || properties["ControlPID"] != "0" {
		return false
	}
	return (properties["ActiveState"] == "inactive" && properties["SubState"] == "dead") ||
		(properties["ActiveState"] == "failed" && properties["SubState"] == "failed")
}

var syncCaddyEnablementForAction = syncCaddyPersistentEnablement

func syncCaddyPersistentEnablement(enabled bool, fragmentPath string) error {
	const systemdRoot = "/etc/systemd/system"
	const wantsDirectory = "/etc/systemd/system/multi-user.target.wants"
	const linkPath = wantsDirectory + "/caddy.service"
	if fragmentPath != "/usr/lib/systemd/system/caddy.service" {
		return errors.New("Caddy fragment path is invalid for persistent enablement")
	}
	for _, directory := range []string{systemdRoot, wantsDirectory} {
		info, err := os.Lstat(directory)
		stat, ok := fsutil.InfoSyscallStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o755 || stat.Uid != 0 || stat.Gid != 0 {
			return errors.Join(fmt.Errorf("Caddy enablement directory %s is unsafe", directory), err)
		}
	}
	if err := verifyCaddyEnablementEntry(linkPath, fragmentPath, enabled); err != nil {
		return err
	}
	if err := fsutil.SyncDirectory(wantsDirectory); err != nil {
		return fmt.Errorf("durably sync Caddy enablement directory: %w", err)
	}
	if err := fsutil.SyncDirectory(systemdRoot); err != nil {
		return fmt.Errorf("durably sync systemd configuration directory: %w", err)
	}
	return verifyCaddyEnablementEntry(linkPath, fragmentPath, enabled)
}

func verifyCaddyEnablementEntry(linkPath, fragmentPath string, enabled bool) error {
	info, err := os.Lstat(linkPath)
	if !enabled {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.Join(errors.New("Caddy persistent enablement entry still exists or is unreadable"), err)
	}
	stat, ok := fsutil.InfoSyscallStat(info)
	if err != nil || !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return errors.Join(errors.New("Caddy persistent enablement symlink is unsafe"), err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil || target != fragmentPath {
		return errors.Join(errors.New("Caddy persistent enablement symlink target is not exact"), err)
	}
	return nil
}

func authenticateCaddyState(unit string, properties map[string]string, verifySource SourceVerifier) error {
	return errors.Join(verifySource(unit, properties), verifyCaddyManagerContract(properties))
}

func caddyPublishingGenerationFromProperties(properties map[string]string) (CaddyPublishingGeneration, error) {
	mainPID, mainErr := strconv.ParseUint(properties["MainPID"], 10, 31)
	controlPID, controlErr := strconv.ParseUint(properties["ControlPID"], 10, 31)
	started, startErr := strconv.ParseUint(properties["ExecMainStartTimestampMonotonic"], 10, 64)
	if properties["LoadState"] != "loaded" || properties["UnitFileState"] != "enabled" || properties["ActiveState"] != "activating" || properties["SubState"] != "start-post" ||
		properties["Result"] != "success" || properties["InvocationID"] == "" || mainErr != nil || controlErr != nil || startErr != nil || mainPID == 0 || controlPID == 0 || mainPID == controlPID || started == 0 {
		return CaddyPublishingGeneration{}, errors.New("Caddy did not enter the exact guarded start-post publication state")
	}
	return CaddyPublishingGeneration{
		MainPID: properties["MainPID"], ControlPID: properties["ControlPID"], InvocationID: properties["InvocationID"],
		ExecMainStartTimestampMonotonic: properties["ExecMainStartTimestampMonotonic"], FragmentPath: properties["FragmentPath"], DropInPaths: properties["DropInPaths"],
		ExecStart: properties["ExecStart"], ExecStartPre: properties["ExecStartPre"], ExecStartPost: properties["ExecStartPost"],
	}, nil
}

func captureCaddyPublishingGeneration(ctx context.Context, controller systemdctl.Controller, expected *CaddyPublishingGeneration) (CaddyPublishingGeneration, error) {
	properties := PropertyNames(false, "caddy.service")
	before, err := controller.Properties(ctx, "caddy.service", properties...)
	if err != nil {
		return CaddyPublishingGeneration{}, err
	}
	if err := authenticateCaddyState("caddy.service", before, VerifyProductionSource); err != nil {
		return CaddyPublishingGeneration{}, err
	}
	generation, err := caddyPublishingGenerationFromProperties(before)
	if err != nil {
		return CaddyPublishingGeneration{}, err
	}
	if expected != nil && generation != *expected {
		return CaddyPublishingGeneration{}, errors.New("Caddy publishing generation changed from its authenticated boundary")
	}
	after, err := controller.Properties(ctx, "caddy.service", properties...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return CaddyPublishingGeneration{}, errors.Join(errors.New("Caddy publishing generation changed during source authentication"), err)
	}
	return generation, nil
}

// SettleCommittedCaddyEdge waits for the blocking publication watcher to
// settle the exact committed Caddy generation into active/running.
func SettleCommittedCaddyEdge(ctx context.Context, controller systemdctl.Controller, expected CaddyPublishingGeneration) error {
	if ctx == nil || controller == nil || expected.MainPID == "" || expected.InvocationID == "" {
		return errors.New("Caddy committed-generation settlement boundary is unavailable")
	}
	propertyNames := PropertyNames(false, "caddy.service")
	var failures []error
	for attempt := 1; attempt <= 100; attempt++ {
		properties, err := controller.Properties(ctx, "caddy.service", propertyNames...)
		if err != nil {
			return fmt.Errorf("read Caddy manager state while its committed watcher settled: %w", err)
		}
		authErr := authenticateCaddyState("caddy.service", properties, VerifyProductionSource)
		stamp, stampErr := strconv.ParseUint(properties["ActiveEnterTimestampMonotonic"], 10, 64)
		stable := properties["MainPID"] == expected.MainPID && properties["InvocationID"] == expected.InvocationID &&
			properties["ExecMainStartTimestampMonotonic"] == expected.ExecMainStartTimestampMonotonic && properties["FragmentPath"] == expected.FragmentPath &&
			properties["DropInPaths"] == expected.DropInPaths && properties["ExecStart"] == expected.ExecStart && properties["ExecStartPre"] == expected.ExecStartPre && properties["ExecStartPost"] == expected.ExecStartPost
		if authErr != nil || !stable {
			return errors.Join(errors.New("Caddy generation or authenticated source changed while its committed watcher settled"), authErr, errorUnless(stable, "Caddy committed generation identity changed"))
		}
		settled := properties["LoadState"] == "loaded" && properties["UnitFileState"] == "enabled" && properties["ActiveState"] == "active" && properties["SubState"] == "running" &&
			properties["ControlPID"] == "0" && properties["Result"] == "success" && stampErr == nil && stamp > 0
		if settled {
			after, readErr := controller.Properties(ctx, "caddy.service", propertyNames...)
			if readErr == nil && reflect.DeepEqual(properties, after) {
				return nil
			}
			return errors.Join(errors.New("Caddy settled generation changed during final authentication"), readErr)
		}
		stillGuarded := properties["ActiveState"] == "activating" && properties["SubState"] == "start-post" && properties["ControlPID"] == expected.ControlPID && properties["Result"] == "success"
		if !stillGuarded {
			return errors.New("Caddy left its exact guarded start-post state without settling active/running")
		}
		failures = append(failures, errors.New("Caddy publication watcher is still settling"))
		if attempt < 100 {
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), errors.Join(failures...))
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return errors.Join(errors.New("Caddy publication watcher did not settle the committed generation"), errors.Join(failures...))
}

// VerifyCaddyLiveConfig proves the running Caddy generation serves exactly
// the signed Caddyfile.
func VerifyCaddyLiveConfig(ctx context.Context, expectedPID string) error {
	account, err := user.Lookup("caddy")
	if err != nil {
		return fmt.Errorf("lookup Caddy service identity: %w", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	pid, pidErr := strconv.ParseUint(expectedPID, 10, 31)
	if uidErr != nil || gidErr != nil || pidErr != nil || pid == 0 {
		return errors.New("Caddy service identity or generation PID is invalid")
	}
	return verifyCaddyLiveConfigAt(ctx, "/run/caddy-admin/admin.sock", filepath.Join(ProductionControlRoot, "share/deploy/caddy/Caddyfile"), int32(pid), uint32(uid), uint32(gid))
}

func verifyCaddyLiveConfigAt(ctx context.Context, socketPath, signedCaddyfilePath string, expectedPID int32, expectedUID, expectedGID uint32) error {
	if ctx == nil || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || !filepath.IsAbs(signedCaddyfilePath) || filepath.Clean(signedCaddyfilePath) != signedCaddyfilePath {
		return errors.New("Caddy live-config verifier layout is invalid")
	}
	parentPath := filepath.Dir(socketPath)
	parentInfo, parentErr := os.Lstat(parentPath)
	parentStat, parentOK := fsutil.InfoSyscallStat(parentInfo)
	socketInfo, socketErr := os.Lstat(socketPath)
	socketStat, socketOK := fsutil.InfoSyscallStat(socketInfo)
	if parentErr != nil || !parentOK || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 || parentStat.Uid != expectedUID || parentStat.Gid != expectedGID {
		return errors.Join(errors.New("Caddy protected admin directory is missing or unsafe"), parentErr)
	}
	if socketErr != nil || !socketOK || socketInfo.Mode()&os.ModeSymlink != 0 || socketInfo.Mode()&os.ModeSocket == 0 || socketStat.Uid != expectedUID || socketStat.Gid != expectedGID || socketStat.Nlink != 1 {
		return errors.Join(errors.New("Caddy protected admin socket is missing or unsafe"), socketErr)
	}
	referenceDigest, err := release.ProtectedFileSHA256(signedCaddyfilePath, true)
	if err != nil {
		return err
	}
	caddyfile, err := os.ReadFile(signedCaddyfilePath)
	if err != nil || len(caddyfile) == 0 || len(caddyfile) > 1024*1024 || fmt.Sprintf("%x", sha256.Sum256(caddyfile)) != referenceDigest {
		return errors.Join(errors.New("signed Caddyfile changed while it was read"), err)
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
			connection, err := dialer.DialContext(dialContext, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			if err := verifyUnixPeerCredentials(connection, expectedPID, expectedUID, expectedGID); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return connection, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Caddy admin API redirected")
	}}
	defer transport.CloseIdleConnections()
	adapted, err := requestCaddyAdminJSON(ctx, client, http.MethodPost, "http://localhost/adapt", bytes.NewReader(caddyfile), "text/caddyfile")
	if err != nil {
		return fmt.Errorf("adapt signed Caddyfile through the running Caddy generation: %w", err)
	}
	// The adapt endpoint wraps the configuration in a result envelope;
	// /config/ returns the bare object. Both are canonical JSON.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(adapted, &envelope); err != nil || len(envelope["result"]) == 0 {
		return errors.Join(errors.New("Caddy adapt response is missing its result configuration"), err)
	}
	live, err := requestCaddyAdminJSON(ctx, client, http.MethodGet, "http://localhost/config/", nil, "")
	if err != nil {
		return fmt.Errorf("read running Caddy configuration: %w", err)
	}
	if !bytes.Equal(envelope["result"], live) {
		return errors.New("running Caddy configuration is not semantically equal to the signed Caddyfile")
	}
	parentAfter, parentAfterErr := os.Lstat(parentPath)
	parentAfterStat, parentAfterOK := fsutil.InfoSyscallStat(parentAfter)
	socketAfter, socketAfterErr := os.Lstat(socketPath)
	socketAfterStat, socketAfterOK := fsutil.InfoSyscallStat(socketAfter)
	if parentAfterErr != nil || socketAfterErr != nil || !parentAfterOK || !socketAfterOK || parentAfterStat.Dev != parentStat.Dev || parentAfterStat.Ino != parentStat.Ino || parentAfterStat.Mode != parentStat.Mode || parentAfterStat.Uid != parentStat.Uid || parentAfterStat.Gid != parentStat.Gid || socketAfterStat.Dev != socketStat.Dev || socketAfterStat.Ino != socketStat.Ino || socketAfterStat.Mode != socketStat.Mode || socketAfterStat.Uid != socketStat.Uid || socketAfterStat.Gid != socketStat.Gid || socketAfterStat.Nlink != socketStat.Nlink {
		return errors.New("Caddy admin socket identity changed during live-config proof")
	}
	return nil
}

func verifyUnixPeerCredentials(connection net.Conn, expectedPID int32, expectedUID, expectedGID uint32) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("Caddy admin connection is not a Unix stream")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return err
	}
	var credentials *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil || credentials == nil || credentials.Pid != expectedPID || credentials.Uid != expectedUID || credentials.Gid != expectedGID {
		return errors.Join(errors.New("Caddy admin socket peer is not the authenticated service generation"), controlErr)
	}
	return nil
}

func requestCaddyAdminJSON(ctx context.Context, client *http.Client, method, endpoint string, body io.Reader, contentType string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" || response.ContentLength > 4*1024*1024 || len(response.Header.Values("Warning")) != 0 {
		return nil, errors.New("Caddy admin API did not return an exact JSON success")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil || len(payload) == 0 || len(payload) > 4*1024*1024 {
		return nil, errors.Join(errors.New("Caddy admin JSON response is invalid or oversized"), err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("Caddy admin response is not exactly one JSON value")
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, errors.New("Caddy admin response is not a non-empty configuration object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}
