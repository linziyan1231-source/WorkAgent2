//go:build linux

// Package serviceaction executes the exact allow-listed systemd service
// mutations and Caddy edge-publication orchestration behind workagent-admin.
package serviceaction

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

// ProductionControlRoot is the signed control release root every source
// authentication digest is bound to.
const ProductionControlRoot = "/opt/workagent/control"

// Confirmation is the exact phrase required to publish the Caddy edge.
const Confirmation = "PUBLISH-WORKAGENT-EDGE"

var allowlist = map[string]map[string]bool{
	"cliproxyapi.service":         {"start": true, "stop": true, "restart": true},
	"caddy.service":               {"enable-now": true},
	"workagent-backup.timer":      {"enable-now": true},
	"workagent-healthcheck.timer": {"enable-now": true},
}

// Allowed reports whether the unit/action pair is allow-listed.
func Allowed(unit, action string) bool {
	allowed, ok := allowlist[unit]
	return ok && allowed[action]
}

// ValidateConfirmation enforces the exact edge-publication confirmation,
// which is restricted to Caddy.
func ValidateConfirmation(action, unit, confirm string) error {
	if unit == "caddy.service" {
		if action != "enable-now" || confirm != Confirmation {
			return errors.New("Caddy edge publication requires --confirm " + Confirmation)
		}
		return nil
	}
	if confirm != "" {
		return errors.New("--confirm is restricted to Caddy edge publication")
	}
	return nil
}

// SourceVerifier authenticates a unit's manager-loaded definition and
// installed source.
type SourceVerifier func(string, map[string]string) error

type dependencyVerifier func(context.Context, systemdctl.Controller, string) error

// EvidenceVerifier authenticates in-flight edge-publication crash evidence.
type EvidenceVerifier func() error

// WithCleanup runs a fail-closed cleanup operation under a fresh bounded
// context so a cancelled or expired operation context cannot skip it.
func WithCleanup(operation func(context.Context) error) error {
	if operation == nil {
		return errors.New("service-action cleanup operation is unavailable")
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return operation(cleanupContext)
}

func errorUnless(condition bool, message string) error {
	if condition {
		return nil
	}
	return errors.New(message)
}

// Execute runs an allow-listed service action against the production source
// contract.
func Execute(ctx context.Context, controller systemdctl.Controller, action, unit string) error {
	return executeWithDependencyVerifier(ctx, controller, action, unit, VerifyProductionSource, verifyProductionDependencies)
}

func executeWithVerifier(ctx context.Context, controller systemdctl.Controller, action, unit string, verifySource SourceVerifier) error {
	return executeWithDependencyVerifier(ctx, controller, action, unit, verifySource, nil)
}

func executeWithDependencyVerifier(ctx context.Context, controller systemdctl.Controller, action, unit string, verifySource SourceVerifier, verifyDependencies dependencyVerifier) error {
	if ctx == nil || controller == nil || verifySource == nil {
		return errors.New("service-action controller is unavailable")
	}
	if !Allowed(unit, action) {
		return errors.New("service-action unit/action pair is not allow-listed")
	}
	isTimer := strings.HasSuffix(unit, ".timer")
	if unit == "caddy.service" {
		return ExecuteCaddyEdgeCommit(ctx, controller, verifySource, func() error { return nil })
	}
	propertyNames := PropertyNames(isTimer, unit)
	before, err := controller.Properties(ctx, unit, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect %s before %s: %w", unit, action, err)
	}
	if err := verifyPrecondition(action, isTimer, before); err != nil {
		return err
	}
	if err := verifySource(unit, before); err != nil {
		return fmt.Errorf("authenticate %s unit source before %s: %w", unit, action, err)
	}
	if verifyDependencies != nil {
		if err := verifyDependencies(ctx, controller, unit); err != nil {
			return fmt.Errorf("authenticate %s target dependency before %s: %w", unit, action, err)
		}
	}
	effectiveAction := action
	if unit == "cliproxyapi.service" && action == "start" && ServiceRunning(before) {
		effectiveAction = "restart"
	}
	if effectiveAction != "restart" {
		if err := verifyDesired(effectiveAction, isTimer, before, before); err == nil {
			return nil
		}
	}
	arguments := []string{effectiveAction, unit}
	if effectiveAction == "enable-now" {
		arguments = []string{"enable", "--now", unit}
	}
	var attempts []error
	var observed map[string]string
	for attempt := 1; attempt <= 2; attempt++ {
		actionErr := controller.Action(ctx, arguments...)
		properties, readErr := controller.Properties(ctx, unit, propertyNames...)
		if readErr == nil {
			observed = properties
			sourceErr := verifySource(unit, properties)
			var dependencyErr error
			if verifyDependencies != nil {
				dependencyErr = verifyDependencies(ctx, controller, unit)
			}
			if sourceErr != nil || dependencyErr != nil {
				cause := errors.Join(errors.New("service-action result is unsafe because its unit or target dependency failed authentication after mutation"), actionErr, sourceErr, dependencyErr)
				if isTimer {
					rollbackErr := WithCleanup(func(cleanupContext context.Context) error {
						return disableTimerFailClosed(cleanupContext, controller, unit, propertyNames, verifySource)
					})
					if rollbackErr == nil {
						return errors.Join(errors.New("timer mutation was durably disabled after authentication failure"), cause)
					}
					return errors.Join(errors.New("timer mutation and its durable final state are ambiguous"), cause, rollbackErr)
				}
				if effectiveAction == "start" || effectiveAction == "restart" {
					compensationErr := WithCleanup(func(cleanupContext context.Context) error {
						return compensateToInactive(cleanupContext, controller, unit, false, before, propertyNames, verifySource)
					})
					return errors.Join(cause, compensationErr)
				}
				return cause
			}
			if properties["FragmentPath"] != before["FragmentPath"] || properties["DropInPaths"] != before["DropInPaths"] ||
				(effectiveAction != "enable-now" && properties["UnitFileState"] != before["UnitFileState"]) {
				return errors.Join(errors.New("service-action result is ambiguous because authenticated source or persistent state changed"), actionErr)
			}
			proofErr := verifyDesired(effectiveAction, isTimer, before, properties)
			if proofErr == nil {
				return nil
			}
			attempts = append(attempts, errors.Join(actionErr, proofErr))
		} else {
			attempts = append(attempts, errors.Join(actionErr, fmt.Errorf("read back %s after %s attempt %d: %w", unit, action, attempt, readErr)))
		}
	}
	cause := errors.Join(attempts...)
	if effectiveAction == "enable-now" {
		if verifyDependencies != nil {
			if dependencyErr := verifyDependencies(ctx, controller, unit); dependencyErr != nil {
				rollbackErr := WithCleanup(func(cleanupContext context.Context) error {
					return disableTimerFailClosed(cleanupContext, controller, unit, propertyNames, verifySource)
				})
				return errors.Join(errors.New("timer target dependency changed before durable settlement"), cause, dependencyErr, rollbackErr)
			}
		}
		return WithCleanup(func(cleanupContext context.Context) error {
			return settleFailedEnableNow(cleanupContext, controller, unit, isTimer, before, observed, propertyNames, verifySource, cause)
		})
	}
	if effectiveAction == "start" || effectiveAction == "restart" {
		compensationErr := WithCleanup(func(cleanupContext context.Context) error {
			return compensateToInactive(cleanupContext, controller, unit, isTimer, before, propertyNames, verifySource)
		})
		if compensationErr == nil {
			return errors.Join(errors.New("service action failed after retry and was compensated to a proved inactive state"), cause)
		}
		return errors.Join(errors.New("service action failed after retry and its final state is ambiguous"), cause, compensationErr)
	}
	return errors.Join(errors.New("stop service action failed after retry and its final state is ambiguous"), cause)
}

func compensateToInactive(ctx context.Context, controller systemdctl.Controller, unit string, isTimer bool, before map[string]string, propertyNames []string, verifySource SourceVerifier) error {
	actionErr := controller.Action(ctx, "stop", unit)
	properties, readErr := controller.Properties(ctx, unit, propertyNames...)
	if readErr != nil {
		return errors.Join(actionErr, readErr)
	}
	if sourceErr := verifySource(unit, properties); sourceErr != nil {
		return errors.Join(actionErr, sourceErr)
	}
	if properties["FragmentPath"] != before["FragmentPath"] || properties["DropInPaths"] != before["DropInPaths"] || properties["UnitFileState"] != before["UnitFileState"] || !UnitStopped(isTimer, properties) {
		return errors.Join(actionErr, errors.New("service-action inactive compensation did not read back exactly"))
	}
	return nil
}

func settleFailedEnableNow(ctx context.Context, controller systemdctl.Controller, unit string, isTimer bool, before, observed map[string]string, propertyNames []string, verifySource SourceVerifier, cause error) error {
	if observed == nil {
		properties, err := controller.Properties(ctx, unit, propertyNames...)
		if err != nil {
			return errors.Join(errors.New("enable-now may have mutated durable state and its final state is unreadable"), cause, err)
		}
		observed = properties
	}
	if err := verifySource(unit, observed); err != nil || observed["FragmentPath"] != before["FragmentPath"] || observed["DropInPaths"] != before["DropInPaths"] {
		return errors.Join(errors.New("enable-now final state is ambiguous because its source is unauthenticated"), cause, err)
	}
	if observed["UnitFileState"] == "enabled" {
		return errors.Join(errors.New("enable-now durable intent is committed but activation is pending; rerun the exact command before cutover"), cause)
	}
	if observed["ActiveState"] == "active" {
		if err := WithCleanup(func(cleanupContext context.Context) error {
			return compensateToInactive(cleanupContext, controller, unit, isTimer, before, propertyNames, verifySource)
		}); err != nil {
			return errors.Join(errors.New("enable-now left an active unit without proved durable intent and compensation is ambiguous"), cause, err)
		}
		return errors.Join(errors.New("enable-now failed and was compensated to a proved inactive state"), cause)
	}
	if observed["UnitFileState"] == before["UnitFileState"] && UnitStopped(isTimer, observed) {
		return errors.Join(errors.New("enable-now failed without changing the proved durable or active state"), cause)
	}
	return errors.Join(errors.New("enable-now failed and its final durable state is ambiguous"), cause)
}

func disableTimerFailClosed(ctx context.Context, controller systemdctl.Controller, unit string, propertyNames []string, verifySource SourceVerifier) error {
	target, ok := TimerTargetService(unit)
	if !ok {
		return errors.New("timer fail-closed target is unavailable")
	}
	targetProperties := PropertyNames(false, target)
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		disableErr := controller.Action(ctx, "disable", "--now", unit)
		stopErr := controller.Action(ctx, "stop", target)
		timerState, timerReadErr := controller.Properties(ctx, unit, propertyNames...)
		targetState, targetReadErr := controller.Properties(ctx, target, targetProperties...)
		timerAuthErr := error(nil)
		targetAuthErr := error(nil)
		if timerReadErr == nil {
			timerAuthErr = verifySource(unit, timerState)
		}
		if targetReadErr == nil {
			targetAuthErr = verifySource(target, targetState)
		}
		timerSafe := timerReadErr == nil && timerAuthErr == nil && timerState["UnitFileState"] == "disabled" && UnitStopped(true, timerState)
		targetSafe := targetReadErr == nil && targetAuthErr == nil && processFreeInactive(targetState)
		if timerSafe && targetSafe {
			return nil
		}
		failures = append(failures, errors.Join(disableErr, stopErr, timerReadErr, targetReadErr, timerAuthErr, targetAuthErr, errorUnless(timerSafe, "timer did not read back as authenticated, disabled, and inactive"), errorUnless(targetSafe, "timer target service did not read back as authenticated and process-free")))
	}
	return errors.Join(failures...)
}

func verifyProductionDependencies(ctx context.Context, controller systemdctl.Controller, unit string) error {
	return verifyServiceActionDependencies(ctx, controller, unit, VerifyProductionSource)
}

func verifyServiceActionDependencies(ctx context.Context, controller systemdctl.Controller, unit string, verifySource SourceVerifier) error {
	if ctx == nil || controller == nil || verifySource == nil {
		return errors.New("service-action dependency verifier is unavailable")
	}
	target, ok := TimerTargetService(unit)
	if !ok {
		return nil
	}
	propertyNames := PropertyNames(false, target)
	before, err := controller.Properties(ctx, target, propertyNames...)
	if err != nil {
		return fmt.Errorf("inspect timer target service %s: %w", target, err)
	}
	if err := verifySource(target, before); err != nil {
		return fmt.Errorf("authenticate timer target service %s: %w", target, err)
	}
	after, err := controller.Properties(ctx, target, propertyNames...)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.Join(errors.New("timer target service changed during source authentication"), err)
	}
	if !processFreeInactive(after) {
		return errors.New("timer target service must be inactive and process-free during timer enablement")
	}
	return nil
}

// TimerTargetService maps a timer unit to the service it activates.
func TimerTargetService(unit string) (string, bool) {
	switch unit {
	case "workagent-backup.timer":
		return "workagent-backup.service", true
	case "workagent-healthcheck.timer":
		return "workagent-healthcheck.service", true
	default:
		return "", false
	}
}

// PropertyNames is the exact systemd property set read for each
// service-action proof.
func PropertyNames(isTimer bool, unit string) []string {
	properties := []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "NeedDaemonReload"}
	if !isTimer {
		properties = append(properties, "MainPID", "ControlPID", "Result", "InvocationID", "ActiveEnterTimestampMonotonic")
	}
	switch unit {
	case "caddy.service":
		properties = append(properties, "ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx", "ExecMainStartTimestampMonotonic", "TimeoutStartUSec", "TimeoutStartFailureMode", "KillMode", "SendSIGKILL", "FinalKillSignal", "Restart", "Type", "User", "Group", "RuntimeDirectory", "RuntimeDirectoryMode", "NoNewPrivileges", "AmbientCapabilities", "CapabilityBoundingSet")
	case "workagent-tenant-config-reconcile.service", "cliproxyapi.service", "workagent-notification.service", "workagent-chatforward.service", "workagent-chatforward-browser.service", "workagent-portal.service", "workagent-backup.service", "workagent-healthcheck.service":
		properties = append(properties, "ExecStart", "ExecStartEx", "ExecStartPre", "ExecStartPreEx", "ExecStartPost", "ExecStartPostEx", "ExecStop", "ExecStopEx", "ExecStopPost", "ExecStopPostEx", "ExecReload", "ExecReloadEx", "Type", "User", "Group")
	case "workagent-backup.timer", "workagent-healthcheck.timer":
		properties = append(properties, "Unit", "Persistent")
	}
	return properties
}

func verifyPrecondition(action string, isTimer bool, properties map[string]string) error {
	if properties["LoadState"] != "loaded" || properties["FragmentPath"] == "" || properties["UnitFileState"] == "" || (!isTimer && properties["ControlPID"] != "0") {
		return errors.New("service-action unit source or persistent state is unavailable before mutation")
	}
	if action == "enable-now" {
		if properties["UnitFileState"] != "disabled" && properties["UnitFileState"] != "enabled" {
			return errors.New("enable-now requires an exactly disabled or already-enabled persistent unit")
		}
		return nil
	}
	if isTimer {
		return errors.New("transient service actions do not accept timer units")
	}
	running := ServiceRunning(properties)
	stopped := UnitStopped(false, properties)
	switch action {
	case "start":
		if !running && !stopped {
			return errors.New("start requires an exactly running or cleanly stopped service")
		}
	case "stop":
		if !running && !stopped {
			return errors.New("stop requires an exactly running or cleanly stopped service")
		}
	case "restart":
		if !running {
			return errors.New("restart requires an exactly running service generation")
		}
	default:
		return errors.New("service-action operation is invalid")
	}
	return nil
}

func verifyDesired(action string, isTimer bool, before, properties map[string]string) error {
	if properties["LoadState"] != "loaded" || (!isTimer && properties["ControlPID"] != "0") {
		return errors.New("service-action unit did not read back as loaded and control-process-free")
	}
	if action == "stop" {
		if !UnitStopped(isTimer, properties) {
			return errors.New("stopped service-action unit is not inactive and process-free")
		}
		return nil
	}
	if isTimer {
		if properties["ActiveState"] != "active" || properties["SubState"] != "waiting" || properties["UnitFileState"] != "enabled" {
			return errors.New("started service-action timer is not active, waiting, and persistently enabled")
		}
		return nil
	}
	if !ServiceRunning(properties) || (action == "enable-now" && properties["UnitFileState"] != "enabled") {
		return errors.New("started service-action service is not active, running, and process-backed")
	}
	if action == "start" || action == "restart" {
		beforeStamp, beforeErr := strconv.ParseUint(before["ActiveEnterTimestampMonotonic"], 10, 64)
		afterStamp, afterErr := strconv.ParseUint(properties["ActiveEnterTimestampMonotonic"], 10, 64)
		if properties["InvocationID"] == "" || properties["InvocationID"] == before["InvocationID"] || afterErr != nil || afterStamp == 0 ||
			(action == "restart" && (before["InvocationID"] == "" || beforeErr != nil || afterStamp <= beforeStamp)) ||
			(action == "start" && beforeErr == nil && afterStamp <= beforeStamp) {
			return errors.New("started service-action unit did not enter a new invocation")
		}
	}
	return nil
}

// ServiceRunning reports whether a unit reads back as an active, running,
// process-backed service generation.
func ServiceRunning(properties map[string]string) bool {
	mainPID, err := strconv.ParseUint(properties["MainPID"], 10, 64)
	return err == nil && mainPID > 0 && properties["ActiveState"] == "active" && properties["SubState"] == "running" &&
		properties["ControlPID"] == "0" && properties["Result"] == "success"
}

// UnitStopped reports whether a unit reads back as inactive and process-free.
func UnitStopped(isTimer bool, properties map[string]string) bool {
	if properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" {
		return false
	}
	if isTimer {
		return true
	}
	return properties["MainPID"] == "0" && properties["ControlPID"] == "0" && properties["Result"] == "success"
}

func processFreeInactive(properties map[string]string) bool {
	return properties["ActiveState"] == "inactive" && properties["SubState"] == "dead" && properties["MainPID"] == "0" && properties["ControlPID"] == "0"
}
