package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/cliproxy"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: workagent-cliproxy <prepare|bootstrap|doctor|stage-migration-bundles|apply-migration-plan|verify-migration-plan> [options]")
	}
	var err error
	switch os.Args[1] {
	case "prepare":
		err = prepare(os.Args[2:])
	case "bootstrap":
		err = bootstrap(os.Args[2:])
	case "doctor":
		err = doctor(os.Args[2:])
	case "stage-migration-bundles":
		err = stageMigrationBundles(os.Args[2:])
	case "apply-migration-plan":
		err = applyMigrationPlan(os.Args[2:])
	case "verify-migration-plan":
		err = verifyMigrationPlan(os.Args[2:])
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func stageMigrationBundles(arguments []string) error {
	flags := commandFlags("stage-migration-bundles")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "Portal production config")
	report := flags.String("report", "/var/lib/workagent/migration/report.json", "protected completed migration report")
	plan := flags.String("plan", "/var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json", "protected quota/usage cutover plan")
	credential := flags.String("credential", "/run/credentials/cliproxyapi.service/cliproxy-management-key", "service-local management credential")
	timeout := flags.Duration("timeout", 5*time.Minute, "bounded all-tenant staging timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("usage: workagent-cliproxy stage-migration-bundles [--portal-config PATH --report PATH --plan PATH --credential PATH --timeout DURATION]")
	}
	portal, err := config.LoadPortal(*portalConfig)
	if err != nil {
		return err
	}
	if err := portal.ValidateProductionLayout(*portalConfig); err != nil {
		return err
	}
	portal.CLIProxy.ManagementCredentialFile = *credential
	policy, err := productconfig.LoadPolicy(portal.PolicyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := cliproxy.StageMigrationBundles(ctx, cliproxy.StageMigrationBundlesOptions{
		ReportPath: *report, PlanPath: *plan, PortalDatabasePath: portal.DatabasePath(), CLIProxy: portal.CLIProxy, Policy: policy,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"staged": true, "users": result.Users, "provisioned": result.Provisioned, "reused": result.Reused,
		"contains_plaintext_key": false,
	})
}

func applyMigrationPlan(arguments []string) error {
	flags := commandFlags("apply-migration-plan")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "Portal production config")
	report := flags.String("report", "/var/lib/workagent/migration/report.json", "protected completed migration report")
	plan := flags.String("plan", "/var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json", "protected quota/usage cutover plan")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("usage: workagent-cliproxy apply-migration-plan [--portal-config PATH --report PATH --plan PATH]")
	}
	portal, err := config.LoadPortal(*portalConfig)
	if err != nil {
		return err
	}
	if err := portal.ValidateProductionLayout(*portalConfig); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := cliproxy.ApplyMigrationPlan(ctx, cliproxy.ApplyMigrationPlanOptions{
		ReportPath: *report, PlanPath: *plan, PortalDatabasePath: portal.DatabasePath(), StatePath: portal.CLIProxy.PolicyStateFile,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"applied": true, "overrides": result.Overrides, "changed": result.Changed, "backup_created": result.BackupCreated,
		"restored_legacy_key_material": false,
	})
}

func verifyMigrationPlan(arguments []string) error {
	flags := commandFlags("verify-migration-plan")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "Portal production config")
	report := flags.String("report", "/var/lib/workagent/migration/report.json", "protected completed migration report")
	plan := flags.String("plan", "/var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json", "protected quota/usage cutover plan")
	credential := flags.String("credential", "/run/credentials/cliproxyapi.service/cliproxy-management-key", "service-local management credential")
	timeout := flags.Duration("timeout", 2*time.Minute, "bounded live readback timeout")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > 10*time.Minute {
		return errors.New("usage: workagent-cliproxy verify-migration-plan [--portal-config PATH --report PATH --plan PATH --credential PATH --timeout DURATION]")
	}
	portal, err := config.LoadPortal(*portalConfig)
	if err != nil {
		return err
	}
	if err := portal.ValidateProductionLayout(*portalConfig); err != nil {
		return err
	}
	portal.CLIProxy.ManagementCredentialFile = *credential
	policy, err := productconfig.LoadPolicy(portal.PolicyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := cliproxy.VerifyMigrationPlan(ctx, cliproxy.VerifyMigrationPlanOptions{
		ReportPath: *report, PlanPath: *plan, PortalDatabasePath: portal.DatabasePath(), CLIProxy: portal.CLIProxy, Policy: policy,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"verified": true, "users": result.Users, "overrides": result.Overrides, "contains_plaintext_key": false,
	})
}

func bootstrap(arguments []string) error {
	flags := commandFlags("bootstrap")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "Portal production config")
	credential := flags.String("credential", "/run/credentials/cliproxyapi.service/cliproxy-management-key", "service-local management credential")
	wait := flags.Duration("wait", 30*time.Second, "bounded wait for reconciliation and full readiness")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *wait < 0 || *wait > 5*time.Minute {
		return errors.New("usage: workagent-cliproxy bootstrap [--portal-config PATH --credential PATH --wait DURATION]")
	}
	portal, err := config.LoadPortal(*portalConfig)
	if err != nil {
		return err
	}
	if err := portal.ValidateProductionLayout(*portalConfig); err != nil {
		return err
	}
	portal.CLIProxy.ManagementCredentialFile = *credential
	policy, err := productconfig.LoadPolicy(portal.PolicyFile)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(*wait)
	for {
		attemptTimeout := 10 * time.Second
		if *wait > 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return err
			}
			if remaining < attemptTimeout {
				attemptTimeout = remaining
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), attemptTimeout)
		err = cliproxy.Bootstrap(ctx, portal.CLIProxy, policy)
		cancel()
		if err == nil {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ready": true, "managed_alias_count": cliproxy.ManagedAliasCount,
				"core_version": portal.CLIProxy.CoreVersion, "core_patch": portal.CLIProxy.CorePatch,
				"plugin_id": portal.CLIProxy.PluginID, "plugin_version": portal.CLIProxy.PluginVersion,
			})
		}
		if *wait == 0 || time.Now().After(deadline) || time.Until(deadline) < 500*time.Millisecond {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func commandFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func prepare(arguments []string) error {
	flags := commandFlags("prepare")
	template := flags.String("template", "/etc/cliproxyapi/config.yaml", "root-owned non-secret template")
	output := flags.String("output", "/var/lib/cliproxyapi/config.yaml", "dedicated-user runtime config")
	credential := flags.String("credential", "/run/credentials/cliproxyapi.service/cliproxy-management-key", "systemd management credential")
	stateRoot := flags.String("state-root", "/var/lib/cliproxyapi", "dedicated-user state root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("usage: workagent-cliproxy prepare [--template PATH --output PATH --credential PATH --state-root PATH]")
	}
	if os.Geteuid() != 0 {
		return errors.New("CLIProxy runtime config preparation must run as root")
	}
	if err := cliproxy.PrepareRuntimeConfig(cliproxy.RuntimeConfigOptions{
		TemplatePath: *template, OutputPath: *output, CredentialPath: *credential,
		StateRoot: *stateRoot, RequireDedicatedOwner: true,
	}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"prepared": true, "output": *output, "contains_plaintext_secret": false})
}

func doctor(arguments []string) error {
	flags := commandFlags("doctor")
	portalConfig := flags.String("portal-config", "/etc/workagent/portal.json", "Portal production config")
	credential := flags.String("credential", "", "optional service-local management credential override")
	wait := flags.Duration("wait", 0, "bounded wait for the full management contract")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *wait < 0 || *wait > 5*time.Minute {
		return errors.New("usage: workagent-cliproxy doctor [--portal-config PATH --credential PATH --wait DURATION]")
	}
	portal, err := config.LoadPortal(*portalConfig)
	if err != nil {
		return err
	}
	if *credential != "" {
		portal.CLIProxy.ManagementCredentialFile = *credential
	}
	policy, err := productconfig.LoadPolicy(portal.PolicyFile)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(*wait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = cliproxy.CheckReadiness(ctx, portal.CLIProxy, policy)
		cancel()
		if err == nil {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"ready": true, "core_version": portal.CLIProxy.CoreVersion, "core_patch": portal.CLIProxy.CorePatch,
				"plugin_id": portal.CLIProxy.PluginID, "plugin_version": portal.CLIProxy.PluginVersion,
			})
		}
		if *wait == 0 || time.Now().After(deadline) {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func fatal(message string) {
	message = strings.ReplaceAll(strings.ReplaceAll(message, "\r", " "), "\n", " ")
	if len(message) > 500 {
		message = message[:500]
	}
	fmt.Fprintln(os.Stderr, "workagent-cliproxy:", message)
	os.Exit(1)
}
