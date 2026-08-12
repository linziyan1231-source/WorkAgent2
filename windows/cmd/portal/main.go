package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aionuiportal/internal/admin"
	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/release"
	"aionuiportal/internal/store"
	"aionuiportal/internal/winutil"
	"golang.org/x/term"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	global := flag.NewFlagSet("portal", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	configPath := global.String("config", "", "absolute Portal configuration path")
	if err := global.Parse(arguments); err != nil || *configPath == "" || len(global.Args()) == 0 {
		usage()
		return 2
	}
	if global.Args()[0] == "service" {
		return provisionServiceCommand(*configPath, global.Args()[1:])
	}
	if _, err := winutil.RequireAdministrator(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	manager, err := admin.Open(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open Portal administration state: %v\n", err)
		return 1
	}
	defer manager.Close()
	release.SetIntegrityVerification(manager.Config.VerifyReleaseIntegrity)
	agentcli.SetIntegrityVerification(manager.Config.VerifyReleaseIntegrity)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := dispatch(ctx, manager, global.Args()); err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		return 1
	}
	return 0
}

func dispatch(ctx context.Context, manager *admin.Manager, arguments []string) error {
	switch arguments[0] {
	case "admin":
		return administratorCommand(ctx, manager, arguments[1:])
	case "user":
		return userCommand(ctx, manager, arguments[1:])
	case "windows-password":
		if len(arguments) != 3 || arguments[1] != "rotate" {
			return errors.New("usage: portal --config <path> windows-password rotate <portal-username>")
		}
		return registerTask(ctx, manager, arguments[2], true)
	case "task":
		return taskCommand(ctx, manager, arguments[1:])
	case "instance":
		return instanceCommand(ctx, manager, arguments[1:])
	case "kimi-oauth":
		return errors.New("native Kimi OAuth has been removed; use model-bootstrap provision --update with the user's CLIProxyAPI keys")
	case "model-bootstrap":
		return modelBootstrapCommand(ctx, manager, arguments[1:])
	case "limits":
		return limitsCommand(ctx, manager, arguments[1:])
	case "chatgpt-pro-limit":
		return chatGPTProLimitCommand(ctx, manager, arguments[1:])
	case "kimi-datasource":
		return kimiDatasourceCommand(ctx, manager, arguments[1:])
	case "logs":
		return logsCommand(ctx, manager, arguments[1:])
	case "release":
		return releaseCommand(ctx, manager, arguments[1:])
	case "acl":
		if len(arguments) != 2 || (arguments[1] != "verify" && arguments[1] != "apply") {
			return errors.New("usage: portal --config <path> acl <apply|verify>")
		}
		if arguments[1] == "apply" {
			return printFailures("ACL application", manager.ApplyACLs(ctx))
		}
		return printFailures("ACL verification", manager.VerifyACLs(ctx))
	case "readiness":
		if len(arguments) != 1 {
			return errors.New("usage: portal --config <path> readiness")
		}
		return printFailures("production readiness", manager.Readiness(ctx))
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func kimiDatasourceCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: portal --config <path> kimi-datasource <grant|revoke|show|sources> ...")
	}
	switch arguments[0] {
	case "sources":
		if len(arguments) != 1 {
			return errors.New("usage: portal --config <path> kimi-datasource sources")
		}
		for _, source := range store.KimiDatasourceSources {
			fmt.Println(source)
		}
		return nil
	case "show":
		if len(arguments) != 2 {
			return errors.New("usage: portal --config <path> kimi-datasource show <portal-username>")
		}
		user, err := manager.Store.UserByUsername(ctx, arguments[1])
		if err != nil {
			return err
		}
		grant, err := manager.Store.KimiDatasourceGrantForUser(ctx, user.ID, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("user=%s enabled=%t sources=%s daily=%d/%d monthly=%d/%d\n", user.Username, grant.Enabled,
			strings.Join(grant.AllowedSources, ","), grant.DailyUsed, grant.DailyLimit, grant.MonthlyUsed, grant.MonthlyLimit)
		return nil
	case "revoke":
		if len(arguments) != 2 {
			return errors.New("usage: portal --config <path> kimi-datasource revoke <portal-username>")
		}
		grant, err := manager.SetKimiDatasourceGrant(ctx, arguments[1], false, nil, 0, 0)
		if err != nil {
			return err
		}
		fmt.Printf("user=%s enabled=false daily_limit=%d monthly_limit=%d\n", arguments[1], grant.DailyLimit, grant.MonthlyLimit)
		return nil
	case "grant":
		flags := newFlags("kimi-datasource grant")
		username := flags.String("username", "", "Portal username")
		sources := flags.String("sources", "", "comma-separated datasource IDs")
		daily := flags.Int("daily", 100, "daily MCP calls")
		monthly := flags.Int("monthly", 1000, "monthly MCP calls")
		if err := flags.Parse(arguments[1:]); err != nil || *username == "" || *sources == "" || flags.NArg() != 0 {
			return errors.New("usage: portal --config <path> kimi-datasource grant --username <name> --sources <id,id> [--daily 100] [--monthly 1000]")
		}
		grant, err := manager.SetKimiDatasourceGrant(ctx, *username, true, strings.Split(*sources, ","), *daily, *monthly)
		if err != nil {
			return err
		}
		fmt.Printf("user=%s enabled=true sources=%s daily_limit=%d monthly_limit=%d\n", *username, strings.Join(grant.AllowedSources, ","), grant.DailyLimit, grant.MonthlyLimit)
		return nil
	default:
		return fmt.Errorf("unknown kimi-datasource subcommand %q", arguments[0])
	}
}

func administratorCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "create" {
		return errors.New("usage: portal --config <path> admin create")
	}
	flags := newFlags("admin create")
	username := flags.String("username", "admin", "Portal administrator username")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("usage: portal --config <path> admin create [--username <name>]")
	}
	password, err := readSecretTwice("New administrator Portal password: ", "Confirm administrator Portal password: ")
	if err != nil {
		return err
	}
	user, err := manager.AddAdministrator(ctx, *username, password)
	if err != nil {
		return err
	}
	fmt.Printf("Created Portal administrator %s without a Windows account or UserHost.\n", user.Username)
	return nil
}

func chatGPTProLimitCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "set" {
		return errors.New("usage: portal --config <path> chatgpt-pro-limit set --username <name> --weekly <n>")
	}
	flags := newFlags("chatgpt-pro-limit set")
	username := flags.String("username", "", "Portal username")
	weekly := flags.Int("weekly", 0, "ChatGPT Pro sends per natural week")
	if err := flags.Parse(arguments[1:]); err != nil || *username == "" || *weekly < 1 || *weekly > 10000 || flags.NArg() != 0 {
		return errors.New("weekly ChatGPT Pro limit must be between 1 and 10000")
	}
	if err := manager.SetChatGPTProWeeklyLimit(ctx, *username, *weekly); err != nil {
		return err
	}
	fmt.Printf("ChatGPT Pro weekly limit for %s is now %d.\n", *username, *weekly)
	return nil
}

func modelBootstrapCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 || (arguments[0] != "provision" && arguments[0] != "rebase" && arguments[0] != "status" && arguments[0] != "catalog-converge") {
		return errors.New("usage: portal --config <path> model-bootstrap <provision|rebase|status|catalog-converge> ...")
	}
	if arguments[0] == "catalog-converge" {
		flags := newFlags("model-bootstrap catalog-converge")
		managementURL := flags.String("management-url", "", "local cpa-key-policy Management API URL")
		managementKeyFile := flags.String("management-key-file", "", "protected local Management API key file")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *managementURL == "" || *managementKeyFile == "" {
			return errors.New("usage: portal --config <path> model-bootstrap catalog-converge --management-url <loopback-url> --management-key-file <path>")
		}
		result, err := manager.ConvergeManagedKimiCatalog(ctx, *managementURL, *managementKeyFile)
		if err != nil {
			return err
		}
		fmt.Printf("Kimi catalog converged: alias_changed=%t keys_changed=%d kimi_keys=%d\n", result.AliasChanged, result.KeysChanged, result.KimiKeys)
		return nil
	}
	if arguments[0] == "status" {
		if len(arguments) != 2 {
			return errors.New("usage: portal --config <path> model-bootstrap status <portal-username>")
		}
		status, err := manager.ModelBootstrapStatus(ctx, arguments[1])
		if err != nil {
			return err
		}
		outcome := "MISSING"
		if status.RebasePending {
			outcome = "REBASE_PENDING"
		} else if status.Pending {
			outcome = "PENDING"
		} else if status.Applied {
			outcome = "APPLIED"
		}
		fmt.Printf("user=%s outcome=%s codex_key_id=%s kimi_key_id=%s\n", arguments[1], outcome, status.State.CodexKeyID, status.State.KimiKeyID)
		if !status.Applied || status.RebasePending {
			return errors.New("model bootstrap is not applied")
		}
		return nil
	}
	if arguments[0] == "rebase" {
		flags := newFlags("model-bootstrap rebase")
		baseURL := flags.String("base-url", "", "replacement employee OpenAI-compatible /v1 Base URL")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 1 || *baseURL == "" {
			return errors.New("usage: portal --config <path> model-bootstrap rebase --base-url <url/v1> <portal-username>")
		}
		result, err := manager.RebaseModelBootstrap(ctx, flags.Arg(0), *baseURL)
		if err != nil {
			return err
		}
		fmt.Printf("user=%s outcome=%s codex_key_id=%s kimi_key_id=%s restarted=%t\n", flags.Arg(0), result.Outcome, result.CodexKeyID, result.KimiKeyID, result.Restarted)
		return nil
	}

	flags := newFlags("model-bootstrap provision")
	managementURL := flags.String("management-url", "", "local cpa-key-policy Management API URL")
	managementKeyFile := flags.String("management-key-file", "", "protected local Management API key file")
	baseURL := flags.String("base-url", "", "employee OpenAI-compatible /v1 base URL")
	codexDefault := flags.String("codex-default-model", modelbootstrap.DefaultCodexModel, "default Codex model alias")
	codexModels := flags.String("codex-models", "", "comma-separated Codex/ChatGPT aliases")
	kimiModels := flags.String("kimi-models", "", "comma-separated Kimi aliases")
	rpm := flags.Int("rpm", 0, "requests per minute; zero means unlimited")
	codexDaily := flags.Float64("codex-daily-usd", admin.DefaultEmployeeCodexDailyUSD, "Codex/ChatGPT daily USD limit")
	codexWeekly := flags.Float64("codex-weekly-usd", admin.DefaultEmployeeCodexWeeklyUSD, "Codex/ChatGPT weekly USD limit")
	kimiDaily := flags.Float64("kimi-daily-usd", admin.DefaultEmployeeKimiDailyUSD, "Kimi daily USD limit")
	kimiWeekly := flags.Float64("kimi-weekly-usd", admin.DefaultEmployeeKimiWeeklyUSD, "Kimi weekly USD limit")
	update := flags.Bool("update", false, "rotate keys and replace an existing initialization")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 || *managementURL == "" || *managementKeyFile == "" || *baseURL == "" {
		return errors.New("usage: portal --config <path> model-bootstrap provision --management-url <loopback-url> --management-key-file <path> --base-url <url/v1> --codex-models <aliases> --kimi-models <aliases> [--update] <portal-username>")
	}
	parseModels := func(value string) ([]string, error) {
		parts := strings.Split(value, ",")
		models := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				return nil, errors.New("model alias lists must not contain empty entries")
			}
			models = append(models, part)
		}
		return models, nil
	}
	parsedCodex, err := parseModels(*codexModels)
	if err != nil {
		return err
	}
	parsedKimi, err := parseModels(*kimiModels)
	if err != nil {
		return err
	}
	result, err := manager.ProvisionModelBootstrap(ctx, flags.Arg(0), admin.ModelBootstrapOptions{ManagementURL: *managementURL, ManagementKeyFile: *managementKeyFile,
		BaseURL: *baseURL, CodexDefaultModel: *codexDefault, CodexModels: parsedCodex, KimiModels: parsedKimi, RPM: *rpm,
		CodexDailyUSD: *codexDaily, CodexWeeklyUSD: *codexWeekly, KimiDailyUSD: *kimiDaily, KimiWeeklyUSD: *kimiWeekly, Update: *update})
	if err != nil {
		return err
	}
	fmt.Printf("user=%s outcome=%s codex_key_id=%s kimi_key_id=%s restarted=%t\n", flags.Arg(0), result.Outcome, result.CodexKeyID, result.KimiKeyID, result.Restarted)
	return nil
}

func userCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("user subcommand is required")
	}
	switch arguments[0] {
	case "add":
		flags := newFlags("user add")
		username := flags.String("username", "", "Portal username")
		windowsAccount := flags.String("windows-account", "", "existing standard Windows account")
		adminRole := flags.Bool("admin", false, "mark Portal record as an administrator")
		if err := flags.Parse(arguments[1:]); err != nil || *username == "" || *windowsAccount == "" || flags.NArg() != 0 {
			return errors.New("usage: portal --config <path> user add --username <portal-name> --windows-account <account> [--admin]")
		}
		password, err := readSecretTwice("New Portal password: ", "Confirm Portal password: ")
		if err != nil {
			return err
		}
		user, err := manager.AddUser(ctx, *username, *windowsAccount, *adminRole, password)
		if err != nil {
			return err
		}
		fmt.Printf("Created Portal user %s mapped to %s (%s).\n", user.Username, user.WindowsUsername, user.WindowsSID)
		return nil
	case "disable", "enable":
		if len(arguments) != 2 {
			return fmt.Errorf("usage: portal --config <path> user %s <portal-username>", arguments[0])
		}
		enabled := arguments[0] == "enable"
		if err := manager.SetUserEnabled(ctx, arguments[1], enabled); err != nil {
			return err
		}
		fmt.Printf("Portal user %s is now %s. Existing sessions were invalidated.\n", arguments[1], arguments[0]+"d")
		return nil
	case "reset-password":
		if len(arguments) != 2 {
			return errors.New("usage: portal --config <path> user reset-password <portal-username>")
		}
		password, err := readSecretTwice("New Portal password: ", "Confirm Portal password: ")
		if err != nil {
			return err
		}
		if err := manager.ResetPortalPassword(ctx, arguments[1], password); err != nil {
			return err
		}
		fmt.Println("Portal password reset. Windows credentials and the scheduled task were not changed.")
		return nil
	case "map-windows-sid":
		flags := newFlags("user map-windows-sid")
		username := flags.String("username", "", "Portal username")
		windowsAccount := flags.String("windows-account", "", "new standard Windows account")
		if err := flags.Parse(arguments[1:]); err != nil || *username == "" || *windowsAccount == "" || flags.NArg() != 0 {
			return errors.New("usage: portal --config <path> user map-windows-sid --username <portal-name> --windows-account <account>")
		}
		user, err := manager.MapWindowsAccount(ctx, *username, *windowsAccount)
		if err != nil {
			return err
		}
		fmt.Printf("Mapped %s to %s (%s). Old SID data was preserved and was not copied. Install the new task explicitly.\n", user.Username, user.WindowsUsername, user.WindowsSID)
		return nil
	default:
		return fmt.Errorf("unknown user subcommand %q", arguments[0])
	}
}

func taskCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) != 2 {
		return errors.New("usage: portal --config <path> task <install|update|remove> <portal-username>")
	}
	switch arguments[0] {
	case "install":
		return registerTask(ctx, manager, arguments[1], true)
	case "update":
		return registerTask(ctx, manager, arguments[1], true)
	case "remove":
		if err := manager.RemoveTask(ctx, arguments[1]); err != nil {
			return err
		}
		fmt.Println("Scheduled task removed; private user data was preserved.")
		return nil
	default:
		return fmt.Errorf("unknown task subcommand %q", arguments[0])
	}
}

func registerTask(ctx context.Context, manager *admin.Manager, username string, restart bool) error {
	password, err := readSecret("Windows account password (stored only by Task Scheduler/LSA): ")
	if err != nil {
		return err
	}
	status, err := manager.InstallOrUpdateTask(ctx, username, password, restart)
	if err != nil {
		return err
	}
	printStatus(status, 0, 0, 0)
	fmt.Println("Task credentials verified by a real password-logon launch and whoami /user SID check.")
	return nil
}

func instanceCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 1 && arguments[0] == "list" {
		items, err := manager.List(ctx)
		if err != nil {
			return err
		}
		for _, item := range items {
			fmt.Printf("user=%s windows=%s sid=%s enabled=%t admin=%t sessions=%d ", item.User.Username, item.User.WindowsUsername, item.User.WindowsSID, item.User.Enabled, item.User.Admin, item.Sessions)
			if item.Status == nil {
				if item.StatusError != nil {
					fmt.Printf("state=unavailable failure=%q\n", item.StatusError)
				} else {
					fmt.Println("state=stopped")
				}
			} else {
				printStatus(*item.Status, item.Sessions, item.Requests, item.WebSockets)
			}
		}
		return nil
	}
	if len(arguments) != 2 {
		return errors.New("usage: portal --config <path> instance <list|status|activity|start|stop|restart> [portal-username]")
	}
	user, err := manager.Store.UserByUsername(ctx, arguments[1])
	if err != nil {
		return err
	}
	switch arguments[0] {
	case "status":
		item, err := manager.UserStatus(ctx, user)
		if err != nil {
			return err
		}
		printStatus(*item.Status, item.Sessions, item.Requests, item.WebSockets)
		return nil
	case "activity":
		activity, err := manager.Instances.ProbeActivity(ctx, user.WindowsSID)
		if err != nil {
			return err
		}
		fmt.Printf("known=%t active=%t checked_at=%s reason=%q\n", activity.Known, activity.Active,
			time.Unix(activity.CheckedAtUnix, 0).UTC().Format(time.RFC3339), activity.Reason)
		return nil
	case "start":
		if !user.Enabled {
			return errors.New("Portal user is disabled")
		}
		status, err := manager.Instances.Ensure(ctx, user.WindowsSID)
		if err != nil {
			return err
		}
		printStatus(status, 0, 0, 0)
		return nil
	case "stop":
		if err := manager.Instances.Stop(ctx, user.WindowsSID); err != nil {
			return err
		}
		fmt.Println("UserHost accepted the stop request; all Job Object children will be terminated on timeout.")
		return nil
	case "restart":
		if err := manager.Instances.Stop(ctx, user.WindowsSID); err != nil {
			return err
		}
		time.Sleep(time.Second)
		status, err := manager.Instances.Ensure(ctx, user.WindowsSID)
		if err != nil {
			return err
		}
		printStatus(status, 0, 0, 0)
		return nil
	default:
		return fmt.Errorf("unknown instance subcommand %q", arguments[0])
	}
}

func limitsCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "set" {
		return errors.New("usage: portal --config <path> limits set --username <name> --memory-mib <n> --cpu-percent <n> --processes <n>")
	}
	flags := newFlags("limits set")
	username := flags.String("username", "", "Portal username")
	memory := flags.Uint64("memory-mib", 0, "Job memory ceiling in MiB")
	cpu := flags.Uint("cpu-percent", 0, "Job CPU hard cap")
	processes := flags.Uint("processes", 0, "maximum active processes")
	if err := flags.Parse(arguments[1:]); err != nil || *username == "" || *memory == 0 || *cpu == 0 || *processes == 0 || flags.NArg() != 0 {
		return errors.New("all limit flags are required")
	}
	limits := config.ResourceLimits{MemoryBytes: *memory * 1024 * 1024, CPUPercent: uint32(*cpu), ActiveProcesses: uint32(*processes)}
	if err := manager.SetLimits(ctx, *username, limits); err != nil {
		return err
	}
	fmt.Println("Limits updated in the fixed UserHost configuration; the stopped instance will use them on next start.")
	return nil
}

func logsCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 || arguments[0] != "show" {
		return errors.New("usage: portal --config <path> logs show [--username <name>] [--lines <n>]")
	}
	flags := newFlags("logs show")
	username := flags.String("username", "", "Portal username; omit for Portal service log")
	lines := flags.Int("lines", 100, "maximum tail lines")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *lines < 1 || *lines > 10000 {
		return errors.New("invalid logs show arguments")
	}
	path := manager.Config.PortalLogPath
	if *username != "" {
		user, err := manager.Store.UserByUsername(ctx, *username)
		if err != nil {
			return err
		}
		dataRoot, err := manager.UserDataRootForSID(user.WindowsSID)
		if err != nil {
			return err
		}
		path, err = newestLog(filepath.Join(dataRoot, "logs"))
		if err != nil {
			return err
		}
	}
	return showSafeTail(path, *lines)
}

func releaseCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("release subcommand is required")
	}
	previous := filepath.Join(filepath.Dir(manager.Config.CurrentReleaseFile), "previous.json")
	switch arguments[0] {
	case "install":
		flags := newFlags("release install")
		source := flags.String("source", "", "packed AionUi Web CLI directory")
		version := flags.String("version", "", "immutable release version")
		coreVersion := flags.String("aioncore-version", "", "bundled aioncore version")
		allowRunning := flags.Bool("allow-running", false, "activate for future UserHost starts while existing instances retain their immutable release")
		if err := flags.Parse(arguments[1:]); err != nil || *source == "" || *version == "" || *coreVersion == "" || flags.NArg() != 0 {
			return errors.New("usage: portal --config <path> release install --source <dir> --version <version> --aioncore-version <version> [--allow-running]")
		}
		running, err := anyRunning(ctx, manager)
		if err != nil {
			return err
		}
		if running && !*allowRunning {
			return errors.New("all UserHost instances must be drained or stopped before release switching")
		}
		backupLabel := "pre-release-" + time.Now().UTC().Format("20060102T150405Z")
		if *allowRunning {
			err = backupRunningUserDatabases(ctx, manager, backupLabel)
		} else {
			err = backupUserDatabases(ctx, manager, backupLabel)
		}
		if err != nil {
			return err
		}
		verified, err := release.Install(*source, manager.Config.ReleasesRoot, *version, *coreVersion, manager.Config.SupportedAionCore)
		if err != nil {
			return err
		}
		if err := winutil.ApplyTreeACL(verified.Path, winutil.SharedReadOnlyPolicy()); err != nil {
			return err
		}
		if err := winutil.VerifyTreeACL(verified.Path, winutil.SharedReadOnlyPolicy()); err != nil {
			return err
		}
		if err := release.Activate(verified, manager.Config.CurrentReleaseFile, previous); err != nil {
			return err
		}
		fmt.Printf("Installed and atomically activated release %s; previous pointer retained at %s.\n", verified.Manifest.Version, previous)
		return nil
	case "rollback":
		if len(arguments) != 1 {
			return errors.New("usage: portal --config <path> release rollback")
		}
		if running, err := anyRunning(ctx, manager); err != nil {
			return err
		} else if running {
			return errors.New("all UserHost instances must be drained or stopped before release switching")
		}
		if err := backupUserDatabases(ctx, manager, "pre-rollback-"+time.Now().UTC().Format("20060102T150405Z")); err != nil {
			return err
		}
		verified, err := release.Rollback(manager.Config.CurrentReleaseFile, previous, manager.Config.ReleasesRoot, manager.Config.SupportedAionCore)
		if err != nil {
			return err
		}
		fmt.Printf("Rolled back current pointer to release %s; user data was not overwritten.\n", verified.Manifest.Version)
		return nil
	default:
		return fmt.Errorf("unknown release subcommand %q", arguments[0])
	}
}

func printStatus(status ipc.Status, sessions, requests, webSockets int) {
	fmt.Printf("state=%s healthy=%t sid=%s userhost_pid=%d web_pid=%d aioncore_pid=%d web_port=%d core_port=%d version=%s cpu=%.2f memory_bytes=%d processes=%d sessions=%d requests=%d websockets=%d last_activity=%s failure=%q\n",
		status.State, status.Healthy, status.WindowsSID, status.UserHostPID, status.WebPID, status.AionCorePID, status.WebPort, status.AionCorePort,
		status.Version, status.CPUPercent, status.MemoryBytes, status.ProcessCount, sessions, requests, webSockets, time.Unix(status.LastActivityUnix, 0).UTC().Format(time.RFC3339), status.FailureReason)
}

func readSecret(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("secret input requires an interactive console; piped or command-line passwords are refused")
	}
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func readSecretTwice(firstPrompt, secondPrompt string) ([]byte, error) {
	first, err := readSecret(firstPrompt)
	if err != nil {
		return nil, err
	}
	second, err := readSecret(secondPrompt)
	if err != nil {
		auth.Zero(first)
		return nil, err
	}
	defer auth.Zero(second)
	if len(first) != len(second) {
		auth.Zero(first)
		return nil, errors.New("password confirmation does not match")
	}
	var difference byte
	for index := range first {
		difference |= first[index] ^ second[index]
	}
	if difference != 0 {
		auth.Zero(first)
		return nil, errors.New("password confirmation does not match")
	}
	return first, nil
}

func anyRunning(ctx context.Context, manager *admin.Manager) (bool, error) {
	items, err := manager.List(ctx)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.Status != nil && (item.Status.Healthy || item.Status.State == "starting" || item.Status.State == "draining") {
			return true, nil
		}
	}
	return false, nil
}

func backupUserDatabases(ctx context.Context, manager *admin.Manager, label string) error {
	users, err := manager.Store.ListManagedUsers(ctx)
	if err != nil {
		return err
	}
	for _, user := range users {
		dataRoot, err := manager.UserDataRootForSID(user.WindowsSID)
		if err != nil {
			return fmt.Errorf("resolve private data root for %s: %w", user.Username, err)
		}
		source := filepath.Join(dataRoot, "data", "aionui-backend.db")
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Backup skipped for %s: database does not exist yet.\n", user.Username)
			continue
		} else if err != nil {
			return err
		}
		directory := filepath.Join(dataRoot, "backups", label)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		var copied []string
		for _, suffix := range []string{"", "-wal", "-shm"} {
			candidate := source + suffix
			if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			hash, err := copyFile(candidate, filepath.Join(directory, filepath.Base(candidate)))
			if err != nil {
				return err
			}
			copied = append(copied, filepath.Base(candidate)+" sha256="+hash)
		}
		if err := winutil.ApplyTreeACL(directory, winutil.PrivateTreePolicy(user.WindowsSID)); err != nil {
			return err
		}
		fmt.Printf("Backed up and hash-verified %s database to %s (%s).\n", user.Username, directory, strings.Join(copied, ", "))
	}
	return nil
}

func backupRunningUserDatabases(ctx context.Context, manager *admin.Manager, label string) error {
	users, err := manager.Store.ListManagedUsers(ctx)
	if err != nil {
		return err
	}
	for _, user := range users {
		dataRoot, err := manager.UserDataRootForSID(user.WindowsSID)
		if err != nil {
			return fmt.Errorf("resolve private data root for %s: %w", user.Username, err)
		}
		source := filepath.Join(dataRoot, "data", "aionui-backend.db")
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			fmt.Printf("Backup skipped for %s: database does not exist yet.\n", user.Username)
			continue
		} else if err != nil {
			return err
		}
		directory := filepath.Join(dataRoot, "backups", label)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		destination := filepath.Join(directory, filepath.Base(source))
		hash, err := snapshotSQLiteDatabase(ctx, source, destination)
		if err != nil {
			return fmt.Errorf("create consistent online backup for %s: %w", user.Username, err)
		}
		if err := winutil.ApplyTreeACL(directory, winutil.PrivateTreePolicy(user.WindowsSID)); err != nil {
			return err
		}
		fmt.Printf("Backed up and integrity-checked live %s database to %s (%s sha256=%s).\n", user.Username, directory, filepath.Base(destination), hash)
	}
	return nil
}

func snapshotSQLiteDatabase(ctx context.Context, source, destination string) (string, error) {
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) {
		return "", errors.New("SQLite snapshot paths must be absolute")
	}
	if _, err := os.Stat(destination); err == nil {
		return "", errors.New("immutable SQLite snapshot already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	dsn := "file:" + filepath.ToSlash(source) + "?_pragma=busy_timeout(10000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return "", err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", filepath.ToSlash(destination)); err != nil {
		return "", err
	}
	backup, err := sql.Open("sqlite", "file:"+filepath.ToSlash(destination)+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer backup.Close()
	var integrity string
	if err := backup.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil {
		return "", err
	}
	if integrity != "ok" {
		return "", fmt.Errorf("SQLite quick_check returned %q", integrity)
	}
	file, err := os.OpenFile(destination, os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return "", err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func copyFile(source, destination string) (string, error) {
	before, err := os.Lstat(source)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("backup source is not a regular file: %s", source)
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		output.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(output, hash), input); err != nil {
		output.Close()
		return "", err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	after, err := input.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", errors.New("backup source changed while it was being copied")
	}
	destinationInfo, err := os.Stat(destination)
	if err != nil || destinationInfo.Size() != before.Size() {
		return "", errors.New("backup destination size verification failed")
	}
	expectedHash := hex.EncodeToString(hash.Sum(nil))
	ok = true
	return expectedHash, nil
}

func newestLog(directory string) (string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	var candidates []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".log") {
			candidates = append(candidates, filepath.Join(directory, entry.Name()))
		}
	}
	if len(candidates) == 0 {
		return "", errors.New("no log file exists")
	}
	sort.Strings(candidates)
	return candidates[len(candidates)-1], nil
}

func showSafeTail(path string, count int) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lines := make([]string, 0, count)
	for scanner.Scan() {
		line := scanner.Text()
		if sensitiveLogLine(line) {
			line = "[REDACTED SENSITIVE LOG LINE]"
		}
		if len(lines) == count {
			copy(lines, lines[1:])
			lines[len(lines)-1] = line
		} else {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return nil
}

func sensitiveLogLine(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{"password", "set-cookie", "authorization:", "aionui-session", "csrf-token", "api_key", "api-key", "oauth", "bearer ", "secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func printFailures(label string, failures []error) error {
	if len(failures) == 0 {
		fmt.Printf("%s: PASS\n", label)
		return nil
	}
	for _, failure := range failures {
		fmt.Printf("%s: FAIL: %v\n", label, failure)
	}
	return fmt.Errorf("%s failed with %d issue(s)", label, len(failures))
}

func newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	return flags
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: portal --config <absolute-path> <admin|user|windows-password|task|instance|model-bootstrap|limits|chatgpt-pro-limit|logs|release|acl|readiness> ...")
}
