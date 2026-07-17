package main

import (
	"bufio"
	"context"
	"crypto/sha256"
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
	"aionuiportal/internal/auth"
	"aionuiportal/internal/config"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/kimi"
	"aionuiportal/internal/release"
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
	codexDefault := flags.String("codex-default-model", "example-reasoning", "default Codex model alias")
	codexModels := flags.String("codex-models", "", "comma-separated Codex/ChatGPT aliases")
	kimiModels := flags.String("kimi-models", "", "comma-separated Kimi aliases")
	rpm := flags.Int("rpm", 0, "requests per minute; zero means unlimited")
	codexDaily := flags.Float64("codex-daily-usd", 20, "Codex/ChatGPT daily USD limit")
	codexWeekly := flags.Float64("codex-weekly-usd", 40, "Codex/ChatGPT weekly USD limit")
	kimiDaily := flags.Float64("kimi-daily-usd", 5, "Kimi daily USD limit")
	kimiWeekly := flags.Float64("kimi-weekly-usd", 10, "Kimi weekly USD limit")
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

func kimiOAuthCommand(ctx context.Context, manager *admin.Manager, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: portal --config <path> kimi-oauth <validate-source|seed|seed-missing|update-all> ...")
	}
	flags := newFlags("kimi-oauth " + arguments[0])
	defaultSource, err := defaultKimiOAuthSource()
	if err != nil {
		return err
	}
	sourceOAuth := flags.String("source-oauth", defaultSource, "source Kimi Code OAuth JSON")
	sourceConfig := flags.String("source-config", "", "source Kimi config.toml; defaults beside the OAuth credentials directory")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if !filepath.IsAbs(*sourceOAuth) {
		return errors.New("--source-oauth must be an absolute path")
	}
	if *sourceConfig == "" {
		*sourceConfig = filepath.Join(filepath.Dir(filepath.Dir(filepath.Clean(*sourceOAuth))), "config.toml")
	}
	if !filepath.IsAbs(*sourceConfig) {
		return errors.New("--source-config must be an absolute path")
	}
	switch arguments[0] {
	case "validate-source":
		if flags.NArg() != 0 {
			return errors.New("usage: portal --config <path> kimi-oauth validate-source [--source-oauth <path>] [--source-config <path>]")
		}
		if err := manager.ValidateKimiOAuthSource(ctx, *sourceOAuth, *sourceConfig); err != nil {
			return err
		}
		fmt.Println("Kimi OAuth source and provider/model metadata: PASS")
		return nil
	case "seed":
		if flags.NArg() != 1 {
			return errors.New("usage: portal --config <path> kimi-oauth seed [--source-oauth <path>] [--source-config <path>] <portal-username>")
		}
		result, err := manager.SeedKimiOAuth(ctx, flags.Arg(0), *sourceOAuth, *sourceConfig)
		if err != nil {
			return err
		}
		fmt.Printf("user=%s outcome=SEEDED sha256=%s restarted=%t\n", flags.Arg(0), result.SHA256, result.Restarted)
		return nil
	case "seed-missing", "update-all":
		if flags.NArg() != 0 {
			return fmt.Errorf("usage: portal --config <path> kimi-oauth %s [--source-oauth <path>] [--source-config <path>]", arguments[0])
		}
		return seedKimiOAuthUsers(ctx, manager, *sourceOAuth, *sourceConfig, arguments[0] == "seed-missing")
	default:
		return fmt.Errorf("unknown kimi-oauth subcommand %q", arguments[0])
	}
}

func seedKimiOAuthUsers(ctx context.Context, manager *admin.Manager, sourceOAuth, sourceConfig string, missingOnly bool) error {
	if err := manager.ValidateKimiOAuthSource(ctx, sourceOAuth, sourceConfig); err != nil {
		return err
	}
	expectedHash, err := kimi.CredentialSHA256(sourceOAuth)
	if err != nil {
		return err
	}
	users, err := manager.Store.ListUsers(ctx)
	if err != nil {
		return err
	}
	usernames := make([]string, 0, len(users))
	for _, user := range users {
		usernames = append(usernames, user.Username)
	}
	rows := executeKimiOAuthBatch(usernames, missingOnly, expectedHash,
		func(username string) (bool, error) { return manager.HasKimiOAuth(ctx, username) },
		func(username string) (admin.KimiOAuthSeedResult, error) {
			return manager.SeedKimiOAuth(ctx, username, sourceOAuth, sourceConfig)
		})
	succeeded, skipped, failed := 0, 0, 0
	for _, row := range rows {
		switch row.Outcome {
		case "SEEDED":
			fmt.Printf("user=%s outcome=SEEDED sha256=%s restarted=%t\n", row.Username, row.SHA256, row.Restarted)
			succeeded++
		case "SKIP":
			fmt.Printf("user=%s outcome=SKIP reason=%q\n", row.Username, row.Detail)
			skipped++
		default:
			fmt.Printf("user=%s outcome=FAIL error=%q\n", row.Username, row.Detail)
			failed++
		}
	}
	if finalHash, err := kimi.CredentialSHA256(sourceOAuth); err != nil {
		fmt.Printf("source outcome=FAIL error=%q\n", err)
		failed++
	} else if !strings.EqualFold(finalHash, expectedHash) {
		fmt.Printf("source outcome=FAIL error=%q\n", "source Kimi OAuth changed during the batch")
		failed++
	}
	fmt.Printf("Kimi OAuth batch summary: seeded=%d skipped=%d failed=%d\n", succeeded, skipped, failed)
	if failed != 0 {
		return fmt.Errorf("Kimi OAuth batch completed with %d failure(s)", failed)
	}
	return nil
}

type kimiOAuthBatchRow struct {
	Username  string
	Outcome   string
	Detail    string
	SHA256    string
	Restarted bool
}

func executeKimiOAuthBatch(usernames []string, missingOnly bool, expectedHash string,
	hasCredential func(string) (bool, error), seed func(string) (admin.KimiOAuthSeedResult, error)) []kimiOAuthBatchRow {
	rows := make([]kimiOAuthBatchRow, 0, len(usernames))
	for _, username := range usernames {
		if missingOnly {
			has, err := hasCredential(username)
			if err != nil {
				rows = append(rows, kimiOAuthBatchRow{Username: username, Outcome: "FAIL", Detail: err.Error()})
				continue
			}
			if has {
				rows = append(rows, kimiOAuthBatchRow{Username: username, Outcome: "SKIP", Detail: "valid Kimi OAuth already exists"})
				continue
			}
		}
		result, err := seed(username)
		if err != nil {
			rows = append(rows, kimiOAuthBatchRow{Username: username, Outcome: "FAIL", Detail: err.Error()})
			continue
		}
		if !strings.EqualFold(result.SHA256, expectedHash) {
			rows = append(rows, kimiOAuthBatchRow{Username: username, Outcome: "FAIL", Detail: "source Kimi OAuth changed during the batch"})
			continue
		}
		rows = append(rows, kimiOAuthBatchRow{Username: username, Outcome: "SEEDED", SHA256: result.SHA256, Restarted: result.Restarted})
	}
	return rows
}

func defaultKimiOAuthSource() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve administrator profile for the default Kimi OAuth source: %w", err)
	}
	return filepath.Join(home, ".kimi", "credentials", "kimi-code.json"), nil
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
		return errors.New("usage: portal --config <path> instance <list|status|start|stop|restart> [portal-username]")
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
	if running, err := anyRunning(ctx, manager); err != nil {
		return err
	} else if running {
		return errors.New("all UserHost instances must be drained or stopped before release switching")
	}
	previous := filepath.Join(filepath.Dir(manager.Config.CurrentReleaseFile), "previous.json")
	switch arguments[0] {
	case "install":
		flags := newFlags("release install")
		source := flags.String("source", "", "packed AionUi Web CLI directory")
		version := flags.String("version", "", "immutable release version")
		coreVersion := flags.String("aioncore-version", "", "bundled aioncore version")
		if err := flags.Parse(arguments[1:]); err != nil || *source == "" || *version == "" || *coreVersion == "" || flags.NArg() != 0 {
			return errors.New("usage: portal --config <path> release install --source <dir> --version <version> --aioncore-version <version>")
		}
		if err := backupUserDatabases(ctx, manager, "pre-release-"+time.Now().UTC().Format("20060102T150405Z")); err != nil {
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
	users, err := manager.Store.ListUsers(ctx)
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
	verification, err := os.Open(destination)
	if err != nil {
		return "", err
	}
	verifiedHash := sha256.New()
	_, copyErr := io.Copy(verifiedHash, verification)
	closeErr := verification.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if !strings.EqualFold(hex.EncodeToString(verifiedHash.Sum(nil)), expectedHash) {
		return "", errors.New("backup destination hash verification failed")
	}
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
	fmt.Fprintln(os.Stderr, "usage: portal --config <absolute-path> <user|windows-password|task|instance|model-bootstrap|limits|logs|release|acl|readiness> ...")
}
