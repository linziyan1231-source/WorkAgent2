package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aionuiportal/internal/agentcli"
	"aionuiportal/internal/winutil"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(arguments []string) int {
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(executable), filepath.Ext(executable)))
	if name == "codex" || name == "kimi" || name == "python" {
		if err := agentcli.RunLauncher(executable, arguments); err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) && exitError.ExitCode() >= 0 {
				return exitError.ExitCode()
			}
			fmt.Fprintf(os.Stderr, "shared %s launcher failed: %v\n", name, err)
			return 1
		}
		return 0
	}
	if _, err := winutil.RequireAdministrator(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := adminCommand(arguments); err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		return 1
	}
	return 0
}

func adminCommand(arguments []string) error {
	if len(arguments) < 2 {
		return errors.New("usage: AionAgentCli.exe <release|acl> <command> [options]")
	}
	switch arguments[0] {
	case "release":
		return releaseCommand(arguments[1:])
	case "acl":
		return aclCommand(arguments[1:])
	default:
		return fmt.Errorf("unknown administration command %q", arguments[0])
	}
}

func releaseCommand(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("release command is required")
	}
	flags := flag.NewFlagSet("release "+arguments[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "", "absolute shared agent CLI root")
	releaseID := flags.String("release-id", "", "immutable release ID")
	switch arguments[0] {
	case "manifest":
		codexVersion := flags.String("codex-version", "", "Codex CLI version")
		kimiVersion := flags.String("kimi-version", "", "Kimi CLI version")
		pythonVersion := flags.String("python-version", "", "Kimi Python runtime version")
		if err := flags.Parse(arguments[1:]); err != nil || *root == "" || *releaseID == "" || *codexVersion == "" || *kimiVersion == "" || *pythonVersion == "" || flags.NArg() != 0 {
			return errors.New("usage: AionAgentCli.exe release manifest --root <path> --release-id <id> --codex-version <version> --kimi-version <version> --python-version <version>")
		}
		releasePath := filepath.Join(*root, "releases", *releaseID)
		manifest, err := agentcli.BuildManifest(releasePath, *releaseID, *codexVersion, *kimiVersion, *pythonVersion)
		if err != nil {
			return err
		}
		hash, err := agentcli.WriteManifest(releasePath, manifest)
		if err != nil {
			return err
		}
		fmt.Printf("Wrote agent CLI manifest with %d files and SHA-256 %s.\n", len(manifest.Files), hash)
		return nil
	case "verify":
		if err := flags.Parse(arguments[1:]); err != nil || *root == "" || flags.NArg() != 0 {
			return errors.New("usage: AionAgentCli.exe release verify --root <path> [--release-id <id>]")
		}
		var verified agentcli.Verified
		var err error
		if *releaseID == "" {
			verified, err = agentcli.VerifyCurrent(*root)
		} else {
			verified, err = agentcli.VerifyRelease(*root, *releaseID)
		}
		if err != nil {
			return err
		}
		fmt.Printf("Verified shared Codex %s / Kimi %s / Python %s release %s (%d files).\n", verified.Manifest.CodexVersion,
			verified.Manifest.KimiVersion, verified.Manifest.PythonVersion, verified.Manifest.ReleaseID, len(verified.Manifest.Files))
		return nil
	case "activate":
		if err := flags.Parse(arguments[1:]); err != nil || *root == "" || *releaseID == "" || flags.NArg() != 0 {
			return errors.New("usage: AionAgentCli.exe release activate --root <path> --release-id <id>")
		}
		verified, err := agentcli.Activate(*root, *releaseID)
		if err != nil {
			return err
		}
		fmt.Printf("Atomically activated shared agent CLI release %s.\n", verified.Manifest.ReleaseID)
		return nil
	default:
		return fmt.Errorf("unknown release command %q", arguments[0])
	}
}

func aclCommand(arguments []string) error {
	if len(arguments) == 0 || (arguments[0] != "apply" && arguments[0] != "verify") {
		return errors.New("usage: AionAgentCli.exe acl <apply|verify> --root <path>")
	}
	flags := flag.NewFlagSet("acl "+arguments[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "", "absolute shared agent CLI root")
	if err := flags.Parse(arguments[1:]); err != nil || *root == "" || flags.NArg() != 0 || !filepath.IsAbs(*root) {
		return errors.New("usage: AionAgentCli.exe acl <apply|verify> --root <absolute-path>")
	}
	if arguments[0] == "apply" {
		if err := winutil.ApplyTreeACL(*root, winutil.SharedReadOnlyPolicy()); err != nil {
			return err
		}
	}
	if err := winutil.VerifyTreeACL(*root, winutil.SharedReadOnlyPolicy()); err != nil {
		return err
	}
	fmt.Printf("Shared agent CLI ACL %s: PASS\n", arguments[0])
	return nil
}
