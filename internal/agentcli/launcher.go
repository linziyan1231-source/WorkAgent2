package agentcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	PerUserSandboxEnvironment = "AIONUI_PER_USER_SANDBOX"
)

type LauncherSpec struct {
	Target string
	Args   []string
	Env    []string
}

type Versions struct {
	Codex  string
	Kimi   string
	Python string
}

func Spec(executablePath string, arguments, environment []string) (LauncherSpec, error) {
	if !filepath.IsAbs(executablePath) {
		return LauncherSpec{}, errors.New("agent CLI launcher path must be absolute")
	}
	root := filepath.Dir(filepath.Dir(filepath.Clean(executablePath)))
	verified, err := loadCurrentFast(root)
	if err != nil {
		return LauncherSpec{}, err
	}
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(executablePath), filepath.Ext(executablePath)))
	spec := LauncherSpec{Args: append([]string(nil), arguments...), Env: append([]string(nil), environment...)}
	switch name {
	case "codex":
		spec.Target = filepath.Join(verified.Path, filepath.FromSlash(CodexRelativePath))
		if environmentValue(spec.Env, PerUserSandboxEnvironment) == "1" {
			spec.Args = append([]string{"-c", `windows.sandbox="unelevated"`}, spec.Args...)
		}
		spec.Env = setEnvironment(spec.Env, "CODEX_MANAGED_PACKAGE_ROOT", filepath.Join(verified.Path, "codex"))
		spec.Env = prependEnvironmentPath(spec.Env, filepath.Join(verified.Path, "codex", "vendor", "x86_64-pc-windows-msvc", "codex-path"))
	case "kimi":
		if _, ok := verified.Manifest.Files[KimiCodeRelativePath]; ok {
			spec.Target = filepath.Join(verified.Path, filepath.FromSlash(KimiCodeRelativePath))
			spec.Env = setEnvironment(spec.Env, "KIMI_CODE_NO_AUTO_UPDATE", "1")
		} else {
			spec.Target = filepath.Join(verified.Path, filepath.FromSlash(KimiRelativePath))
			spec.Args = append([]string{"-m", "kimi_cli"}, spec.Args...)
			spec.Env = setEnvironment(spec.Env, "PYTHONDONTWRITEBYTECODE", "1")
		}
	case "python":
		spec.Target = filepath.Join(verified.Path, filepath.FromSlash(PythonRelativePath))
		// The shared Python runtime is an immutable, manifest-verified release.
		// Prevent imports (notably `python -m pip`) from refreshing bytecode in
		// that protected tree when the launcher is invoked by an administrator.
		spec.Env = setEnvironment(spec.Env, "PYTHONDONTWRITEBYTECODE", "1")
	default:
		return LauncherSpec{}, fmt.Errorf("unsupported shared agent CLI launcher name %q", name)
	}
	return spec, nil
}

func RunLauncher(executablePath string, arguments []string) error {
	spec, err := Spec(executablePath, arguments, os.Environ())
	if err != nil {
		return err
	}
	command := exec.Command(spec.Target, spec.Args...)
	command.Env = spec.Env
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func Probe(ctx context.Context, binDirectory string, environment []string, prepare func(*exec.Cmd) error) (Versions, error) {
	if !filepath.IsAbs(binDirectory) {
		return Versions{}, errors.New("agent CLI bin directory must be absolute")
	}
	verified, err := loadCurrentFast(filepath.Dir(filepath.Clean(binDirectory)))
	if err != nil {
		return Versions{}, err
	}
	checks := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "Codex", path: filepath.Join(binDirectory, "codex.exe"), expected: "codex-cli " + verified.Manifest.CodexVersion},
		{name: "Kimi", path: filepath.Join(binDirectory, "kimi.exe"), expected: expectedKimiVersion(verified.Manifest)},
		{name: "Python", path: filepath.Join(binDirectory, "python.exe"), expected: "Python " + verified.Manifest.PythonVersion},
	}
	versions := Versions{Codex: verified.Manifest.CodexVersion, Kimi: verified.Manifest.KimiVersion, Python: verified.Manifest.PythonVersion}
	for _, check := range checks {
		resolved, err := executableFromPath(environment, filepath.Base(check.path))
		if err != nil {
			return Versions{}, fmt.Errorf("%s CLI PATH lookup failed: %w", check.name, err)
		}
		if !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(check.path)) {
			return Versions{}, fmt.Errorf("%s CLI PATH resolved to %s instead of protected launcher %s", check.name, resolved, check.path)
		}
		probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		command := exec.CommandContext(probeCtx, resolved, "--version")
		command.Env = environment
		if prepare != nil {
			if err := prepare(command); err != nil {
				cancel()
				return Versions{}, fmt.Errorf("prepare %s CLI version probe: %w", check.name, err)
			}
		}
		output, commandErr := command.CombinedOutput()
		cancel()
		if commandErr != nil {
			return Versions{}, fmt.Errorf("%s CLI version probe failed: %w (%s)", check.name, commandErr, strings.TrimSpace(string(output)))
		}
		if actual := strings.TrimSpace(string(output)); actual != check.expected {
			return Versions{}, fmt.Errorf("%s CLI reported %q, expected %q", check.name, actual, check.expected)
		}
	}
	return versions, nil
}

func expectedKimiVersion(manifest Manifest) string {
	if _, ok := manifest.Files[KimiCodeRelativePath]; ok {
		return manifest.KimiVersion
	}
	return "kimi, version " + manifest.KimiVersion
}

func executableFromPath(environment []string, name string) (string, error) {
	for _, directory := range filepath.SplitList(environmentValue(environment, "PATH")) {
		if directory == "" {
			continue
		}
		candidate := filepath.Join(directory, name)
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("%s was not found in PATH", name)
}

func PrependPath(environment []string, directory string) []string {
	return prependEnvironmentPath(environment, directory)
}

func prependEnvironmentPath(environment []string, directory string) []string {
	current := environmentValue(environment, "PATH")
	for _, segment := range filepath.SplitList(current) {
		if strings.EqualFold(filepath.Clean(segment), filepath.Clean(directory)) {
			return environment
		}
	}
	value := directory
	if current != "" {
		value += string(os.PathListSeparator) + current
	}
	return setEnvironment(environment, "PATH", value)
}

func setEnvironment(environment []string, key, value string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name := entry
		if index := strings.IndexByte(entry, '='); index >= 0 {
			name = entry[:index]
		}
		if !strings.EqualFold(name, key) {
			result = append(result, entry)
		}
	}
	return append(result, key+"="+value)
}

func environmentValue(environment []string, key string) string {
	for _, entry := range environment {
		if index := strings.IndexByte(entry, '='); index >= 0 && strings.EqualFold(entry[:index], key) {
			return entry[index+1:]
		}
	}
	return ""
}
