package cliproxy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/fsutil"
)

type RuntimeConfigOptions struct {
	TemplatePath          string
	OutputPath            string
	CredentialPath        string
	StateRoot             string
	KeyCopyPath           string
	RequireDedicatedOwner bool
}

type yamlTemplateField struct {
	line  int
	value string
}

// PrepareRuntimeConfig renders the immutable non-secret template to a
// dedicated-user-owned 0600 runtime file. The management plaintext is never
// written: only its bcrypt hash is inserted into remote-management.secret-key.
func PrepareRuntimeConfig(options RuntimeConfigOptions) error {
	for name, value := range map[string]string{
		"template": options.TemplatePath, "output": options.OutputPath,
		"credential": options.CredentialPath, "state root": options.StateRoot,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
			return fmt.Errorf("CLIProxy %s path must be clean and absolute", name)
		}
	}
	if filepath.Dir(options.OutputPath) != options.StateRoot {
		return errors.New("CLIProxy runtime config must be written directly inside the state root")
	}
	_, stateStat, err := protectedDirectory(options.StateRoot, 0o700)
	if err != nil {
		return fmt.Errorf("CLIProxy state root: %w", err)
	}
	if options.RequireDedicatedOwner && stateStat.Uid == 0 {
		return errors.New("CLIProxy state root must be owned by its dedicated non-root user")
	}
	if err := protectedChildDirectory(config.CLIProxyAuthDirectory, stateStat); err != nil {
		return fmt.Errorf("CLIProxy OAuth auth-dir: %w", err)
	}
	if err := protectedChildDirectory(filepath.Dir(config.CLIProxyPolicyStateFile), stateStat); err != nil {
		return fmt.Errorf("CLIProxy policy directory: %w", err)
	}
	if err := protectedTemplate(options.TemplatePath); err != nil {
		return err
	}
	credential, err := readRootCredential(options.CredentialPath)
	if err != nil {
		return err
	}
	defer clear(credential)
	if options.KeyCopyPath != "" {
		if err := writeManagementKeyCopy(options.KeyCopyPath, credential, stateStat); err != nil {
			return err
		}
	}
	template, err := os.ReadFile(options.TemplatePath)
	if err != nil {
		return errors.New("CLIProxy config template could not be read")
	}
	defer clear(template)
	rendered, err := renderRuntimeConfig(template, credential)
	if err != nil {
		return err
	}
	defer clear(rendered)
	if err := verifyExistingRuntimeConfig(options.OutputPath, stateStat); err != nil {
		return err
	}
	if err := atomicWriteRuntimeConfig(options.OutputPath, rendered, stateStat); err != nil {
		return err
	}
	return nil
}

// writeManagementKeyCopy publishes the plaintext management key where a
// privileged ExecStartPost on the host mount namespace can read it. systemd
// moves LoadCredentialEncrypted material into the unit namespace once the
// main process starts, so elevated post-start processes cannot use the
// per-unit credentials directory. The copy is root-owned, group-readable by
// the dedicated CLIProxy identity only.
func writeManagementKeyCopy(path string, credential []byte, owner *syscall.Stat_t) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("CLIProxy management key copy path must be clean and absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("CLIProxy management key copy parent is unsafe")
	}
	return fsutil.WriteFileAtomic(path, append(append([]byte(nil), credential...), '\n'), fsutil.AtomicWriteOptions{
		Mode:        0o440,
		Owner:       &fsutil.AtomicOwner{UID: 0, GID: int(owner.Gid)},
		TempPattern: ".management-key.partial-*",
		CreateError: errors.New("create CLIProxy management key copy"),
	})
}

func protectedDirectory(path string, mode os.FileMode) (os.FileInfo, *syscall.Stat_t, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode {
		return nil, nil, errors.New("directory is missing, linked, or has unsafe permissions")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, errors.New("directory ownership is unavailable")
	}
	return info, stat, nil
}

func protectedChildDirectory(path string, owner *syscall.Stat_t) error {
	_, stat, err := protectedDirectory(path, 0o700)
	if err != nil {
		return err
	}
	if stat.Uid != owner.Uid || stat.Gid != owner.Gid {
		return errors.New("directory ownership does not match the state root")
	}
	return nil
}

func protectedTemplate(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxRuntimeConfigResponse || info.Mode().Perm()&0o022 != 0 {
		return errors.New("CLIProxy config template is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("CLIProxy config template must be owned by root")
	}
	return nil
}

func readRootCredential(path string) ([]byte, error) {
	// systemd exposes LoadCredentialEncrypted files as root:root 0440 with a
	// service-group read grant, so group readability is accepted here while
	// any world access stays forbidden.
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 1024 || info.Mode().Perm()&0o007 != 0 {
		return nil, errors.New("CLIProxy management credential is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("CLIProxy management credential must be owned by root")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("CLIProxy management credential could not be read")
	}
	defer clear(raw)
	payload := bytes.TrimSpace(raw)
	if !managementKeyPattern.Match(payload) {
		return nil, errors.New("CLIProxy management credential has invalid content")
	}
	return append([]byte(nil), payload...), nil
}

func renderRuntimeConfig(template, credential []byte) ([]byte, error) {
	identity, err := parseRuntimeConfigIdentity(template)
	if err != nil {
		return nil, fmt.Errorf("CLIProxy config template: %w", err)
	}
	if identity.Host != "127.0.0.1" || identity.Port != 8317 || identity.AllowRemote || identity.AuthDir != config.CLIProxyAuthDirectory {
		return nil, errors.New("CLIProxy config template does not match the locked listener/auth contract")
	}
	fields, lines, trailingNewline, err := parseYAMLTemplateFields(template)
	if err != nil {
		return nil, err
	}
	required := map[string]string{
		"remote-management.allow-remote":              "false",
		"remote-management.disable-control-panel":     "true",
		"remote-management.disable-auto-update-panel": "true",
		"logs-max-total-size-mb":                      "256",
		"error-logs-max-files":                        "10",
		"proxy-url":                                   "http://127.0.0.1:8118",
		"plugins.enabled":                             "true",
		"plugins.dir":                                 config.CLIProxyPluginDirectory,
		"plugins.configs.cpa-key-policy.enabled":      "true",
		"plugins.configs.cpa-key-policy.priority":     "10",
		"plugins.configs.cpa-key-policy.state_file":   config.CLIProxyPolicyStateFile,
	}
	for path, expected := range required {
		field, ok := fields[path]
		if !ok || field.value != expected {
			return nil, fmt.Errorf("CLIProxy config template field %s does not match the production contract", path)
		}
	}
	secret, ok := fields["remote-management.secret-key"]
	if !ok || secret.value != "" {
		return nil, errors.New("CLIProxy config template must contain one empty remote-management.secret-key")
	}
	hash, err := bcrypt.GenerateFromPassword(credential, bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("CLIProxy management credential could not be hashed")
	}
	defer clear(hash)
	lines[secret.line] = "  secret-key: " + strconv.Quote(string(hash))
	result := []byte(strings.Join(lines, "\n"))
	if trailingNewline {
		result = append(result, '\n')
	}
	return result, nil
}

func parseYAMLTemplateFields(raw []byte) (map[string]yamlTemplateField, []string, bool, error) {
	if bytes.IndexByte(raw, 0) >= 0 || len(raw) == 0 || len(raw) > maxRuntimeConfigResponse {
		return nil, nil, false, errors.New("CLIProxy config template is empty or unsafe")
	}
	text := string(raw)
	trailingNewline := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	parents := make([]string, 0, 8)
	fields := make(map[string]yamlTemplateField)
	for index, original := range lines {
		line := strings.TrimSuffix(original, "\r")
		if strings.ContainsRune(line, '\t') {
			return nil, nil, false, errors.New("CLIProxy config template contains tabs")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			return nil, nil, false, errors.New("CLIProxy config template uses unsupported indentation")
		}
		depth := indent / 2
		colon := strings.IndexByte(trimmed, ':')
		if colon < 1 || depth > len(parents) {
			continue
		}
		key := strings.TrimSpace(trimmed[:colon])
		if strings.ContainsAny(key, " \"'") {
			continue
		}
		parents = parents[:depth]
		pathParts := append(append([]string(nil), parents...), key)
		path := strings.Join(pathParts, ".")
		rawValue := strings.TrimSpace(trimmed[colon+1:])
		value, scalarErr := parseYAMLScalar(rawValue)
		if rawValue == "" || strings.HasPrefix(rawValue, "#") {
			parents = append(parents, key)
			continue
		}
		if scalarErr != nil {
			continue
		}
		if _, duplicate := fields[path]; duplicate {
			return nil, nil, false, fmt.Errorf("CLIProxy config template field %s is duplicated", path)
		}
		fields[path] = yamlTemplateField{line: index, value: value}
	}
	return fields, lines, trailingNewline, nil
}

func verifyExistingRuntimeConfig(path string, owner *syscall.Stat_t) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("existing CLIProxy runtime config is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner.Uid || stat.Gid != owner.Gid {
		return errors.New("existing CLIProxy runtime config has unexpected ownership")
	}
	return nil
}

func atomicWriteRuntimeConfig(path string, payload []byte, owner *syscall.Stat_t) error {
	return fsutil.WriteFileAtomic(path, payload, fsutil.AtomicWriteOptions{
		Mode:        0o600,
		Owner:       &fsutil.AtomicOwner{UID: int(owner.Uid), GID: int(owner.Gid)},
		TempPattern: ".config.yaml.partial-*",
		CreateError: errors.New("create CLIProxy runtime config"),
	})
}
