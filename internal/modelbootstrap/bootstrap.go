package modelbootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	FormatVersion     = 1
	BundleFileName    = "model-bootstrap-v1.json"
	MarkerFileName    = "model-bootstrap-v1.applied.json"
	CodexProviderID   = "managed-cliproxy-chatgpt"
	KimiProviderID    = "managed-cliproxy-kimi"
	maxBootstrapFile  = 256 * 1024
	CodexProviderName = "ChatGPT (CLIProxyAPI)"
	KimiProviderName  = "Kimi for Coding (CLIProxyAPI)"
)

var (
	keyIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	apiKeyPattern = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	modelPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type State struct {
	FormatVersion     int      `json:"format_version"`
	BaseURL           string   `json:"base_url"`
	CodexKeyID        string   `json:"codex_key_id"`
	KimiKeyID         string   `json:"kimi_key_id"`
	CodexDefaultModel string   `json:"codex_default_model"`
	CodexModels       []string `json:"codex_models"`
	KimiModels        []string `json:"kimi_models"`
}

type Bundle struct {
	State
	CodexAPIKey string `json:"codex_api_key"`
	KimiAPIKey  string `json:"kimi_api_key"`
}

type Status struct {
	Applied bool
	Pending bool
	State   State
}

func (s State) Validate() error {
	if s.FormatVersion != FormatVersion {
		return fmt.Errorf("unsupported model bootstrap format_version %d", s.FormatVersion)
	}
	parsed, err := url.Parse(s.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("model bootstrap base_url must be an absolute HTTP or HTTPS URL without credentials, query, or fragment")
	}
	if parsed.Path != "/v1" || strings.HasSuffix(s.BaseURL, "/") {
		return errors.New("model bootstrap base_url must end exactly in /v1")
	}
	if !keyIDPattern.MatchString(s.CodexKeyID) || !keyIDPattern.MatchString(s.KimiKeyID) || s.CodexKeyID == s.KimiKeyID {
		return errors.New("model bootstrap key ids are invalid or duplicated")
	}
	if err := validateModels("Codex", s.CodexModels); err != nil {
		return err
	}
	if err := validateModels("Kimi", s.KimiModels); err != nil {
		return err
	}
	if !modelPattern.MatchString(s.CodexDefaultModel) || !contains(s.CodexModels, s.CodexDefaultModel) {
		return errors.New("Codex default model must be one of the configured Codex models")
	}
	return nil
}

func (b Bundle) Validate() error {
	if err := b.State.Validate(); err != nil {
		return err
	}
	if !apiKeyPattern.MatchString(b.CodexAPIKey) || !apiKeyPattern.MatchString(b.KimiAPIKey) || b.CodexAPIKey == b.KimiAPIKey {
		return errors.New("model bootstrap API keys are invalid or duplicated")
	}
	return nil
}

func validateModels(name string, models []string) error {
	if len(models) == 0 || len(models) > 64 {
		return fmt.Errorf("%s models must contain between 1 and 64 entries", name)
	}
	seen := make(map[string]bool, len(models))
	for _, model := range models {
		lower := strings.ToLower(model)
		if !modelPattern.MatchString(model) || seen[lower] {
			return fmt.Errorf("%s models contain an invalid or duplicated entry", name)
		}
		seen[lower] = true
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func Paths(dataRoot string) (bundlePath, markerPath string, err error) {
	if !filepath.IsAbs(dataRoot) {
		return "", "", errors.New("model bootstrap data root must be absolute")
	}
	root := filepath.Clean(dataRoot)
	return filepath.Join(root, "credentials", BundleFileName), filepath.Join(root, "config", MarkerFileName), nil
}

func Inspect(dataRoot string) (Status, error) {
	bundlePath, markerPath, err := Paths(dataRoot)
	if err != nil {
		return Status{}, err
	}
	bundleExists, err := regularFileExists(bundlePath)
	if err != nil {
		return Status{}, fmt.Errorf("inspect pending model bootstrap: %w", err)
	}
	markerExists, err := regularFileExists(markerPath)
	if err != nil {
		return Status{}, fmt.Errorf("inspect model bootstrap marker: %w", err)
	}
	if bundleExists && markerExists {
		return Status{}, errors.New("model bootstrap has both a pending bundle and an applied marker")
	}
	if markerExists {
		var state State
		if err := readStrictJSON(markerPath, &state); err != nil {
			return Status{}, fmt.Errorf("read model bootstrap marker: %w", err)
		}
		if err := state.Validate(); err != nil {
			return Status{}, fmt.Errorf("validate model bootstrap marker: %w", err)
		}
		return Status{Applied: true, State: state}, nil
	}
	if bundleExists {
		var bundle Bundle
		if err := readStrictJSON(bundlePath, &bundle); err != nil {
			return Status{}, fmt.Errorf("read pending model bootstrap: %w", err)
		}
		if err := bundle.Validate(); err != nil {
			return Status{}, fmt.Errorf("validate pending model bootstrap: %w", err)
		}
		return Status{Pending: true, State: bundle.State}, nil
	}
	return Status{}, nil
}

func LoadPending(dataRoot string) (Bundle, bool, error) {
	status, err := Inspect(dataRoot)
	if err != nil {
		return Bundle{}, false, err
	}
	if !status.Pending {
		return Bundle{}, false, nil
	}
	bundlePath, _, _ := Paths(dataRoot)
	var bundle Bundle
	if err := readStrictJSON(bundlePath, &bundle); err != nil {
		return Bundle{}, false, err
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, false, err
	}
	return bundle, true, nil
}

func Stage(dataRoot string, bundle Bundle, replace bool) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	status, err := Inspect(dataRoot)
	if err != nil {
		return err
	}
	if (status.Applied || status.Pending) && !replace {
		return errors.New("model bootstrap is already applied or pending")
	}
	bundlePath, markerPath, _ := Paths(dataRoot)
	if status.Applied {
		if err := os.Remove(markerPath); err != nil {
			return fmt.Errorf("remove previous model bootstrap marker: %w", err)
		}
	}
	if err := writeJSONAtomic(bundlePath, bundle); err != nil {
		return fmt.Errorf("stage model bootstrap bundle: %w", err)
	}
	return nil
}

func Complete(dataRoot string, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	bundlePath, markerPath, err := Paths(dataRoot)
	if err != nil {
		return err
	}
	exists, err := regularFileExists(bundlePath)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("pending model bootstrap bundle is missing")
	}
	if err := os.Remove(bundlePath); err != nil {
		return fmt.Errorf("remove consumed model bootstrap bundle: %w", err)
	}
	if err := writeJSONAtomic(markerPath, state); err != nil {
		return fmt.Errorf("write model bootstrap marker: %w", err)
	}
	return nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("path must be a regular non-symlink file")
	}
	if info.Size() > maxBootstrapFile {
		return false, fmt.Errorf("file exceeds %d bytes", maxBootstrapFile)
	}
	return true, nil
}

func readStrictJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > maxBootstrapFile {
		return fmt.Errorf("file exceeds %d bytes", maxBootstrapFile)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("model bootstrap parent must be a regular directory")
	}
	temporary, err := os.CreateTemp(directory, ".model-bootstrap.tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return nil
}

func SortedModels(models []string) []string {
	result := append([]string(nil), models...)
	sort.Strings(result)
	return result
}
