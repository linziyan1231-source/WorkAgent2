package modelbootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	FormatVersion               = 1
	BundleFileName              = "model-bootstrap-v1.json"
	MarkerFileName              = "model-bootstrap-v1.applied.json"
	RebaseFileName              = "model-bootstrap-v1.rebase.json"
	CodexProviderID             = "managed-cliproxy-chatgpt"
	KimiProviderID              = "managed-cliproxy-kimi"
	maxBootstrapFile            = 256 * 1024
	CodexProviderName           = "ChatGPT"
	KimiProviderName            = "KIMI"
	DefaultCodexModel           = "gpt-5.6-sol"
	DefaultCodexReasoningEffort = "low"
)

var (
	managedCodexModels        = []string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"}
	managedKimiModels         = []string{"kimi-for-coding", "kimi-for-coding-highspeed", "kimi-k3"}
	previousManagedKimiModels = []string{"kimi-for-coding", "kimi-for-coding-highspeed"}
)

func ManagedCodexModels() []string { return append([]string(nil), managedCodexModels...) }

func ManagedKimiModels() []string { return append([]string(nil), managedKimiModels...) }

var (
	keyIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	apiKeyPattern = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	modelPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

var ErrAppliedMarkerMissing = errors.New("applied model bootstrap marker is missing")

type State struct {
	FormatVersion     int      `json:"format_version"`
	BaseURL           string   `json:"base_url"`
	CodexKeyID        string   `json:"codex_key_id"`
	KimiKeyID         string   `json:"kimi_key_id"`
	CodexDefaultModel string   `json:"codex_default_model"`
	CodexModels       []string `json:"codex_models"`
	KimiModels        []string `json:"kimi_models"`
}

type KeyIDs struct {
	CodexKeyID string `json:"codex_key_id"`
	KimiKeyID  string `json:"kimi_key_id"`
}

type Bundle struct {
	State
	CodexAPIKey string `json:"codex_api_key"`
	KimiAPIKey  string `json:"kimi_api_key"`
}

type Status struct {
	Applied       bool
	Pending       bool
	RebasePending bool
	State         State
}

type Rebase struct {
	FormatVersion int   `json:"format_version"`
	Previous      State `json:"previous"`
	Target        State `json:"target"`
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
	if !slices.Equal(s.KimiModels, managedKimiModels) {
		return errors.New("Kimi models must match the managed model policy")
	}
	if !modelPattern.MatchString(s.CodexDefaultModel) || !contains(s.CodexModels, s.CodexDefaultModel) {
		return errors.New("Codex default model must be one of the configured Codex models")
	}
	return nil
}

func KeyIDsForSID(windowsSID string) KeyIDs {
	digest := sha256.Sum256([]byte(strings.ToUpper(windowsSID)))
	prefix := "aionui-" + hex.EncodeToString(digest[:10])
	return KeyIDs{CodexKeyID: prefix + "-chatgpt", KimiKeyID: prefix + "-kimi"}
}

func (ids KeyIDs) ValidateForSID(windowsSID string) error {
	if !keyIDPattern.MatchString(ids.CodexKeyID) || !keyIDPattern.MatchString(ids.KimiKeyID) || ids.CodexKeyID == ids.KimiKeyID {
		return errors.New("model bootstrap key ids are invalid or duplicated")
	}
	if ids != KeyIDsForSID(windowsSID) {
		return errors.New("model bootstrap key ids do not match the Windows SID")
	}
	return nil
}

func (s State) ValidateForSID(windowsSID string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	return (KeyIDs{CodexKeyID: s.CodexKeyID, KimiKeyID: s.KimiKeyID}).ValidateForSID(windowsSID)
}

func (s State) validateApplied() error {
	if slices.Equal(s.KimiModels, previousManagedKimiModels) {
		current := s
		current.KimiModels = managedKimiModels
		return current.Validate()
	}
	return s.Validate()
}

func (s State) validateAppliedForSID(windowsSID string) error {
	if err := s.validateApplied(); err != nil {
		return err
	}
	return (KeyIDs{CodexKeyID: s.CodexKeyID, KimiKeyID: s.KimiKeyID}).ValidateForSID(windowsSID)
}

func AppliedKeyIDs(dataRoot, windowsSID string) (KeyIDs, error) {
	_, markerPath, err := Paths(dataRoot)
	if err != nil {
		return KeyIDs{}, err
	}
	exists, err := regularFileExists(markerPath)
	if err != nil {
		return KeyIDs{}, fmt.Errorf("inspect applied model bootstrap marker: %w", err)
	}
	if !exists {
		return KeyIDs{}, ErrAppliedMarkerMissing
	}
	var state State
	if err := readStrictJSON(markerPath, &state); err != nil {
		return KeyIDs{}, fmt.Errorf("read applied model bootstrap marker: %w", err)
	}
	if err := state.validateAppliedForSID(windowsSID); err != nil {
		return KeyIDs{}, fmt.Errorf("validate applied model bootstrap marker: %w", err)
	}
	return KeyIDs{CodexKeyID: state.CodexKeyID, KimiKeyID: state.KimiKeyID}, nil
}

func UpdateAppliedCodexDefaultModel(dataRoot, model string) (bool, error) {
	status, err := Inspect(dataRoot)
	if err != nil {
		return false, err
	}
	if !status.Applied || status.Pending || status.RebasePending {
		return false, errors.New("model bootstrap must be applied without a pending operation")
	}
	if status.State.CodexDefaultModel == model {
		return false, nil
	}
	updated := status.State
	updated.CodexDefaultModel = model
	if err := updated.Validate(); err != nil {
		return false, fmt.Errorf("validate updated Codex default model: %w", err)
	}
	_, markerPath, err := Paths(dataRoot)
	if err != nil {
		return false, err
	}
	if err := writeJSONAtomic(markerPath, updated); err != nil {
		return false, fmt.Errorf("write updated model bootstrap marker: %w", err)
	}
	verified, err := Inspect(dataRoot)
	if err != nil {
		return false, fmt.Errorf("verify updated model bootstrap marker: %w", err)
	}
	if !verified.Applied || verified.Pending || verified.RebasePending || !statesEqual(verified.State, updated) {
		return false, errors.New("updated model bootstrap marker did not persist exactly")
	}
	return true, nil
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

func rebasePath(dataRoot string) (string, error) {
	if !filepath.IsAbs(dataRoot) {
		return "", errors.New("model bootstrap data root must be absolute")
	}
	return filepath.Join(filepath.Clean(dataRoot), "credentials", RebaseFileName), nil
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
	rebaseFile, _ := rebasePath(dataRoot)
	rebaseExists, err := regularFileExists(rebaseFile)
	if err != nil {
		return Status{}, fmt.Errorf("inspect pending model bootstrap rebase: %w", err)
	}
	if bundleExists && rebaseExists {
		return Status{}, errors.New("model bootstrap has both a pending key bundle and a pending rebase")
	}
	if bundleExists && markerExists {
		return Status{}, errors.New("model bootstrap has both a pending bundle and an applied marker")
	}
	if rebaseExists {
		rebase, err := loadRebase(rebaseFile)
		if err != nil {
			return Status{}, fmt.Errorf("read pending model bootstrap rebase: %w", err)
		}
		state := rebase.Previous
		if markerExists {
			if err := readStrictJSON(markerPath, &state); err != nil {
				return Status{}, fmt.Errorf("read model bootstrap marker: %w", err)
			}
			if !statesEqual(state, rebase.Previous) && !statesEqual(state, rebase.Target) {
				return Status{}, errors.New("model bootstrap marker does not match the pending rebase")
			}
		}
		return Status{Applied: markerExists, RebasePending: true, State: state}, nil
	}
	if markerExists {
		var state State
		if err := readStrictJSON(markerPath, &state); err != nil {
			return Status{}, fmt.Errorf("read model bootstrap marker: %w", err)
		}
		if err := state.validateApplied(); err != nil {
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

func StageRebase(dataRoot, baseURL string) (Rebase, error) {
	status, err := Inspect(dataRoot)
	if err != nil {
		return Rebase{}, err
	}
	if !status.Applied || status.Pending || status.RebasePending {
		return Rebase{}, errors.New("model bootstrap must be applied without another pending operation")
	}
	target, err := PrepareRebaseTarget(status.State, baseURL)
	if err != nil {
		return Rebase{}, err
	}
	rebase := Rebase{FormatVersion: FormatVersion, Previous: status.State, Target: target}
	path, _ := rebasePath(dataRoot)
	if err := writeJSONAtomic(path, rebase); err != nil {
		return Rebase{}, fmt.Errorf("stage model bootstrap rebase: %w", err)
	}
	return rebase, nil
}

func PrepareRebaseTarget(previous State, baseURL string) (State, error) {
	target := previous
	target.BaseURL = baseURL
	if slices.Equal(target.KimiModels, previousManagedKimiModels) {
		target.KimiModels = ManagedKimiModels()
	}
	if err := target.Validate(); err != nil {
		return State{}, err
	}
	if target.BaseURL == previous.BaseURL {
		return State{}, errors.New("model bootstrap base_url is already set to the requested value")
	}
	return target, nil
}

func LoadPendingRebase(dataRoot string) (Rebase, bool, error) {
	path, err := rebasePath(dataRoot)
	if err != nil {
		return Rebase{}, false, err
	}
	exists, err := regularFileExists(path)
	if err != nil || !exists {
		return Rebase{}, false, err
	}
	rebase, err := loadRebase(path)
	return rebase, true, err
}

func CompleteRebase(dataRoot string, target State) error {
	path, err := rebasePath(dataRoot)
	if err != nil {
		return err
	}
	rebase, err := loadRebase(path)
	if err != nil {
		return errors.New("pending model bootstrap rebase is missing or invalid")
	}
	if !statesEqual(rebase.Target, target) {
		return errors.New("completed model bootstrap state does not match the pending rebase")
	}
	_, markerPath, _ := Paths(dataRoot)
	if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove previous model bootstrap marker: %w", err)
	}
	if err := writeJSONAtomic(markerPath, target); err != nil {
		return fmt.Errorf("write rebased model bootstrap marker: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove completed model bootstrap rebase: %w", err)
	}
	return nil
}

func loadRebase(path string) (Rebase, error) {
	var rebase Rebase
	if err := readStrictJSON(path, &rebase); err != nil {
		return Rebase{}, err
	}
	if rebase.FormatVersion != FormatVersion {
		return Rebase{}, errors.New("unsupported model bootstrap rebase format")
	}
	if err := rebase.Previous.validateApplied(); err != nil {
		return Rebase{}, fmt.Errorf("validate previous model bootstrap state: %w", err)
	}
	if err := rebase.Target.Validate(); err != nil {
		return Rebase{}, fmt.Errorf("validate target model bootstrap state: %w", err)
	}
	if !validRebaseTransition(rebase.Previous, rebase.Target) || rebase.Previous.BaseURL == rebase.Target.BaseURL {
		return Rebase{}, errors.New("model bootstrap rebase may change only base_url and the exact managed Kimi catalog upgrade")
	}
	return rebase, nil
}

func validRebaseTransition(previous, target State) bool {
	previous.BaseURL, target.BaseURL = "", ""
	if statesEqual(previous, target) {
		return true
	}
	if !slices.Equal(previous.KimiModels, previousManagedKimiModels) || !slices.Equal(target.KimiModels, managedKimiModels) {
		return false
	}
	previous.KimiModels = managedKimiModels
	return statesEqual(previous, target)
}

func statesEqual(left, right State) bool {
	return left.FormatVersion == right.FormatVersion && left.BaseURL == right.BaseURL &&
		left.CodexKeyID == right.CodexKeyID && left.KimiKeyID == right.KimiKeyID &&
		left.CodexDefaultModel == right.CodexDefaultModel && slices.Equal(left.CodexModels, right.CodexModels) &&
		slices.Equal(left.KimiModels, right.KimiModels)
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
