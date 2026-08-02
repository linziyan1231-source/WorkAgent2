package modelbootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

const (
	FormatVersion               = 1
	CodexProviderID             = "managed-cliproxy-chatgpt"
	KimiProviderID              = "managed-cliproxy-kimi"
	CodexProviderName           = "ChatGPT"
	KimiProviderName            = "KIMI"
	DefaultCodexModel           = "gpt-5.6-sol"
	DefaultCodexReasoningEffort = "low"
	DefaultKimiModel            = "kimi-k3"
)

var (
	managedCodexModels      = []string{"gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra"}
	managedKimiModels       = []string{"kimi-for-coding", "kimi-for-coding-highspeed", "kimi-k3"}
	legacyManagedKimiModels = []string{"kimi-for-coding", "kimi-for-coding-highspeed"}
	keyIDPattern            = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	apiKeyPattern           = regexp.MustCompile(`^cpa_[A-Za-z0-9_-]{20,256}$`)
	modelPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

func ManagedCodexModels() []string { return append([]string(nil), managedCodexModels...) }

func ManagedKimiModels() []string { return append([]string(nil), managedKimiModels...) }

type State struct {
	FormatVersion     int      `json:"format_version"`
	PolicyID          string   `json:"policy_id"`
	BaseURL           string   `json:"base_url"`
	CodexKeyID        string   `json:"codex_key_id"`
	KimiKeyID         string   `json:"kimi_key_id"`
	CodexDefaultModel string   `json:"codex_default_model"`
	KimiDefaultModel  string   `json:"kimi_default_model"`
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

func KeyIDsForTenant(tenantID string) KeyIDs {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(tenantID))))
	prefix := "workagent-" + hex.EncodeToString(digest[:10])
	return KeyIDs{CodexKeyID: prefix + "-codex", KimiKeyID: prefix + "-kimi"}
}

func (ids KeyIDs) ValidateForTenant(tenantID string) error {
	parsed, err := uuid.Parse(tenantID)
	if err != nil || parsed.String() != tenantID || !keyIDPattern.MatchString(ids.CodexKeyID) || !keyIDPattern.MatchString(ids.KimiKeyID) || ids.CodexKeyID == ids.KimiKeyID || ids != KeyIDsForTenant(tenantID) {
		return errors.New("model key ids do not match the canonical tenant id")
	}
	return nil
}

func StateFromPolicy(policy productconfig.Policy, apiBaseURL, tenantID string) (State, error) {
	if err := policy.Validate(); err != nil {
		return State{}, err
	}
	ids := KeyIDsForTenant(tenantID)
	if err := ids.ValidateForTenant(tenantID); err != nil {
		return State{}, err
	}
	codexDefault, codexOK := policy.DefaultModel("codex")
	kimiDefault, kimiOK := policy.DefaultModel("kimi")
	if !codexOK || !kimiOK {
		return State{}, errors.New("policy must enable one default Codex model and one default Kimi model")
	}
	if codexDefault.ID != DefaultCodexModel {
		return State{}, fmt.Errorf("policy Codex default must be %s", DefaultCodexModel)
	}
	state := State{FormatVersion: FormatVersion, PolicyID: policy.PolicyID, BaseURL: apiBaseURL, CodexKeyID: ids.CodexKeyID, KimiKeyID: ids.KimiKeyID,
		CodexDefaultModel: codexDefault.ID, KimiDefaultModel: kimiDefault.ID}
	for _, model := range policy.EnabledModels("codex") {
		state.CodexModels = append(state.CodexModels, model.ID)
	}
	for _, model := range policy.EnabledModels("kimi") {
		state.KimiModels = append(state.KimiModels, model.ID)
	}
	if !sameModelSet(state.CodexModels, managedCodexModels) {
		return State{}, errors.New("policy Codex models must match the managed three-model catalog")
	}
	if kimiDefault.ID != DefaultKimiModel || !sameModelSet(state.KimiModels, managedKimiModels) {
		return State{}, fmt.Errorf("policy Kimi models must match the managed catalog with default %s", DefaultKimiModel)
	}
	state.CodexModels = ManagedCodexModels()
	state.KimiModels = ManagedKimiModels()
	if err := state.ValidateForTenant(tenantID); err != nil {
		return State{}, err
	}
	return state, nil
}

// WithCodexDefaultModel returns a tenant-bound state with only the Codex
// default changed. It deliberately accepts a valid legacy default so UserHost
// can migrate an already-applied bootstrap marker without rotating either key.
func (s State) WithCodexDefaultModel(tenantID, model string) (State, bool, error) {
	if err := s.ValidateForTenant(tenantID); err != nil {
		return State{}, false, err
	}
	if s.CodexDefaultModel == model {
		return s, false, nil
	}
	updated := s
	updated.CodexDefaultModel = model
	if err := updated.ValidateForTenant(tenantID); err != nil {
		return State{}, false, fmt.Errorf("validate updated Codex default model: %w", err)
	}
	return updated, true, nil
}

// WithManagedKimiDefaults upgrades an already-applied two-model Kimi state
// without changing either tenant key or any Codex policy. Unknown model sets
// fail closed instead of being silently replaced.
func (s State) WithManagedKimiDefaults(tenantID string) (State, bool, error) {
	if err := s.ValidateForTenant(tenantID); err != nil {
		return State{}, false, err
	}
	if !sameModelSet(s.KimiModels, legacyManagedKimiModels) && !sameModelSet(s.KimiModels, managedKimiModels) {
		return State{}, false, errors.New("applied Kimi models do not match a supported managed catalog")
	}
	if s.KimiDefaultModel == DefaultKimiModel && slices.Equal(s.KimiModels, managedKimiModels) {
		return s, false, nil
	}
	updated := s
	updated.KimiDefaultModel = DefaultKimiModel
	updated.KimiModels = ManagedKimiModels()
	if err := updated.ValidateManagedForTenant(tenantID); err != nil {
		return State{}, false, fmt.Errorf("validate updated Kimi defaults: %w", err)
	}
	return updated, true, nil
}

func (s State) ValidateForTenant(tenantID string) error {
	if s.FormatVersion != FormatVersion || strings.TrimSpace(s.PolicyID) == "" {
		return errors.New("model bootstrap version or policy id is invalid")
	}
	parsed, err := url.Parse(s.BaseURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "/v1" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(s.BaseURL, "/") {
		return errors.New("model bootstrap base_url must be an exact loopback HTTP /v1 URL")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.IsLoopback() || parsed.Port() == "" {
		return errors.New("model bootstrap base_url must use a numeric loopback address and explicit port")
	}
	if err := (KeyIDs{CodexKeyID: s.CodexKeyID, KimiKeyID: s.KimiKeyID}).ValidateForTenant(tenantID); err != nil {
		return err
	}
	if err := validateModels("Codex", s.CodexModels, s.CodexDefaultModel); err != nil {
		return err
	}
	return validateModels("Kimi", s.KimiModels, s.KimiDefaultModel)
}

func (s State) ValidateManagedForTenant(tenantID string) error {
	if err := s.ValidateForTenant(tenantID); err != nil {
		return err
	}
	if s.CodexDefaultModel != DefaultCodexModel || !slices.Equal(s.CodexModels, managedCodexModels) {
		return errors.New("Codex state does not match the managed model policy")
	}
	if s.KimiDefaultModel != DefaultKimiModel || !slices.Equal(s.KimiModels, managedKimiModels) {
		return errors.New("Kimi state does not match the managed model policy")
	}
	return nil
}

func (b *Bundle) ValidateForTenant(tenantID string) error {
	if b == nil {
		return errors.New("model bootstrap bundle is missing")
	}
	if err := b.State.ValidateForTenant(tenantID); err != nil {
		return err
	}
	if !apiKeyPattern.MatchString(b.CodexAPIKey) || !apiKeyPattern.MatchString(b.KimiAPIKey) || b.CodexAPIKey == b.KimiAPIKey {
		return errors.New("model bootstrap API keys are invalid or duplicated")
	}
	return nil
}

func (b *Bundle) ValidateManagedForTenant(tenantID string) error {
	if err := b.ValidateForTenant(tenantID); err != nil {
		return err
	}
	return b.State.ValidateManagedForTenant(tenantID)
}

func (b *Bundle) Zero() {
	if b == nil {
		return
	}
	b.CodexAPIKey = ""
	b.KimiAPIKey = ""
}

func (s State) Equal(other State) bool {
	return s.FormatVersion == other.FormatVersion && s.PolicyID == other.PolicyID && s.BaseURL == other.BaseURL && s.CodexKeyID == other.CodexKeyID && s.KimiKeyID == other.KimiKeyID &&
		s.CodexDefaultModel == other.CodexDefaultModel && s.KimiDefaultModel == other.KimiDefaultModel && slices.Equal(s.CodexModels, other.CodexModels) && slices.Equal(s.KimiModels, other.KimiModels)
}

func validateModels(label string, models []string, defaultModel string) error {
	if len(models) == 0 || len(models) > 64 || !modelPattern.MatchString(defaultModel) {
		return fmt.Errorf("%s model catalog is empty or invalid", label)
	}
	seen := make(map[string]bool, len(models))
	defaultFound := false
	for _, model := range models {
		key := strings.ToLower(model)
		if !modelPattern.MatchString(model) || seen[key] {
			return fmt.Errorf("%s model catalog contains an invalid or duplicate model", label)
		}
		seen[key] = true
		defaultFound = defaultFound || model == defaultModel
	}
	if !defaultFound {
		return fmt.Errorf("%s default model is outside the catalog", label)
	}
	return nil
}

func sameModelSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	wanted := make(map[string]struct{}, len(right))
	for _, value := range right {
		wanted[value] = struct{}{}
	}
	for _, value := range left {
		if _, ok := wanted[value]; !ok {
			return false
		}
		delete(wanted, value)
	}
	return len(wanted) == 0
}
