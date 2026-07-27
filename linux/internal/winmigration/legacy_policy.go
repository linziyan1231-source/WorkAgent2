package winmigration

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
)

const legacyCPAStateRelative = "cliproxy/cpa-key-policy-state.json"

var (
	legacyKeyHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	usdNumberPattern     = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)
)

type legacyPolicyKey struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Enabled        bool        `json:"enabled"`
	KeyHash        string      `json:"key_hash"`
	DailyLimitUSD  json.Number `json:"daily_limit_usd"`
	WeeklyLimitUSD json.Number `json:"weekly_limit_usd"`
}

type legacyPolicyState struct {
	keys  map[string]legacyPolicyKey
	usage map[string]json.RawMessage
	used  map[string]bool
}

type legacyBootstrapMarker struct {
	FormatVersion     int      `json:"format_version"`
	BaseURL           string   `json:"base_url"`
	CodexKeyID        string   `json:"codex_key_id"`
	KimiKeyID         string   `json:"kimi_key_id"`
	CodexDefaultModel string   `json:"codex_default_model"`
	KimiDefaultModel  string   `json:"kimi_default_model,omitempty"`
	CodexModels       []string `json:"codex_models"`
	KimiModels        []string `json:"kimi_models"`
}

func readLegacyPolicyState(payload []byte) (*legacyPolicyState, error) {
	var envelope struct {
		Version int                        `json:"version"`
		Keys    []legacyPolicyKey          `json:"keys"`
		Usage   map[string]json.RawMessage `json:"usage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Version < 1 || len(envelope.Keys) == 0 {
		return nil, errors.New("legacy CLIProxy policy state is invalid")
	}
	state := &legacyPolicyState{keys: make(map[string]legacyPolicyKey, len(envelope.Keys)), usage: envelope.Usage, used: make(map[string]bool)}
	for _, key := range envelope.Keys {
		if key.ID == "" || state.keys[key.ID].ID != "" || strings.TrimSpace(key.Name) == "" || !key.Enabled || !legacyKeyHashPattern.MatchString(key.KeyHash) {
			return nil, errors.New("legacy CLIProxy policy contains an invalid or duplicate key")
		}
		if err := validateUSDLimit(key.DailyLimitUSD); err != nil {
			return nil, errors.New("legacy CLIProxy daily limit is invalid")
		}
		if err := validateUSDLimit(key.WeeklyLimitUSD); err != nil {
			return nil, errors.New("legacy CLIProxy weekly limit is invalid")
		}
		if usage, exists := state.usage[key.ID]; exists && !json.Valid(usage) {
			return nil, errors.New("legacy CLIProxy usage state is invalid")
		}
		state.keys[key.ID] = key
	}
	return state, nil
}

func validateUSDLimit(value json.Number) error {
	text := value.String()
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil || !usdNumberPattern.MatchString(text) || parsed <= 0 || parsed > 1_000_000 {
		return errors.New("invalid USD limit")
	}
	return nil
}

func (state *legacyPolicyState) inspectTenant(snapshotFD int, tenant *plannedTenant) ([]plannedQuotaOverride, error) {
	markerRelative := pathJoin(tenant.sourceRelative, "config/model-bootstrap-v1.applied.json")
	payload, err := readSecureFile(snapshotFD, markerRelative, 256*1024)
	if err != nil {
		return nil, errors.New("managed model bootstrap marker is required for a provisioned Windows tenant")
	}
	defer clear(payload)
	var marker legacyBootstrapMarker
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil || decoder.Decode(&struct{}{}) != io.EOF || marker.FormatVersion != 1 || marker.CodexKeyID == "" || marker.KimiKeyID == "" || marker.CodexKeyID == marker.KimiKeyID {
		return nil, errors.New("managed model bootstrap marker is invalid")
	}
	codexKey, codexOK := state.keys[marker.CodexKeyID]
	kimiKey, kimiOK := state.keys[marker.KimiKeyID]
	if !codexOK || !kimiOK || state.used[codexKey.ID] || state.used[kimiKey.ID] {
		return nil, errors.New("managed model bootstrap keys are missing or reused")
	}
	if !strings.HasSuffix(codexKey.ID, "-chatgpt") || !strings.HasSuffix(kimiKey.ID, "-kimi") {
		return nil, errors.New("managed model bootstrap key providers are invalid")
	}
	if err := validateCodexManagedAuth(snapshotFD, tenant.sourceRelative, codexKey.KeyHash); err != nil {
		return nil, err
	}
	for _, relative := range []string{"profile/.kimi-code/config.toml", "profile/.kimi/config.toml"} {
		if !plannedFileExists(tenant.entries, relative) {
			continue
		}
		configPayload, err := readSecureFile(snapshotFD, pathJoin(tenant.sourceRelative, relative), 1024*1024)
		if err != nil {
			return nil, err
		}
		key, found, extractErr := extractManagedKimiKey(configPayload)
		clear(configPayload)
		if extractErr != nil {
			return nil, extractErr
		}
		if found && keyHash(key) != kimiKey.KeyHash {
			return nil, errors.New("managed Kimi configuration does not match its legacy CLIProxy key")
		}
	}
	if configPayload, err := readSecureFile(snapshotFD, pathJoin(tenant.sourceRelative, "config/codex/config.toml"), 1024*1024); err == nil {
		_, count, sanitizeErr := sanitizeCodexConfig(configPayload)
		clear(configPayload)
		if sanitizeErr != nil {
			return nil, sanitizeErr
		}
		tenant.report.ModelInvalidation.CodexManagedSettings = count
	} else {
		return nil, errors.New("managed Codex configuration is missing")
	}
	kimiConfigs := 0
	for _, relative := range []string{"profile/.kimi-code/config.toml", "profile/.kimi/config.toml"} {
		if !plannedFileExists(tenant.entries, relative) {
			continue
		}
		configPayload, err := readSecureFile(snapshotFD, pathJoin(tenant.sourceRelative, relative), 1024*1024)
		if err != nil {
			return nil, err
		}
		_, changed, sanitizeErr := sanitizeKimiConfig(configPayload)
		clear(configPayload)
		if sanitizeErr != nil {
			return nil, sanitizeErr
		}
		if changed > 0 {
			kimiConfigs++
		}
	}
	state.used[codexKey.ID], state.used[kimiKey.ID] = true, true
	tenant.legacyCodexHash, tenant.legacyKimiHash = codexKey.KeyHash, kimiKey.KeyHash
	tenant.report.ModelInvalidation.AppliedMarkers = 1
	if plannedFileExists(tenant.entries, "credentials/model-bootstrap-v1.pending.json") {
		tenant.report.ModelInvalidation.PendingBundles = 1
	}
	tenant.report.ModelInvalidation.CodexManagedAuthFiles = 1
	tenant.report.ModelInvalidation.KimiManagedConfigs = kimiConfigs
	ids := modelbootstrap.KeyIDsForTenant(tenant.report.TenantID)
	overrides := []plannedQuotaOverride{
		{Username: tenant.user.Username, TenantID: tenant.report.TenantID, Provider: "codex", NewKeyID: ids.CodexKeyID, DailyLimitUSD: codexKey.DailyLimitUSD.String(), WeeklyLimitUSD: codexKey.WeeklyLimitUSD.String(), Usage: cloneUsage(state.usage[codexKey.ID])},
		{Username: tenant.user.Username, TenantID: tenant.report.TenantID, Provider: "kimi", NewKeyID: ids.KimiKeyID, DailyLimitUSD: kimiKey.DailyLimitUSD.String(), WeeklyLimitUSD: kimiKey.WeeklyLimitUSD.String(), Usage: cloneUsage(state.usage[kimiKey.ID])},
	}
	for _, override := range overrides {
		tenant.report.QuotaOverrides = append(tenant.report.QuotaOverrides, QuotaOverrideReport{Provider: override.Provider, NewKeyID: override.NewKeyID, DailyLimitUSD: override.DailyLimitUSD, WeeklyLimitUSD: override.WeeklyLimitUSD})
	}
	return overrides, nil
}

func (state *legacyPolicyState) validateAllKeysMapped() error {
	if len(state.used) != len(state.keys) {
		return errors.New("legacy CLIProxy state contains keys that cannot be mapped safely to Portal tenants")
	}
	return nil
}

func validateCodexManagedAuth(snapshotFD int, sourceRelative, expectedHash string) error {
	payload, err := readSecureFile(snapshotFD, pathJoin(sourceRelative, "config/codex/auth.json"), 64*1024)
	if err != nil {
		return errors.New("managed Codex authentication file is missing")
	}
	defer clear(payload)
	var auth struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&auth); err != nil || decoder.Decode(&struct{}{}) != io.EOF || auth.AuthMode != "apikey" || keyHash(auth.APIKey) != expectedHash {
		return errors.New("managed Codex authentication does not match its legacy CLIProxy key")
	}
	return nil
}

func extractManagedKimiKey(payload []byte) (string, bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	inManaged := false
	found := false
	var key string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			inManaged = line == `[providers."managed:kimi-code"]`
			continue
		}
		if !inManaged || !strings.HasPrefix(line, "api_key") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "api_key" || found {
			return "", false, errors.New("managed Kimi provider contains an ambiguous API key")
		}
		value, err := parseTOMLString(strings.TrimSpace(parts[1]))
		if err != nil {
			return "", false, errors.New("managed Kimi provider API key is invalid")
		}
		key, found = value, true
	}
	if err := scanner.Err(); err != nil {
		return "", false, err
	}
	return key, found, nil
}

func parseTOMLString(value string) (string, error) {
	if strings.HasPrefix(value, `"`) {
		return strconv.Unquote(value)
	}
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' && !strings.Contains(value[1:len(value)-1], "'") {
		return value[1 : len(value)-1], nil
	}
	return "", errors.New("not a TOML basic string")
}

func keyHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func plannedFileExists(entries []treeEntry, target string) bool {
	for _, entry := range entries {
		if entry.Path == target && entry.Kind == 'f' {
			return true
		}
	}
	return false
}

func cloneUsage(value json.RawMessage) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(`{}`)
	}
	return append(json.RawMessage(nil), value...)
}

func pathJoin(first, second string) string {
	return strings.TrimSuffix(first, "/") + "/" + strings.TrimPrefix(second, "/")
}
