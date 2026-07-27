package cliproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

const (
	maxRuntimeConfigResponse   = 512 * 1024
	maxProviderAuthResponse    = 1024 * 1024
	maxProviderAuthFiles       = 100
	maxProviderAuthFileBytes   = 1024 * 1024
	providerRecentRequestSlots = 20
)

type runtimeConfigIdentity struct {
	Host                   string
	Port                   int
	AllowRemote            bool
	DisableControlPanel    bool
	DisableAutoUpdatePanel bool
	LogsMaxTotalSizeMB     int
	ErrorLogsMaxFiles      int
	AuthDir                string
}

type pluginListResponse struct {
	PluginsEnabled bool              `json:"plugins_enabled"`
	PluginsDir     string            `json:"plugins_dir"`
	Plugins        []pluginListEntry `json:"plugins"`
}

type pluginListEntry struct {
	ID               string              `json:"id"`
	Path             string              `json:"path"`
	Configured       bool                `json:"configured"`
	Registered       bool                `json:"registered"`
	Enabled          bool                `json:"enabled"`
	EffectiveEnabled bool                `json:"effective_enabled"`
	SupportsOAuth    bool                `json:"supports_oauth"`
	OAuthProvider    string              `json:"oauth_provider"`
	Logo             string              `json:"logo"`
	ConfigFields     []json.RawMessage   `json:"config_fields"`
	Menus            []json.RawMessage   `json:"menus"`
	Metadata         *pluginMetadataInfo `json:"metadata"`
}

type pluginMetadataInfo struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Author           string            `json:"author"`
	GitHubRepository string            `json:"github_repository"`
	Logo             string            `json:"logo"`
	ConfigFields     []json.RawMessage `json:"config_fields"`
}

type keyPolicyStatus struct {
	Enabled   bool                       `json:"enabled"`
	StateFile string                     `json:"state_file"`
	KeyCount  int                        `json:"key_count"`
	RPMUsage  map[string]json.RawMessage `json:"rpm_usage"`
	Usage     map[string]json.RawMessage `json:"usage"`
}

type readinessManagementClient interface {
	JSON(context.Context, string, string, any, any) error
	coreJSON(context.Context, string, string, any) (http.Header, error)
	coreRaw(context.Context, string, int64) ([]byte, http.Header, error)
}

// CheckReadiness verifies the locked core build, its live loopback-only
// configuration, the registered policy plugin, and the policy catalog/state.
// It intentionally does not trust /healthz because that endpoint is an
// unauthenticated static 200 in CLIProxyAPI 7.2.81.
func CheckReadiness(ctx context.Context, endpoint config.CLIProxy, policy productconfig.Policy) error {
	if err := endpoint.Validate(); err != nil {
		return fmt.Errorf("CLIProxy contract: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("CLIProxy policy: %w", err)
	}
	client, err := NewManagementClient(ManagementOptions{BaseURL: endpoint.ManagementURL, KeyFile: endpoint.ManagementCredentialFile})
	if err != nil {
		return err
	}
	defer client.Close()
	return checkReadinessWithClient(ctx, endpoint, policy, client)
}

func checkReadinessWithClient(ctx context.Context, endpoint config.CLIProxy, policy productconfig.Policy, client readinessManagementClient) error {
	if err := checkPolicyReadinessWithClient(ctx, endpoint, policy, client); err != nil {
		return err
	}
	rawAuth, _, err := client.coreRaw(ctx, "/v0/management/auth-files", maxProviderAuthResponse)
	if err != nil {
		return err
	}
	defer clear(rawAuth)
	return verifyProviderAuthFiles(rawAuth, endpoint.AuthDirectory)
}

// checkPolicyReadinessWithClient is the pre-OAuth service-start contract. It is
// deliberately separate from the full readiness check: CLIProxy must be able
// to start and render its protected runtime configuration before an operator
// can complete the host-local OAuth flows, while Portal/doctor readiness must
// remain red until both required provider credentials are live.
func checkPolicyReadinessWithClient(ctx context.Context, endpoint config.CLIProxy, policy productconfig.Policy, client readinessManagementClient) error {
	if err := endpoint.Validate(); err != nil {
		return fmt.Errorf("CLIProxy contract: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("CLIProxy policy: %w", err)
	}
	if err := checkHostReadinessWithClient(ctx, endpoint, client); err != nil {
		return err
	}
	catalog, err := readCatalog(ctx, client, policy)
	if err != nil {
		return err
	}
	if err := verifyManagedAliases(catalog); err != nil {
		return err
	}
	return verifyPolicyCatalog(policy, catalog)
}

type providerAuthEntry struct {
	id          string
	index       string
	name        string
	typeName    string
	provider    string
	status      string
	statusMsg   string
	disabled    bool
	unavailable bool
	runtimeOnly bool
	source      string
	path        string
	size        int64
	qualified   bool
}

// verifyProviderAuthFiles consumes only the authenticated loopback management
// response and returns provider names, never credential filenames, account
// labels, paths, tokens, or response bodies. The parser intentionally locks the
// exact 7.2.81 response shape and detects duplicate JSON keys before deciding
// that a file-backed OAuth credential is usable.
func verifyProviderAuthFiles(raw []byte, authDirectory string) error {
	if len(raw) == 0 || len(raw) > maxProviderAuthResponse || bytes.IndexByte(raw, 0) >= 0 ||
		!filepath.IsAbs(authDirectory) || filepath.Clean(authDirectory) != authDirectory {
		return errors.New("CLIProxy provider OAuth status response is empty, oversized, or unsafe")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("CLIProxy provider OAuth status response has an invalid JSON shape")
	}
	seenRoot := make(map[string]struct{}, 1)
	seenIDs := make(map[string]struct{})
	seenIndexes := make(map[string]struct{})
	ready := map[string]bool{"codex": false, "kimi": false}
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return errors.New("CLIProxy provider OAuth status response has a non-string key")
		}
		if _, duplicate := seenRoot[key]; duplicate {
			return errors.New("CLIProxy provider OAuth status response has a duplicate key")
		}
		seenRoot[key] = struct{}{}
		if key != "files" {
			return errors.New("CLIProxy provider OAuth status response has an unknown field")
		}
		if err := parseProviderAuthArray(decoder, authDirectory, seenIDs, seenIndexes, ready); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seenRoot) != 1 {
		return errors.New("CLIProxy provider OAuth status response is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("CLIProxy provider OAuth status response has trailing data")
	}
	for _, provider := range []string{"codex", "kimi"} {
		if !ready[provider] {
			return fmt.Errorf("CLIProxy %s provider has no enabled, available, active, file-backed OAuth credential", provider)
		}
	}
	return nil
}

func parseProviderAuthArray(decoder *json.Decoder, authDirectory string, seenIDs, seenIndexes map[string]struct{}, ready map[string]bool) error {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('[') {
		return errors.New("CLIProxy provider OAuth files field is not an array")
	}
	count := 0
	for decoder.More() {
		count++
		if count > maxProviderAuthFiles {
			return errors.New("CLIProxy provider OAuth file count exceeds the production bound")
		}
		entry, err := parseProviderAuthEntry(decoder)
		if err != nil {
			return err
		}
		if _, duplicate := seenIDs[entry.id]; duplicate {
			return errors.New("CLIProxy provider OAuth status contains a duplicate credential id")
		}
		if _, duplicate := seenIndexes[entry.index]; duplicate {
			return errors.New("CLIProxy provider OAuth status contains a duplicate credential index")
		}
		seenIDs[entry.id] = struct{}{}
		seenIndexes[entry.index] = struct{}{}
		entry.qualified = providerAuthEntryQualified(entry, authDirectory)
		if entry.qualified && (entry.provider == "codex" || entry.provider == "kimi") {
			ready[entry.provider] = true
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return errors.New("CLIProxy provider OAuth files array is incomplete")
	}
	return nil
}

func parseProviderAuthEntry(decoder *json.Decoder) (providerAuthEntry, error) {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry is not an object")
	}
	var entry providerAuthEntry
	seen := make(map[string]struct{}, 32)
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry has a non-string key")
		}
		if _, duplicate := seen[key]; duplicate {
			return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry has a duplicate key")
		}
		seen[key] = struct{}{}
		switch key {
		case "id":
			err = decoder.Decode(&entry.id)
		case "auth_index":
			err = decoder.Decode(&entry.index)
		case "name":
			err = decoder.Decode(&entry.name)
		case "type":
			err = decoder.Decode(&entry.typeName)
		case "provider":
			err = decoder.Decode(&entry.provider)
		case "label":
			err = decodeBoundedString(decoder, 4096)
		case "status":
			err = decoder.Decode(&entry.status)
		case "status_message":
			err = decoder.Decode(&entry.statusMsg)
		case "disabled":
			err = decoder.Decode(&entry.disabled)
		case "unavailable":
			err = decoder.Decode(&entry.unavailable)
		case "runtime_only":
			err = decoder.Decode(&entry.runtimeOnly)
		case "source":
			err = decoder.Decode(&entry.source)
		case "path":
			err = decoder.Decode(&entry.path)
		case "size":
			entry.size, err = decodeBoundedInteger(decoder, 0, maxProviderAuthFileBytes)
		case "success", "failed":
			_, err = decodeBoundedInteger(decoder, 0, 1<<62)
		case "priority":
			_, err = decodeBoundedInteger(decoder, -1_000_000, 1_000_000)
		case "email", "project_id", "account_type", "account", "note":
			err = decodeBoundedString(decoder, 16*1024)
		case "created_at", "modtime", "updated_at", "last_refresh", "next_retry_after":
			err = decodeProviderTimestamp(decoder)
		case "websockets":
			var value bool
			err = decoder.Decode(&value)
		case "recent_requests":
			err = decodeRecentProviderRequests(decoder)
		case "id_token":
			err = decodeProviderIDTokenSummary(decoder)
		default:
			return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry has an unknown field")
		}
		if err != nil {
			return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry has an invalid field type or value")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry is incomplete")
	}
	for _, required := range []string{"id", "auth_index", "name", "type", "provider", "label", "status", "status_message", "disabled", "unavailable", "runtime_only", "source", "size", "success", "failed", "recent_requests"} {
		if _, ok := seen[required]; !ok {
			return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry is missing a required field")
		}
	}
	if !boundedIdentifier(entry.id) || !boundedIdentifier(entry.index) || !boundedIdentifier(entry.name) ||
		entry.typeName == "" || len(entry.typeName) > 64 || entry.provider == "" || len(entry.provider) > 64 ||
		len(entry.status) > 64 || len(entry.statusMsg) > 4096 || len(entry.source) > 64 || len(entry.path) > 4096 {
		return providerAuthEntry{}, errors.New("CLIProxy provider OAuth file entry has an invalid identifier")
	}
	return entry, nil
}

func providerAuthEntryQualified(entry providerAuthEntry, authDirectory string) bool {
	if entry.provider != entry.typeName || entry.status != "active" || entry.disabled || entry.unavailable || entry.runtimeOnly ||
		entry.source != "file" || entry.size < 1 || entry.path == "" || !filepath.IsAbs(entry.path) || filepath.Clean(entry.path) != entry.path ||
		filepath.Dir(entry.path) != authDirectory || filepath.Ext(entry.path) != ".json" {
		return false
	}
	base := filepath.Base(entry.path)
	return base != "." && base != ".." && base == entry.name
}

func boundedIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func decodeBoundedString(decoder *json.Decoder, maximum int) error {
	var value string
	if err := decoder.Decode(&value); err != nil || len(value) > maximum || strings.ContainsRune(value, 0) {
		return errors.New("invalid bounded string")
	}
	return nil
}

func decodeBoundedInteger(decoder *json.Decoder, minimum, maximum int64) (int64, error) {
	var value json.Number
	if err := decoder.Decode(&value); err != nil {
		return 0, err
	}
	integer, err := value.Int64()
	if err != nil || integer < minimum || integer > maximum {
		return 0, errors.New("invalid bounded integer")
	}
	return integer, nil
}

func decodeProviderTimestamp(decoder *json.Decoder) error {
	var value string
	if err := decoder.Decode(&value); err != nil || len(value) > 64 {
		return errors.New("invalid timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return errors.New("invalid timestamp")
	}
	return nil
}

func decodeRecentProviderRequests(decoder *json.Decoder) error {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('[') {
		return errors.New("recent provider requests is not an array")
	}
	count := 0
	for decoder.More() {
		count++
		if count > providerRecentRequestSlots {
			return errors.New("recent provider request history exceeds its bound")
		}
		opening, err = decoder.Token()
		if err != nil || opening != json.Delim('{') {
			return errors.New("recent provider request bucket is invalid")
		}
		seen := make(map[string]struct{}, 3)
		for decoder.More() {
			keyToken, tokenErr := decoder.Token()
			key, ok := keyToken.(string)
			if tokenErr != nil || !ok {
				return errors.New("recent provider request bucket key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("recent provider request bucket key is duplicated")
			}
			seen[key] = struct{}{}
			switch key {
			case "time":
				err = decodeRecentProviderRequestTime(decoder)
			case "success", "failed":
				_, err = decodeBoundedInteger(decoder, 0, 1<<62)
			default:
				return errors.New("recent provider request bucket has an unknown field")
			}
			if err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') || len(seen) != 3 {
			return errors.New("recent provider request bucket is incomplete")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') || count != providerRecentRequestSlots {
		return errors.New("recent provider request history is incomplete")
	}
	return nil
}

func decodeRecentProviderRequestTime(decoder *json.Decoder) error {
	var value string
	if err := decoder.Decode(&value); err != nil || len(value) != 11 || value[2] != ':' || value[5] != '-' || value[8] != ':' {
		return errors.New("recent provider request time is invalid")
	}
	if _, err := time.Parse("15:04", value[:5]); err != nil {
		return errors.New("recent provider request time is invalid")
	}
	if _, err := time.Parse("15:04", value[6:]); err != nil {
		return errors.New("recent provider request time is invalid")
	}
	return nil
}

func decodeProviderIDTokenSummary(decoder *json.Decoder) error {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("provider identity summary is not an object")
	}
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return errors.New("provider identity summary key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("provider identity summary key is duplicated")
		}
		seen[key] = struct{}{}
		switch key {
		case "chatgpt_account_id", "plan_type":
			err = decodeBoundedString(decoder, 4096)
		case "chatgpt_subscription_active_start", "chatgpt_subscription_active_until":
			var scalar any
			err = decoder.Decode(&scalar)
			switch value := scalar.(type) {
			case string:
				if len(value) > 128 || strings.ContainsRune(value, 0) {
					err = errors.New("provider identity timestamp is invalid")
				}
			case json.Number:
				if _, numberErr := value.Int64(); numberErr != nil {
					err = errors.New("provider identity timestamp is invalid")
				}
			default:
				err = errors.New("provider identity timestamp is invalid")
			}
		default:
			return errors.New("provider identity summary has an unknown field")
		}
		if err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) == 0 {
		return errors.New("provider identity summary is incomplete")
	}
	return nil
}

func checkHostReadinessWithClient(ctx context.Context, endpoint config.CLIProxy, client readinessManagementClient) error {
	rawConfig, headers, err := client.coreRaw(ctx, "/v0/management/config.yaml", maxRuntimeConfigResponse)
	if err != nil {
		return err
	}
	defer clear(rawConfig)
	if err := verifyCoreIdentity(headers, endpoint); err != nil {
		return err
	}
	runtimeIdentity, err := parseRuntimeConfigIdentity(rawConfig)
	if err != nil {
		return err
	}
	if err := verifyRuntimeConfigIdentity(runtimeIdentity, endpoint); err != nil {
		return err
	}

	var plugins pluginListResponse
	if _, err := client.coreJSON(ctx, http.MethodGet, "/v0/management/plugins", &plugins); err != nil {
		return err
	}
	if err := verifyPluginIdentity(plugins, endpoint); err != nil {
		return err
	}
	if err := verifyPluginConfig(ctx, client, endpoint); err != nil {
		return err
	}

	var status keyPolicyStatus
	if err := client.JSON(ctx, http.MethodGet, "/status", nil, &status); err != nil {
		return err
	}
	if !status.Enabled || status.StateFile != endpoint.PolicyStateFile || status.KeyCount < 0 || status.RPMUsage == nil || status.Usage == nil {
		return errors.New("CLIProxy cpa-key-policy status does not match the protected runtime contract")
	}
	keys, err := readKeys(ctx, client)
	if err != nil {
		return err
	}
	if status.KeyCount != len(keys) {
		return errors.New("CLIProxy cpa-key-policy state count does not match key readback")
	}
	if err := verifyKeyReadbackShape(keys); err != nil {
		return err
	}
	return nil
}

func verifyCoreIdentity(headers http.Header, endpoint config.CLIProxy) error {
	required := map[string]string{
		"X-CPA-VERSION":        endpoint.CoreVersion,
		"X-CPA-COMMIT":         endpoint.CorePatch,
		"X-CPA-SUPPORT-PLUGIN": "1",
	}
	for name, expected := range required {
		values := headers.Values(name)
		if len(values) != 1 || strings.TrimSpace(values[0]) != expected {
			return fmt.Errorf("CLIProxy core identity header %s did not match the production lock", name)
		}
	}
	buildDates := headers.Values("X-CPA-BUILD-DATE")
	if len(buildDates) != 1 {
		return errors.New("CLIProxy core build date identity is missing")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(buildDates[0])); err != nil {
		return errors.New("CLIProxy core build date identity is invalid")
	}
	return nil
}

func verifyRuntimeConfigIdentity(runtimeIdentity runtimeConfigIdentity, endpoint config.CLIProxy) error {
	parsed, err := url.Parse(endpoint.APIBaseURL)
	if err != nil {
		return errors.New("CLIProxy API URL is invalid")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || runtimeIdentity.Host != parsed.Hostname() || runtimeIdentity.Port != port {
		return errors.New("CLIProxy live listener does not match the configured loopback origin")
	}
	if runtimeIdentity.AllowRemote || endpoint.AllowRemote == nil || runtimeIdentity.AllowRemote != *endpoint.AllowRemote {
		return errors.New("CLIProxy live remote-management policy is not allow-remote=false")
	}
	if !runtimeIdentity.DisableControlPanel || !runtimeIdentity.DisableAutoUpdatePanel {
		return errors.New("CLIProxy live management panel or its network auto-updater is enabled")
	}
	if runtimeIdentity.LogsMaxTotalSizeMB != 256 || runtimeIdentity.ErrorLogsMaxFiles != 10 {
		return errors.New("CLIProxy live log retention caps do not match the production contract")
	}
	if runtimeIdentity.AuthDir != endpoint.AuthDirectory {
		return errors.New("CLIProxy live OAuth auth-dir does not match the protected runtime contract")
	}
	return nil
}

func verifyPluginIdentity(response pluginListResponse, endpoint config.CLIProxy) error {
	if !response.PluginsEnabled || response.PluginsDir != endpoint.PluginDirectory {
		return errors.New("CLIProxy plugin host is disabled or uses an unexpected directory")
	}
	var selected *pluginListEntry
	for index := range response.Plugins {
		if response.Plugins[index].ID != endpoint.PluginID {
			continue
		}
		if selected != nil {
			return errors.New("CLIProxy cpa-key-policy plugin identity is duplicated")
		}
		selected = &response.Plugins[index]
	}
	if selected == nil || !selected.Configured || !selected.Registered || !selected.Enabled || !selected.EffectiveEnabled || selected.Metadata == nil || selected.Metadata.Name != endpoint.PluginID || selected.Metadata.Version != endpoint.PluginVersion {
		return errors.New("CLIProxy cpa-key-policy plugin is not registered and effective at the locked version")
	}
	return nil
}

func verifyPluginConfig(ctx context.Context, client readinessManagementClient, endpoint config.CLIProxy) error {
	var raw map[string]json.RawMessage
	route := "/v0/management/plugins/" + endpoint.PluginID + "/config"
	if _, err := client.coreJSON(ctx, http.MethodGet, route, &raw); err != nil {
		return err
	}
	if len(raw) != 3 {
		return errors.New("CLIProxy cpa-key-policy configuration has an unexpected shape")
	}
	var enabled bool
	var priority int
	var stateFile string
	if err := decodeExactJSONScalar(raw["enabled"], &enabled); err != nil || !enabled {
		return errors.New("CLIProxy cpa-key-policy configuration is not enabled")
	}
	if err := decodeExactJSONScalar(raw["priority"], &priority); err != nil || priority != 10 {
		return errors.New("CLIProxy cpa-key-policy priority does not match the production contract")
	}
	if err := decodeExactJSONScalar(raw["state_file"], &stateFile); err != nil || stateFile != endpoint.PolicyStateFile {
		return errors.New("CLIProxy cpa-key-policy state_file does not match the protected runtime contract")
	}
	return nil
}

func decodeExactJSONScalar(raw json.RawMessage, output any) error {
	if len(raw) == 0 {
		return errors.New("missing JSON field")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(output); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return errors.New("invalid JSON scalar")
	}
	return nil
}

func verifyKeyReadbackShape(keys []listedKey) error {
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if !policyKeyIDPattern.MatchString(key.ID) {
			return errors.New("CLIProxy cpa-key-policy key readback contains an invalid id")
		}
		if _, duplicate := seen[key.ID]; duplicate {
			return errors.New("CLIProxy cpa-key-policy key readback contains a duplicate id")
		}
		seen[key.ID] = struct{}{}
		if key.Name == "" || key.RPM < 0 || key.RPM > 100000 || key.Usage == nil {
			return fmt.Errorf("CLIProxy cpa-key-policy key %s has an invalid state", key.ID)
		}
	}
	return nil
}

func verifyPolicyCatalog(policy productconfig.Policy, catalog map[string]catalogAlias) error {
	enabled := 0
	for _, model := range policy.Models {
		if !model.Enabled {
			continue
		}
		enabled++
		alias, ok := catalog[strings.ToLower(model.ID)]
		if !ok || len(alias.Targets) == 0 {
			return fmt.Errorf("CLIProxy alias %s is missing from the live policy catalog", model.ID)
		}
		price, ok := policy.Pricing[model.ID]
		if !ok || price.Currency != "USD" || !numberEqual(alias.InputPricePerMillion, price.InputPerMillion) || !numberEqual(alias.OutputPricePerMillion, price.OutputPerMillion) {
			return fmt.Errorf("CLIProxy alias %s pricing does not match policy", model.ID)
		}
		if _, ok := policy.Quotas[model.ID]; !ok {
			return fmt.Errorf("CLIProxy alias %s has no downstream quota policy", model.ID)
		}
		for _, target := range alias.Targets {
			if target.Provider != model.Provider || strings.TrimSpace(target.TargetModel) == "" {
				return fmt.Errorf("CLIProxy alias %s target does not match provider policy", model.ID)
			}
		}
	}
	if enabled == 0 {
		return errors.New("CLIProxy policy enables no aliases")
	}
	return nil
}

func parseRuntimeConfigIdentity(raw []byte) (runtimeConfigIdentity, error) {
	if len(raw) == 0 || len(raw) > maxRuntimeConfigResponse || bytes.IndexByte(raw, 0) >= 0 {
		return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config response is empty or unsafe")
	}
	values := make(map[string]string, 9)
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxRuntimeConfigResponse)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.ContainsRune(line, '\t') {
			return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config contains tabs")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config uses unsupported indentation")
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon < 1 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colon])
		rawValue := strings.TrimSpace(trimmed[colon+1:])
		if indent == 0 {
			section = key
			switch key {
			case "host", "port", "auth-dir", "logs-max-total-size-mb", "error-logs-max-files":
				value, err := parseYAMLScalar(rawValue)
				if err != nil || value == "" {
					return runtimeConfigIdentity{}, fmt.Errorf("CLIProxy runtime config field %s is invalid", key)
				}
				if _, duplicate := values[key]; duplicate {
					return runtimeConfigIdentity{}, fmt.Errorf("CLIProxy runtime config field %s is duplicated", key)
				}
				values[key] = value
			case "remote-management":
				if rawValue != "" && !strings.HasPrefix(rawValue, "#") {
					return runtimeConfigIdentity{}, errors.New("CLIProxy remote-management config must be a mapping")
				}
				if _, duplicate := values["remote-management"]; duplicate {
					return runtimeConfigIdentity{}, errors.New("CLIProxy remote-management config is duplicated")
				}
				values["remote-management"] = "mapping"
			}
			continue
		}
		if section == "remote-management" && indent == 2 && (key == "allow-remote" || key == "disable-control-panel" || key == "disable-auto-update-panel") {
			value, err := parseYAMLScalar(rawValue)
			expected := "true"
			if key == "allow-remote" {
				expected = "false"
			}
			if err != nil || value != expected {
				return runtimeConfigIdentity{}, fmt.Errorf("CLIProxy remote-management.%s must be %s", key, expected)
			}
			if _, duplicate := values[key]; duplicate {
				return runtimeConfigIdentity{}, fmt.Errorf("CLIProxy remote-management.%s is duplicated", key)
			}
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config response is unreadable")
	}
	for _, required := range []string{"host", "port", "auth-dir", "logs-max-total-size-mb", "error-logs-max-files", "remote-management", "allow-remote", "disable-control-panel", "disable-auto-update-panel"} {
		if values[required] == "" {
			return runtimeConfigIdentity{}, fmt.Errorf("CLIProxy runtime config field %s is missing", required)
		}
	}
	port, err := strconv.Atoi(values["port"])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != values["port"] {
		return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config port is invalid")
	}
	logsMaxTotalSizeMB, err := strconv.Atoi(values["logs-max-total-size-mb"])
	if err != nil || logsMaxTotalSizeMB <= 0 || strconv.Itoa(logsMaxTotalSizeMB) != values["logs-max-total-size-mb"] {
		return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config logs-max-total-size-mb is invalid")
	}
	errorLogsMaxFiles, err := strconv.Atoi(values["error-logs-max-files"])
	if err != nil || errorLogsMaxFiles <= 0 || strconv.Itoa(errorLogsMaxFiles) != values["error-logs-max-files"] {
		return runtimeConfigIdentity{}, errors.New("CLIProxy runtime config error-logs-max-files is invalid")
	}
	return runtimeConfigIdentity{
		Host: values["host"], Port: port, AllowRemote: false,
		DisableControlPanel: true, DisableAutoUpdatePanel: true,
		LogsMaxTotalSizeMB: logsMaxTotalSizeMB, ErrorLogsMaxFiles: errorLogsMaxFiles,
		AuthDir: values["auth-dir"],
	}, nil
}

func parseYAMLScalar(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.HasPrefix(raw, "\"") {
		var value string
		decoder := json.NewDecoder(strings.NewReader(raw))
		if err := decoder.Decode(&value); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			return "", errors.New("invalid double-quoted YAML scalar")
		}
		return value, nil
	}
	if strings.HasPrefix(raw, "'") {
		if len(raw) < 2 || !strings.HasSuffix(raw, "'") {
			return "", errors.New("invalid single-quoted YAML scalar")
		}
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'"), nil
	}
	if index := strings.Index(raw, " #"); index >= 0 {
		raw = strings.TrimSpace(raw[:index])
	}
	if raw == "" || strings.ContainsAny(raw, "\r\n") || strings.Contains("!&*|>{[", raw[:1]) {
		return "", errors.New("unsupported YAML scalar")
	}
	return raw, nil
}
