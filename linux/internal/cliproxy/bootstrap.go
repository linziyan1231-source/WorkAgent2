package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
)

const ManagedAliasCount = 16

// Bootstrap verifies the locked core and plugin before reconciling the exact
// Windows-managed alias catalog. It is idempotent and preserves non-managed
// aliases; a final pre-OAuth policy readiness pass verifies the persisted
// readback. Full Portal/doctor readiness additionally requires live Codex and
// Kimi file-backed OAuth credentials, which cannot exist on first service start.
func Bootstrap(ctx context.Context, endpoint config.CLIProxy, policy productconfig.Policy) error {
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
	return bootstrapWithClient(ctx, endpoint, policy, client)
}

func bootstrapWithClient(ctx context.Context, endpoint config.CLIProxy, policy productconfig.Policy, client readinessManagementClient) error {
	if err := endpoint.Validate(); err != nil {
		return fmt.Errorf("CLIProxy contract: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("CLIProxy policy: %w", err)
	}
	// Do not permit a management write until the authenticated listener, build,
	// plugin metadata/configuration, state path, and key readback are verified.
	if err := checkHostReadinessWithClient(ctx, endpoint, client); err != nil {
		return err
	}
	if err := ensureManagedAliases(ctx, client); err != nil {
		return err
	}
	return checkPolicyReadinessWithClient(ctx, endpoint, policy, client)
}

func ensureManagedAliases(ctx context.Context, client managementJSONClient) error {
	catalog, err := readCatalogUnchecked(ctx, client)
	if err != nil {
		return err
	}
	for _, desired := range managedAliases() {
		actual, present := catalog[strings.ToLower(desired.Alias)]
		if present && catalogAliasEqual(actual, desired) {
			continue
		}
		if err := client.JSON(ctx, http.MethodPost, "/aliases", desired, nil); err != nil {
			return fmt.Errorf("reconcile CLIProxy managed alias %s: %w", desired.Alias, err)
		}
	}
	catalog, err = readCatalogUnchecked(ctx, client)
	if err != nil {
		return err
	}
	return verifyManagedAliases(catalog)
}

func verifyManagedAliases(catalog map[string]catalogAlias) error {
	for _, desired := range managedAliases() {
		actual, present := catalog[strings.ToLower(desired.Alias)]
		if !present || !catalogAliasEqual(actual, desired) {
			return fmt.Errorf("CLIProxy managed alias %s does not match the Windows production contract", desired.Alias)
		}
	}
	return nil
}

func catalogAliasEqual(left, right catalogAlias) bool {
	if left.Alias != right.Alias || left.Dispatch != right.Dispatch || left.BillingMode != right.BillingMode || len(left.Targets) != len(right.Targets) ||
		!catalogNumberEqual(left.InputPricePerMillion, right.InputPricePerMillion) || !catalogNumberEqual(left.OutputPricePerMillion, right.OutputPricePerMillion) ||
		!catalogNumberEqual(left.CacheReadPricePerMillion, right.CacheReadPricePerMillion) || !catalogNumberEqual(left.PerCallUSD, right.PerCallUSD) {
		return false
	}
	for index := range left.Targets {
		if left.Targets[index] != right.Targets[index] {
			return false
		}
	}
	return true
}

func catalogNumberEqual(left, right json.Number) bool {
	leftText := left.String()
	rightText := right.String()
	if leftText == "" {
		leftText = "0"
	}
	if rightText == "" {
		rightText = "0"
	}
	if !numberEqual(json.Number(leftText), rightText) {
		return false
	}
	return true
}

func managedAliases() []catalogAlias {
	return []catalogAlias{
		managedTokenAlias("codex-auto-review", "codex", "codex-auto-review", "1.75", "14", "0.175"),
		managedTokenAlias("gpt-5.3-codex-spark", "codex", "gpt-5.3-codex-spark", "1.75", "14", "0.175"),
		managedTokenAlias("gpt-5.4", "codex", "gpt-5.4", "2.5", "15", "0.25"),
		managedTokenAlias("gpt-5.4-mini", "codex", "gpt-5.4-mini", "0.75", "4.5", "0.075"),
		managedTokenAlias("gpt-5.5", "codex", "gpt-5.5", "5", "30", "0.5"),
		managedTokenAlias("gpt-5.6-luna", "codex", "gpt-5.6-luna", "1", "6", "0.1"),
		managedTokenAlias("gpt-5.6-sol", "codex", "gpt-5.6-sol", "5", "30", "0.5"),
		managedTokenAlias("gpt-5.6-terra", "codex", "gpt-5.6-terra", "2.5", "15", "0.25"),
		managedTokenAlias("kimi-for-coding", "kimi", "kimi-k2.7-code", "0.95", "4", "0.19"),
		managedTokenAlias("kimi-for-coding-highspeed", "kimi", "kimi-k2.7-code-highspeed", "1.9", "8", "0.38"),
		managedTokenAlias("kimi-k3", "kimi", "kimi-k3", "3", "15", "0.3"),
		managedTokenAlias("kimi-k2.5", "kimi", "kimi-k2.5", "0.6", "3", "0.1"),
		managedTokenAlias("kimi-k2.6", "kimi", "kimi-k2.6", "0.95", "4", "0.16"),
		managedTokenAlias("kimi-k2.7", "kimi", "kimi-k2.7-code", "0.95", "4", "0.19"),
		managedTokenAlias("kimi-k2.7-code", "kimi", "kimi-k2.7-code", "0.95", "4", "0.19"),
		managedTokenAlias("kimi-k2.7-code-highspeed", "kimi", "kimi-k2.7-code-highspeed", "1.9", "8", "0.38"),
	}
}

func managedTokenAlias(alias, provider, targetModel, input, output, cache string) catalogAlias {
	return catalogAlias{
		Alias: alias, Targets: []catalogTarget{{Provider: provider, TargetModel: targetModel}},
		Dispatch: "priority", BillingMode: "tokens",
		InputPricePerMillion: json.Number(input), OutputPricePerMillion: json.Number(output), CacheReadPricePerMillion: json.Number(cache),
	}
}
