package cliproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
)

type aliasReconcileFixture struct {
	catalog map[string]catalogAlias
	posts   []catalogAlias
}

func (f *aliasReconcileFixture) JSON(_ context.Context, method, route string, input, output any) error {
	if route != "/aliases" {
		return errors.New("unexpected alias route")
	}
	switch method {
	case http.MethodGet:
		aliases := make([]catalogAlias, 0, len(f.catalog))
		for _, alias := range f.catalog {
			aliases = append(aliases, alias)
		}
		sort.Slice(aliases, func(i, j int) bool { return aliases[i].Alias < aliases[j].Alias })
		return assignJSON(map[string]any{"aliases": aliases}, output)
	case http.MethodPost:
		payload, err := json.Marshal(input)
		if err != nil {
			return err
		}
		var alias catalogAlias
		if err := decodeManagementJSON(payload, &alias); err != nil {
			return err
		}
		f.posts = append(f.posts, alias)
		f.catalog[strings.ToLower(alias.Alias)] = alias
		return nil
	default:
		return errors.New("unexpected alias method")
	}
}

func TestManagedAliasCatalogMatchesReadOnlyWindowsHelper(t *testing.T) {
	aliases := managedAliases()
	if len(aliases) != ManagedAliasCount {
		t.Fatalf("managed aliases = %d, want %d", len(aliases), ManagedAliasCount)
	}
	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Alias < aliases[j].Alias })
	normalized := make([]map[string]any, 0, len(aliases))
	for _, alias := range aliases {
		normalized = append(normalized, map[string]any{
			"alias": alias.Alias, "targets": []any{map[string]any{"provider": alias.Targets[0].Provider, "target_model": alias.Targets[0].TargetModel}},
			"dispatch": alias.Dispatch, "billing_mode": alias.BillingMode,
			"input_price_per_million": alias.InputPricePerMillion, "output_price_per_million": alias.OutputPricePerMillion,
			"cache_read_price_per_million": alias.CacheReadPricePerMillion,
		})
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if got, want := hex.EncodeToString(digest[:]), "fafe6da30aed43dbc08cba75b4bd60252e23bc790050507483dd0ee0a9844469"; got != want {
		t.Fatalf("managed alias catalog SHA-256 = %s, want Windows lock %s", got, want)
	}
}

func TestEnsureManagedAliasesRepairsOnlyDriftedWindowsEntries(t *testing.T) {
	fixture := &aliasReconcileFixture{catalog: make(map[string]catalogAlias)}
	for _, alias := range managedAliases() {
		fixture.catalog[strings.ToLower(alias.Alias)] = alias
	}
	drifted := fixture.catalog["gpt-5.6-sol"]
	drifted.OutputPricePerMillion = json.Number("999")
	fixture.catalog["gpt-5.6-sol"] = drifted
	delete(fixture.catalog, "kimi-k3")
	extra := managedTokenAlias("operator-extra", "codex", "operator-extra", "1", "2", "0.1")
	fixture.catalog[extra.Alias] = extra

	if err := ensureManagedAliases(context.Background(), fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.posts) != 2 {
		t.Fatalf("managed alias writes = %d, want 2", len(fixture.posts))
	}
	if _, preserved := fixture.catalog[extra.Alias]; !preserved {
		t.Fatal("non-managed operator alias was removed")
	}
	if err := verifyManagedAliases(fixture.catalog); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapRefusesAliasWritesBeforeCoreIdentityVerification(t *testing.T) {
	fixture := validReadinessClient()
	fixture.headers = http.Header{}
	if err := bootstrapWithClient(context.Background(), readinessEndpoint(), readinessPolicy(), fixture); err == nil {
		t.Fatal("bootstrap accepted a core without locked build identity")
	}
	if fixture.aliasWrites != 0 {
		t.Fatalf("bootstrap performed %d writes before core verification", fixture.aliasWrites)
	}
}
