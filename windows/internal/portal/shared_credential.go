package portal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"aionuiportal/internal/cliproxy"
	"aionuiportal/internal/ipc"
)

type sharedManagementKey struct {
	ID      string            `json:"id"`
	Aliases []json.RawMessage `json:"aliases"`
}

type sharedManagementKeyList struct {
	Keys []json.RawMessage `json:"keys"`
}

func decodeSharedManagementKeys(list sharedManagementKeyList) ([]sharedManagementKey, error) {
	keys := make([]sharedManagementKey, 0, len(list.Keys))
	for _, raw := range list.Keys {
		var key sharedManagementKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return nil, fmt.Errorf("decode shared management key: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

type sharedCredentialResponse struct {
	Key       json.RawMessage `json:"key"`
	PlainKey  string          `json:"plain_key"`
	Generated bool            `json:"generated"`
}

func sharedCredentialID(conversationID string) string {
	digest := sha256.Sum256([]byte("shared-conversation\x00" + strings.TrimSpace(conversationID)))
	return "shared-" + hex.EncodeToString(digest[:16])
}

func retrySharedCredentialOperation(ctx context.Context, operation func() error) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := operation(); err == nil {
			return nil
		} else {
			last = err
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
			}
		}
	}
	return last
}

func (s *Server) ensureSharedAgentCredential(ctx context.Context, ownerSID, conversationID string, payerKeyIDs []string) (string, error) {
	client, err := cliproxy.NewManagementClient(cliproxy.ManagementOptions{
		BaseURL: s.cfg.UsageManagementURL,
		KeyFile: s.cfg.UsageManagementKeyFile,
	})
	if err != nil {
		return "", err
	}
	var listed sharedManagementKeyList
	if err := retrySharedCredentialOperation(ctx, func() error {
		listed.Keys = nil
		return client.JSON(ctx, http.MethodGet, "/keys", nil, &listed)
	}); err != nil {
		return "", err
	}
	listedKeys, err := decodeSharedManagementKeys(listed)
	if err != nil {
		return "", err
	}
	byID := make(map[string]sharedManagementKey, len(listedKeys))
	for _, key := range listedKeys {
		byID[key.ID] = key
	}
	targetSet := make(map[string]struct{}, len(payerKeyIDs))
	aliasSet := make(map[string]json.RawMessage)
	for _, rawID := range payerKeyIDs {
		id := strings.TrimSpace(rawID)
		key, ok := byID[id]
		if !ok {
			return "", fmt.Errorf("frozen shared payer key %q is unavailable", id)
		}
		targetSet[id] = struct{}{}
		for _, rawAlias := range key.Aliases {
			var alias struct {
				Alias string `json:"alias"`
			}
			if json.Unmarshal(rawAlias, &alias) != nil || strings.TrimSpace(alias.Alias) == "" {
				return "", errors.New("shared payer key contained an invalid alias")
			}
			aliasSet[strings.ToLower(strings.TrimSpace(alias.Alias))] = append(json.RawMessage(nil), rawAlias...)
		}
	}
	if len(aliasSet) == 0 {
		return "", errors.New("frozen shared payers expose no managed model aliases")
	}
	targets := make([]string, 0, len(targetSet))
	for id := range targetSet {
		targets = append(targets, id)
	}
	sort.Strings(targets)
	aliasNames := make([]string, 0, len(aliasSet))
	for name := range aliasSet {
		aliasNames = append(aliasNames, name)
	}
	sort.Strings(aliasNames)
	aliases := make([]json.RawMessage, 0, len(aliasNames))
	for _, name := range aliasNames {
		aliases = append(aliases, aliasSet[name])
	}
	credentialID := sharedCredentialID(conversationID)
	payload := map[string]any{
		"id": credentialID, "name": "Shared conversation " + conversationID[:8], "enabled": true,
		"rpm": 60, "aliases": aliases, "daily_limit_usd": 0, "weekly_limit_usd": 0,
		"allow_models_endpoint": true, "collaboration_target_key_ids": targets,
	}
	_, exists := byID[credentialID]
	var oneTime sharedCredentialResponse
	if exists {
		if err := retrySharedCredentialOperation(ctx, func() error {
			return client.JSON(ctx, http.MethodPatch, "/keys", payload, nil)
		}); err != nil {
			return "", err
		}
		installed, err := s.instances.VerifySharedAgentCredential(ctx, ownerSID, credentialID)
		if err != nil {
			return "", err
		}
		if installed {
			return credentialID, nil
		}
		if err := retrySharedCredentialOperation(ctx, func() error {
			oneTime.PlainKey = ""
			return client.JSON(ctx, http.MethodPost, "/keys/rotate", map[string]string{"id": credentialID}, &oneTime)
		}); err != nil {
			return "", err
		}
	} else if err := client.JSON(ctx, http.MethodPost, "/keys", payload, &oneTime); err != nil {
		// A create timeout is ambiguous. Re-list and rotate only if the exact
		// stable key appeared; otherwise fail without blindly duplicating it.
		var reconciled sharedManagementKeyList
		if listErr := retrySharedCredentialOperation(ctx, func() error {
			reconciled.Keys = nil
			return client.JSON(ctx, http.MethodGet, "/keys", nil, &reconciled)
		}); listErr != nil {
			return "", errors.Join(err, listErr)
		}
		reconciledKeys, decodeErr := decodeSharedManagementKeys(reconciled)
		if decodeErr != nil {
			return "", errors.Join(err, decodeErr)
		}
		found := false
		for _, key := range reconciledKeys {
			found = found || key.ID == credentialID
		}
		if !found {
			return "", err
		}
		if rotateErr := retrySharedCredentialOperation(ctx, func() error {
			oneTime.PlainKey = ""
			return client.JSON(ctx, http.MethodPost, "/keys/rotate", map[string]string{"id": credentialID}, &oneTime)
		}); rotateErr != nil {
			return "", errors.Join(err, rotateErr)
		}
	}
	if strings.TrimSpace(oneTime.PlainKey) == "" {
		return "", errors.New("CPA returned no one-time shared credential")
	}
	managementURL, _ := url.Parse(s.cfg.UsageManagementURL)
	managementURL.Path = "/v1"
	request := ipc.SharedAgentCredentialRequest{
		CredentialID: credentialID,
		PlainKey:     oneTime.PlainKey,
		BaseURL:      managementURL.String(),
	}
	if err := retrySharedCredentialOperation(ctx, func() error {
		return s.instances.InstallSharedAgentCredential(ctx, ownerSID, request)
	}); err != nil {
		rollbackErr := retrySharedCredentialOperation(ctx, func() error {
			return client.JSON(ctx, http.MethodDelete, "/keys", map[string]string{"id": credentialID}, nil)
		})
		if rollbackErr != nil {
			return "", errors.Join(err, rollbackErr)
		}
		return "", err
	}
	oneTime.PlainKey = ""
	request.PlainKey = ""
	return credentialID, nil
}
