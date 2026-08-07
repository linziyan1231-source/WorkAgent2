package portal

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDecodeSharedManagementKeysAcceptsPublicKeyFields(t *testing.T) {
	var list sharedManagementKeyList
	if err := json.Unmarshal([]byte(`{"keys":[{"id":"payer","name":"Alice Codex","enabled":true,"key_preview":"cpa_...","rpm":60,"models":[],"aliases":[{"alias":"gpt-5.6-sol"}],"daily_limit_usd":10,"weekly_limit_usd":50,"allow_models_endpoint":true,"usage":{}}]}`), &list); err != nil {
		t.Fatal(err)
	}
	keys, err := decodeSharedManagementKeys(list)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != "payer" || len(keys[0].Aliases) != 1 {
		t.Fatalf("decoded keys=%+v", keys)
	}
}

func TestSharedCredentialResponseAcceptsManagementWriteShape(t *testing.T) {
	decoder := json.NewDecoder(bytes.NewBufferString(`{"key":{"id":"shared-123","name":"Shared conversation"},"plain_key":"cpa_one_time","generated":true}`))
	decoder.DisallowUnknownFields()
	var response sharedCredentialResponse
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.PlainKey != "cpa_one_time" || !response.Generated || len(response.Key) == 0 {
		t.Fatalf("decoded response=%+v", response)
	}
}
