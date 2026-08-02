package cliproxy

import (
	"bytes"
	"testing"
)

func validBackupPolicyState() []byte {
	return []byte(`{
  "version": 1,
  "keys": [
    {"id":"tenant-codex","enabled":true,"key_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","key_preview":"cpa_ABC...VWXYZ"},
    {"id":"tenant-kimi","enabled":false,"key_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","key_preview":"cpa_DEF...QRSTU","unknown":{"preserve":true}}
  ],
  "usage": {},
  "unknown_top": {"preserve":true}
}`)
}

func TestValidatePolicyStatePayload(t *testing.T) {
	if err := ValidatePolicyStatePayload(validBackupPolicyState()); err != nil {
		t.Fatalf("valid policy state rejected: %v", err)
	}
	for name, payload := range map[string][]byte{
		"duplicate key": bytes.Replace(validBackupPolicyState(), []byte(`tenant-kimi`), []byte(`tenant-codex`), 1),
		"bad key id":    bytes.Replace(validBackupPolicyState(), []byte(`tenant-kimi`), []byte(`../tenant-kimi`), 1),
		"bad hash":      bytes.Replace(validBackupPolicyState(), []byte(`sha256:bbbb`), []byte(`sha256:zzzz`), 1),
		"bad usage":     bytes.Replace(validBackupPolicyState(), []byte(`"usage": {}`), []byte(`"usage":{"tenant-codex":{"daily":{"total_usd":"not-a-number"}}}`), 1),
		"trailing":      append(validBackupPolicyState(), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePolicyStatePayload(payload); err == nil {
				t.Fatal("invalid policy state was accepted")
			}
		})
	}
}
