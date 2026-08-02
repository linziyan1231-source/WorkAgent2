package winutil

import (
	"os"
	"strings"
	"testing"
)

func standardAccountsForIntegrationTest(t *testing.T) []string {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("AIONUI_TEST_STANDARD_ACCOUNTS"))
	if raw == "" {
		t.Skip("set AIONUI_TEST_STANDARD_ACCOUNTS to local standard accounts for Windows account integration tests")
	}
	accounts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	if len(accounts) < 2 {
		t.Fatal("AIONUI_TEST_STANDARD_ACCOUNTS must contain at least two comma- or semicolon-separated accounts")
	}
	return accounts
}

func TestValidateKnownStandardAccounts(t *testing.T) {
	for _, account := range standardAccountsForIntegrationTest(t) {
		sid, canonical, err := ValidateStandardAccount(account)
		if err != nil {
			t.Fatalf("%s: %v", account, err)
		}
		if sid == "" || canonical == "" {
			t.Fatalf("%s resolved to empty identity", account)
		}
	}
}

func TestDotSlashLocalAccountResolvesToTheSameIdentity(t *testing.T) {
	for _, account := range standardAccountsForIntegrationTest(t) {
		plainSID, plainCanonical, err := ValidateStandardAccount(account)
		if err != nil {
			t.Fatalf("resolve %s: %v", account, err)
		}
		dotSID, dotCanonical, err := ValidateStandardAccount(`.\` + account)
		if err != nil {
			t.Fatalf("resolve .\\%s: %v", account, err)
		}
		if !strings.EqualFold(plainSID, dotSID) || !strings.EqualFold(plainCanonical, dotCanonical) {
			t.Fatalf("local account forms differ: %s/%s versus %s/%s", plainSID, plainCanonical, dotSID, dotCanonical)
		}
	}
}

func TestAdministratorIsNotAcceptedAsUserHostAccount(t *testing.T) {
	if _, _, err := ValidateStandardAccount("Administrator"); err == nil {
		t.Fatal("built-in Administrator was accepted as a standard UserHost account")
	}
}
