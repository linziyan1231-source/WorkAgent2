package winutil

import (
	"strings"
	"testing"
)

func TestValidateKnownStandardAccounts(t *testing.T) {
	for _, account := range []string{"test1", "test2"} {
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
	for _, account := range []string{"test1", "test2"} {
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
