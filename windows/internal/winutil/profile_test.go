package winutil

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownStandardAccountProfilesAreDistinctDirectChildrenOfCUsers(t *testing.T) {
	seen := make(map[string]string)
	for _, account := range standardAccountsForIntegrationTest(t) {
		sid, _, err := ValidateStandardAccount(account)
		if err != nil {
			t.Fatalf("%s: %v", account, err)
		}
		profile, err := ProfileDirectoryForSID(sid)
		if err != nil {
			t.Fatalf("%s profile: %v", account, err)
		}
		if !strings.EqualFold(filepath.Dir(profile), `C:\Users`) {
			t.Fatalf("%s profile %s is not directly below C:\\Users", account, profile)
		}
		key := strings.ToLower(filepath.Clean(profile))
		if previous := seen[key]; previous != "" {
			t.Fatalf("%s and %s share Windows profile %s", previous, account, profile)
		}
		seen[key] = account
	}
}
