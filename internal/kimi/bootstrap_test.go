package kimi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedValidatesThenCopiesAndConfiguresRealShapedCredential(t *testing.T) {
	root := t.TempDir()
	sourceOAuth := filepath.Join(root, "administrator", ".kimi", "credentials", "kimi-code.json")
	sourceConfig := filepath.Join(root, "administrator", ".kimi", "config.toml")
	targetProfile := filepath.Join(root, "test1", "AionUiPortal", "profile")
	for _, directory := range []string{filepath.Dir(sourceOAuth), filepath.Dir(sourceConfig), targetProfile} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	credential := []byte(`{"access_token":"access-value","refresh_token":"refresh-value","token_type":"Bearer","expires_at":1893456000,"scope":"openid"}`)
	if err := os.WriteFile(sourceOAuth, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceConfig, []byte("default_model = \"kimi-code/kimi-for-coding\"\n[providers.\"managed:kimi-code\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validated := false
	configured := false
	configure := func(_ context.Context, _, gotSource, target, mode string) (string, error) {
		if gotSource != sourceConfig {
			t.Fatalf("source config=%s want=%s", gotSource, sourceConfig)
		}
		switch mode {
		case "validate":
			if target != "-" {
				t.Fatalf("validate target=%q", target)
			}
			validated = true
			return "Validated Kimi provider metadata with 2 model(s).", nil
		case "configure":
			if !validated {
				t.Fatal("target configuration ran before source validation")
			}
			configured = true
			return "Configured Kimi OAuth provider with 2 model(s).", os.WriteFile(target, []byte("default_model = \"kimi-code/kimi-for-coding\"\n"), 0o600)
		default:
			t.Fatalf("unexpected mode %q", mode)
			return "", nil
		}
	}
	beforeWrite := false
	result, err := Seed(context.Background(), SeedOptions{
		SourceOAuthPath: sourceOAuth, SourceConfigPath: sourceConfig, TargetProfile: targetProfile,
		PythonPath: "protected-python.exe", Configure: configure,
		BeforeWrite: func() error {
			beforeWrite = true
			if !validated {
				t.Fatal("UserHost stop hook ran before source validation")
			}
			if _, err := os.Stat(filepath.Join(targetProfile, ".kimi", "credentials", "kimi-code.json")); !os.IsNotExist(err) {
				t.Fatalf("credential existed before stop hook: %v", err)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !beforeWrite || !configured || result.SHA256 == "" || !strings.Contains(result.Output, "2 model(s)") {
		t.Fatalf("incomplete result before=%t configured=%t result=%+v", beforeWrite, configured, result)
	}
	copied, err := os.ReadFile(filepath.Join(targetProfile, ".kimi", "credentials", "kimi-code.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != string(credential) {
		t.Fatal("target OAuth bytes do not exactly match the source")
	}
	config, err := os.ReadFile(filepath.Join(targetProfile, ".kimi", "config.toml"))
	if err != nil || !strings.Contains(string(config), "kimi-code/kimi-for-coding") {
		t.Fatalf("target config was not verified: %q err=%v", config, err)
	}

	updated := []byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer"}`)
	if err := os.WriteFile(sourceOAuth, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Seed(context.Background(), SeedOptions{
		SourceOAuthPath: sourceOAuth, SourceConfigPath: sourceConfig, TargetProfile: targetProfile,
		PythonPath: "protected-python.exe", Configure: configure,
	}); err != nil {
		t.Fatalf("overwrite existing OAuth: %v", err)
	}
	copied, err = os.ReadFile(filepath.Join(targetProfile, ".kimi", "credentials", "kimi-code.json"))
	if err != nil || string(copied) != string(updated) {
		t.Fatalf("updated OAuth was not copied exactly: %q err=%v", copied, err)
	}
}

func TestSeedRejectsInvalidCredentialBeforeStoppingUserHost(t *testing.T) {
	root := t.TempDir()
	sourceOAuth := filepath.Join(root, "kimi-code.json")
	if err := os.WriteFile(sourceOAuth, []byte(`{"access_token":"","refresh_token":"refresh","token_type":"Bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := Seed(context.Background(), SeedOptions{
		SourceOAuthPath: sourceOAuth,
		BeforeWrite: func() error {
			called = true
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires non-empty") {
		t.Fatalf("invalid credential error=%v", err)
	}
	if called {
		t.Fatal("invalid source stopped the target UserHost")
	}
}

func TestHasCredentialDistinguishesMissingFromMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kimi-code.json")
	if found, err := HasCredential(path); err != nil || found {
		t.Fatalf("missing credential found=%t err=%v", found, err)
	}
	if err := os.WriteFile(path, []byte(`{"access_token":"only-one-field"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := HasCredential(path); err == nil || found {
		t.Fatalf("malformed credential found=%t err=%v", found, err)
	}
}
