package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedCredentialIsFixedHighEntropyBase64URL(t *testing.T) {
	first, err := generateCredential()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	second, err := generateCredential()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second)
	if len(first) != base64.RawURLEncoding.EncodedLen(generatedCredentialEntropyBytes) {
		t.Fatalf("unexpected encoded credential length: %d", len(first))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(first))
	if err != nil || len(decoded) != generatedCredentialEntropyBytes {
		t.Fatalf("generated credential is not canonical base64url: bytes=%d err=%v", len(decoded), err)
	}
	clear(decoded)
	if bytes.Equal(first, second) {
		t.Fatal("independent generated credentials matched")
	}
}

func TestCredentialNameAllowlists(t *testing.T) {
	for _, name := range []string{"chatforward-key", "cliproxy-management-key", "notifications-key"} {
		if !generatedCredentialNames[name] || !installableCredentialNames[name] {
			t.Fatalf("required generated credential %q is not allow-listed", name)
		}
	}
	if len(generatedCredentialNames) != 3 {
		t.Fatalf("generated credential allowlist changed unexpectedly: %#v", generatedCredentialNames)
	}
	if generatedCredentialNames["admin-master-password-hash"] || !installableCredentialNames["admin-master-password-hash"] {
		t.Fatal("administrator password hash must be manually installable but never randomly generated")
	}
	for _, name := range []string{"arbitrary", "provider-api-key", "../escape", ""} {
		if generatedCredentialNames[name] || installableCredentialNames[name] {
			t.Fatalf("unexpected credential name was allow-listed: %q", name)
		}
	}
}

func TestEncryptCredentialUsesStdinVerifiesAndRotates(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, "systemd-creds")
	script := `#!/bin/sh
set -eu
case "$1" in
  encrypt)
    test "$#" -eq 6
    test "$2" = "--with-key=host"
    test "$3" = "--newline=no"
    test "$4" = "--name=chatforward-key"
    test "$5" = "-"
    if test "${WORKAGENT_TEST_FAIL_ENCRYPT:-}" = 1; then
      cat >/dev/null
      printf '%s\n' 'CHILD-OUTPUT-MUST-NOT-ESCAPE' >&2
      exit 73
    fi
    cat >"$6"
    ;;
  decrypt)
    test "$#" -eq 5
    test "$2" = "--newline=no"
    test "$3" = "--name=chatforward-key"
    test "$5" = "-"
    if test "${WORKAGENT_TEST_CORRUPT:-}" = 1; then
      printf '%s' 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    else
      cat "$4"
    fi
    ;;
  *) exit 91 ;;
esac
`
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := systemdCredsCommand
	systemdCredsCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(fake, arguments...)
	}
	t.Cleanup(func() { systemdCredsCommand = previous })

	first := []byte(strings.Repeat("A", 64))
	for _, invalid := range []struct {
		name      string
		store     string
		plaintext []byte
	}{
		{name: "../escape", store: store, plaintext: first},
		{name: "chatforward-key", store: "relative", plaintext: first},
		{name: "chatforward-key", store: store, plaintext: nil},
	} {
		if _, err := encryptCredential(invalid.name, invalid.store, false, invalid.plaintext); err == nil {
			t.Fatalf("unsafe direct encryption input was accepted: %#v", invalid)
		}
	}
	target, err := encryptCredential("chatforward-key", store, false, first)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(store, "chatforward-key.cred") {
		t.Fatalf("unexpected target: %q", target)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("encrypted credential mode = %04o", info.Mode().Perm())
	}
	if _, err := encryptCredential("chatforward-key", store, false, first); err == nil {
		t.Fatal("existing credential was replaced without --rotate")
	}
	second := []byte(strings.Repeat("B", 64))
	if os.Geteuid() != 0 {
		if _, err := encryptCredential("chatforward-key", store, true, second); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("non-root-owned encrypted credential was accepted for rotation: %v", err)
		}
		return
	}
	if _, err := encryptCredential("chatforward-key", store, true, second); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(installed)
	if !bytes.Equal(installed, second) {
		t.Fatal("credential rotation did not install the verified replacement")
	}
	t.Setenv("WORKAGENT_TEST_FAIL_ENCRYPT", "1")
	if _, err := encryptCredential("chatforward-key", store, true, []byte(strings.Repeat("E", 64))); err == nil || strings.Contains(err.Error(), "CHILD-OUTPUT-MUST-NOT-ESCAPE") || !strings.Contains(err.Error(), "diagnostic redacted") {
		t.Fatalf("child encryption output was not fully redacted: %v", err)
	}
	t.Setenv("WORKAGENT_TEST_FAIL_ENCRYPT", "0")
	t.Setenv("WORKAGENT_TEST_CORRUPT", "1")
	if _, err := encryptCredential("chatforward-key", store, true, []byte(strings.Repeat("D", 64))); err == nil {
		t.Fatal("credential with a mismatched read-back was installed")
	}
	unchanged, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(unchanged)
	if !bytes.Equal(unchanged, second) {
		t.Fatal("failed read-back changed the installed credential")
	}
}

func TestDiagnosticsAreSingleLineAndBounded(t *testing.T) {
	message := sanitizeDiagnostic("  first\r\nsecond\n" + strings.Repeat("x", 600))
	if strings.ContainsAny(message, "\r\n") {
		t.Fatalf("diagnostic contains a line break: %q", message)
	}
	if len([]rune(message)) != 512 {
		t.Fatalf("diagnostic length = %d", len([]rune(message)))
	}
	if sanitizeDiagnostic(" \r\n ") != "operation failed" {
		t.Fatal("empty diagnostic did not use its safe fallback")
	}
}

func TestInstallResultContainsOnlyStatusAndPath(t *testing.T) {
	var output bytes.Buffer
	target := "/etc/credstore.encrypted/workagent/chatforward-key.cred"
	if err := writeInstallResult(&output, target); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded["installed"] != true || decoded["path"] != target {
		t.Fatalf("unexpected installation output: %#v", decoded)
	}
}
