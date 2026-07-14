package portalusage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aionuiportal/internal/modelbootstrap"
)

func testSSHClient(t *testing.T) *SSHClient {
	t.Helper()
	root := t.TempDir()
	identity := filepath.Join(root, "usage_ed25519")
	knownHosts := filepath.Join(root, "known_hosts")
	for _, path := range []string{identity, knownHosts} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := NewSSHClient(SSHOptions{Target: "contact@example.invalid", HelperPath: "/root/cliproxyapi/cpa-key-policy-admin.py",
		IdentityFile: identity, KnownHostsFile: knownHosts, Executable: "ssh-test"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func validRemoteJSON() string {
	return `{"version":1,"as_of":"2026-07-14T05:00:00Z","providers":[` +
		`{"kind":"chatgpt","daily":{"limit_usd":"20","used_usd":"1.25"},"weekly":{"limit_usd":"40","used_usd":"3.5"}},` +
		`{"kind":"kimi","daily":{"limit_usd":"5","used_usd":"0.4"},"weekly":{"limit_usd":"10","used_usd":"1.1"}}]}`
}

func TestSSHQueryUsesFixedHelperCommandAndDoesNotPutIDsInArguments(t *testing.T) {
	client := testSSHClient(t)
	ids := modelbootstrap.KeyIDsForSID(testSID1)
	client.run = func(_ context.Context, executable string, args []string, stdin []byte, stdout, _ io.Writer) error {
		joined := strings.Join(args, " ")
		if executable != "ssh-test" || !strings.Contains(joined, client.options.HelperPath+" usage") ||
			strings.Contains(joined, ids.CodexKeyID) || strings.Contains(joined, ids.KimiKeyID) {
			t.Fatalf("unsafe SSH invocation: executable=%q args=%q", executable, joined)
		}
		payload := string(stdin)
		if !strings.Contains(payload, ids.CodexKeyID) || !strings.Contains(payload, ids.KimiKeyID) {
			t.Fatalf("bounded stdin did not contain the exact requested IDs: %s", payload)
		}
		_, _ = io.WriteString(stdout, validRemoteJSON())
		return nil
	}
	got, err := client.Query(context.Background(), ids)
	if err != nil || len(got.Providers) != 2 {
		t.Fatalf("valid remote response failed: got=%+v err=%v", got, err)
	}
}

func TestRemoteResponseRejectsUnknownTruncatedAndTrailingData(t *testing.T) {
	unknown := strings.Replace(validRemoteJSON(), `"as_of":`, `"unknown":true,"as_of":`, 1)
	for name, value := range map[string]string{
		"unknown":   unknown,
		"truncated": validRemoteJSON()[:len(validRemoteJSON())-1],
		"trailing":  validRemoteJSON() + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRemoteResponse([]byte(value)); err == nil {
				t.Fatal("invalid remote response was accepted")
			}
		})
	}
}

func TestSSHQueryFailsOnOutputLimitTimeoutAndSecretBearingDiagnostics(t *testing.T) {
	ids := modelbootstrap.KeyIDsForSID(testSID1)
	t.Run("output limit", func(t *testing.T) {
		client := testSSHClient(t)
		client.run = func(_ context.Context, _ string, _ []string, _ []byte, stdout, _ io.Writer) error {
			_, _ = stdout.Write(make([]byte, maxSSHOutput+1))
			return nil
		}
		if _, err := client.Query(context.Background(), ids); err == nil {
			t.Fatal("oversized SSH output was accepted")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		client := testSSHClient(t)
		client.run = func(ctx context.Context, _ string, _ []string, _ []byte, _, _ io.Writer) error {
			<-ctx.Done()
			return ctx.Err()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		if _, err := client.Query(ctx, ids); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout was not preserved: %v", err)
		}
	})
	t.Run("generic failure", func(t *testing.T) {
		client := testSSHClient(t)
		client.run = func(_ context.Context, _ string, _ []string, _ []byte, _, stderr io.Writer) error {
			_, _ = io.WriteString(stderr, "cpa_plaintext-secret "+ids.KimiKeyID+" ManagementKey")
			return errors.New("ssh failed")
		}
		_, err := client.Query(context.Background(), ids)
		if err == nil || err.Error() != "remote usage helper failed" {
			t.Fatalf("remote diagnostic was exposed: %v", err)
		}
	})
}
