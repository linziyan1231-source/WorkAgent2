package userhost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedLogRedactsSensitiveOutputAcrossWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backend.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := &boundedLogWriter{file: file, remaining: maximumBackendLogSize}
	if _, err := writer.Write([]byte("starting normally\napi_")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("key=must-not-survive\ncallback https://example.test/cb?code=hidden\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if !strings.Contains(text, "starting normally") || !strings.Contains(text, "[REDACTED SENSITIVE OUTPUT]") {
		t.Fatalf("expected log content missing: %q", text)
	}
	for _, secret := range []string{"must-not-survive", "hidden"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q survived in backend log: %q", secret, text)
		}
	}
}
