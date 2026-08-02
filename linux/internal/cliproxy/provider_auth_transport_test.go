package cliproxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderOAuthManagementReadEnforcesAuthenticationStatusAndSize(t *testing.T) {
	key := bytes.Repeat([]byte{'A'}, 48)
	keyFile := filepath.Join(t.TempDir(), "management-key")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		status  int
		payload []byte
		wantErr bool
	}{
		"success":            {status: http.StatusOK, payload: validProviderAuthFiles("codex", "kimi")},
		"non-success status": {status: http.StatusServiceUnavailable, payload: []byte(`{"error":"unavailable"}`), wantErr: true},
		"oversized response": {status: http.StatusOK, payload: bytes.Repeat([]byte{' '}, maxProviderAuthResponse+1), wantErr: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.RequestURI() != "/v0/management/auth-files" ||
					request.Header.Get("Authorization") != "Bearer "+string(key) {
					t.Error("provider OAuth management request did not use the protected authenticated route")
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write(test.payload)
			}))
			defer server.Close()

			client, err := NewManagementClient(ManagementOptions{
				BaseURL: server.URL + "/v0/management/plugins/cpa-key-policy",
				KeyFile: keyFile,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			payload, _, err := client.coreRaw(context.Background(), "/v0/management/auth-files", maxProviderAuthResponse)
			clear(payload)
			if (err != nil) != test.wantErr {
				t.Fatalf("authenticated provider OAuth read error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
	clear(key)
}
