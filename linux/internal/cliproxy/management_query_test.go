package cliproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyUsageUsesFixedQueryAndEmptyGETBody(t *testing.T) {
	const keyID = "workagent-0123456789abcdef0123-codex"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v0/management/plugins/cpa-key-policy/keys/usage" || request.URL.Query().Get("id") != keyID || len(request.URL.Query()) != 1 {
			t.Errorf("unexpected key usage request: method=%s path=%s query_keys=%d", request.Method, request.URL.Path, len(request.URL.Query()))
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || len(body) != 0 {
			t.Errorf("GET body length = %d, err = %v", len(body), err)
			http.Error(writer, "body not permitted", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"key_id": keyID, "key_name": "tenant", "aliases": []any{}})
	}))
	defer server.Close()
	credential := filepath.Join(t.TempDir(), "management-key")
	if err := os.WriteFile(credential, []byte("0123456789abcdefghijklmnopqrstuvwxyzAB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewManagementClient(ManagementOptions{BaseURL: server.URL + "/v0/management/plugins/cpa-key-policy", KeyFile: credential})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var response struct {
		KeyID   string `json:"key_id"`
		KeyName string `json:"key_name"`
		Aliases []any  `json:"aliases"`
	}
	if err := client.keyUsage(context.Background(), keyID, &response); err != nil {
		t.Fatal(err)
	}
	if response.KeyID != keyID || response.KeyName != "tenant" || response.Aliases == nil {
		t.Fatalf("unexpected response shape: key=%q name=%q aliases_nil=%v", response.KeyID, response.KeyName, response.Aliases == nil)
	}
}
