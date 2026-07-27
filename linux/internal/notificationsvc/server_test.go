package notificationsvc

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerIsLoopbackAuthenticatedAndReturnsValidatedPayload(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root ownership contract")
	}
	root := t.TempDir()
	payload := filepath.Join(root, "notification.json")
	credential := filepath.Join(root, "credential")
	if err := os.WriteFile(payload, []byte(`{"notifications":[{"id":"n-1","message":"hello"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{ListenAddress: "127.0.0.1:0", PayloadFile: payload, CredentialFile: credential, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	httpServer := &http.Server{}
	go func() { _ = server.Serve(httpServer) }()
	defer httpServer.Close()

	response, err := http.Get("http://" + server.Address() + "/notification")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://"+server.Address()+"/notification", nil)
	request.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":"n-1"`) {
		t.Fatalf("authenticated response = %d %q", response.StatusCode, body)
	}
}

func TestServerRejectsPublicListenerAndInvalidPayload(t *testing.T) {
	if _, err := New(Config{ListenAddress: "0.0.0.0:0"}); err == nil {
		t.Fatal("public listener accepted")
	}
	if os.Getuid() != 0 {
		t.Skip("root ownership contract")
	}
	root := t.TempDir()
	payload := filepath.Join(root, "notification.json")
	credential := filepath.Join(root, "credential")
	_ = os.WriteFile(payload, []byte(`{"notifications":[{"id":"n-1","message":""}]}`), 0o600)
	_ = os.WriteFile(credential, []byte("0123456789abcdef0123456789abcdef"), 0o600)
	if _, err := New(Config{ListenAddress: "127.0.0.1:0", PayloadFile: payload, CredentialFile: credential}); err == nil {
		t.Fatal("invalid payload accepted")
	}
}
