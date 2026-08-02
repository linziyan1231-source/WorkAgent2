//go:build linux

package provisionipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServeRoundTripAuthenticatesPeerAndEchoesNonce(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("peer-UID round trip requires an unprivileged test identity")
	}
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "provision.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server, err := Serve(ctx, listener, uint32(os.Getuid()), func(_ context.Context, request Request) Response {
		return Response{OK: true, User: &User{Username: request.Username, TenantID: "tenant", RuntimeUser: "runtime", Enabled: true}}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	connection, err := net.DialTimeout("unix", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := Request{ProtocolVersion: ProtocolVersion, Command: "add-user", Username: "alice", PortalPassword: []byte("correct horse battery staple"), Actor: "admin", Nonce: "0123456789abcdef"}
	if err := writeFrame(connection, request); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := readFrame(connection, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Nonce != request.Nonce || response.ProtocolVersion != ProtocolVersion || response.User == nil || response.User.Username != "alice" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestValidateRequestRejectsMixedCommandFields(t *testing.T) {
	enabled := true
	base := Request{ProtocolVersion: ProtocolVersion, Username: "alice", Actor: "admin", Nonce: "0123456789abcdef"}
	for _, request := range []Request{
		base,
		{ProtocolVersion: ProtocolVersion, Command: "add-user", Username: "alice", PortalPassword: []byte("password"), Enabled: &enabled, Actor: "admin", Nonce: base.Nonce},
		{ProtocolVersion: ProtocolVersion, Command: "set-enabled", Username: "alice", PortalPassword: []byte("password"), Enabled: &enabled, Actor: "admin", Nonce: base.Nonce},
	} {
		if err := validateRequest(request); err == nil {
			t.Fatalf("invalid request was accepted: %+v", request)
		}
	}
}
