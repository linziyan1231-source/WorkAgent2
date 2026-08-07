package ipc

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func currentSID(t *testing.T) string {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

func TestProtectedPipeRoundTrip(t *testing.T) {
	sid := currentSID(t)
	sddl, err := SDDL(sid, sid)
	if err != nil {
		t.Fatal(err)
	}
	pipe := fmt.Sprintf(`\\.\pipe\AionUiWeb-%s-%d`, sid, os.Getpid())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := Listen(ctx, pipe, sddl, func(_ context.Context, request Request) Response {
		if request.Command != "status" {
			return Response{OK: false, ErrorCode: "UNKNOWN_COMMAND"}
		}
		return Response{OK: true, Status: &Status{WindowsSID: sid, Healthy: true, WebPort: 35001}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	callCtx, callCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer callCancel()
	response, err := Call(callCtx, pipe, Request{ProtocolVersion: ProtocolVersion, Command: "status", Nonce: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Status == nil || response.Status.WindowsSID != sid || response.Status.WebPort != 35001 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestSDDLRejectsNonSID(t *testing.T) {
	if _, err := SDDL("alice", "S-1-5-18"); err == nil {
		t.Fatal("non-SID owner accepted")
	}
}

func TestSharedAgentRequestUsesRunSizedDeadline(t *testing.T) {
	if requestTimeout("status") != 15*time.Second {
		t.Fatalf("status timeout=%s", requestTimeout("status"))
	}
	if requestTimeout("shared_agent_run") <= 30*time.Minute {
		t.Fatalf("shared agent timeout=%s", requestTimeout("shared_agent_run"))
	}
}

func TestSharedAgentFrameFitsValidatedContextLimits(t *testing.T) {
	request := Request{
		ProtocolVersion: ProtocolVersion,
		Command:         "shared_agent_run",
		Nonce:           "0123456789abcdef",
		SharedAgent: &SharedAgentRequest{
			Context:         string(bytes.Repeat([]byte("a"), 512*1024)),
			RecoveryContext: string(bytes.Repeat([]byte("b"), 768*1024)),
		},
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, request); err != nil {
		t.Fatal(err)
	}
	var decoded Request
	if err := readFrame(&frame, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.SharedAgent.Context) != 512*1024 || len(decoded.SharedAgent.RecoveryContext) != 768*1024 {
		t.Fatal("shared agent context was truncated")
	}
}
