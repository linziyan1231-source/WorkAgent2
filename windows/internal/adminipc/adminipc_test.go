package adminipc

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"aionuiportal/internal/ipc"
)

func TestProtectedAdminPipeRoundTripContainsMetricsNotCredentials(t *testing.T) {
	serviceSID := "S-1-5-21-100-200-300-500"
	sddl, err := SDDL(serviceSID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pipeName := fmt.Sprintf(`\\.\pipe\AionUiPortalAdmin-Test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	server, err := listen(ctx, pipeName, sddl, func(_ context.Context, request Request) Response {
		return Response{OK: true, Status: &ipc.Status{WindowsSID: request.WindowsSID, Healthy: true}, Sessions: 2, Requests: 3, WebSockets: 1}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	callCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	response, err := call(callCtx, pipeName, Request{Command: "status", WindowsSID: "S-1-5-21-1-2-3-1017", Nonce: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status == nil || response.Sessions != 2 || response.Requests != 3 || response.WebSockets != 1 {
		t.Fatalf("unexpected admin metrics: %+v", response)
	}
}
