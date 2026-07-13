package adminipc

import (
	"context"
	"testing"
	"time"

	"aionuiportal/internal/ipc"
)

func TestProtectedAdminPipeRoundTripContainsMetricsNotCredentials(t *testing.T) {
	serviceSID := "S-1-5-21-1336342516-1675899976-1060380851-3083"
	sddl, err := SDDL(serviceSID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := Listen(ctx, sddl, func(_ context.Context, request Request) Response {
		return Response{OK: true, Status: &ipc.Status{WindowsSID: request.WindowsSID, Healthy: true}, Sessions: 2, Requests: 3, WebSockets: 1}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	callCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	response, err := Call(callCtx, Request{Command: "status", WindowsSID: "S-1-5-21-1316577768-1960996551-1198996772-8181", Nonce: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status == nil || response.Sessions != 2 || response.Requests != 3 || response.WebSockets != 1 {
		t.Fatalf("unexpected admin metrics: %+v", response)
	}
}
