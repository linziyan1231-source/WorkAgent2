package userhost

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

type lifecycleRoundTripper struct {
	started  chan string
	canceled chan struct{}
	release  chan struct{}
}

func (transport *lifecycleRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.started <- request.Header.Get(workAgentRuntimeHeader)
	<-request.Context().Done()
	close(transport.canceled)
	<-transport.release
	return nil, errors.New("runtime stopped")
}

func TestFinishRunWaitsForProxyHandlersBeforeClearingRuntimeToken(t *testing.T) {
	expectedToken := strings.Repeat("A", workAgentRuntimeTokenTextBytes)
	token := []byte(expectedToken)
	target, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	transport := &lifecycleRoundTripper{
		started:  make(chan string, 1),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
	}
	host := &Host{
		cfg:          config.Tenant{TenantID: "11111111-1111-4111-8111-111111111111"},
		runtimeToken: token,
		ready:        true,
	}
	host.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			rewriteBackendProxyRequest(proxyRequest, target, backendAuthMaterial{}, host.runtimeToken)
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			writer.WriteHeader(http.StatusBadGateway)
		},
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requestContext, cancelRequests := context.WithCancel(context.Background())
	server := &http.Server{
		Handler:     host.routes(),
		BaseContext: func(net.Listener) context.Context { return requestContext },
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-WorkAgent-Tenant", host.cfg.TenantID)
	request.Header.Set("X-WorkAgent-User-Request", "1")
	clientDone := make(chan struct{})
	go func() {
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr == nil {
			response.Body.Close()
		}
		close(clientDone)
	}()

	select {
	case received := <-transport.started:
		if received != expectedToken {
			t.Fatalf("proxy received runtime token %q", received)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy request did not start")
	}

	finishDone := make(chan struct{})
	go func() {
		host.finishRun(server, cancelRequests)
		close(finishDone)
	}()
	select {
	case <-transport.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime shutdown did not cancel the proxy request")
	}
	if string(host.runtimeToken) != expectedToken {
		t.Fatal("runtime token was cleared while a proxy handler still owned it")
	}
	close(transport.release)
	select {
	case <-finishDone:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime shutdown did not wait for the proxy handler")
	}
	if host.runtimeToken != nil || !bytes.Equal(token, make([]byte, len(token))) {
		t.Fatal("runtime token was not cleared after all handlers stopped")
	}
	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy client remained active after runtime shutdown")
	}
	select {
	case serveErr := <-serverDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("unexpected HTTP server result: %v", serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP server remained active after runtime shutdown")
	}
}
