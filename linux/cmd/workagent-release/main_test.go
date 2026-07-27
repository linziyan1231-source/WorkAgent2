package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

type releaseSystemd struct {
	states  map[string]string
	checked *[]string
}

func TestMaintenanceNoticeIsObservedThroughAuthenticatedPortalEndpoint(t *testing.T) {
	const targetRelease = "runtime-20260726"
	const session = "portal-session-abcdefghijklmnopqrstuvwxyz"
	observedAt := time.Unix(1_800_000_000, 0).UTC()
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("__Host-aionui-portal")
		if err != nil || cookie.Value != session || request.Host != "portal.example.test" || request.Header.Get("X-Forwarded-Proto") != "https" || request.URL.Path != "/api/portal/me/notifications" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"data":{"notifications":[{"id":"` + release.ExpectedMaintenanceNoticeID(targetRelease) + `","message":"` + release.MaintenanceNoticeMessage + `","published_at":"` + observedAt.Add(-2*time.Minute).Format(time.RFC3339) + `"}]}}`))
	}))
	defer upstream.Close()
	address := upstream.Listener.Addr().String()
	if host, _, err := net.SplitHostPort(address); err != nil || host != "127.0.0.1" {
		t.Skipf("test server did not bind an IPv4 loopback address: %s", address)
	}
	portal := config.Portal{
		Listener: config.Listener{Network: "tcp", Address: address, PublicOrigin: "https://portal.example.test", RequireForwardedHTTPS: true},
		Session:  config.SessionPolicy{CookieName: "__Host-aionui-portal"},
	}
	notice, err := checkMaintenanceNoticeWithSession(context.Background(), portal, []byte(session), targetRelease, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if notice.ID != release.ExpectedMaintenanceNoticeID(targetRelease) || notice.Message != release.MaintenanceNoticeMessage || !notice.PublishedAt.Equal(observedAt.Add(-2*time.Minute)) {
		t.Fatalf("unexpected maintenance notice evidence: %+v", notice)
	}
}

func (s releaseSystemd) Properties(_ context.Context, unit string, _ ...string) (map[string]string, error) {
	if s.checked != nil {
		*s.checked = append(*s.checked, unit)
	}
	return map[string]string{"LoadState": "loaded", "ActiveState": s.states[unit]}, nil
}

func (releaseSystemd) Action(context.Context, ...string) error { return nil }

func TestReleaseDrainGateIncludesSocketsAndServices(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	configs := map[string]string{tenantID: "/etc/workagent/users/" + tenantID + ".json"}
	controller := releaseSystemd{states: map[string]string{
		"workagent-userhost@" + tenantID + ".socket":  "active",
		"workagent-userhost@" + tenantID + ".service": "inactive",
		"workagent-portal.service":                    "inactive",
	}}
	portal := config.Portal{Renderer: config.RendererRelease{Scope: release.ScopeRuntime}}
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, controller); err == nil {
		t.Fatal("active socket was accepted during release activation")
	}
	controller.states["workagent-userhost@"+tenantID+".socket"] = "inactive"
	if err := ensureReleaseFleetStopped(context.Background(), portal, configs, release.ScopeRuntime, controller); err != nil {
		t.Fatalf("fully stopped runtime fleet was rejected: %v", err)
	}
}

func TestSharedReleaseDrainGateRequiresChatForwardBrowserThenBridge(t *testing.T) {
	checked := []string{}
	controller := releaseSystemd{
		states: map[string]string{
			"workagent-chatforward-browser.service": "active",
			"workagent-chatforward.service":         "inactive",
		},
		checked: &checked,
	}
	if err := ensureReleaseFleetStopped(context.Background(), config.Portal{}, nil, release.ScopeShared, controller); err == nil {
		t.Fatal("active ChatForward browser was accepted during shared release activation")
	}
	if len(checked) != 1 || checked[0] != "workagent-chatforward-browser.service" {
		t.Fatalf("ChatForward drain check did not start with the browser: %#v", checked)
	}

	checked = checked[:0]
	controller.states["workagent-chatforward-browser.service"] = "inactive"
	controller.states["workagent-chatforward.service"] = "inactive"
	if err := ensureReleaseFleetStopped(context.Background(), config.Portal{}, nil, release.ScopeShared, controller); err != nil {
		t.Fatalf("stopped ChatForward services were rejected: %v", err)
	}
	want := []string{"workagent-chatforward-browser.service", "workagent-chatforward.service"}
	if len(checked) != len(want) || checked[0] != want[0] || checked[1] != want[1] {
		t.Fatalf("unexpected ChatForward drain order: got %#v want %#v", checked, want)
	}
}
