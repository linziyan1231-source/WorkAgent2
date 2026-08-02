//go:build linux

package edgepublication

import (
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func TestEdgePublicationRequiresSignedBindingAndFullReadiness(t *testing.T) {
	portal := config.Portal{Listener: config.Listener{Address: productionPortalAddress, PublicOrigin: productionPortalPublicOrigin}}
	if err := ValidateProductionPortalEdgeBinding(portal); err != nil {
		t.Fatal(err)
	}
	portal.Listener.PublicOrigin = "https://foreign.example.test"
	if err := ValidateProductionPortalEdgeBinding(portal); err == nil {
		t.Fatal("Portal origin not represented by the signed Caddyfile was accepted")
	}
	now := time.Now().UTC()
	components := map[string]ReadinessComponent{}
	for _, name := range []string{"audit", "brand", "chat_forward", "cli_proxy", "database", "host", "notifications", "policy", "renderer", "tenants"} {
		components[name] = ReadinessComponent{Ready: true}
	}
	report := ReadinessReport{Status: "ready", Ready: true, CheckedAt: now, PolicyID: "policy", BrandID: "brand", Components: components}
	if err := ValidateReadinessReport(report, now, "policy", "brand"); err != nil {
		t.Fatal(err)
	}
	components["cli_proxy"] = ReadinessComponent{}
	if err := ValidateReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("unready dependency was accepted for edge publication")
	}
	components["cli_proxy"] = ReadinessComponent{Ready: true}
	report.CheckedAt = now.Add(-time.Minute)
	if err := ValidateReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("stale readiness evidence was accepted for edge publication")
	}
	report.CheckedAt = now
	components["foreign"] = ReadinessComponent{Ready: true}
	if err := ValidateReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("unexpected readiness component set was accepted")
	}
	delete(components, "foreign")
	report.PolicyID = "foreign-policy"
	if err := ValidateReadinessReport(report, now, "policy", "brand"); err == nil {
		t.Fatal("readiness from a different protected policy was accepted")
	}
}
