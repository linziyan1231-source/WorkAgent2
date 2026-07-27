package productconfig

import "testing"

func TestPolicyDefaultsToDeny(t *testing.T) {
	valid := Policy{SchemaVersion: 1, PolicyID: "workagent-deny-all-v1", DefaultAction: "deny", Models: []Model{}, Aliases: map[string]string{}, Pricing: map[string]Price{}, Quotas: map[string]Quota{}, ApprovalRequired: true}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.DefaultAction = "allow"
	if err := valid.Validate(); err == nil {
		t.Fatal("allow-by-default policy was accepted")
	}
}

func TestBrandBaseline(t *testing.T) {
	value := Brand{SchemaVersion: 1, BrandID: "workagent", CompanyName: "WorkAgent", PlatformName: "WorkAgent2", PrimaryColor: "#EA3E00", Assets: Assets{Logo: "logo.svg", LogoDark: "logo-dark.svg", Favicon: "favicon.svg", AppIcon: "app-icon.svg"}}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	value.CompanyName = "Example Company"
	if err := value.Validate(); err == nil {
		t.Fatal("unapproved brand name was accepted")
	}
}
