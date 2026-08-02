package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialProvisionCannotStartRuntime(t *testing.T) {
	if err := validateProvisionActivationMode(true, true); err == nil {
		t.Fatal("initial provisioning accepted --start")
	}
	for _, value := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		if err := validateProvisionActivationMode(value[0], value[1]); err != nil {
			t.Fatalf("valid provisioning mode initial=%v start=%v rejected: %v", value[0], value[1], err)
		}
	}
}

func TestNewProvisionCannotStartBeforePortalIdentityExists(t *testing.T) {
	if err := validateProvisionExistingActivation(false, true); err == nil {
		t.Fatal("new tenant provisioning accepted --start before a Portal identity can exist")
	}
	for _, value := range [][2]bool{{false, false}, {true, false}, {true, true}} {
		if err := validateProvisionExistingActivation(value[0], value[1]); err != nil {
			t.Fatalf("valid existing/start state reconciling=%v start=%v rejected: %v", value[0], value[1], err)
		}
	}
}

func TestNextProjectIDReservesCrashRecoveryPendingRecords(t *testing.T) {
	tenantDirectory := filepath.Join(t.TempDir(), "tenants")
	pendingDirectory := filepath.Join(t.TempDir(), "pending")
	if err := os.Mkdir(tenantDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pendingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(pendingProvision{SchemaVersion: 1, UsernameNorm: "alice", TenantID: "tenant", RuntimeUser: "runtime", ProjectID: firstTenantProjectID, Phase: "allocated"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDirectory, "alice.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	projectID, err := nextProjectID(tenantDirectory, pendingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if projectID != firstTenantProjectID+1 {
		t.Fatalf("project ID reused a pending allocation: got %d", projectID)
	}
}
