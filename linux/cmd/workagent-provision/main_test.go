package main

import "testing"

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
