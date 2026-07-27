package main

import "testing"

func TestSyntheticFixtureAcceptsProductionAionUiStartContract(t *testing.T) {
	address, err := parseListenAddress([]string{"start", "--port", "43123", "--data-dir", "/tmp/data", "--work-dir", "/tmp/workspace", "--log-dir", "/tmp/logs", "--static-dir", "/tmp/static", "--backend-bin", "/tmp/aioncore", "--no-open"})
	if err != nil || address != "127.0.0.1:43123" {
		t.Fatalf("address=%q err=%v", address, err)
	}
}
