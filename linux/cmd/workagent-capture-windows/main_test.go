//go:build linux

package main

import "testing"

func TestParseArgumentsAcceptsOnlyCompleteExclusiveModes(t *testing.T) {
	id := "cutover-20260727t120000z"
	valid := [][]string{
		{"--check", "--spec", "/root/private/spec.json", "--rehearsal-id", "rehearsal-20260727-0001", "--receipt-output", "/root/private/receipt-1.json", "--writers-quiesced", "--confirm", "REHEARSAL-WRITERS-QUIESCED:rehearsal-20260727-0001"},
		{"--seal-rehearsal-gate", "--spec", "/root/private/spec.json", "--rehearsal-receipt", "/root/private/receipt-1.json", "--rehearsal-receipt", "/root/private/receipt-2.json", "--rehearsal-receipt", "/root/private/receipt-3.json", "--gate-output", "/root/private/gate.json"},
		{"--capture", "--spec", "/root/private/spec.json", "--rehearsal-gate", "/root/private/gate.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen", "--confirm", "FINAL-WINDOWS-CAPTURE:" + id},
		{"--verify-final-delta", "--spec", "/root/private/spec.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen", "--confirm", "FINAL-WINDOWS-DELTA:" + id},
		{"--init-spec", "--legacy-snapshot", "/root/private/legacy", "--migration-report", "/root/private/report.json", "--spec-output", "/root/private/spec.json"},
	}
	for index, arguments := range valid {
		if _, err := parseArguments(arguments); err != nil {
			t.Fatalf("valid mode %d rejected: %v", index, err)
		}
	}

	invalid := [][]string{
		nil,
		{"--check", "--capture", "--spec", "/root/private/spec.json"},
		{"--check", "--spec", "/root/private/spec.json", "trailing"},
		{"--check"},
		{"--check", "--spec", "/root/private/spec.json", "--rehearsal-id", "rehearsal-20260727-0001", "--receipt-output", "/root/private/receipt-1.json"},
		{"--check", "--spec", "/root/private/spec.json", "--destination", "/root/private/capture"},
		{"--seal-rehearsal-gate", "--rehearsal-receipt", "/root/private/receipt-1.json", "--gate-output", "/root/private/gate.json"},
		{"--seal-rehearsal-gate", "--rehearsal-receipt", "/root/private/receipt-1.json", "--rehearsal-receipt", "/root/private/receipt-2.json", "--rehearsal-receipt", "/root/private/receipt-3.json", "--gate-output", "/root/private/gate.json"},
		{"--capture", "--spec", "/root/private/spec.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen"},
		{"--capture", "--spec", "/root/private/spec.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen", "--confirm", "FINAL-WINDOWS-DELTA:" + id},
		{"--verify-final-delta", "--spec", "/root/private/spec.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen"},
		{"--verify-final-delta", "--spec", "/root/private/spec.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen", "--confirm", "FINAL-WINDOWS-CAPTURE:" + id},
		{"--verify-final-delta", "--spec", "/root/private/spec.json", "--destination", "/root/private/" + id, "--capture-id", id, "--windows-frozen", "--confirm", "FINAL-WINDOWS-DELTA:" + id, "--migration-report", "/root/private/report.json"},
		{"--init-spec", "--legacy-snapshot", "/root/private/legacy", "--migration-report", "/root/private/report.json"},
		{"--unknown"},
	}
	for index, arguments := range invalid {
		if _, err := parseArguments(arguments); err == nil {
			t.Fatalf("invalid mode %d accepted: %#v", index, arguments)
		}
	}
}
