package main

import "testing"

func TestQuiesceJournalAcceptsOnlyCanonicalWorkAgentUnits(t *testing.T) {
	valid := quiesceJournal{SchemaVersion: 1, Units: []string{
		"workagent-portal.service",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.socket",
		"workagent-userhost@11111111-1111-4111-8111-111111111111.service",
		"cliproxyapi.service",
	}}
	if err := validateQuiesceJournal(valid); err != nil {
		t.Fatalf("valid recovery journal rejected: %v", err)
	}
	for _, units := range [][]string{
		{"ssh.service"},
		{"workagent-userhost@../escape.service"},
		{"workagent-portal.service", "workagent-portal.service"},
	} {
		if err := validateQuiesceJournal(quiesceJournal{SchemaVersion: 1, Units: units}); err == nil {
			t.Fatalf("unsafe recovery journal accepted: %v", units)
		}
	}
}

func TestParseQuiesceUnitStateRejectsTransitionsAndResidualProcesses(t *testing.T) {
	activeService := "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nControlPID=0\n"
	activeSocket := "LoadState=loaded\nActiveState=active\nSubState=listening\nMainPID=0\nControlPID=0\n"
	inactive := "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n"
	for unit, payload := range map[string]string{
		"workagent-portal.service":                                       activeService,
		"workagent-userhost@11111111-1111-4111-8111-111111111111.socket": activeSocket,
	} {
		active, err := parseQuiesceUnitState(unit, payload)
		if err != nil || !active {
			t.Fatalf("active %s rejected: active=%v err=%v", unit, active, err)
		}
	}
	if active, err := parseQuiesceUnitState("cliproxyapi.service", inactive); err != nil || active {
		t.Fatalf("inactive unit state rejected: active=%v err=%v", active, err)
	}
	for name, payload := range map[string]string{
		"transition":          "LoadState=loaded\nActiveState=activating\nSubState=start\nMainPID=0\nControlPID=43\n",
		"service without pid": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\nControlPID=0\n",
		"inactive residual":   "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=42\nControlPID=0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseQuiesceUnitState("workagent-portal.service", payload); err == nil {
				t.Fatal("unsafe unit state was accepted")
			}
		})
	}
}
