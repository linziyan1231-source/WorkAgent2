package userhost

import (
	"os"
	"strings"
	"testing"
)

func TestStageRuntimeTokenCreatesPrivateOneShotFile(t *testing.T) {
	path, err := stageRuntimeToken(t.TempDir(), strings.Repeat("A", workAgentRuntimeTokenBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != strings.Repeat("A", workAgentRuntimeTokenBytes) {
		t.Fatal("staged token did not match")
	}
}

func TestStageRuntimeTokenRejectsInvalidToken(t *testing.T) {
	if _, err := stageRuntimeToken(t.TempDir(), "short"); err == nil {
		t.Fatal("invalid token was accepted")
	}
}
