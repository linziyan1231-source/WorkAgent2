package userhost

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aionuiportal/internal/config"
	"aionuiportal/internal/ipc"
	"aionuiportal/internal/modelbootstrap"
)

const modelKeyIDsTestSID = "S-1-5-21-100-200-300-1017"

func TestModelKeyIDsIPCReadsOnlyAppliedSIDBoundMarker(t *testing.T) {
	root := t.TempDir()
	state := modelKeyIDsTestState(modelKeyIDsTestSID)
	writeModelKeyIDsMarker(t, root, state)
	host := Host{cfg: config.UserHost{WindowsSID: modelKeyIDsTestSID, DataRoot: root}}

	response := host.handleIPC(context.Background(), ipc.Request{Command: "model_key_ids"})
	if !response.OK || response.ModelKeyIDs == nil {
		t.Fatalf("valid applied marker failed: %+v", response)
	}
	if response.ModelKeyIDs.CodexKeyID != state.CodexKeyID || response.ModelKeyIDs.KimiKeyID != state.KimiKeyID {
		t.Fatalf("wrong key IDs: %+v", response.ModelKeyIDs)
	}
	encoded, err := json.Marshal(response.ModelKeyIDs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "base_url") || strings.Contains(string(encoded), "models") {
		t.Fatalf("IPC exposed unrelated marker fields: %s", encoded)
	}
}

func TestModelKeyIDsIPCRejectsUnavailableOrInvalidMarkers(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T, string)
		wantCode string
	}{
		{name: "missing", setup: func(*testing.T, string) {}, wantCode: "MODEL_MARKER_MISSING"},
		{name: "corrupt", setup: func(t *testing.T, root string) {
			writeModelKeyIDsMarkerBytes(t, root, []byte(`{"format_version":`))
		}, wantCode: "MODEL_MARKER_INVALID"},
		{name: "unknown field", setup: func(t *testing.T, root string) {
			state := modelKeyIDsTestState(modelKeyIDsTestSID)
			encoded, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)
			writeModelKeyIDsMarkerBytes(t, root, encoded)
		}, wantCode: "MODEL_MARKER_INVALID"},
		{name: "duplicate IDs", setup: func(t *testing.T, root string) {
			state := modelKeyIDsTestState(modelKeyIDsTestSID)
			state.KimiKeyID = state.CodexKeyID
			writeModelKeyIDsMarker(t, root, state)
		}, wantCode: "MODEL_MARKER_INVALID"},
		{name: "illegal ID", setup: func(t *testing.T, root string) {
			state := modelKeyIDsTestState(modelKeyIDsTestSID)
			state.CodexKeyID = "not valid!"
			writeModelKeyIDsMarker(t, root, state)
		}, wantCode: "MODEL_MARKER_INVALID"},
		{name: "another user IDs", setup: func(t *testing.T, root string) {
			state := modelKeyIDsTestState("S-1-5-21-100-200-300-1018")
			writeModelKeyIDsMarker(t, root, state)
		}, wantCode: "MODEL_MARKER_INVALID"},
		{name: "pending only", setup: func(t *testing.T, root string) {
			for _, directory := range []string{"config", "credentials"} {
				if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			bundle := modelbootstrap.Bundle{State: modelKeyIDsTestState(modelKeyIDsTestSID),
				CodexAPIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", KimiAPIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654"}
			if err := modelbootstrap.Stage(root, bundle, false); err != nil {
				t.Fatal(err)
			}
		}, wantCode: "MODEL_MARKER_MISSING"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.setup(t, root)
			host := Host{cfg: config.UserHost{WindowsSID: modelKeyIDsTestSID, DataRoot: root}}
			response := host.handleIPC(context.Background(), ipc.Request{Command: "model_key_ids"})
			if response.OK || response.ModelKeyIDs != nil || response.ErrorCode != test.wantCode {
				t.Fatalf("invalid marker response=%+v, want code %s", response, test.wantCode)
			}
		})
	}
}

func modelKeyIDsTestState(sid string) modelbootstrap.State {
	ids := modelbootstrap.KeyIDsForSID(sid)
	return modelbootstrap.State{FormatVersion: modelbootstrap.FormatVersion, BaseURL: "http://43.134.118.158:8317/v1",
		CodexKeyID: ids.CodexKeyID, KimiKeyID: ids.KimiKeyID, CodexDefaultModel: "gpt-5.6-luna",
		CodexModels: []string{"gpt-5.6-luna", "gpt-5.4-mini"}, KimiModels: modelbootstrap.ManagedKimiModels()}
}

func writeModelKeyIDsMarker(t *testing.T, root string, state modelbootstrap.State) {
	t.Helper()
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	writeModelKeyIDsMarkerBytes(t, root, encoded)
}

func writeModelKeyIDsMarkerBytes(t *testing.T, root string, encoded []byte) {
	t.Helper()
	directory := filepath.Join(root, "config")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, modelbootstrap.MarkerFileName), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
