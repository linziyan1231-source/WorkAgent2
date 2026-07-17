package modelbootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func realBundle() Bundle {
	return Bundle{State: State{FormatVersion: 1, BaseURL: "http://203.0.113.52:8317/v1", CodexKeyID: "aionui-0123456789abcdef-chatgpt",
		KimiKeyID: "aionui-0123456789abcdef-kimi", CodexDefaultModel: "example-reasoning", CodexModels: []string{"example-reasoning", "gpt-5.4-mini"}, KimiModels: ManagedKimiModels()},
		CodexAPIKey: "cpa_abcdefghijklmnopqrstuvwxyz012345", KimiAPIKey: "cpa_zyxwvutsrqponmlkjihgfedcba987654"}
}

func TestStageInspectLoadAndCompleteRealShapedBootstrap(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"credentials", "config"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := realBundle()
	if err := Stage(root, bundle, false); err != nil {
		t.Fatal(err)
	}
	status, err := Inspect(root)
	if err != nil || !status.Pending || status.Applied {
		t.Fatalf("unexpected pending status: %+v err=%v", status, err)
	}
	loaded, found, err := LoadPending(root)
	if err != nil || !found || !reflect.DeepEqual(loaded, bundle) {
		t.Fatalf("unexpected pending bundle: found=%t bundle=%+v err=%v", found, loaded, err)
	}
	if err := Complete(root, bundle.State); err != nil {
		t.Fatal(err)
	}
	status, err = Inspect(root)
	if err != nil || !status.Applied || status.Pending || !reflect.DeepEqual(status.State, bundle.State) {
		t.Fatalf("unexpected applied status: %+v err=%v", status, err)
	}
	if _, err := os.Stat(filepath.Join(root, "credentials", BundleFileName)); !os.IsNotExist(err) {
		t.Fatal("one-time key bundle still exists after completion")
	}
}

func TestValidationRejectsSharedOrMalformedCredentials(t *testing.T) {
	tests := []func(*Bundle){
		func(bundle *Bundle) { bundle.BaseURL = "http://203.0.113.52:8317/v1/" },
		func(bundle *Bundle) { bundle.KimiKeyID = bundle.CodexKeyID },
		func(bundle *Bundle) { bundle.KimiAPIKey = bundle.CodexAPIKey },
		func(bundle *Bundle) { bundle.CodexModels = append(bundle.CodexModels, "example-reasoning") },
		func(bundle *Bundle) { bundle.CodexDefaultModel = "not-allowed" },
		func(bundle *Bundle) { bundle.KimiModels = []string{"kimi-for-coding"} },
		func(bundle *Bundle) { bundle.KimiModels = append(bundle.KimiModels, "kimi-other") },
	}
	for index, mutate := range tests {
		bundle := realBundle()
		mutate(&bundle)
		if err := bundle.Validate(); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}

func TestManagedModelPolicyIsExactAndReturnsCopies(t *testing.T) {
	codex := ManagedCodexModels()
	kimi := ManagedKimiModels()
	if !reflect.DeepEqual(codex, []string{"example-reasoning", "example-balanced", "example-fast"}) || !reflect.DeepEqual(kimi, []string{"kimi-for-coding", "kimi-for-coding-highspeed", "kimi-k3"}) {
		t.Fatalf("unexpected managed model policy: codex=%v kimi=%v", codex, kimi)
	}
	codex[0] = "changed"
	if ManagedCodexModels()[0] != "example-reasoning" {
		t.Fatal("managed model policy leaked mutable storage")
	}
}

func TestKeyIDsAreStableAndBoundToUppercaseSID(t *testing.T) {
	const sid = "S-1-5-21-1335169958-1819941586-1322872941-1322"
	want := KeyIDs{CodexKeyID: "aionui-c6caa7a66c7a1ad24ed9-chatgpt", KimiKeyID: "aionui-c6caa7a66c7a1ad24ed9-kimi"}
	if got := KeyIDsForSID(sid); got != want {
		t.Fatalf("key IDs=%+v, want %+v", got, want)
	}
	if got := KeyIDsForSID("S-1-5-21-1335169958-1819941586-1322872941-1322"); got != want {
		t.Fatalf("lowercase SID derived different key IDs: %+v", got)
	}
	if err := want.ValidateForSID(sid); err != nil {
		t.Fatal(err)
	}
	other := KeyIDsForSID("S-1-5-21-1836781275-1957422218-1832856846-7828")
	if err := other.ValidateForSID(sid); err == nil {
		t.Fatal("another user's well-formed key IDs matched this SID")
	}
}

func TestAppliedKeyIDsReadsOnlySIDBoundAppliedMarker(t *testing.T) {
	const sid = "S-1-5-21-1335169958-1819941586-1322872941-1322"
	root := t.TempDir()
	ids := KeyIDsForSID(sid)
	state := realBundle().State
	state.CodexKeyID = ids.CodexKeyID
	state.KimiKeyID = ids.KimiKeyID
	bundlePath, markerPath, err := Paths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Dir(bundlePath), filepath.Dir(markerPath)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte(`{"codex_api_key":"cpa_must-not-be-read"`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := AppliedKeyIDs(root, sid)
	if err != nil || got != ids {
		t.Fatalf("marker-only key lookup failed: ids=%+v err=%v", got, err)
	}
	if _, err := AppliedKeyIDs(root, "S-1-5-21-1988320210-1174886911-1684912000-8042"); err == nil {
		t.Fatal("marker key IDs were accepted for another Windows SID")
	}
}
