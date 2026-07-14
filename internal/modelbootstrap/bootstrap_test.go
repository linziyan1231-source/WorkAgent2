package modelbootstrap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func realBundle() Bundle {
	return Bundle{State: State{FormatVersion: 1, BaseURL: "http://203.0.113.52:8317/v1", CodexKeyID: "aionui-0123456789abcdef-chatgpt",
		KimiKeyID: "aionui-0123456789abcdef-kimi", CodexDefaultModel: "example-reasoning", CodexModels: []string{"example-reasoning", "gpt-5.4-mini"}, KimiModels: []string{"kimi-k2.7"}},
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
	}
	for index, mutate := range tests {
		bundle := realBundle()
		mutate(&bundle)
		if err := bundle.Validate(); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}
