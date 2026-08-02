package userhost

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
)

func TestApplyKimiModelDefaultsUpdatesOnlyAppliedStateWithoutTouchingAuth(t *testing.T) {
	rootPath := t.TempDir()
	root, err := projectfs.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, directory := range []string{"config", "config/codex", "credentials"} {
		if err := root.EnsureDirectory(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bundle := bootstrapTestBundle(t, "http://127.0.0.1:8317/v1")
	legacy := bundle.State
	legacy.KimiDefaultModel = "kimi-for-coding"
	legacy.KimiModels = []string{"kimi-for-coding", "kimi-for-coding-highspeed"}
	payload, err := encodeStrictJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFileAtomic(modelBootstrapMarkerPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	auth := []byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"cpa_AAAAAAAAAAAAAAAAAAAAAAAA"}`)
	if err := root.WriteFileAtomic(codexAuthPath, auth, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &Host{cfg: config.Tenant{TenantID: bootstrapTestTenant}, dataRoot: root}
	updated, applied, err := host.applyKimiModelDefaults()
	if err != nil || !applied {
		t.Fatalf("apply Kimi defaults: applied=%t err=%v", applied, err)
	}
	if updated.KimiDefaultModel != modelbootstrap.DefaultKimiModel || !reflect.DeepEqual(updated.KimiModels, modelbootstrap.ManagedKimiModels()) || updated.CodexKeyID != legacy.CodexKeyID || updated.KimiKeyID != legacy.KimiKeyID {
		t.Fatalf("unexpected migrated state: %+v", updated)
	}
	after, err := root.ReadFile(codexAuthPath, 64*1024)
	if err != nil || !bytes.Equal(after, auth) {
		t.Fatalf("Codex auth changed during Kimi migration: err=%v", err)
	}
	if _, applied, err := host.applyKimiModelDefaults(); err != nil || applied {
		t.Fatalf("second Kimi migration was not a no-op: applied=%t err=%v", applied, err)
	}
	marker, err := root.ReadFile(kimiModelDefaultsMarkerPath, 4096)
	if err != nil || string(marker) != kimiModelDefaultsMarkerContent {
		t.Fatalf("Kimi defaults marker mismatch: %q err=%v", marker, err)
	}
}
