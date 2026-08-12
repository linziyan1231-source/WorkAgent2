package userhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSharedManifestHonorsContentHashSwitch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.txt")
	if err := os.WriteFile(path, []byte("shared-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	hashed, err := buildSharedManifest(context.Background(), root, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashed) != 1 || hashed[0].SHA256 == ([32]byte{}) {
		t.Fatalf("hash-enabled manifest did not record content digests: %+v", hashed)
	}
	metadataOnly, err := buildSharedManifest(context.Background(), root, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadataOnly) != 1 || metadataOnly[0].SHA256 != ([32]byte{}) || metadataOnly[0].Size != int64(len("shared-content")) {
		t.Fatalf("hash-disabled manifest did not record metadata only: %+v", metadataOnly)
	}
	// With hashing disabled, same-size content changes no longer affect the
	// comparison: intranet mode gives up concurrent-modification detection.
	if err := os.WriteFile(path, []byte("shared-CHANGED"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := buildSharedManifest(context.Background(), root, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSharedManifest(metadataOnly, changed) {
		t.Fatal("metadata-only manifests differed after a same-size content change")
	}
	if err := os.WriteFile(path, []byte("longer shared content"), 0o600); err != nil {
		t.Fatal(err)
	}
	resized, err := buildSharedManifest(context.Background(), root, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if sameSharedManifest(metadataOnly, resized) {
		t.Fatal("metadata-only manifests ignored a size change")
	}
}
