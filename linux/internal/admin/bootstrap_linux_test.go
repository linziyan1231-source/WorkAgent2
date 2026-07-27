package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

func TestInitialBootstrapCreatesEnabledAdminWithoutActiveRelease(t *testing.T) {
	root := t.TempDir()
	channel := filepath.Join(root, "runtime")
	if err := os.Mkdir(channel, 0o700); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(channel, "current.json")
	portal := config.Portal{}
	tenant := config.Tenant{Release: config.TenantRelease{PointerFile: pointer}}
	infrastructureCalled := false
	verification, err := verifyTenantBootstrap(portal, tenant, func(config.Portal, config.Tenant) (TenantVerification, error) {
		infrastructureCalled = true
		return TenantVerification{RuntimeUID: 2001, PortalUID: 1001}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !infrastructureCalled || verification.RuntimeUID != 2001 || verification.Release.Manifest.ReleaseID != "" {
		t.Fatalf("bootstrap verification unexpectedly resolved a release: %+v", verification)
	}

	state := filepath.Join(root, "portal")
	data, err := store.Open(filepath.Join(state, "portal.db"), filepath.Join(state, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword([]byte("a sufficiently long bootstrap password"))
	if err != nil {
		data.Close()
		t.Fatal(err)
	}
	const tenantID = "11111111-1111-4111-8111-111111111111"
	created, err := data.CreateUser(context.Background(), "bootstrap-admin", hash, tenantID, "workagent_bootstrap", filepath.Join(root, "tenant"), true, time.Now().UTC())
	closeErr := data.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if !created.Admin || !created.Enabled {
		t.Fatalf("initial administrator is not enabled: %+v", created)
	}
	if _, err := os.Lstat(pointer); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap identity creation published or aliased a runtime pointer: %v", err)
	}
}

func TestInitialBootstrapRejectsAnyExistingPointerInode(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			channel := t.TempDir()
			pointer := filepath.Join(channel, "current.json")
			if kind == "file" {
				if err := os.WriteFile(pointer, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink("missing", pointer); err != nil {
				t.Fatal(err)
			}
			called := false
			_, err := verifyTenantBootstrap(config.Portal{}, config.Tenant{Release: config.TenantRelease{PointerFile: pointer}}, func(config.Portal, config.Tenant) (TenantVerification, error) {
				called = true
				return TenantVerification{}, nil
			})
			if err == nil || called {
				t.Fatalf("existing %s pointer was accepted: called=%v err=%v", kind, called, err)
			}
		})
	}
}

func TestInitialBootstrapRejectsUnsafeOrMissingChannelParent(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, pointer := range []string{filepath.Join(unsafe, "current.json"), filepath.Join(root, "missing", "current.json")} {
		if err := RequireInitialReleasePointerAbsent(pointer); err == nil {
			t.Fatalf("unsafe initial channel was accepted: %s", pointer)
		}
	}
}
