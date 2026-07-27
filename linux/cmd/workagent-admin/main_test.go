package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/auth"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/store"
)

func TestVerifyTenantQuiescenceIsExplicitStartupOnlyMode(t *testing.T) {
	const runtimeUID = 2001
	options, err := parseVerifyTenantOptions([]string{"--config", "/etc/workagent/portal.json", "--tenant-id", "tenant-one"})
	if err != nil {
		t.Fatal(err)
	}
	if options.requireQuiescent {
		t.Fatal("ordinary online verify-tenant unexpectedly requires an empty runtime UID")
	}
	called := 0
	sentinel := errors.New("residual process")
	check := func(uid uint32) error {
		called++
		if uid != runtimeUID {
			t.Fatalf("runtime UID=%d want %d", uid, runtimeUID)
		}
		return sentinel
	}
	if err := verifyTenantQuiescence(runtimeUID, options.requireQuiescent, check); err != nil || called != 0 {
		t.Fatalf("ordinary online verification invoked quiescence check: calls=%d err=%v", called, err)
	}

	options, err = parseVerifyTenantOptions([]string{"--tenant-id", "tenant-one", "--require-quiescent"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.requireQuiescent {
		t.Fatal("startup verify-tenant mode did not require runtime UID quiescence")
	}
	if err := verifyTenantQuiescence(runtimeUID, options.requireQuiescent, check); !errors.Is(err, sentinel) || called != 1 {
		t.Fatalf("startup verification did not fail closed through the quiescence check: calls=%d err=%v", called, err)
	}
}

type recordingSystemd struct {
	actions [][]string
}

func (r *recordingSystemd) Properties(context.Context, string, ...string) (map[string]string, error) {
	return nil, nil
}

func (r *recordingSystemd) Action(_ context.Context, arguments ...string) error {
	r.actions = append(r.actions, append([]string(nil), arguments...))
	return nil
}

func TestDisableUserRevokesIdentityBeforeStoppingRuntime(t *testing.T) {
	root := t.TempDir()
	portal := config.Portal{Paths: config.PortalPaths{PortalState: filepath.Join(root, "state")}}
	data, err := store.Open(filepath.Join(root, "state", "portal.db"), filepath.Join(root, "state", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	hash, err := auth.HashPassword([]byte("a sufficiently long password"))
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "11111111-1111-4111-8111-111111111111"
	if _, err := data.CreateUser(context.Background(), "alice", hash, tenantID, "workagent_alice", filepath.Join(root, "tenant"), false, time.Now()); err != nil {
		t.Fatal(err)
	}
	controller := &recordingSystemd{}
	if err := applyUserEnabledState(context.Background(), portal, data, "alice", false, controller); err != nil {
		t.Fatal(err)
	}
	userValue, err := data.UserByUsername(context.Background(), "alice")
	if err != nil || userValue.Enabled {
		t.Fatalf("user remains enabled: %+v err=%v", userValue, err)
	}
	want := [][]string{{"disable", "--now", "workagent-userhost@" + tenantID + ".socket"}, {"stop", "workagent-userhost@" + tenantID + ".service"}}
	if !reflect.DeepEqual(controller.actions, want) {
		t.Fatalf("actions=%v want=%v", controller.actions, want)
	}
}
