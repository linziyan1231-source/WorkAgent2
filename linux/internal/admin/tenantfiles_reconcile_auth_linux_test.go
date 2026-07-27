//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"testing"
)

type tenantReconcileAuthenticationGuard struct {
	closed bool
}

func (guard *tenantReconcileAuthenticationGuard) Close() error {
	guard.closed = true
	return nil
}

func TestTenantFileReconcilerAuthenticatesInsideLocksBeforePortalRead(t *testing.T) {
	sentinel := errors.New("running executable is not current signed control")
	guard := &tenantReconcileAuthenticationGuard{}
	acquired := false
	authenticated := false

	_, err := reconcileTenantFilesWithAuthentication(
		context.Background(),
		"/path/that/must/not/be-read/portal.json",
		nil,
		func(context.Context) (io.Closer, error) {
			acquired = true
			return guard, nil
		},
		func() error {
			authenticated = true
			if !acquired || guard.closed {
				t.Fatal("running executable authentication did not execute inside the catalog/control guard lifetime")
			}
			return sentinel
		},
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("authentication failure did not precede Portal configuration access: %v", err)
	}
	if !authenticated || !guard.closed {
		t.Fatalf("authenticated=%t guardClosed=%t, want authentication followed by guard release", authenticated, guard.closed)
	}
}

func TestTenantFileReconcilerRejectsMissingAuthenticatorBeforeLockAcquisition(t *testing.T) {
	acquired := false
	_, err := reconcileTenantFilesWithAuthentication(
		context.Background(),
		"/etc/workagent/portal.json",
		nil,
		func(context.Context) (io.Closer, error) {
			acquired = true
			return &tenantReconcileAuthenticationGuard{}, nil
		},
		nil,
	)
	if err == nil || acquired {
		t.Fatalf("missing authenticator was not rejected before mutation lock acquisition: acquired=%t err=%v", acquired, err)
	}
}
