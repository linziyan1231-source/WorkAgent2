package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

// RequireInitialReleasePointerAbsent is the explicit boundary used while
// building the durable Portal/tenant state before the first runtime release is
// activated.  A missing pointer is accepted only beside an existing, real,
// non-writable-by-untrusted-users channel directory.
func RequireInitialReleasePointerAbsent(pointerPath string) error {
	if pointerPath == "" || !filepath.IsAbs(pointerPath) || filepath.Clean(pointerPath) != pointerPath || filepath.Base(pointerPath) != "current.json" {
		return errors.New("initial bootstrap release pointer path is invalid")
	}
	parent := filepath.Dir(pointerPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect initial bootstrap release channel: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("initial bootstrap release channel directory is unsafe")
	}
	if _, err := os.Lstat(pointerPath); err == nil {
		return errors.New("initial bootstrap requires no active release pointer")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect initial bootstrap release pointer: %w", err)
	}
	return nil
}

// VerifyTenantBootstrap validates everything that can be trusted before the
// first pointer exists.  It deliberately does not resolve or execute a runtime
// release; candidate admission remains the release preflight's responsibility.
// Production callers hold the catalog lifecycle lock shared across this check
// and any bootstrap state commit so activation cannot publish the pointer.
func VerifyTenantBootstrap(portal config.Portal, tenant config.Tenant) (TenantVerification, error) {
	return verifyTenantBootstrap(portal, tenant, VerifyTenantInfrastructure)
}

func verifyTenantBootstrap(portal config.Portal, tenant config.Tenant, verifyInfrastructure func(config.Portal, config.Tenant) (TenantVerification, error)) (TenantVerification, error) {
	if verifyInfrastructure == nil {
		return TenantVerification{}, errors.New("tenant bootstrap infrastructure verifier is required")
	}
	if err := RequireInitialReleasePointerAbsent(tenant.Release.PointerFile); err != nil {
		return TenantVerification{}, err
	}
	return verifyInfrastructure(portal, tenant)
}
