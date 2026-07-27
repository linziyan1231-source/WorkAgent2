package admin

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/posixacl"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/release"
)

type TenantVerification struct {
	RuntimeUID uint32
	PortalUID  uint32
	Release    release.Verified
}

func ValidateTenantBinding(portal config.Portal, tenant config.Tenant) error {
	if err := portal.Validate(); err != nil {
		return err
	}
	if err := tenant.Validate(); err != nil {
		return err
	}
	if tenant.DataRoot != filepath.Join(portal.Paths.TenantData, tenant.TenantID) {
		return errors.New("tenant data_root does not match the Portal tenant-data root")
	}
	if tenant.SocketPath != filepath.Join(portal.Paths.RuntimeSockets, tenant.TenantID+".sock") {
		return errors.New("tenant socket_path does not match the Portal runtime-socket root")
	}
	if strings.TrimSuffix(tenant.PortalOrigin, "/") != strings.TrimSuffix(portal.Listener.PublicOrigin, "/") {
		return errors.New("tenant portal_origin does not match the Portal public origin")
	}
	if tenant.OutboundProxyURL != portal.OutboundProxyURL {
		return errors.New("tenant outbound_proxy_url does not match the Portal policy")
	}
	if tenant.Capacity.MaxInstances != portal.Runtime.MaxConcurrentInstances {
		return errors.New("tenant capacity maximum does not match the Portal policy")
	}
	if !pathWithin(portal.Paths.ReleaseRoot, tenant.Release.ReleasesRoot) {
		return errors.New("tenant release channel is outside the Portal release root")
	}
	if portal.Renderer.Configured() && (tenant.Release.ReleasesRoot != portal.Renderer.ReleasesRoot ||
		tenant.Release.PointerFile != portal.Renderer.PointerFile ||
		tenant.Release.PublicKeyFile != portal.Renderer.PublicKeyFile ||
		tenant.Release.Scope != portal.Renderer.Scope) {
		return errors.New("tenant release channel does not match the Portal Renderer channel")
	}
	return nil
}

func VerifyTenantHost(portal config.Portal, tenant config.Tenant) (TenantVerification, error) {
	verification, err := VerifyTenantInfrastructure(portal, tenant)
	if err != nil {
		return TenantVerification{}, err
	}
	required := append([]string(nil), tenant.Backend.RequiredReleaseFiles...)
	requiredExecutables := []string{tenant.Backend.Executable}
	if tenant.Backend.Migration.Enabled {
		requiredExecutables = append(requiredExecutables, tenant.Backend.Migration.Executable)
	}
	if tenant.Backend.AgentCLI.BinDirectory != "" {
		requiredExecutables = append(requiredExecutables, tenant.Backend.AgentCLI.CodexExecutable, tenant.Backend.AgentCLI.KimiExecutable, tenant.Backend.AgentCLI.PythonExecutable)
	}
	verified, err := release.ResolveActive(tenant.Release.ReleasesRoot, tenant.Release.PointerFile, tenant.Release.PublicKeyFile, release.ResolveOptions{
		Scope: tenant.Release.Scope, RequiredPaths: required, RequiredExecutablePaths: requiredExecutables, RequireRootOwner: true,
	})
	if err != nil {
		return TenantVerification{}, err
	}
	verification.Release = verified
	return verification, nil
}

// VerifyTenantInfrastructure validates the durable host identity, storage and
// quota contract without resolving an active release. It is the bootstrap-safe
// portion of VerifyTenantHost used before the first signed pointer exists.
func VerifyTenantInfrastructure(portal config.Portal, tenant config.Tenant) (TenantVerification, error) {
	if err := ValidateTenantBinding(portal, tenant); err != nil {
		return TenantVerification{}, err
	}
	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return TenantVerification{}, fmt.Errorf("lookup Portal account: %w", err)
	}
	portalUID, err := parseUID(portalAccount.Uid)
	if err != nil || portalUID == 0 || tenant.PortalUID != portalUID {
		return TenantVerification{}, errors.New("tenant Portal UID does not match the configured Portal account")
	}
	runtimeAccount, err := VerifyRuntimeAccount(tenant, RuntimeAccountVerificationOptions{RequireSlotGroup: true})
	if err != nil {
		return TenantVerification{}, err
	}
	runtimeUID := runtimeAccount.UID
	if runtimeUID == portalUID {
		return TenantVerification{}, errors.New("tenant runtime UID is invalid or shared with the Portal")
	}
	info, err := os.Lstat(tenant.DataRoot)
	if err != nil {
		return TenantVerification{}, fmt.Errorf("inspect tenant data root: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != runtimeUID || stat.Gid != runtimeAccount.GID || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return TenantVerification{}, errors.New("tenant data root must be a real 0700 directory owned by its runtime UID")
	}
	if portal.Runtime.RequireProjectQuota {
		if tenant.Capacity.ProjectID == 0 || tenant.Capacity.DiskHardLimitBytes == 0 {
			return TenantVerification{}, errors.New("tenant project quota is not configured")
		}
		if _, err := hostcheck.VerifyTenantQuota(tenant.DataRoot, tenant.Capacity.ProjectID, tenant.Capacity.DiskHardLimitBytes); err != nil {
			return TenantVerification{}, fmt.Errorf("verify tenant project quota: %w", err)
		}
	}
	return TenantVerification{RuntimeUID: runtimeUID, PortalUID: portalUID}, nil
}

func VerifyTenantConfigPath(portal config.Portal, tenant config.Tenant, path string) error {
	expected := filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json")
	if path != expected {
		return errors.New("tenant configuration filename is not canonical")
	}
	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return fmt.Errorf("lookup Portal account for tenant configuration: %w", err)
	}
	portalGID, err := parseUID(portalAccount.Gid)
	if err != nil || portalGID == 0 {
		return errors.New("Portal group for tenant configuration is invalid")
	}
	return verifyTenantConfigAccess(tenant, path, portal.Paths.TenantConfigs, portalGID)
}

// VerifyRuntimeTenantConfigPath lets UserHost independently enforce its
// canonical root-managed configuration and exclusive named-user ACL even when
// it is started outside the normal ExecStartPre verification sequence.
func VerifyRuntimeTenantConfigPath(tenant config.Tenant, path string) error {
	const tenantConfigRoot = "/etc/workagent/users"
	expected := filepath.Join(tenantConfigRoot, tenant.TenantID+".json")
	if path != expected {
		return errors.New("runtime tenant configuration filename is not canonical")
	}
	portalAccount, err := user.LookupId(strconv.FormatUint(uint64(tenant.PortalUID), 10))
	if err != nil || portalAccount.Username != "workagent" {
		return errors.New("runtime tenant configuration Portal account is invalid")
	}
	portalGID, err := parseUID(portalAccount.Gid)
	if err != nil || portalGID == 0 {
		return errors.New("runtime tenant configuration Portal group is invalid")
	}
	return verifyTenantConfigAccess(tenant, path, tenantConfigRoot, portalGID)
}

func verifyTenantConfigAccess(tenant config.Tenant, path, tenantConfigRoot string, portalGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != portalGID || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
		return errors.New("tenant configuration must be a root-owned, Portal-group 0640 regular file")
	}
	runtimeAccount, err := user.Lookup(tenant.RuntimeUser)
	if err != nil {
		return fmt.Errorf("lookup runtime account for tenant configuration: %w", err)
	}
	runtimeUID, err := parseUID(runtimeAccount.Uid)
	if err != nil || runtimeUID == 0 {
		return errors.New("tenant runtime UID is invalid")
	}
	if err := posixacl.VerifyExclusiveUserPermissions(path, runtimeUID, 0o4); err != nil {
		return fmt.Errorf("tenant configuration ACL is not restricted to its runtime account: %w", err)
	}
	for _, directory := range []string{filepath.Dir(tenantConfigRoot), tenantConfigRoot} {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect tenant configuration directory %s: %w", directory, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("tenant configuration directory is unsafe: %s", directory)
		}
		permission, err := posixacl.UserPermissions(directory, runtimeUID)
		if err != nil || permission.Perm() != 0o1 {
			return fmt.Errorf("tenant configuration directory ACL does not grant execute-only runtime access on %s: %w", directory, err)
		}
	}
	return nil
}

func parseUID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
