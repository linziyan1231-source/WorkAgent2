package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func ResourceDropInPayload(limits config.ResourceLimits) []byte {
	limits = limits.Effective()
	return []byte(fmt.Sprintf("[Service]\nMemoryHigh=%d\nMemoryMax=%d\nCPUQuota=%d%%\nTasksMax=%d\n", limits.MemoryBytes, limits.MemoryBytes, limits.CPUPercent, limits.ActiveProcesses))
}

// WriteTenantFiles atomically publishes the root-owned tenant configuration
// and its systemd identity/resource drop-ins. The ACL is attached to the
// temporary file before rename so a published config is never unreadable by
// the tenant runtime.
func WriteTenantFiles(ctx context.Context, portal config.Portal, tenant config.Tenant) error {
	if os.Geteuid() != 0 {
		return errors.New("tenant configuration updates require root")
	}
	if err := ValidateTenantBinding(portal, tenant); err != nil {
		return err
	}
	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return err
	}
	portalGID, err := strconv.ParseUint(portalAccount.Gid, 10, 32)
	if err != nil || portalGID == 0 {
		return errors.New("Portal group is invalid")
	}
	runtimeAccount, err := user.Lookup(tenant.RuntimeUser)
	if err != nil {
		return err
	}
	runtimeUID, err := strconv.ParseUint(runtimeAccount.Uid, 10, 32)
	if err != nil || runtimeUID == 0 {
		return errors.New("tenant runtime UID is invalid")
	}
	configPath := filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json")
	for _, directory := range []string{filepath.Dir(portal.Paths.TenantConfigs), portal.Paths.TenantConfigs} {
		if err := setACL(ctx, directory, "u:"+strconv.FormatUint(runtimeUID, 10)+":--x"); err != nil {
			return fmt.Errorf("grant tenant configuration traversal on %s: %w", directory, err)
		}
	}
	payload, err := json.MarshalIndent(tenant, "", "  ")
	if err != nil {
		return err
	}
	dropInRoot := filepath.Join("/etc/systemd/system", "workagent-userhost@"+tenant.TenantID+".service.d")
	if err := atomicWriteOwned(ctx, filepath.Join(dropInRoot, "identity.conf"), []byte("[Service]\nUser="+tenant.RuntimeUser+"\nGroup="+tenant.RuntimeUser+"\n"), 0o644, 0, 0, ""); err != nil {
		return err
	}
	if err := atomicWriteOwned(ctx, filepath.Join(dropInRoot, "resources.conf"), ResourceDropInPayload(tenant.Limits), 0o644, 0, 0, ""); err != nil {
		return err
	}
	if err := atomicWriteOwned(ctx, configPath, append(payload, '\n'), 0o640, 0, int(portalGID), "u:"+strconv.FormatUint(runtimeUID, 10)+":r--"); err != nil {
		return err
	}
	return VerifyTenantConfigPath(portal, tenant, configPath)
}

func atomicWriteOwned(ctx context.Context, path string, payload []byte, mode os.FileMode, uid, gid int, acl string) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("configuration parent is unsafe")
	}
	temporary, err := os.CreateTemp(parent, ".workagent-admin-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	closeWith := func(operation error) error {
		closeErr := temporary.Close()
		return errors.Join(operation, closeErr)
	}
	if err := temporary.Chmod(mode); err != nil {
		return closeWith(err)
	}
	if err := temporary.Chown(uid, gid); err != nil {
		return closeWith(err)
	}
	if acl != "" {
		if err := setExclusiveFileACL(ctx, temporaryPath, acl); err != nil {
			return closeWith(err)
		}
	}
	if _, err := temporary.Write(payload); err != nil {
		return closeWith(err)
	}
	if err := temporary.Sync(); err != nil {
		return closeWith(err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func setACL(ctx context.Context, path, entry string) error {
	return runSetfacl(ctx, path, "--no-mask", "--modify", entry)
}

func setExclusiveFileACL(ctx context.Context, path, reader string) error {
	policy := strings.Join([]string{"u::rw-", reader, "g::r--", "m::r--", "o::---"}, ",")
	return runSetfacl(ctx, path, "--set", policy)
}

func runSetfacl(ctx context.Context, path string, arguments ...string) error {
	commandContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, "/usr/bin/setfacl", append(arguments, path)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
