//go:build linux

package stagepublish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/admin"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
)

type productionEnvironment struct{}

func (productionEnvironment) EffectiveUID() uint32 { return uint32(os.Geteuid()) }
func (productionEnvironment) LoadPortal(path string) (config.Portal, error) {
	return config.LoadPortal(path)
}
func (productionEnvironment) VerifyPortalFiles(portal config.Portal, path string) error {
	return admin.VerifyPortalFiles(portal, path)
}
func (productionEnvironment) InspectHost(portal config.Portal) (hostcheck.Report, error) {
	return hostcheck.Inspect(portal)
}
func (productionEnvironment) PortalAccount(portal config.Portal) (accountIdentity, error) {
	account, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return accountIdentity{}, err
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return accountIdentity{}, errors.New("Portal runtime identity is invalid")
	}
	return accountIdentity{UID: uint32(uid), GID: uint32(gid)}, nil
}

func (productionEnvironment) InspectTenantAccount(tenant config.Tenant) (accountIdentity, bool, error) {
	_, err := user.Lookup(tenant.RuntimeUser)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return accountIdentity{}, false, nil
		}
		return accountIdentity{}, false, err
	}
	verified, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true})
	if err != nil {
		return accountIdentity{}, true, err
	}
	return accountIdentity{UID: verified.UID, GID: verified.GID}, true, nil
}

func (productionEnvironment) EnsureTenantAccount(ctx context.Context, tenant config.Tenant) (accountIdentity, error) {
	_, lookupErr := user.Lookup(tenant.RuntimeUser)
	if lookupErr != nil {
		var unknown user.UnknownUserError
		if !errors.As(lookupErr, &unknown) {
			return accountIdentity{}, lookupErr
		}
		shell := "/usr/sbin/nologin"
		if info, statErr := os.Lstat(shell); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			shell = "/sbin/nologin"
		}
		if err := runProtected(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", tenant.DataRoot, "--shell", shell, tenant.RuntimeUser); err != nil {
			return accountIdentity{}, err
		}
	} else if _, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{}); err != nil {
		return accountIdentity{}, err
	}
	if err := runProtected(ctx, "usermod", "--append", "--groups", "workagent-slots", tenant.RuntimeUser); err != nil {
		return accountIdentity{}, err
	}
	if err := runProtected(ctx, "passwd", "--lock", tenant.RuntimeUser); err != nil {
		return accountIdentity{}, err
	}
	verified, err := admin.VerifyRuntimeAccount(tenant, admin.RuntimeAccountVerificationOptions{RequireSlotGroup: true, RequirePasswordLocked: true})
	if err != nil {
		return accountIdentity{}, err
	}
	return accountIdentity{UID: verified.UID, GID: verified.GID}, nil
}

func (productionEnvironment) EnsureCapacity(ctx context.Context, directory string, maximum int) error {
	return admin.EnsureCapacitySlots(ctx, directory, maximum)
}

func (productionEnvironment) EnsureTenantConfig(ctx context.Context, portal config.Portal, tenant config.Tenant) error {
	configPath := filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json")
	existing, err := config.LoadTenant(configPath)
	if err == nil {
		if !reflect.DeepEqual(existing, tenant) {
			return errors.New("existing tenant configuration conflicts with the migration identity")
		}
		return admin.VerifyTenantConfigPath(portal, tenant, configPath)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing tenant configuration: %w", err)
	}
	dropIn := filepath.Join("/etc/systemd/system", "workagent-userhost@"+tenant.TenantID+".service.d")
	for _, name := range []string{"identity.conf", "resources.conf"} {
		if _, statErr := os.Lstat(filepath.Join(dropIn, name)); statErr == nil {
			return errors.New("tenant systemd drop-in exists without its protected configuration")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	return admin.WriteTenantFiles(ctx, portal, tenant)
}

func (productionEnvironment) VerifyTenantConfig(ctx context.Context, portal config.Portal, tenant config.Tenant) error {
	path := filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json")
	loaded, err := config.LoadTenant(path)
	if err != nil || !reflect.DeepEqual(loaded, tenant) {
		return errors.New("published tenant configuration readback does not match")
	}
	if err := admin.VerifyTenantConfigPath(portal, tenant, path); err != nil {
		return err
	}
	return admin.VerifyTenantService(ctx, portal, tenant, admin.ServiceVerificationOptions{})
}

func (productionEnvironment) AssignQuota(path string, projectID uint32, hardLimit uint64) (hostcheck.ProjectQuotaStatus, error) {
	return hostcheck.AssignTenantQuota(path, projectID, hardLimit)
}
func (productionEnvironment) VerifyQuota(path string, projectID uint32, hardLimit uint64) (hostcheck.ProjectQuotaStatus, error) {
	return hostcheck.VerifyTenantQuota(path, projectID, hardLimit)
}
func (productionEnvironment) Systemd() systemdctl.Controller { return systemdctl.Default() }
func (productionEnvironment) ListUserHostUnits(ctx context.Context) ([]string, error) {
	client := systemdctl.Default()
	return client.ListUnits(ctx, "workagent-userhost@*.service", "workagent-userhost@*.socket")
}
func (productionEnvironment) LookupGroup(name string) (*user.Group, error) {
	return user.LookupGroup(name)
}
func (productionEnvironment) Now() time.Time { return time.Now().UTC() }

func runProtected(ctx context.Context, name string, arguments ...string) error {
	commandPath, err := protectedAccountExecutable(name)
	if err != nil {
		return err
	}
	commandContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandContext, commandPath, arguments...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 512 || strings.ContainsAny(message, "\r\n") {
		message = "output redacted"
	}
	return fmt.Errorf("account operation %s failed: %w: %s", name, err, message)
}

func protectedAccountExecutable(name string) (string, error) {
	var commandPath string
	switch name {
	case "useradd":
		commandPath = "/usr/sbin/useradd"
	case "usermod":
		commandPath = "/usr/sbin/usermod"
	case "passwd":
		commandPath = "/usr/bin/passwd"
	default:
		return "", errors.New("account operation is not in the fixed executable allowlist")
	}
	if err := validateProtectedExecutable(commandPath); err != nil {
		return "", err
	}
	return commandPath, nil
}

func validateProtectedExecutable(commandPath string) error {
	if commandPath == "" || !filepath.IsAbs(commandPath) || filepath.Clean(commandPath) != commandPath {
		return errors.New("protected account executable path is invalid")
	}
	for current := commandPath; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		stat, ok := fileStat(info)
		if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("protected account executable or ancestor is unsafe")
		}
		if current == commandPath {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return errors.New("protected account executable is not a root-owned executable regular file")
			}
		} else if !info.IsDir() {
			return errors.New("protected account executable ancestor is not a real directory")
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	return nil
}

type flockCloser struct{ file *os.File }

func (l *flockCloser) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

func (productionEnvironment) AcquireCLIProxyLock(path string) (io.Closer, error) {
	group, err := user.LookupGroup("cliproxyapi")
	if err != nil {
		return nil, errors.New("CLIProxy dedicated group is unavailable")
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 || path != "/run/workagent/cliproxy-migration.lock" {
		return nil, errors.New("CLIProxy migration lock identity is invalid")
	}
	return acquireValidatedCLIProxyLock(path, uint32(gid))
}

func acquireValidatedCLIProxyLock(path string, expectedGID uint32) (io.Closer, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedGID == 0 {
		return nil, errors.New("CLIProxy migration lock path or group is invalid")
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return nil, err
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	parentStat, ok := fileStat(parentInfo)
	if err != nil || !ok || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o755 || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return nil, errors.New("CLIProxy migration lock parent is unsafe")
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("CLIProxy migration lock is missing")
	}
	info, err := file.Stat()
	stat, typed := fileStat(info)
	if err != nil || !typed || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || stat.Uid != 0 || stat.Gid != expectedGID {
		file.Close()
		return nil, errors.New("CLIProxy migration lock protection is invalid")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("CLIProxy is active or starting; exclusive migration lock is unavailable")
	}
	return &flockCloser{file: file}, nil
}

func rejectSymlinkAncestors(target string) error {
	for current := filepath.Clean(target); current != string(filepath.Separator); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && current == target {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("protected production path has an unsafe ancestor")
		}
	}
	return nil
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
