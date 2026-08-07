package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/store"
	"aionuiportal/internal/winutil"
)

type EmployeeProvisioner struct {
	Manager          *Manager
	ScriptsDirectory string
}

const (
	DefaultEmployeeCodexDailyUSD  = 40
	DefaultEmployeeCodexWeeklyUSD = 80
	DefaultEmployeeKimiDailyUSD   = 10
	DefaultEmployeeKimiWeeklyUSD  = 20
)

func (p EmployeeProvisioner) Add(ctx context.Context, username string, portalPassword []byte) (store.User, error) {
	return p.AddWithProgress(ctx, username, portalPassword, nil)
}

func (p EmployeeProvisioner) AddWithProgress(ctx context.Context, username string, portalPassword []byte, report func(int, string)) (store.User, error) {
	progress := func(percent int, step string) {
		if report != nil {
			report(percent, step)
		}
	}
	progress(10, "validating")
	if p.Manager == nil {
		return store.User{}, errors.New("Portal manager is required")
	}
	defer auth.Zero(portalPassword)
	if err := winutil.ValidateLocalUsername(username); err != nil {
		return store.User{}, err
	}
	if err := auth.ValidatePortalPassword(portalPassword); err != nil {
		return store.User{}, err
	}
	progress(20, "checking_accounts")
	portalUser, portalErr := p.Manager.Store.UserByUsername(ctx, username)
	portalExists := portalErr == nil
	if portalErr != nil && !errors.Is(portalErr, store.ErrNotFound) {
		return store.User{}, portalErr
	}
	if portalExists && (portalUser.Admin || !portalUser.Enabled) {
		return store.User{}, errors.New("existing Portal account is not an enabled employee account")
	}

	progress(30, "configuring_windows_account")
	windowsPassword, err := generateWindowsPassword(32)
	if err != nil {
		return store.User{}, err
	}
	defer auth.Zero(windowsPassword)
	sid, canonical, comment, windowsExists, err := winutil.InspectLocalStandardAccount(username)
	if err != nil {
		return store.User{}, err
	}
	if portalExists {
		if !windowsExists || !strings.EqualFold(portalUser.WindowsSID, sid) || !strings.EqualFold(portalUser.WindowsUsername, canonical) {
			return store.User{}, errors.New("existing Portal account does not match the Windows account")
		}
		if comment == winutil.ManagedAccountComment {
			return store.User{}, errors.New("Portal username already exists")
		}
	} else if windowsExists {
		if comment != winutil.ProvisioningAccountComment {
			return store.User{}, errors.New("an unmanaged Windows account already uses this username")
		}
		if mapped, lookupErr := p.Manager.Store.UserBySID(ctx, sid); lookupErr == nil {
			return store.User{}, fmt.Errorf("Windows account is already mapped to Portal user %s", mapped.Username)
		} else if !errors.Is(lookupErr, store.ErrNotFound) {
			return store.User{}, lookupErr
		}
	}
	if !windowsExists {
		sid, canonical, err = winutil.CreateLocalStandardAccount(username, windowsPassword)
		if err != nil {
			return store.User{}, err
		}
	} else {
		if err := winutil.SetLocalAccountComment(username, winutil.ProvisioningAccountComment); err != nil {
			return store.User{}, err
		}
		if err := winutil.SetLocalAccountPassword(username, windowsPassword); err != nil {
			return store.User{}, err
		}
	}
	progress(42, "applying_security_policy")
	for _, script := range []string{"Remove-CodexSandboxGroupMembership.ps1", "Set-UserHostRights.ps1"} {
		if err := p.runScript(ctx, script, canonical); err != nil {
			return store.User{}, err
		}
	}
	progress(52, "creating_windows_profile")
	if _, err := winutil.EnsureProfileForAccount(sid, username, windowsPassword); err != nil {
		return store.User{}, err
	}
	progress(62, "creating_portal_account")
	user := portalUser
	if portalExists {
		if err := p.Manager.ResetPortalPassword(ctx, user.Username, portalPassword); err != nil {
			return store.User{}, err
		}
	} else {
		user, err = p.Manager.AddUser(ctx, username, canonical, false, portalPassword)
		if err != nil {
			return store.User{}, err
		}
	}
	progress(70, "applying_storage_quota")
	if err := p.runScript(ctx, "Set-UserDiskQuota.ps1", canonical); err != nil {
		return user, err
	}
	progress(78, "configuring_models")
	_, err = p.Manager.ProvisionModelBootstrap(ctx, user.Username, ModelBootstrapOptions{
		ManagementURL:     p.Manager.Config.UsageManagementURL,
		ManagementKeyFile: p.Manager.Config.UsageManagementKeyFile,
		BaseURL:           "http://127.0.0.1:8317/v1",
		CodexDefaultModel: modelbootstrap.DefaultCodexModel,
		CodexModels:       modelbootstrap.ManagedCodexModels(),
		KimiModels:        modelbootstrap.ManagedKimiModels(),
		CodexDailyUSD:     DefaultEmployeeCodexDailyUSD,
		CodexWeeklyUSD:    DefaultEmployeeCodexWeeklyUSD,
		KimiDailyUSD:      DefaultEmployeeKimiDailyUSD,
		KimiWeeklyUSD:     DefaultEmployeeKimiWeeklyUSD,
	})
	if err != nil {
		return user, err
	}
	progress(88, "installing_runtime")
	if _, err := p.Manager.InstallOrUpdateTask(ctx, user.Username, windowsPassword, true); err != nil {
		return user, err
	}
	progress(96, "verifying")
	status, err := p.Manager.ModelBootstrapStatus(ctx, user.Username)
	if err != nil {
		return user, fmt.Errorf("read model bootstrap status: %w", err)
	}
	if !status.Applied || status.RebasePending {
		return user, errors.New("model bootstrap did not finish")
	}
	if failures := p.Manager.VerifyACLs(ctx); len(failures) != 0 {
		return user, fmt.Errorf("verify Portal ACLs: %w", errors.Join(failures...))
	}
	if err := winutil.SetLocalAccountComment(username, winutil.ManagedAccountComment); err != nil {
		return user, err
	}
	return user, nil
}

func (p EmployeeProvisioner) runScript(ctx context.Context, name, windowsAccount string) error {
	path := filepath.Join(p.ScriptsDirectory, name)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("required administration script is missing: %s", name)
	}
	command := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path, "-WindowsAccount", windowsAccount)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func generateWindowsPassword(length int) ([]byte, error) {
	if length < 16 {
		return nil, errors.New("generated Windows password length must be at least 16")
	}
	groups := []string{"ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%_-+="}
	alphabet := strings.Join(groups, "")
	result := make([]byte, length)
	for index := range result {
		group := alphabet
		if index < len(groups) {
			group = groups[index]
		}
		value, err := rand.Int(rand.Reader, big.NewInt(int64(len(group))))
		if err != nil {
			auth.Zero(result)
			return nil, err
		}
		result[index] = group[value.Int64()]
	}
	for index := len(result) - 1; index > 0; index-- {
		value, err := rand.Int(rand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			auth.Zero(result)
			return nil, err
		}
		other := int(value.Int64())
		result[index], result[other] = result[other], result[index]
	}
	return result, nil
}
