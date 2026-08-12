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
	"time"

	"aionuiportal/internal/auth"
	"aionuiportal/internal/modelbootstrap"
	"aionuiportal/internal/store"
	"aionuiportal/internal/winutil"
)

type EmployeeProvisioner struct {
	Manager          *Manager
	ScriptsDirectory string
	locks            provisionLocks
}

const (
	DefaultEmployeeCodexDailyUSD  = 40
	DefaultEmployeeCodexWeeklyUSD = 80
	DefaultEmployeeKimiDailyUSD   = 10
	DefaultEmployeeKimiWeeklyUSD  = 20
)

func (p *EmployeeProvisioner) Add(ctx context.Context, username string, portalPassword []byte) (store.User, error) {
	return p.AddWithProgress(ctx, username, portalPassword, nil)
}

func (p *EmployeeProvisioner) AddWithProgress(ctx context.Context, username string, portalPassword []byte, report func(int, string)) (result store.User, resultErr error) {
	if report != nil {
		report(10, "validating")
	}
	defer auth.Zero(portalPassword)
	if err := winutil.ValidateLocalUsername(username); err != nil {
		return store.User{}, err
	}
	if err := auth.ValidatePortalPassword(portalPassword); err != nil {
		return store.User{}, err
	}
	release, err := p.locks.acquire(username)
	if err != nil {
		return store.User{}, err
	}
	defer release()
	stateStore := provisionStateStore{directory: filepath.Join(filepath.Dir(p.Manager.Config.DatabasePath), "provision-jobs"), now: time.Now}
	if err := os.MkdirAll(stateStore.directory, 0o700); err != nil {
		return store.User{}, fmt.Errorf("create provisioning state directory: %w", err)
	}
	if err := winutil.ApplyTreeACL(stateStore.directory, winutil.ServicePrivatePolicy(p.Manager.Config.PortalServiceSID)); err != nil {
		return store.User{}, fmt.Errorf("protect provisioning state: %w", err)
	}
	if err := winutil.VerifyTreeACL(stateStore.directory, winutil.ServicePrivatePolicy(p.Manager.Config.PortalServiceSID)); err != nil {
		return store.User{}, fmt.Errorf("verify provisioning state protection: %w", err)
	}
	state, err := stateStore.open(username)
	if err != nil {
		return store.User{}, err
	}
	if state.Status == "complete" {
		return store.User{}, errors.New("provisioning already completed for this username")
	}
	if state.ResumeStep != "" && report != nil {
		// Retry deliberately replays idempotent operations because it rotates the
		// ephemeral Windows password and must revalidate dependent task/profile
		// gates. This persisted marker is the exact interrupted stage exposed to
		// operators and the protected progress IPC.
		report(15, "resuming_from_"+state.ResumeStep)
	}
	resumeStep := state.ResumeStep
	currentStep := ""
	advance := func(percent int, step string) error {
		if currentStep != "" {
			if err := stateStore.complete(state, currentStep); err != nil {
				return fmt.Errorf("persist completed provisioning step %s: %w", currentStep, err)
			}
		}
		currentStep = step
		if err := stateStore.begin(state, step); err != nil {
			return fmt.Errorf("persist provisioning step %s: %w", step, err)
		}
		if report != nil {
			report(percent, step)
		}
		return nil
	}
	defer func() {
		if resultErr != nil {
			_ = stateStore.fail(state, currentStep)
			return
		}
		if currentStep != "" {
			if err := stateStore.complete(state, currentStep); err != nil {
				resultErr = fmt.Errorf("provisioning succeeded but its final step state could not be saved: %w", err)
				return
			}
		}
		if err := stateStore.finish(state); err != nil {
			resultErr = fmt.Errorf("provisioning succeeded but completion state could not be saved: %w", err)
		}
	}()
	if err := advance(20, "checking_accounts"); err != nil {
		return store.User{}, err
	}
	portalUser, portalErr := p.Manager.Store.UserByUsername(ctx, username)
	portalExists := portalErr == nil
	if portalErr != nil && !errors.Is(portalErr, store.ErrNotFound) {
		return store.User{}, portalErr
	}
	if portalExists && (portalUser.Admin || !portalUser.Enabled) {
		return store.User{}, errors.New("existing Portal account is not an enabled employee account")
	}

	if err := advance(30, "configuring_windows_account"); err != nil {
		return store.User{}, err
	}
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
		if comment == winutil.ManagedAccountComment && resumeStep != "graduating_account" {
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
	state.WindowsSID = sid
	if err := stateStore.save(state); err != nil {
		return store.User{}, fmt.Errorf("persist provisioned Windows SID: %w", err)
	}
	if err := advance(42, "applying_security_policy"); err != nil {
		return store.User{}, err
	}
	for _, script := range []string{"Remove-CodexSandboxGroupMembership.ps1", "Set-UserHostRights.ps1"} {
		if err := p.runScript(ctx, script, canonical); err != nil {
			return store.User{}, err
		}
	}
	if err := advance(52, "creating_windows_profile"); err != nil {
		return store.User{}, err
	}
	if _, err := winutil.EnsureProfileForAccount(sid, username, windowsPassword); err != nil {
		return store.User{}, err
	}
	if err := advance(62, "creating_portal_account"); err != nil {
		return store.User{}, err
	}
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
	if err := advance(70, "applying_storage_quota"); err != nil {
		return store.User{}, err
	}
	if err := p.runScript(ctx, "Set-UserDiskQuota.ps1", canonical); err != nil {
		return user, err
	}
	if err := advance(78, "configuring_models"); err != nil {
		return store.User{}, err
	}
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
	if err := advance(88, "installing_runtime"); err != nil {
		return store.User{}, err
	}
	runtimeStatus, err := p.Manager.InstallOrUpdateTask(ctx, user.Username, windowsPassword, true)
	if err != nil {
		return user, err
	}
	if !runtimeStatus.Healthy || runtimeStatus.UserHostPID == 0 || runtimeStatus.AionCorePID == 0 || runtimeStatus.WebPID == 0 {
		return user, errors.New("UserHost and Core health gates did not pass")
	}
	if err := advance(94, "verifying_model_bootstrap"); err != nil {
		return store.User{}, err
	}
	status, err := p.Manager.ModelBootstrapStatus(ctx, user.Username)
	if err != nil {
		return user, fmt.Errorf("read model bootstrap status: %w", err)
	}
	if !status.Applied || status.RebasePending {
		return user, errors.New("model bootstrap did not finish")
	}
	if err := advance(96, "applying_skill_policy"); err != nil {
		return store.User{}, err
	}
	dataRoot, err := p.Manager.UserDataRootForSID(user.WindowsSID)
	if err != nil {
		return user, fmt.Errorf("resolve user data root for Skill policy: %w", err)
	}
	if err := p.applySkillPolicy(ctx, dataRoot); err != nil {
		return user, err
	}
	if err := advance(97, "verifying_acl"); err != nil {
		return store.User{}, err
	}
	if failures := p.Manager.VerifyUserACLs(user); len(failures) != 0 {
		return user, fmt.Errorf("verify Portal ACLs: %w", errors.Join(failures...))
	}
	if err := advance(98, "verifying_login_health"); err != nil {
		return store.User{}, err
	}
	verifiedUser, err := p.Manager.Store.UserByUsername(ctx, user.Username)
	if err != nil || !verifiedUser.Enabled || verifiedUser.Admin || !auth.VerifyPassword(verifiedUser.PasswordHash, portalPassword) {
		return user, errors.New("Portal login credential health gate did not pass")
	}
	if err := advance(99, "graduating_account"); err != nil {
		return user, err
	}
	if err := winutil.SetLocalAccountComment(username, winutil.ManagedAccountComment); err != nil {
		return user, err
	}
	return user, nil
}

func (p *EmployeeProvisioner) runScript(ctx context.Context, name, windowsAccount string) error {
	return p.runPowerShellScript(ctx, name, "-WindowsAccount", windowsAccount)
}

func (p *EmployeeProvisioner) applySkillPolicy(ctx context.Context, dataRoot string) error {
	name, arguments := p.skillPolicyInvocation(dataRoot)
	if err := p.runPowerShellScript(ctx, name, arguments...); err != nil {
		return fmt.Errorf("apply managed Skill policy: %w", err)
	}
	return nil
}

func (p *EmployeeProvisioner) skillPolicyInvocation(dataRoot string) (string, []string) {
	bundleRoot := filepath.Join(p.ScriptsDirectory, "skill-policy")
	return filepath.Join("skill-policy", "Apply-UserSkillPolicy.ps1"), []string{
		"-DataRoot", dataRoot,
		"-PluginRoot", filepath.Join(bundleRoot, "llm-wiki"),
		"-BuiltinReferenceRoot", filepath.Join(dataRoot, "data", "builtin-skills"),
	}
}

func (p *EmployeeProvisioner) runPowerShellScript(ctx context.Context, name string, arguments ...string) error {
	scriptsRoot, err := filepath.Abs(p.ScriptsDirectory)
	if err != nil {
		return fmt.Errorf("resolve administration scripts directory: %w", err)
	}
	path, err := filepath.Abs(filepath.Join(scriptsRoot, name))
	if err != nil {
		return fmt.Errorf("resolve administration script %s: %w", name, err)
	}
	relative, err := filepath.Rel(scriptsRoot, path)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("administration script escaped its directory: %s", name)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("required administration script is missing: %s", name)
	}
	commandArguments := []string{"-NoLogo", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}
	commandArguments = append(commandArguments, arguments...)
	command := exec.CommandContext(ctx, "powershell.exe", commandArguments...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func generateWindowsPassword(length int) ([]byte, error) {
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
