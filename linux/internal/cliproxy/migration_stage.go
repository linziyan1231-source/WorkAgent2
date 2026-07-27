package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/modelbootstrap"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/productconfig"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/projectfs"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/servicelock"

	"golang.org/x/sys/unix"
)

const (
	migrationPendingPath = "credentials/model-bootstrap-v1.pending.json"
	migrationAppliedPath = "config/model-bootstrap-v1.applied.json"
	maxPendingBytes      = 256 * 1024
)

var lookupMigrationRuntimeIdentity = lookupSystemRuntimeIdentity

type StageMigrationBundlesOptions struct {
	ReportPath         string
	PlanPath           string
	PortalDatabasePath string
	CLIProxy           config.CLIProxy
	Policy             productconfig.Policy
}

type StageMigrationBundlesResult struct {
	Users       int `json:"users"`
	Provisioned int `json:"provisioned"`
	Reused      int `json:"reused"`
}

type stagedMigrationTenant struct {
	user portalMigrationUser
	uid  uint32
	gid  uint32
	root *projectfs.Root
	lock *servicelock.Lock
}

type pendingReadResult struct {
	bundle      modelbootstrap.Bundle
	exists      bool
	recoverable bool
}

// StageMigrationBundles provisions or rotates every deterministic tenant key
// while CLIProxy is online, then atomically places the one-time keys in the
// tenant-owned startup handoff consumed by UserHost. It never performs a
// Portal login or exposes a plaintext key in its result or errors.
func StageMigrationBundles(ctx context.Context, options StageMigrationBundlesOptions) (StageMigrationBundlesResult, error) {
	if err := options.CLIProxy.Validate(); err != nil {
		return StageMigrationBundlesResult{}, fmt.Errorf("CLIProxy contract: %w", err)
	}
	if err := options.Policy.Validate(); err != nil {
		return StageMigrationBundlesResult{}, fmt.Errorf("CLIProxy policy: %w", err)
	}
	artifacts, err := loadMigrationArtifacts(ctx, options.ReportPath, options.PlanPath, options.PortalDatabasePath)
	if err != nil {
		return StageMigrationBundlesResult{}, err
	}
	tenants, err := lockMigrationTenants(artifacts.users)
	if err != nil {
		return StageMigrationBundlesResult{}, err
	}
	defer closeMigrationTenants(tenants)
	provisioner := Provisioner{Config: options.CLIProxy}
	result := StageMigrationBundlesResult{Users: len(tenants)}
	for _, tenant := range tenants {
		if err := rejectAppliedMigrationMarker(tenant.root); err != nil {
			return StageMigrationBundlesResult{}, err
		}
		pending, err := readMigrationPending(tenant.root, tenant.uid, tenant.gid)
		if err != nil {
			return StageMigrationBundlesResult{}, err
		}
		reuse := false
		if pending.exists && !pending.recoverable {
			reuse, err = pendingBundleMatchesLive(ctx, provisioner, tenant.user, artifacts.byTenant[tenant.user.TenantID], options.Policy, pending.bundle)
			pending.bundle.Zero()
			if err != nil {
				return StageMigrationBundlesResult{}, err
			}
		}
		if reuse {
			result.Reused++
			continue
		}
		bundle, err := provisioner.Provision(ctx, tenant.user.TenantID, tenant.user.Username, options.Policy)
		if err != nil {
			return StageMigrationBundlesResult{}, err
		}
		if err := writeMigrationPending(tenant, &bundle); err != nil {
			bundle.Zero()
			return StageMigrationBundlesResult{}, err
		}
		bundle.Zero()
		result.Provisioned++
	}
	if err := verifyAllMigrationPending(ctx, provisioner, tenants, artifacts, options.Policy); err != nil {
		return StageMigrationBundlesResult{}, err
	}
	return result, nil
}

func lockMigrationTenants(users []portalMigrationUser) ([]stagedMigrationTenant, error) {
	ordered := append([]portalMigrationUser(nil), users...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].TenantID < ordered[j].TenantID })
	result := make([]stagedMigrationTenant, 0, len(ordered))
	fail := func(err error) ([]stagedMigrationTenant, error) {
		closeMigrationTenants(result)
		return nil, err
	}
	for _, value := range ordered {
		uid, gid, err := lookupMigrationRuntimeIdentity(value.RuntimeUser)
		if err != nil || uid == 0 || gid == 0 {
			return fail(errors.New("migrated tenant runtime account is missing or invalid"))
		}
		lock, err := servicelock.AcquireExclusive(filepath.Join(value.DataRoot, ".runtime.lock"), uid, gid)
		if err != nil {
			return fail(fmt.Errorf("migrated tenant is not quiescent: %w", err))
		}
		root, err := projectfs.OpenRoot(value.DataRoot)
		if err != nil {
			lock.Close()
			return fail(err)
		}
		if err := root.ValidatePrivateOwner(uid); err != nil {
			root.Close()
			lock.Close()
			return fail(err)
		}
		if err := validateTenantPrivateDirectory(root, "credentials", uid, gid); err != nil {
			root.Close()
			lock.Close()
			return fail(err)
		}
		result = append(result, stagedMigrationTenant{user: value, uid: uid, gid: gid, root: root, lock: lock})
	}
	return result, nil
}

func closeMigrationTenants(tenants []stagedMigrationTenant) {
	for index := len(tenants) - 1; index >= 0; index-- {
		if tenants[index].root != nil {
			_ = tenants[index].root.Close()
		}
		if tenants[index].lock != nil {
			_ = tenants[index].lock.Close()
		}
	}
}

func lookupSystemRuntimeIdentity(name string) (uint32, uint32, error) {
	if !migrationRuntimePattern.MatchString(name) {
		return 0, 0, errors.New("runtime account name is invalid")
	}
	account, err := osuser.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := parsePositiveUint32(account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := parsePositiveUint32(account.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func validateTenantPrivateDirectory(root *projectfs.Root, relative string, uid, gid uint32) error {
	file, err := root.Open(relative, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("tenant private directory is missing or unsafe")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("tenant private directory must have mode 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return errors.New("tenant private directory ownership does not match its runtime account")
	}
	return nil
}

func rejectAppliedMigrationMarker(root *projectfs.Root) error {
	file, err := root.Open(migrationAppliedPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		file.Close()
	}
	return errors.New("a migrated tenant already has an applied model marker; refuse key rotation")
}

func readMigrationPending(root *projectfs.Root, uid, gid uint32) (pendingReadResult, error) {
	file, err := root.Open(migrationPendingPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return pendingReadResult{}, nil
	}
	if err != nil {
		return pendingReadResult{}, errors.New("tenant migration bundle could not be opened safely")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return pendingReadResult{}, errors.New("tenant migration bundle is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return pendingReadResult{}, errors.New("tenant migration bundle ownership does not match")
	}
	if info.Size() < 1 || info.Size() > maxPendingBytes {
		return pendingReadResult{exists: true, recoverable: true}, nil
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxPendingBytes+1))
	if err != nil || len(payload) > maxPendingBytes {
		clear(payload)
		return pendingReadResult{}, errors.New("tenant migration bundle could not be read safely")
	}
	defer clear(payload)
	var bundle modelbootstrap.Bundle
	if err := decodeStrictJSON(payload, &bundle); err != nil || bundle.ValidateManagedForTenant(filepath.Base(root.Path())) != nil {
		bundle.Zero()
		return pendingReadResult{exists: true, recoverable: true}, nil
	}
	return pendingReadResult{bundle: bundle, exists: true}, nil
}

func writeMigrationPending(tenant stagedMigrationTenant, bundle *modelbootstrap.Bundle) error {
	if bundle == nil || bundle.ValidateManagedForTenant(tenant.user.TenantID) != nil {
		return errors.New("generated tenant migration bundle is invalid")
	}
	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return errors.New("encode tenant migration bundle")
	}
	payload = append(payload, '\n')
	defer clear(payload)
	if err := tenant.root.WriteFileAtomicOwned(migrationPendingPath, payload, 0o600, tenant.uid, tenant.gid); err != nil {
		return errors.New("activate tenant migration bundle")
	}
	readback, err := readMigrationPending(tenant.root, tenant.uid, tenant.gid)
	if err != nil || !readback.exists || readback.recoverable || !readback.bundle.State.Equal(bundle.State) ||
		readback.bundle.CodexAPIKey != bundle.CodexAPIKey || readback.bundle.KimiAPIKey != bundle.KimiAPIKey {
		readback.bundle.Zero()
		return errors.New("tenant migration bundle readback did not match")
	}
	readback.bundle.Zero()
	return nil
}

func pendingBundleMatchesLive(ctx context.Context, provisioner Provisioner, user portalMigrationUser, overrides [2]migrationQuotaOverride, policy productconfig.Policy, bundle modelbootstrap.Bundle) (bool, error) {
	expectedState, desired, client, err := migrationDesiredAndLive(ctx, provisioner, user, policy)
	if err != nil {
		return false, err
	}
	defer client.Close()
	if !bundle.State.Equal(expectedState) || bundle.ValidateManagedForTenant(user.TenantID) != nil {
		return false, nil
	}
	keys, err := readKeys(ctx, client)
	if err != nil {
		return false, err
	}
	if !pendingMatchesKeyReadback(bundle, desired, overrides, keys) {
		return false, nil
	}
	if err := verifyPendingKeyAuthentication(ctx, provisioner.Config.APIBaseURL, user.TenantID, bundle); err != nil {
		return false, nil
	}
	return true, nil
}

func migrationDesiredAndLive(ctx context.Context, provisioner Provisioner, user portalMigrationUser, policy productconfig.Policy) (modelbootstrap.State, []keyWrite, *ManagementClient, error) {
	state, err := modelbootstrap.StateFromPolicy(policy, provisioner.Config.APIBaseURL, user.TenantID)
	if err != nil {
		return modelbootstrap.State{}, nil, nil, err
	}
	client, err := NewManagementClient(ManagementOptions{BaseURL: provisioner.Config.ManagementURL, KeyFile: provisioner.Config.ManagementCredentialFile})
	if err != nil {
		return modelbootstrap.State{}, nil, nil, err
	}
	catalog, err := readCatalog(ctx, client, policy)
	if err != nil {
		client.Close()
		return modelbootstrap.State{}, nil, nil, err
	}
	desired := make([]keyWrite, 0, 2)
	for _, provider := range []struct {
		name, label, id string
		models          []string
	}{{"codex", "ChatGPT-Codex", state.CodexKeyID, state.CodexModels}, {"kimi", "Kimi", state.KimiKeyID, state.KimiModels}} {
		key, err := desiredKey(user.Username+" / "+provider.label, provider.id, provider.name, provider.models, policy, catalog)
		if err != nil {
			client.Close()
			return modelbootstrap.State{}, nil, nil, err
		}
		desired = append(desired, key)
	}
	return state, desired, client, nil
}

func pendingMatchesKeyReadback(bundle modelbootstrap.Bundle, desired []keyWrite, overrides [2]migrationQuotaOverride, keys []listedKey) bool {
	if err := verifyKeys(desired, keys); err != nil {
		withTransferredQuota := append([]keyWrite(nil), desired...)
		for index := range withTransferredQuota {
			override := overrides[0]
			if withTransferredQuota[index].ID == overrides[1].NewKeyID {
				override = overrides[1]
			}
			withTransferredQuota[index].DailyLimitUSD = json.Number(override.DailyLimitUSD)
			withTransferredQuota[index].WeeklyLimitUSD = json.Number(override.WeeklyLimitUSD)
		}
		if err := verifyKeys(withTransferredQuota, keys); err != nil {
			return false
		}
	}
	byID := make(map[string]listedKey, len(keys))
	for _, key := range keys {
		byID[key.ID] = key
	}
	return byID[bundle.CodexKeyID].KeyPreview == migrationKeyPreview(bundle.CodexAPIKey) && byID[bundle.KimiKeyID].KeyPreview == migrationKeyPreview(bundle.KimiAPIKey)
}

func migrationKeyPreview(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 12 {
		return key
	}
	return key[:7] + "..." + key[len(key)-5:]
}

func verifyPendingKeyAuthentication(ctx context.Context, apiBaseURL, tenantID string, bundle modelbootstrap.Bundle) error {
	if bundle.ValidateManagedForTenant(tenantID) != nil || apiBaseURL != bundle.BaseURL {
		return errors.New("pending migration key authentication input is invalid")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
	}
	client := &http.Client{
		Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer transport.CloseIdleConnections()
	for _, key := range []string{bundle.CodexAPIKey, bundle.KimiAPIKey} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBaseURL+"/models", nil)
		if err != nil {
			return errors.New("create pending migration key verification request")
		}
		request.Header.Set("Authorization", "Bearer "+key)
		response, err := client.Do(request)
		request.Header.Del("Authorization")
		if err != nil {
			return errors.New("pending migration key authentication request failed")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 512*1024+1))
		closeErr := response.Body.Close()
		valid := response.StatusCode == http.StatusOK && readErr == nil && closeErr == nil && len(payload) <= 512*1024 && json.Valid(payload)
		clear(payload)
		if !valid {
			return errors.New("pending migration key did not authenticate against the loopback models endpoint")
		}
	}
	return nil
}

func verifyAllMigrationPending(ctx context.Context, provisioner Provisioner, tenants []stagedMigrationTenant, artifacts migrationArtifacts, policy productconfig.Policy) error {
	client, err := NewManagementClient(ManagementOptions{BaseURL: provisioner.Config.ManagementURL, KeyFile: provisioner.Config.ManagementCredentialFile})
	if err != nil {
		return err
	}
	defer client.Close()
	catalog, err := readCatalog(ctx, client, policy)
	if err != nil {
		return err
	}
	keys, err := readKeys(ctx, client)
	if err != nil {
		return err
	}
	for _, tenant := range tenants {
		pending, err := readMigrationPending(tenant.root, tenant.uid, tenant.gid)
		if err != nil || !pending.exists || pending.recoverable {
			return errors.New("tenant migration bundle final readback failed")
		}
		state, err := modelbootstrap.StateFromPolicy(policy, provisioner.Config.APIBaseURL, tenant.user.TenantID)
		if err != nil || !pending.bundle.State.Equal(state) {
			pending.bundle.Zero()
			return errors.New("tenant migration bundle final policy readback failed")
		}
		desired := make([]keyWrite, 0, 2)
		for _, provider := range []struct {
			name, label, id string
			models          []string
		}{{"codex", "ChatGPT-Codex", state.CodexKeyID, state.CodexModels}, {"kimi", "Kimi", state.KimiKeyID, state.KimiModels}} {
			key, desiredErr := desiredKey(tenant.user.Username+" / "+provider.label, provider.id, provider.name, provider.models, policy, catalog)
			if desiredErr != nil {
				pending.bundle.Zero()
				return desiredErr
			}
			desired = append(desired, key)
		}
		matches := pendingMatchesKeyReadback(pending.bundle, desired, artifacts.byTenant[tenant.user.TenantID], keys)
		if matches {
			matches = verifyPendingKeyAuthentication(ctx, provisioner.Config.APIBaseURL, tenant.user.TenantID, pending.bundle) == nil
		}
		pending.bundle.Zero()
		if !matches {
			return errors.New("tenant migration keys failed final management readback")
		}
	}
	return nil
}
