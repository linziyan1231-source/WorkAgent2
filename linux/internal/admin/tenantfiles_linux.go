package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
)

func ResourceDropInPayload(limits config.ResourceLimits) []byte {
	limits = limits.Effective()
	return []byte(fmt.Sprintf("[Service]\nMemoryHigh=%d\nMemoryMax=%d\nCPUQuota=%d%%\nTasksMax=%d\n", limits.MemoryBytes, limits.MemoryBytes, limits.CPUPercent, limits.ActiveProcesses))
}

type tenantFilePublication struct {
	portal       config.Portal
	tenant       config.Tenant
	configPath   string
	configParent string
	runtimeUID   uint32
	plan         tenantFileSetPlan
}

// prepareTenantFilePublication performs the complete non-mutating portion of
// a tenant publication. Batch callers prepare every tenant before the first
// directory, ACL, stage, or journal can be changed.
func prepareTenantFilePublication(portal config.Portal, tenant config.Tenant, systemdRoot string) (tenantFilePublication, error) {
	if err := ValidateTenantBinding(portal, tenant); err != nil {
		return tenantFilePublication{}, err
	}
	portalAccount, err := user.Lookup(portal.RuntimeUser)
	if err != nil {
		return tenantFilePublication{}, err
	}
	portalGID, err := strconv.ParseUint(portalAccount.Gid, 10, 32)
	if err != nil || portalGID == 0 {
		return tenantFilePublication{}, errors.New("Portal group is invalid")
	}
	runtimeAccount, err := user.Lookup(tenant.RuntimeUser)
	if err != nil {
		return tenantFilePublication{}, err
	}
	runtimeUID, err := strconv.ParseUint(runtimeAccount.Uid, 10, 32)
	if err != nil || runtimeUID == 0 {
		return tenantFilePublication{}, errors.New("tenant runtime UID is invalid")
	}
	if !cleanTenantFilePath(systemdRoot) {
		return tenantFilePublication{}, errors.New("tenant systemd root is invalid")
	}
	configPath := filepath.Join(portal.Paths.TenantConfigs, tenant.TenantID+".json")
	payload, err := json.MarshalIndent(tenant, "", "  ")
	if err != nil {
		return tenantFilePublication{}, err
	}
	dropInRoot := filepath.Join(systemdRoot, "workagent-userhost@"+tenant.TenantID+".service.d")
	identityPath := filepath.Join(dropInRoot, "identity.conf")
	resourcesPath := filepath.Join(dropInRoot, "resources.conf")
	plan := tenantFileSetPlan{
		TenantID:    tenant.TenantID,
		JournalPath: filepath.Join(dropInRoot, ".workagent-tenant-files.transaction.json"),
		Entries: []tenantFileIntent{
			{Name: tenantFileIdentity, ProtectedRoot: systemdRoot, Target: identityPath, Stage: identityPath + ".workagent-stage", Payload: []byte("[Service]\nUser=" + tenant.RuntimeUser + "\nGroup=" + tenant.RuntimeUser + "\n"), Mode: 0o644, UID: 0, GID: 0},
			{Name: tenantFileResources, ProtectedRoot: systemdRoot, Target: resourcesPath, Stage: resourcesPath + ".workagent-stage", Payload: ResourceDropInPayload(tenant.Limits), Mode: 0o644, UID: 0, GID: 0},
			{Name: tenantFileConfig, ProtectedRoot: portal.Paths.TenantConfigs, Target: configPath, Stage: configPath + ".workagent-stage", Payload: append(payload, '\n'), Mode: 0o640, UID: 0, GID: uint32(portalGID), ACLUser: uint32(runtimeUID)},
		},
	}
	plan.ValidateJournal = func(entries []tenantFileJournalEntry) error {
		return validateTenantFileJournalPayloads(portal, tenant.TenantID, entries)
	}
	if err := validateTenantFileSetPlan(plan); err != nil {
		return tenantFilePublication{}, err
	}
	// The package-managed tenant configuration root must already exist, as it
	// did before the journal protocol. Validate its parent separately because
	// both directories receive traversal ACLs, but never synthesize a 0755
	// replacement for the package's narrower root:Portal-group directory.
	configParent := filepath.Dir(portal.Paths.TenantConfigs)
	if err := validateTenantFileDirectoryAncestry(configParent, configParent); err != nil {
		return tenantFilePublication{}, fmt.Errorf("validate tenant configuration parent: %w", err)
	}
	for _, entry := range plan.Entries {
		if err := validateTenantFileDirectoryAncestry(entry.ProtectedRoot, filepath.Dir(entry.Target)); err != nil {
			return tenantFilePublication{}, fmt.Errorf("validate tenant file parent %s: %w", filepath.Dir(entry.Target), err)
		}
	}
	return tenantFilePublication{
		portal: portal, tenant: tenant, configPath: configPath, configParent: configParent,
		runtimeUID: uint32(runtimeUID), plan: plan,
	}, nil
}

// publishPreparedTenantFiles must be called only by an active catalog
// transaction. It attaches directory traversal ACLs before staging and leaves
// systemd reload/readback to the transaction's batch commit boundary.
func publishPreparedTenantFiles(ctx context.Context, publication tenantFilePublication) error {
	return publishPreparedTenantFilesWithHook(ctx, publication, nil)
}

func publishPreparedTenantFilesWithHook(ctx context.Context, publication tenantFilePublication, hook tenantFileFaultHook) error {
	if err := probeTenantFileAnonymousCapabilities(publication.plan); err != nil {
		return err
	}
	// Establish and validate every directory through pinned dirfds before the
	// path-based ACL utility is allowed to mutate either traversal directory.
	if err := prepareTenantFileDirectories(publication.plan, unix.Fsync); err != nil {
		return err
	}
	for _, directory := range []string{publication.configParent, publication.portal.Paths.TenantConfigs} {
		if err := setACL(ctx, directory, "u:"+strconv.FormatUint(uint64(publication.runtimeUID), 10)+":--x"); err != nil {
			return fmt.Errorf("grant tenant configuration traversal on %s: %w", directory, err)
		}
		// setfacl changes the directory inode. Fsync that exact directory so a
		// successful publication never outlives the traversal ACL it requires.
		if err := syncTenantFileDirectory(directory); err != nil {
			return fmt.Errorf("persist tenant configuration traversal ACL on %s: %w", directory, err)
		}
	}
	if err := publishTenantFileSet(ctx, publication.plan, hook); err != nil {
		return err
	}
	return VerifyTenantConfigPath(publication.portal, publication.tenant, publication.configPath)
}

func validateTenantFileJournalPayloads(portal config.Portal, tenantID string, entries []tenantFileJournalEntry) error {
	if len(entries) != 3 || entries[0].Name != tenantFileIdentity || entries[1].Name != tenantFileResources || entries[2].Name != tenantFileConfig {
		return errors.New("tenant file journal payload order is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(entries[2].Payload))
	decoder.DisallowUnknownFields()
	var pending config.Tenant
	if err := decoder.Decode(&pending); err != nil {
		return errors.New("tenant file journal config payload is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tenant file journal config payload has trailing data")
	}
	if pending.TenantID != tenantID || pending.Validate() != nil || ValidateTenantBinding(portal, pending) != nil {
		return errors.New("tenant file journal config payload is not bound to this tenant")
	}
	identity := []byte("[Service]\nUser=" + pending.RuntimeUser + "\nGroup=" + pending.RuntimeUser + "\n")
	if !bytes.Equal(entries[0].Payload, identity) || !bytes.Equal(entries[1].Payload, ResourceDropInPayload(pending.Limits)) {
		return errors.New("tenant file journal drop-ins do not match its config payload")
	}
	runtimeAccount, err := user.Lookup(pending.RuntimeUser)
	if err != nil {
		return errors.New("tenant file journal runtime account is unavailable")
	}
	runtimeUID, err := strconv.ParseUint(runtimeAccount.Uid, 10, 32)
	if err != nil || runtimeUID == 0 || entries[2].ACLUser != uint32(runtimeUID) {
		return errors.New("tenant file journal ACL identity does not match its runtime account")
	}
	return nil
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
