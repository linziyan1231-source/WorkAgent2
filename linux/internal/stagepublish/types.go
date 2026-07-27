// Package stagepublish performs the privileged, restart-safe publication of a
// reviewed Linux migration stage into the fixed WorkAgent production layout.
// It never reads from or writes to the Windows source host.
package stagepublish

import (
	"context"
	"errors"
	"io"
	"os/user"
	"time"

	"github.com/linziyan1231-source/WorkAgent2/linux/internal/config"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/hostcheck"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/systemdctl"
	"github.com/linziyan1231-source/WorkAgent2/linux/internal/winmigration"
)

const (
	ConfirmPublication = "PUBLISH-WORKAGENT-MIGRATION"
	JournalSchema      = 1
)

type Options struct {
	Stage                     string
	ExpectedSourceFingerprint string
	ExpectedOutputFingerprint string
	Check                     bool
	Apply                     bool
	Confirm                   string
}

type Result struct {
	Ready                     bool   `json:"ready"`
	Published                 bool   `json:"published"`
	Resumed                   bool   `json:"resumed"`
	Tenants                   int    `json:"tenants"`
	Files                     int    `json:"files"`
	Bytes                     int64  `json:"bytes"`
	SourceFingerprint         string `json:"source_fingerprint"`
	OutputFingerprint         string `json:"output_fingerprint"`
	JournalPath               string `json:"journal_path"`
	RollbackDestination       string `json:"rollback_destination"`
	QuotaBackupDirectoryReady bool   `json:"quota_backup_directory_ready"`
}

type layout struct {
	portalConfig   string
	portalDatabase string
	tenantRoot     string
	tenantConfigs  string
	systemdRoot    string
	journalRoot    string
	journalPath    string
	rollbackRoot   string
	quotaBackupDir string
	cliproxyLock   string
}

func productionLayout() layout {
	return layout{
		portalConfig: "/etc/workagent/portal.json", portalDatabase: "/var/lib/workagent/portal/portal.db",
		tenantRoot: "/srv/workagent/users", tenantConfigs: "/etc/workagent/users", systemdRoot: "/etc/systemd/system",
		journalRoot: "/var/lib/workagent/migration/import-stage", journalPath: "/var/lib/workagent/migration/import-stage/journal.json",
		rollbackRoot: "/var/lib/workagent/migration/rollback", quotaBackupDir: "/var/lib/workagent/migration/backups/cliproxy",
		cliproxyLock: "/run/workagent/cliproxy-migration.lock",
	}
}

type accountIdentity struct {
	UID uint32
	GID uint32
}

type environment interface {
	EffectiveUID() uint32
	LoadPortal(string) (config.Portal, error)
	VerifyPortalFiles(config.Portal, string) error
	InspectHost(config.Portal) (hostcheck.Report, error)
	PortalAccount(config.Portal) (accountIdentity, error)
	InspectTenantAccount(config.Tenant) (accountIdentity, bool, error)
	EnsureTenantAccount(context.Context, config.Tenant) (accountIdentity, error)
	EnsureCapacity(context.Context, string, int) error
	EnsureTenantConfig(context.Context, config.Portal, config.Tenant) error
	VerifyTenantConfig(context.Context, config.Portal, config.Tenant) error
	AssignQuota(string, uint32, uint64) (hostcheck.ProjectQuotaStatus, error)
	VerifyQuota(string, uint32, uint64) (hostcheck.ProjectQuotaStatus, error)
	Systemd() systemdctl.Controller
	ListUserHostUnits(context.Context) ([]string, error)
	AcquireCLIProxyLock(string) (io.Closer, error)
	LookupGroup(string) (*user.Group, error)
	Now() time.Time
}

type stageVerifier func(context.Context, string, string, string, uint32) (winmigration.PublicationStage, error)

type runner struct {
	env         environment
	layout      layout
	verifyStage stageVerifier
	production  bool
}

func (o Options) validate() error {
	if o.Check == o.Apply {
		return errors.New("select exactly one of --check or --apply")
	}
	if o.Apply && o.Confirm != ConfirmPublication {
		return errors.New("--apply requires the exact publication confirmation token")
	}
	if o.Check && o.Confirm != "" {
		return errors.New("--confirm is valid only with --apply")
	}
	return nil
}
