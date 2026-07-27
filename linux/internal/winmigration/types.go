// Package winmigration builds an offline, reviewable Linux staging tree from
// a read-only WorkAgent Windows snapshot. It never publishes into production
// paths; deployment is a separate, privileged operation.
package winmigration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	ReportSchemaVersion  = 3
	TenantDiskLimitBytes = uint64(20 * 1024 * 1024 * 1024)
)

type Options struct {
	SnapshotRoot              string
	CaptureSpec               string
	StagingDir                string
	TenantDataRoot            string
	ExternalWorkspaceManifest string
	DryRun                    bool
	verifyCompletedCapture    completedCaptureVerifier
}

type PortalReport struct {
	Users                  int `json:"users"`
	AuditEvents            int `json:"audit_events"`
	LoginLimits            int `json:"login_limits"`
	ProLimits              int `json:"chatgpt_pro_limits"`
	ProUsage               int `json:"chatgpt_pro_usage"`
	ProEvents              int `json:"chatgpt_pro_events"`
	InvalidatedSessions    int `json:"invalidated_sessions"`
	InvalidatedOAuthStates int `json:"invalidated_oauth_states"`
}

type RewriteReport struct {
	SkillPaths                   int `json:"skills_path"`
	TeamWorkspaces               int `json:"teams_workspace"`
	ChannelWorkspaces            int `json:"assistant_sessions_workspace"`
	ConversationWorkspaces       int `json:"conversations_extra_workspace"`
	ConversationDefaultFiles     int `json:"conversations_extra_default_files"`
	CronWorkspaces               int `json:"cron_jobs_agent_config_workspace"`
	InvalidatedManagedProviders  int `json:"invalidated_managed_aion_providers"`
	UnmappedExternalWindowsPaths int `json:"unmapped_external_windows_paths"`
}

type ModelInvalidationReport struct {
	AppliedMarkers        int `json:"applied_markers"`
	PendingBundles        int `json:"pending_bundles"`
	CodexManagedAuthFiles int `json:"codex_managed_auth_files"`
	CodexManagedSettings  int `json:"codex_managed_settings"`
	KimiManagedConfigs    int `json:"kimi_managed_configs"`
}

type QuotaOverrideReport struct {
	Provider       string `json:"provider"`
	NewKeyID       string `json:"new_key_id"`
	DailyLimitUSD  string `json:"daily_limit_usd"`
	WeeklyLimitUSD string `json:"weekly_limit_usd"`
}

type ExternalWorkspaceSourceSummary struct {
	Files            int    `json:"files"`
	Directories      int    `json:"directories"`
	Bytes            int64  `json:"bytes"`
	Symlinks         int    `json:"symlinks"`
	SpecialFiles     int    `json:"special_files"`
	LargestFileBytes int64  `json:"largest_file_bytes"`
	GitBranch        string `json:"git_branch,omitempty"`
	GitTrackedFiles  int    `json:"git_tracked_files,omitempty"`
	GitIgnoredFiles  int    `json:"git_ignored_files,omitempty"`
	GitStatusEntries int    `json:"git_status_entries,omitempty"`
}

type ExternalWorkspaceReport struct {
	SourcePathSHA256    string                         `json:"source_path_sha256"`
	DestinationRelative string                         `json:"destination_relative"`
	Files               int                            `json:"captured_files"`
	Directories         int                            `json:"captured_directories"`
	Bytes               int64                          `json:"captured_bytes"`
	SourceTreeSHA256    string                         `json:"captured_tree_sha256"`
	ExcludedPaths       []string                       `json:"excluded_paths"`
	SourceSummary       ExternalWorkspaceSourceSummary `json:"source_summary"`
}

func (r RewriteReport) Total() int {
	return r.SkillPaths + r.TeamWorkspaces + r.ChannelWorkspaces + r.ConversationWorkspaces + r.ConversationDefaultFiles + r.CronWorkspaces + r.InvalidatedManagedProviders
}

type TenantReport struct {
	Username              string                    `json:"username"`
	WindowsSID            string                    `json:"windows_sid"`
	SourceDirectory       string                    `json:"source_directory"`
	TenantID              string                    `json:"tenant_id"`
	RuntimeUser           string                    `json:"runtime_user"`
	DataRoot              string                    `json:"data_root"`
	ProjectID             uint32                    `json:"project_id"`
	DiskHardLimitBytes    uint64                    `json:"disk_hard_limit_bytes"`
	Files                 int                       `json:"files"`
	Directories           int                       `json:"directories"`
	Symlinks              int                       `json:"symlinks"`
	Bytes                 int64                     `json:"bytes"`
	SourceTreeSHA256      string                    `json:"source_tree_sha256"`
	PathRewrites          RewriteReport             `json:"path_rewrites"`
	ModelInvalidation     ModelInvalidationReport   `json:"model_invalidation"`
	QuotaOverrides        []QuotaOverrideReport     `json:"quota_overrides"`
	SkippedTransientFiles []string                  `json:"skipped_transient_files,omitempty"`
	ExternalWorkspaces    []ExternalWorkspaceReport `json:"external_workspaces,omitempty"`
}

type Report struct {
	SchemaVersion                int            `json:"schema_version"`
	Status                       string         `json:"status"`
	CaptureID                    string         `json:"capture_id"`
	CaptureSpecSHA256            string         `json:"capture_spec_sha256"`
	CaptureManifestSHA256        string         `json:"capture_manifest_sha256"`
	CaptureCompletedAt           time.Time      `json:"capture_completed_at"`
	SourceFingerprint            string         `json:"source_fingerprint"`
	SourcePortalSHA256           string         `json:"source_portal_sha256"`
	SourcePortalWALSHA256        string         `json:"source_portal_wal_sha256"`
	SourcePortalSHMSHA256        string         `json:"source_portal_shm_sha256"`
	SourceCPAStateSHA256         string         `json:"source_cpa_state_sha256"`
	SourceExternalManifestSHA256 string         `json:"source_external_manifest_sha256"`
	OutputFingerprint            string         `json:"output_fingerprint,omitempty"`
	TenantDataRoot               string         `json:"tenant_data_root"`
	Portal                       PortalReport   `json:"portal"`
	Tenants                      []TenantReport `json:"tenants"`
	SessionsPolicy               string         `json:"sessions_policy"`
	OAuthStatesPolicy            string         `json:"oauth_states_policy"`
	PublicationPolicy            string         `json:"publication_policy"`
	LegacyKeyPolicy              string         `json:"legacy_key_policy"`
	LegacyUsagePolicy            string         `json:"legacy_usage_policy"`
}

type sourceUser struct {
	ID              int64
	Username        string
	UsernameNorm    string
	PasswordHash    string
	WindowsSID      string
	WindowsUsername string
	Enabled         int
	Admin           int
	AuthVersion     int64
	CreatedAt       int64
	UpdatedAt       int64
	LastLoginAt     *int64
}

type treeEntry struct {
	Path        string
	Kind        byte
	Mode        uint32
	Size        int64
	ModUnixNano int64
	SHA256      string
	LinkTarget  string
}

type plannedTenant struct {
	user               sourceUser
	sourceRelative     string
	windowsLeaf        string
	report             TenantReport
	entries            []treeEntry
	legacyCodexHash    string
	legacyKimiHash     string
	externalWorkspaces []plannedExternalWorkspace
}

type plannedExternalWorkspace struct {
	windowsPath         string
	sourceRelative      string
	destinationRelative string
	entries             []treeEntry
	report              ExternalWorkspaceReport
}

type plannedQuotaOverride struct {
	Username       string          `json:"username"`
	TenantID       string          `json:"tenant_id"`
	Provider       string          `json:"provider"`
	NewKeyID       string          `json:"new_key_id"`
	DailyLimitUSD  string          `json:"daily_limit_usd"`
	WeeklyLimitUSD string          `json:"weekly_limit_usd"`
	Usage          json.RawMessage `json:"legacy_usage"`
}

type migrationPlan struct {
	options                Options
	report                 Report
	portalPath             string
	portalWorkRoot         string
	portalSource           portalSourceSet
	cpaStatePath           string
	cpaStateSHA256         string
	externalManifestSHA256 string
	users                  []sourceUser
	tenants                []plannedTenant
	quotaOverrides         []plannedQuotaOverride
}

func normalizeOptions(options Options) (Options, error) {
	for label, value := range map[string]string{
		"snapshot root":     options.SnapshotRoot,
		"capture spec":      options.CaptureSpec,
		"staging directory": options.StagingDir,
		"tenant data root":  options.TenantDataRoot,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return Options{}, fmt.Errorf("%s must be an absolute, clean path", label)
		}
	}
	if options.SnapshotRoot == string(filepath.Separator) || options.StagingDir == string(filepath.Separator) || options.TenantDataRoot == string(filepath.Separator) {
		return Options{}, errors.New("filesystem root is not an allowed migration path")
	}
	if pathsOverlap(options.SnapshotRoot, options.StagingDir) {
		return Options{}, errors.New("staging directory and snapshot root must not overlap")
	}
	if options.StagingDir == options.TenantDataRoot {
		return Options{}, errors.New("staging directory must not be the production tenant-data root")
	}
	expectedManifest := filepath.Join(options.SnapshotRoot, "external-workspaces.json")
	if options.ExternalWorkspaceManifest != expectedManifest {
		return Options{}, errors.New("external workspace manifest must be exactly <snapshot-root>/external-workspaces.json")
	}
	return options, nil
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func Plan(ctx context.Context, options Options) (Report, error) {
	options.DryRun = true
	plan, err := buildPlan(ctx, options)
	if err != nil {
		return Report{}, err
	}
	defer plan.cleanup()
	return plan.report, nil
}
