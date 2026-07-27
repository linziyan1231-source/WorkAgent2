//go:build linux

// Package wincapture implements the Linux-side, read-only final capture of a
// frozen Windows WorkAgent data set.  It deliberately has no operation that
// can stop, checkpoint, or write to the Windows host.
package wincapture

import "time"

const (
	SpecSchemaVersion = 1

	RolePortalDatabase = "portal_database"
	RolePortalWAL      = "portal_wal"
	RolePortalSHM      = "portal_shm"
	RolePortalConfig   = "portal_config"
	RoleNotification   = "notification_state"
	RoleChatForward    = "chatforward_state"
	RoleTenantTree     = "tenant_tree"
	RolePolicyState    = "cliproxy_policy_state"
	RoleCLIProxyConfig = "cliproxy_config"
	RoleCLIProxyAdmin  = "cliproxy_management_state"
	RoleExternal       = "external_workspace"
	RoleSupplemental   = "supplemental"

	SourceFile      = "file"
	SourceDirectory = "directory"

	ExcludeNodeModules        = "node_modules"
	ExcludePythonVenv         = "python_venv"
	ExcludePythonBytecode     = "python_bytecode_cache"
	ExcludePytestCache        = "pytest_cache"
	ExcludeMypyCache          = "mypy_cache"
	ExcludeRuffCache          = "ruff_cache"
	ExcludeDownloadCache      = "download_cache"
	ExcludeNPMCache           = "npm_cache"
	ExcludePNPMStore          = "pnpm_store"
	ExcludeExternalBackendEnv = "external_backend_venv"
)

// Spec is private operator input. Source paths, tenant destination leaves and
// local input paths are intentionally absent from all public reports.
type Spec struct {
	SchemaVersion                  int             `json:"schema_version"`
	ExpectedTenantCount            int             `json:"expected_tenant_count"`
	ExpectedExternalWorkspaceCount int             `json:"expected_external_workspace_count"`
	Sources                        []Source        `json:"sources"`
	OAuthEvidence                  OAuthEvidence   `json:"oauth_evidence"`
	LocalFiles                     []LocalFile     `json:"local_files,omitempty"`
	Limits                         AggregateLimits `json:"limits"`
}

type Source struct {
	ID          string      `json:"id"`
	Role        string      `json:"role"`
	SourcePath  string      `json:"source_path"`
	Destination string      `json:"destination"`
	Kind        string      `json:"kind"`
	MaxFiles    int64       `json:"max_files"`
	MaxBytes    int64       `json:"max_bytes"`
	MaxTarBytes int64       `json:"max_tar_bytes"`
	Exclusions  []Exclusion `json:"exclusions,omitempty"`
}

type Exclusion struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// OAuthEvidence is inventoried but is never copied.  The remote protocol
// exposes only count, aggregate bytes, and a digest of anonymous records.
type OAuthEvidence struct {
	SourcePath string `json:"source_path"`
	MaxFiles   int64  `json:"max_files"`
	MaxBytes   int64  `json:"max_bytes"`
}

// LocalFile admits only a root-owned 0600 regular file with an exact digest.
// It is used for private, Linux-authored migration metadata such as the
// external-workspace mapping; it is never a route for Windows data.
type LocalFile struct {
	SourcePath  string `json:"source_path"`
	Destination string `json:"destination"`
	SHA256      string `json:"sha256"`
	MaxBytes    int64  `json:"max_bytes"`
}

type AggregateLimits struct {
	MaxSources      int   `json:"max_sources"`
	MaxTotalFiles   int64 `json:"max_total_files"`
	MaxTotalBytes   int64 `json:"max_total_bytes"`
	MaxCaptureBytes int64 `json:"max_capture_bytes"`
	MinFreeBytes    int64 `json:"min_free_bytes"`
}

type Summary struct {
	Files       int64  `json:"files"`
	Directories int64  `json:"directories"`
	Symlinks    int64  `json:"symlinks"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
}

type OAuthSummary struct {
	Files  int64  `json:"files"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Report is safe for stdout and operational logs. It contains neither source
// paths, destination leaves, tenant identifiers, nor OAuth filenames.
type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Status        string       `json:"status"`
	CaptureID     string       `json:"capture_id,omitempty"`
	SpecSHA256    string       `json:"spec_sha256"`
	Sources       int          `json:"sources"`
	Summary       Summary      `json:"summary"`
	OAuth         OAuthSummary `json:"oauth_evidence"`
	CompletedAt   time.Time    `json:"completed_at,omitempty"`
}

type CheckOptions struct {
	SpecPath string
}

type CaptureOptions struct {
	SpecPath      string
	Destination   string
	CaptureID     string
	Confirm       string
	WindowsFrozen bool
}
