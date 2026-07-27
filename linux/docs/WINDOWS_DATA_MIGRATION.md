# Windows data migration

The production cutover snapshot must be created through the frozen,
Linux-side-only procedure in [WINDOWS_FINAL_CAPTURE.md](WINDOWS_FINAL_CAPTURE.md).
An earlier copied snapshot or a successful read-only rehearsal is not final
cutover evidence.

`workagent-migrate-windows` converts a read-only WorkAgent Windows snapshot into an offline Linux staging tree. It does not publish files into production paths, start services, change ownership, assign XFS projects, or restore legacy credentials. Those remain explicit cutover steps after the staging report has been reviewed.

## Required snapshot layout

The snapshot root must be a real, private directory on one filesystem. The migration opens all source content beneath that directory without following symbolic links.

```text
snapshot/
  global/portal.windows.db                 # Portal schema v3
  global/portal.windows.db-wal             # required; may be zero bytes
  global/portal.windows.db-shm             # required SQLite companion
  cliproxy/cpa-key-policy-state.json       # legacy quota/usage state
  tenants/raw/<SID-or-account>/AionUiPortal/
  external-workspaces/                     # optional approved captures
  external-workspaces.json                 # optional; mode 0600
```

Every Portal user must map to exactly one tenant directory, and every tenant directory must map to a Portal user. The tool deterministically derives the Linux tenant UUID, runtime user, data root, and XFS project ID from the canonical Windows SID, then rejects any collision. Each tenant is assigned a 20 GiB hard-limit plan.

The Portal database, WAL, and SHM are one mandatory frozen source set. All three
are hashed into report schema v2 and its source fingerprint. Migration copies
the set into a private temporary directory and opens only that copy with
WAL-aware read-only SQLite semantics; it never opens the captured originals as
a database. This preserves committed rows that have not yet been checkpointed
while keeping the capture byte-for-byte unchanged. The exact original trio is
retained under `backups/`, and both stage verification and privileged
publication compare every archived file with the corresponding report hash.

## External workspace manifest

An Aion database path outside `C:\Users\<owner>\AionUiPortal` is rejected by default. An external workspace can be admitted only with an explicit private manifest inside the snapshot. The manifest binds one canonical Windows root to one Portal SID, one captured source directory, and one destination below the tenant's `workspace/` directory.

```json
{
  "schema_version": 1,
  "workspaces": [
    {
      "tenant_windows_sid": "S-1-5-21-111-222-333-1001",
      "windows_path": "C:\\projects\\approved-project",
      "source_relative": "external-workspaces/approved-project",
      "destination_relative": "workspace/imported/approved-project",
      "excluded_paths": [
        "node_modules",
        "backend/.venv"
      ],
      "source_summary": {
        "files": 1000,
        "directories": 200,
        "bytes": 50000000,
        "symlinks": 0,
        "special_files": 0,
        "largest_file_bytes": 5000000,
        "git_branch": "main",
        "git_tracked_files": 150,
        "git_ignored_files": 800,
        "git_status_entries": 0
      }
    }
  ]
}
```

The source summary must come from a read-only audit performed before capture. Sources with links or special files are not eligible. Captures may contain directories and regular files only; declared exclusions must be absent. Capture paths and Windows roots cannot overlap. The public report records the captured tree hash, counts, exclusions, audited summary, and a hash of the Windows path—not the Windows path itself. A private copy of the manifest is retained under `backups/external/`.

Dependency directories such as `node_modules` and virtual environments should be excluded from capture. Preserve source, lockfiles, Git metadata, application databases, business data, and required private configuration, then install dependencies from the retained lockfiles on Linux during cutover.

The final recapture contract is deliberately narrower than a generic name-based filter. A read-only inventory found that the dominant post-snapshot growth was installed JavaScript dependencies, with additional Python bytecode/test caches and package-download caches; those objects are reproducible from retained manifests and lockfiles. The final capture may therefore exclude only inventory-approved dependency roots (`node_modules`, Python environments positively identified as virtual environments, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.cache`, `.npm`, and `.pnpm-store`) plus the external-workspace exclusions recorded in its private manifest. Do not apply those names as an unreviewed recursive deletion rule: bind every excluded root to the final capture manifest and confirm that it is a rebuildable dependency/cache location.

Logs, every SQLite database and its WAL/SHM companions, Portal and CLI state, credentials/configuration that the migration sanitizers will process, source/workspace content, and all unknown or user-data categories remain in scope. In particular, never use broad `config`, `data`, `workspace`, `*.db`, `*.sqlite`, `*.log`, or unknown-file exclusions. Reinstall excluded dependencies on Linux from the captured lockfiles; absence of an approved lockfile is a capture blocker, not permission to discard the directory.

## Plan and stage

Run both commands as the migration operator with a private umask. All paths must be absolute and clean; the staging directory must not exist before the first write.

```bash
umask 077

/absolute/path/to/migration-tools/bin/workagent-migrate-windows \
  --snapshot-root /private/workagent/windows-snapshot \
  --staging-dir /private/workagent/linux-staging \
  --tenant-data-root /srv/workagent/users \
  --external-workspace-manifest /private/workagent/windows-snapshot/external-workspaces.json \
  --dry-run

/absolute/path/to/migration-tools/bin/workagent-migrate-windows \
  --snapshot-root /private/workagent/windows-snapshot \
  --staging-dir /private/workagent/linux-staging \
  --tenant-data-root /srv/workagent/users \
  --external-workspace-manifest /private/workagent/windows-snapshot/external-workspaces.json
```

Omit `--external-workspace-manifest` when no external workspace is needed. A dry run reads, validates, hashes, and reports without creating the staging directory. A real run builds a private sibling partial directory, verifies it, syncs it, and publishes it with one rename. Repeating the same command against an existing matching stage performs an integrity and source-plan check and returns the original completed report.

## Migration semantics

The stage preserves Portal user IDs, usernames, password hashes, enabled/admin state, auth versions, timestamps, login limits, audit history, and ChatGPT Pro limits, usage, and events while upgrading Portal schema v3 to v4. Audit Windows SIDs become deterministic tenant IDs.

All Windows Portal sessions and in-flight OAuth states are intentionally invalidated. Users authenticate again after cutover.

Within each Aion database, only these schema-aware locations are rewritten:

- `skills.path`
- `teams.workspace`
- `assistant_sessions.workspace`
- `conversations.extra.workspace`
- `conversations.extra.default_files`
- `cron_jobs.agent_config.workspace`

Message content is never searched or rewritten. Database rewrites run in a transaction with pre- and post-migration `quick_check` and foreign-key checks, and the original database is retained under `backups/tenants/<tenant-id>/`.

Legacy managed Codex and Kimi credentials, bootstrap markers, pending bundles, tenant key bindings, and managed Aion provider rows are invalidated. Custom CLI configuration and custom Aion providers are preserved. The private `cutover/cliproxy-quota-overrides.json` maps the archived quota limits and usage windows to deterministic new Linux key IDs; it contains no plaintext key and must be applied only after Portal has provisioned and verified the new tenant-bound keys.

## Privileged stage publication

`workagent-import-stage` is the only supported bridge from a completed Linux stage into the fixed production data paths. It is built into the signed control root, runs only when explicitly invoked by root, and is never a service. Supply both fingerprints from the independently reviewed report; the command does not infer or accept a newer stage silently:

```bash
/opt/workagent/control/bin/workagent-import-stage \
  --check \
  --stage /private/workagent/linux-staging \
  --expected-source-fingerprint REVIEWED_SOURCE_SHA256 \
  --expected-output-fingerprint REVIEWED_OUTPUT_SHA256

/opt/workagent/control/bin/workagent-import-stage \
  --apply \
  --confirm PUBLISH-WORKAGENT-MIGRATION \
  --stage /private/workagent/linux-staging \
  --expected-source-fingerprint REVIEWED_SOURCE_SHA256 \
  --expected-output-fingerprint REVIEWED_OUTPUT_SHA256
```

Before `--apply`, independently preserve the old synthetic Linux deployment in a recoverable archive and retain its receipt. The publisher does not create that archive and its JSON `rollback_destination` is only the protected, currently unused destination reserved for an operator-directed rollback; it must not be cited as backup evidence.

The check and apply paths require the canonical production Portal configuration, the dedicated `/srv/workagent/users` XFS mount with `prjquota`, sufficient free space, a blank Portal database target, and a tenant root containing no data outside the matching durable journal. Caddy, Portal, CLIProxy, notifications, both ChatForward units, backup/health units and timers, every reported UserHost service/socket, and every other discovered UserHost instance must be loaded but exactly `inactive/dead` with zero main/control PID. The publisher also takes the CLIProxy migration lock and Portal/UserHost runtime locks, and repeats the systemd proof immediately before every atomic activation. It never starts or enables a unit.

The private stage root and `report.json` must be root-owned mode `0700`/`0600` real objects. Validation strictly decodes the completed report, recomputes its source fingerprint and the full output fingerprint, verifies the archived Portal DB/WAL/SHM files against their three report hashes, checks Portal schema v4 with SQLite `quick_check` and foreign keys, cross-checks every Portal/report identity, inventories every tenant content/type/mode/hash/count, admits only non-escaping relative in-tenant links, and proves that managed legacy auth/provider state is absent. Only `portal/portal.db` and `tenants/<uuid>/...` are selected for publication. `backups/`, `cutover/`, `portal/audit.jsonl`, the report itself, legacy OAuth/session material and every other stage object are never copied by this command.

Before the first data rename, apply creates or strictly verifies all locked same-name runtime accounts, root-managed schema-v5 tenant configurations, systemd identity/resource drop-ins and 20 GiB XFS project quotas. Account mutation uses only fixed absolute root-owned, non-writable, non-symlink system executables under a minimal environment; caller `PATH` is never used. The namespace gate rejects every template-wide or per-instance UserHost socket drop-in and every service drop-in except the canonical identity/resource pair for a reported tenant. Copying is descriptor-relative with `openat2`/no-follow confinement, rejects devices/FIFOs/sockets and filesystem crossings, preserves only private `0700` directories plus `0600`/owner-executable `0700` files, and changes ownership to the dedicated tenant UID/GID. Portal is published as workagent-owned mode `0600`. Each temporary sibling and file is fsynced and content-read back before `RENAME_NOREPLACE`; no existing data target is overwritten.

The root-only mode-`0700` journal directory is `/var/lib/workagent/migration/import-stage`, with a mode-`0600` journal bound to the exact stage path and both fingerprints. Journal-bound partial files are prefix-verified and resumed; an empty root-owned directory left between `mkdir` and `chown` can be safely adopted, while any unexpected or conflicting residue fails closed for explicit archival. A crash after rename is recovered by verifying the final content against the journal before marking it published. Final success repeats all content hashes, SQLite checks, account/config/ownership and quota checks. It also safely creates and verifies `/var/lib/workagent/migration/backups/cliproxy/` as `0700 root:root`, but never creates, reads, replaces, chmods or removes a CLIProxy fingerprint backup file.

If publication stops after one or more atomic tenant activations, keep every unit stopped and do not delete or overwrite anything. Use the protected journal to identify exactly which targets were published, preserve them under the reported unused `rollback_destination` with no-replace moves, and restore only from the independently verified pre-cutover archive. Investigate and repeat `--check`; never edit the journal to force progress.

## CLIProxy quota and usage cutover

Install the completed `report.json` and its `cutover/cliproxy-quota-overrides.json` under `/var/lib/workagent/migration/`, owned by root with mode `0600`, and pre-create `/var/lib/workagent/migration/backups/cliproxy/` as `0700 root:root`. The deployed Portal database, every tenant root/`credentials` directory, CLIProxy state, `/run/workagent/cliproxy-migration.lock`, runtime accounts, policy, and management credential must already satisfy the production ownership contracts. The tracked tmpfiles rule creates the fixed lock as `0640 root:cliproxyapi`; the CLIProxy service can read/lock but cannot modify it, and holds a nonblocking shared lock for its entire process lifetime. Never create, replace, chmod, unlink, or bypass that lock during cutover.

Keep every UserHost stopped, leave CLIProxy running, and stage all one-time tenant bundles:

```bash
/usr/bin/systemd-run --quiet --wait --pipe --collect --service-type=exec \
  --unit=workagent-cliproxy-migration-stage.service \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=PrivateTmp=yes \
  --property='ReadWritePaths=/srv/workagent/users' \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
  --property=LoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/cliproxy-management-key.cred \
  /opt/workagent/control/bin/workagent-cliproxy stage-migration-bundles \
  --portal-config /etc/workagent/portal.json \
  --report /var/lib/workagent/migration/report.json \
  --plan /var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json \
  --credential %d/cliproxy-management-key \
  --timeout 5m
```

The service-local path `/run/credentials/cliproxyapi.service/...` is not a
host-shell credential interface: systemd mounts it only inside that service's
credential namespace. The fixed, collected transient unit above receives the
same host-bound ciphertext under its own `%d` credential directory. Never
decrypt the management credential to a temporary file, shell variable,
argument, or environment value. `ProtectSystem=strict` keeps the host
read-only except for the tenant roots that this stage must lock and update.

This root-only command validates the completed report, protected plan, schema-v4 Portal database, every Portal/report identity, deterministic key ID, runtime account and tenant ownership. It acquires all tenant runtime locks in stable tenant-ID order. For each tenant it either proves that an existing `credentials/model-bootstrap-v1.pending.json` still matches the live key preview and policy, or uses the management API to provision/rotate the two keys and atomically writes a tenant-owned `0600` pending bundle. Before accepting either path, it proves that both pending keys authenticate against the local `/v1/models` endpoint without contacting a model provider. It never logs or returns a plaintext key and performs no administrator impersonated login. A partial run is recoverable: a subsequent run read-verifies and reuses every completed handoff before continuing.

Do not start a UserHost yet. Explicitly stop CLIProxy and prove that systemd reports `inactive/dead` with zero main/control PID, then run the offline importer:

```bash
/usr/bin/systemctl stop cliproxyapi.service
/usr/bin/systemctl show --property=ActiveState --property=SubState --property=MainPID --property=ControlPID cliproxyapi.service

/opt/workagent/control/bin/workagent-cliproxy apply-migration-plan \
  --portal-config /etc/workagent/portal.json \
  --report /var/lib/workagent/migration/report.json \
  --plan /var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json
```

The importer first takes the fixed lock exclusively and nonblockingly, then rechecks systemd while holding it. A concurrent service start can therefore never overlap state replacement. It validates the protected v1 policy state and requires every newly provisioned deterministic key to have a valid new hash/preview. It changes only `daily_limit_usd`, `weekly_limit_usd`, and that key's archived `usage`; it refuses conflicting non-zero new-key usage and never restores a Windows hash or plaintext key. Before the first change it creates, without replacement, a root-owned `0600` backup under `/var/lib/workagent/migration/backups/cliproxy/`, named `cpa-key-policy-state.pre-windows-migration.<source-fingerprint>.json`; the CLIProxy service cannot alter this recovery evidence. The replacement and directory are fsynced, then parsed and checked again. Repeating a completed apply proves that applying the protected plan to that fingerprint-specific backup converges to the exact current state; repeating an interrupted pre-write apply requires the existing backup to match the exact pre-state.

Restart CLIProxy and, still before any UserHost starts, perform live readback:

```bash
/usr/bin/systemctl start cliproxyapi.service

/usr/bin/systemd-run --quiet --wait --pipe --collect --service-type=exec \
  --unit=workagent-cliproxy-migration-verify.service \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=PrivateTmp=yes \
  --property='ReadWritePaths=/srv/workagent/users' \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
  --property=LoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/cliproxy-management-key.cred \
  /opt/workagent/control/bin/workagent-cliproxy verify-migration-plan \
  --portal-config /etc/workagent/portal.json \
  --report /var/lib/workagent/migration/report.json \
  --plan /var/lib/workagent/migration/cutover/cliproxy-quota-overrides.json \
  --credential %d/cliproxy-management-key \
  --timeout 2m
```

Verification holds every tenant runtime lock and checks the protected
pre-OAuth CLIProxy build/plugin/policy/catalog contract, exact key
configuration and transferred quotas, usage totals/counters, per-alias
daily/weekly windows, pending-key previews through the loopback management
API, and live authentication of both pending keys against the local
`/v1/models` endpoint. It deliberately does not require provider OAuth: the
new host's provider credentials do not exist yet. Only after it succeeds may
UserHosts start and consume their pending bundles. If staging sees an applied
marker, apply sees active/conflicting state, or verification sees a
consumed/mismatched handoff, stop and investigate; never force rotation, reset
usage, edit the plan, or bypass a lock.

## Review and cutover handoff

Do not publish a stage unless `report.json` has `status: "complete"` and a non-empty output fingerprint. Review at least:

- Portal row counts and the explicit session/OAuth invalidation counts
- all SID-to-tenant identities, runtime users, data roots, project IDs, and 20 GiB limits
- zero `unmapped_external_windows_paths` for every tenant
- source and output fingerprints
- skipped SQLite transient files
- model invalidation counts and deterministic quota override IDs
- external workspace captured/audited summaries and exclusions

The separate privileged cutover must copy the staged Portal database and tenant trees into their production destinations, assign the recorded runtime ownership and XFS project quotas, install approved CLI packages, install retained project dependencies from lockfiles, execute the staged/offline/live CLIProxy sequence above, and start the normal readiness-gated services. The old Windows snapshot and private stage backups must remain unavailable to application users because they intentionally retain legacy encrypted and plaintext credential material for rollback/audit only.

After the internal migration verification above succeeds, complete both
host-local CLIProxyAPI provider OAuth flows by following
`docs/CLIPROXY_OAUTH_LINUX.md`, then complete the chat-mode account login.
Only the subsequent CLIProxy doctor, Portal/full readiness, real provider
requests and two-tenant browser acceptance can authorize cutover. No legacy
session, OAuth state, or managed API key should be restored to avoid those
logins.
