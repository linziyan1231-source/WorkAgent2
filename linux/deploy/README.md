# Production deployment runbook

The templates install the WorkAgent2 control plane under `/opt/workagent`, `/etc/workagent`, `/var/lib/workagent`, `/srv/workagent` and `/run/workagent`. Commands below never place a password or API key in an argument.

## 1. Build and approve

Run the checksum-pinned default `quality` gate from a clean committed revision:

```bash
scripts/install-ci-tools.sh /absolute/private/tool-dir
GO_BIN=/absolute/go1.26.5/bin/go \
GITLEAKS_BIN=/absolute/private/tool-dir/gitleaks \
GOVULNCHECK_BIN=/absolute/private/tool-dir/govulncheck \
SHELLCHECK_BIN=/absolute/private/tool-dir/shellcheck \
scripts/source-gate.sh /absolute/empty/artifact-dir
```

The default quality gate deliberately leaves the artifact directory empty. Obtain production source-gate evidence only from the final, cache-free `verify` CI job after its separate quality job passed the identical revision; a locally forced artifact-mode directory is rehearsal output, not production authorization. The final CI archive contains ten online control-plane binaries (`portal`, `userhost`, `admin`, `provision`, `import-stage`, `release`, `backup`, `secret`, `cliproxy`, `notification`), the health helper, protected host-preparation/preflight helpers and the exact non-secret configuration/deployment/docs tree under `control-plane`. The root-only `workagent-import-stage` publisher is part of the verified online control root but never runs as a service. It packages `workagent-capture-windows` and `workagent-migrate-windows` separately as root-only offline tools; never install either offline reader on the production service path. Build the shared payload with `scripts/assemble-shared-linux.sh`, which accepts only the exact CLIProxyAPI `7.2.81 / per-key-models.4`, `cpa-key-policy 0.4.5`, ChatForward, Node.js and `ws` hashes.

Do not assume that an RPM pipeline supplies missing evidence. Follow `docs/RELEASE_EVIDENCE.md` to build the complete control payload with scope `portal` and the complete shared payload with scope `shared`, then create each unsigned manifest and verify the full hash inventory. Never copy an uncommitted developer build over a running binary.

## 2. Prepare the host

Install the files in this directory into their normal systemd, sysusers.d and
tmpfiles.d locations before installing either fixed root. In particular, the
checked-in base unit must be installed exactly as
`/usr/lib/systemd/system/caddy.service`, with the companion drop-in at
`/usr/lib/systemd/system/caddy.service.d/workagent.conf`; an OS-vendor Caddy
unit is not an equivalent production contract. From the unpacked
final source-gate `control-plane` directory, install both versioned lifecycle
helpers and the independent edge-publication admission helper exactly once;
each installer uses an atomic no-replace hard link,
verifies an existing copy byte-for-byte, and never edits or replaces v1 in
place. Each power-crash state machine treats only an exact reserved-name,
single-link, `0600 root:root` work inode as uncommitted and deletion-authorized;
it fsyncs complete bytes before committing mode `0555`, which must always
verify byte-for-byte. Any symlink, hard link, foreign owner, other mode, or
conflicting destination fails closed. A future protocol must use a new
versioned path:

```bash
systemd-sysusers \
  /usr/lib/sysusers.d/workagent.conf \
  /usr/lib/sysusers.d/workagent-chatforward.conf \
  /usr/lib/sysusers.d/workagent-notification.conf
systemd-tmpfiles --create \
  /usr/lib/tmpfiles.d/workagent.conf \
  /usr/lib/tmpfiles.d/workagent-chatforward.conf \
  /usr/lib/tmpfiles.d/workagent-caddy.conf \
  /usr/lib/tmpfiles.d/workagent-monitoring.conf
/absolute/verified/final-source-gate/control-plane/admin/install-fixed-root-exec-v1
/absolute/verified/final-source-gate/control-plane/admin/install-recovery-activation-admission-v1
/absolute/verified/final-source-gate/control-plane/admin/install-edge-publication-admission-v1
systemctl daemon-reload
```

The tmpfiles pass creates the empty root-owned catalog, control, and shared
release-lock inodes, the empty single-link `root:cliproxyapi` mode-`0640`
CLIProxy migration and OAuth-writer lock inodes, plus the mode-`0700` edge
journal and permit directories;
it never creates either edge evidence file. Keep every WorkAgent service and
tenant instance stopped.
Prepare each complete release tree as a root-owned mode-`0555` sibling on the
same `/opt/workagent` filesystem, using the exact reserved name
`.control.stage-RELEASE_ID` or `.shared.stage-RELEASE_ID`. For the first
control install, execute the `workagent-release` binary whose hash and clean
embedded Git revision were verified from final source-gate evidence; do not
execute an untrusted copy from the candidate it is being asked to admit:

```bash
/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-install \
  --destination /opt/workagent/control \
  --staged-root /opt/workagent/.control.stage-CONTROL_RELEASE_ID

/opt/workagent/control/bin/workagent-release fixed-install \
  --destination /opt/workagent/shared \
  --staged-root /opt/workagent/.shared.stage-SHARED_RELEASE_ID
```

The command derives the exact production scope and consumer contract; verifies
the candidate manifest, root ownership, complete bytes, and current component
baseline against its own clean embedded 40-hex source revision; proves every
persistent consumer inactive without stopping it; then takes the fixed-channel
lock and performs a journaled same-filesystem rename. The first control install
expects no tenant instances. It does not accept an expected-current ID.

For upgrades, stop the same fleet first and bind the request to the observed
current release:

```bash
/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-install \
  --destination /opt/workagent/control \
  --staged-root /opt/workagent/.control.stage-NEW_CONTROL_RELEASE_ID \
  --expected-current-release CURRENT_CONTROL_RELEASE_ID

/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-install \
  --destination /opt/workagent/shared \
  --staged-root /opt/workagent/.shared.stage-NEW_SHARED_RELEASE_ID \
  --expected-current-release CURRENT_SHARED_RELEASE_ID
```

The admission executable must be the separately verified final source-gate
binary from the candidate's exact revision; an older installed control binary
cannot authorize a newer source revision. An interrupted pending operation
must be resumed with that same-revision admission binary from its protected
journal, never by manually renaming a tree. Repeat the identical
`fixed-install` invocation for an interrupted first install, or use the narrow
initial reconciler; it accepts only an actual pending first control-install
journal under both lifecycle locks and reads no Portal/tenant configuration.
Once protected tenant configuration exists, an upgrade journal is resumed
without `--initial`:

```bash
# Pending first control install before Portal/tenant configuration:
/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-reconcile \
  --destination /opt/workagent/control \
  --initial

# Pending control upgrade after protected configuration exists:
/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-reconcile \
  --destination /opt/workagent/control

# Explicit historical rollback (not candidate admission):
/opt/workagent/control/bin/workagent-release fixed-rollback \
  --destination /opt/workagent/control \
  --expected-current-release CURRENT_CONTROL_RELEASE_ID \
  --expected-previous-release PREVIOUS_CONTROL_RELEASE_ID
```

Use the install, non-initial reconcile, and rollback forms with destination
`/opt/workagent/shared`; `--initial` is control-only. A completed upgrade
preserves the immediately prior release tree at
`/opt/workagent/.control.previous` or `.shared.previous` and archives an older
previous tree under the transaction ID; no release tree is deleted or edited
in place. Reload and start services only after the JSON result identifies the
intended current release and a direct historical verification succeeds.

Install the OS package that provides `setfacl`; tenant configuration delivery fails closed without POSIX ACL support. Before provisioning any tenant, follow `docs/PRODUCTION_HOST.md`: run `scripts/production-host-prepare.sh --check`, archive the old synthetic deployment separately, and only then explicitly apply the dedicated 192 GiB sparse XFS image/mount contract. Never mount over a non-empty directory. The script verifies `prjquota`, POSIX ACLs, cgroup v2, systemd and `kernel.yama.ptrace_scope >= 2`, and preserves a 32 GiB backing-filesystem reserve. The ptrace restriction is mandatory because tenant supervisors retain an in-memory request verifier that must not be readable by same-UID agent subprocesses. `/opt/workagent/control/bin/workagent-admin verify-host` checks both the host and the exact loaded Portal service sandbox; startup rejects Portal file ownership, mode, ACL, manifest or unit-property drift.

For the initial Windows migration, do not recreate the reported tenants one at a time with `workagent-provision` and do not copy stage paths by hand. Keep every WorkAgent service/socket/timer, Caddy and CLIProxy stopped, retain the separately verified synthetic archive, and use the verified `workagent-import-stage --check` followed by explicit `--apply --confirm PUBLISH-WORKAGENT-MIGRATION` procedure in `docs/WINDOWS_DATA_MIGRATION.md`. The publisher creates/verifies all tenant accounts, configuration, drop-ins and XFS quotas before its first no-replace rename, publishes only the staged Portal database and tenant trees, creates the protected CLIProxy backup directory without touching backup files, records a durable resume journal, and starts nothing. Its `rollback_destination` is merely a reserved no-replace destination; it is not a backup receipt.

## 3. Install configuration and credentials

Install approved schema v5 `portal.json`, `policy.json`, brand assets and schema v2 `backup.json` as protected root-owned files. Install `chatforward.env` as `root:workagent-chatforward` mode `0640`, `notification.json` as `root:workagent-notification` mode `0640`, and the CLIProxy template as `root:cliproxyapi` mode `0640`; production preflight checks those exact identities, and the notification unit independently proves that its unprivileged UID can read the complete path before startup. `/etc/workagent` is execute-only (not listable) to other service identities, while every sensitive child directory retains its narrower mode. The checked-in non-secret production example fixes the public origin to `https://workagent.example.invalid`, max/idle runtime policy to `20`/`1800`, and provider egress to the existing mihomo HTTP proxy at `http://127.0.0.1:8118`; provisioning copies that exact policy into every tenant. Install the canonical WorkAgent2 `brand.json`, logo, dark logo, favicon and app icon under `/etc/workagent/branding/workagent`; each brand file must be a non-symlink regular file readable by the `workagent` service (for example root-owned mode 0644) and not writable by group or other users. Tenant files remain schema v5. Generate the backup encryption key and keep an offline escrow copy outside the archive and credential store:

```bash
/opt/workagent/control/bin/workagent-backup keygen --key-file /etc/workagent-backup/encryption.key
```

Generate and install the three internal service credentials directly into the host-bound encrypted systemd store. Each command creates 48 bytes of entropy in memory, base64url-encodes it, streams it to `/usr/bin/systemd-creds` over stdin, decrypts it back for constant-time verification, clears the plaintext buffers, and reports only the installed path:

```bash
/opt/workagent/control/bin/workagent-secret generate-install --name cliproxy-management-key
/opt/workagent/control/bin/workagent-secret generate-install --name chatforward-key
/opt/workagent/control/bin/workagent-secret generate-install --name notifications-key
```

Use `--rotate` to atomically replace an existing value during an approved coordinated rotation, then restart every consumer of that name and complete readiness/provider checks. Generated names are restricted to those three internal credentials. The optional administrator master-password hash is not randomly generated; install its already-Argon2id value from a temporary root-owned mode-0600 file with the manual `install --name admin-master-password-hash --input-file ...` flow. Install `workagent-portal.service.d/credentials.conf` from the example after the credentials exist.

`workagent-tenant-catalog-ready.target` is a static boot-lifetime latch. Its first activation requires the root-only tenant reconciliation oneshot to finish; it deliberately does not use `StopWhenUnneeded`. Portal, UserHost, and privileged manual activation paths require the active latch and then retain the shared catalog lock from the clean-marker check through systemd activation and readback. A fixed-control-root change must first drain the latch with the rest of the control fleet.

Every tenant catalog change freezes the entire sorted final catalog—not only the requested tenant—into one canonical global intent containing each member's payload plus exact Before and Desired states. That serialized full-generation intent has a deterministic 64 MiB aggregate limit. The limit is checked while the catalog is still read-only, before the marker, directory, ACL, stage, or target can be changed; a generation that does not fit is rejected without mutation. Because every supported create, migration, recovery, resource update, and rollback uses this same full-catalog transaction path, a successful generation can always be replayed within the same bound.

Production schema v5 requires both integrations: ChatForward must be the loopback service at `127.0.0.1:3210`, and the notification source must be an approved HTTPS or loopback endpoint. Optional Windows-parity administrator impersonation accepts only an Argon2id hash loaded as the `admin-master-password-hash` encrypted systemd credential; set `admin_master_password_hash_file` to its canonical `/run/credentials/...` path. It is disabled when the field is absent.

The backup destination must be a mounted NFS/NFS4/CIFS/SMB3/Ceph/approved remote FUSE filesystem rooted at `/mnt/workagent-backup` and distinct from the local backup filesystem. The service assertion, strict configuration, and backup implementation fail closed when the mount is absent, `require_remote_filesystem` is not true, or the path is merely another local directory. The current host has no approved remote mount, so production activation remains blocked. Quiesced backup writes the previously active WorkAgent unit list to root-only `/run/workagent-backup/quiesce.json`; the service's `ExecStopPost` resumes it after normal failure or forced termination, and the next backup also recovers a stale journal before stopping anything. Stop-post recovery first proves the externally held activation lock, then takes the catalog/control read snapshot in the normal lock order, verifies that the running `workagent-backup` inode is the current control release executable, and proves every activation/recovery protocol clean before it may read the quiescence journal or invoke systemd. The unit's outer shared catalog/control locks are compatible with and ordered identically to that in-process authenticated snapshot; both layers remain held through journal settlement.

## 4. Publish verified releases

Every release root must be immutable, root-owned and contain its component revision list before manifest creation. The manifest is unsigned; verification replays the complete per-file SHA-256 inventory recorded in it.

Example runtime manifest invocation (schema numbers are release-specific and
must come from the migration owner). Use the separately verified final
source-gate binary for `APPROVED_40_HEX_REVISION`; the command rejects a source
revision that differs from its own clean embedded Git revision:

```bash
/absolute/verified/final-source-gate/control-plane/bin/workagent-release manifest \
  --root /opt/workagent/aionui/releases/RELEASE_ID \
  --release-id RELEASE_ID \
  --source-revision APPROVED_40_HEX_REVISION \
  --branding-version APPROVED_BRAND_VERSION \
  --policy-version APPROVED_POLICY_VERSION \
  --scope runtime \
  --data-schema-version WRITE_SCHEMA \
  --minimum-readable-data-schema MIN_READ_SCHEMA \
  --maximum-readable-data-schema MAX_READ_SCHEMA \
  --components /absolute/protected/components.json \
  --required workagent-builtin-assistants/assistants.json \
  --required workagent-builtin-assistants/rules/aionui-assistant.en-US.md \
  --required workagent-builtin-assistants/rules/aionui-assistant.ru-RU.md \
  --required workagent-builtin-assistants/rules/aionui-assistant.zh-CN.md \
  --required static/index.html \
  --required-executable bin/aioncore \
  --required-executable bin/aionui-web \
  --required-executable bin/codex \
  --required-executable bin/kimi \
  --required-executable bin/python3
```

Portal's Renderer and every UserHost resolve the release JSON pointer at startup. The production runtime lock is AionUi `2.1.0-beta.editfork.21`, whose static/assistant payload is byte-verified against the read-only Windows `.20` reference and whose Linux host adds the fd3 possession-channel boundary, plus the Linux compatibility upgrade AionCore `v0.1.42-editfork.10`, `@noble/hashes` 2.2.0, Codex 0.144.4, Kimi Code `0.29.1-fork-steer.1`, and Python 3.13.13. The `.21` Renderer must contain the locked pure-JS SHA-256 upload path and must not depend on `crypto.subtle`; `.21/.10` must pass the 1 GiB limit, 16 MiB chunk, three-concurrent-upload, SHA/offset, 24-hour resume, idempotent init/complete and no-overwrite acceptance suite. A version string alone is not browser evidence. The shared lock also covers CLIProxyAPI 7.2.81, `per-key-models.4`, `cpa-key-policy` 0.4.5, ChatForward `zombie-reap-20260725-2329`, extension 0.16.0, Node.js 24.15.0 and ws 8.21.1. Do not claim production activation until every required verified component and external login prerequisite is present at its approved version.

## 5. Provision tenants and users

Create a canonical UUID, a unique locked account and an unused XFS project ID for each tenant:

```bash
/opt/workagent/control/bin/workagent-provision tenant \
  --tenant-id TENANT_UUID \
  --runtime-user workagent_tenant_NAME \
  --project-id UNIQUE_PROJECT_ID \
  --disk-hard-limit-bytes BYTES \
  --initial
```

The command creates and locks a same-name, nologin account; rejects unexpected supplementary groups; creates any missing global capacity leases; assigns/read-verifies the hard quota; writes the root-owned schema v5 tenant configuration with a read-only ACL for exactly that runtime UID; writes identity and resource-limit drop-ins; and reloads systemd. `--initial` is a narrow first-activation mode: it holds the release-configuration lifecycle lock, requires that `current.json` does not exist, verifies durable identity/storage/quota and the loaded socket/service sandbox, and refuses `--start`; it never resolves or runs the not-yet-activated runtime. Without `--initial`, provisioning also verifies the active release. Add `--start` only after activation and all verification passes. `--memory-bytes`, `--cpu-percent` and `--active-processes` default to the Windows parity values of 6 GiB, 50% and 64.

Create the first Portal administrator from a protected password file:

```bash
/opt/workagent/control/bin/workagent-admin init-admin \
  --tenant-config /etc/workagent/users/TENANT_UUID.json \
  --username USERNAME \
  --password-file /absolute/root-only/password.input \
  --initial
```

`init-admin --initial` is root-only, requires the same missing pointer and verified tenant infrastructure, and holds the lifecycle lock until the enabled administrator is durable. After reading the protected password input it permanently drops to the configured `workagent` identity before creating the Portal database, SQLite sidecars, audit sink or runtime lock, so no root-owned state can strand Portal startup. For a Windows migration, the protected imported Portal database already contains the migrated enabled identities and administrators; do not run either fresh-provisioning command when those identities were published. After the documented CLIProxy migration verification has durably published its short-lived, root-only live-verification receipt, run `workagent-admin activate-tenant-catalog` once to revalidate that receipt and durably map the complete imported enabled-state catalog to systemd before starting every enabled socket. Use `create-user`, `set-password`, `set-enabled`, `set-limits`, `runtime-status`, `runtime-start`, `runtime-stop`, `runtime-restart` and `set-chatgpt-pro-limit` for later lifecycle operations. Each enabled-state change first persists a complete previous/desired transaction, commits the database bit and session revocation as its linearization point, replays systemd to that complete state, and removes the transaction only after exact full-catalog readback. Re-enablement additionally verifies identity, ACL, release, drop-ins and the live socket before success.

## 6. Initial activation and upgrades

Generate a preflight report while the target and all configuration are stable. Preflight infers the first-activation path from the protected absence of `current.json`; pass `--initial` only to the subsequent activation command. Later activations additionally require a fully decrypted and verified backup no older than four hours. Preflight, activation and rollback accept only the protected Portal Renderer channel (`releases_root`, pointer and `runtime` scope), require every tenant to use that exact channel, and derive an exact sorted contract from the protected Portal and tenant files (the checked-in configuration baseline is 5 data files and 5 executables; tenant customization may only extend that derived set through protected configuration). Optional repeated `--required` and `--required-executable` arguments are assertions only and must equal the derived contract exactly. The schema-v4 preflight report binds that contract, release manifest, Portal and every tenant config, backup config and key, brand config/assets, policy identity/config, and release pointer. Activation reloads and compares all evidence while holding the configuration lifecycle lock before it may move the pointer. Fixed control/shared roots use direct release-root verification and are replaced atomically instead of using this pointer lifecycle.

For every upgrade, make the configured `/notification` source return a new notice whose ID is `workagent-upgrade-RELEASE_ID`, message is exactly `系统正在升级，正在进行的任务可能会中断`, and `published_at` is RFC3339. Publish it at least 60 seconds before preflight/cutover. Put only the value of a currently authenticated administrator's `__Host-aionui-portal` cookie in a temporary root-owned 0600 file. Preflight fetches `/api/portal/me/notifications` over the local trusted Portal boundary, requires that exact notice, and binds its ID, publication time and observation time into the protected report. Remove the temporary session file through the approved secret-disposal procedure after preflight.

```bash
/opt/workagent/control/bin/workagent-release preflight [channel and release options] \
  --portal-config /etc/workagent/portal.json \
  --backup-config /etc/workagent/backup.json \
  --maintenance-session-file /absolute/root-only/portal-session.input \
  --output /var/lib/workagent/preflight-UNIQUE_RELEASE_ID.json

/opt/workagent/control/bin/workagent-backup create --quiesce-systemd

/opt/workagent/control/bin/workagent-release activate [same channel and release options] \
  --preflight /var/lib/workagent/preflight.json \
  --backup-archive /absolute/verified/archive \
  --backup-receipt /absolute/verified/receipt
```

For the first activation, omit `--maintenance-session-file` and pass `--initial` to `activate`; there is no existing user session to notify. Immediately after the release pointer is active, and before attempting `provision --start`, `runtime-start`, or Portal startup, close the bootstrap enabled-state gap with `/opt/workagent/control/bin/workagent-admin activate-tenant-catalog --initial --config /etc/workagent/portal.json`. Initial mode requires exactly one enabled administrator and proves that no Windows-migration report, plan, publication journal, receipt or receipt stage exists. This full-catalog transaction is required because `init-admin --initial` deliberately committed an enabled Portal identity while the not-yet-resolvable runtime socket remained disabled. It is idempotent and is the only supported first-start bridge; do not manually enable the socket or use `--initial` for imported state.

The report output is immutable and must not already exist. Its parent must be a protected directory owned by the invoking root identity; the command rejects symbolic-link paths, hard-link aliases and any alias of a bound input.

Activation uses compare-and-swap on the runtime pointer and rejects a target that cannot read the active data schema. Portal, shared and combined pointer activation are rejected because those payloads are fixed-root atomic installations. Affected Portal, sockets and UserHost services must be inactive before the runtime pointer moves. Rollback applies the same drain gate, re-verifies both releases against the re-derived consumer contract, and is allowed only when the previous release can read the schema the active release may have written; otherwise restore the verified pre-upgrade backup onto a blank host.

The tracked tmpfiles rules pre-create `/run/workagent/release-config.lock` and `/opt/workagent/aionui/current.json.lock` as empty, single-link `0600 root:root` inodes. On the production systemd 255 host, Portal and every UserHost receive both through named read-only `OpenFile=` descriptors. Startup takes the configuration lock shared until all protected configuration and the release resolve successfully, then holds the runtime-channel lock shared for the full process lifetime. Preflight takes the configuration lock shared; configuration writers, activation and rollback take it exclusive. Pointer switching is nonblocking and fails if any runtime consumer still holds the channel. Never unlink, replace, populate, hard-link, chmod or bypass either lock; run tmpfiles and the read-only production preflight before enabling services.

## 7. Verify and rehearse recovery

A validation-only recovery target must not already exist. The install pass normally uses a different fresh target. If an install is killed after the target was published, repeat the exact same archive, receipt and target: recovery accepts it only after proving every byte, entry, mode and archived UID/GID against the authenticated manifest. It never adopts a changed or extra entry. Installation is allowed only on a blank, package-prepared host where the production binaries, unit templates and every immutable release named as either `current` or `previous` already exist. `mihomo.service` must be active/running; Caddy, the backup and health services/timers, every WorkAgent application service and the exact restored tenant service/socket set must be loaded and inactive/dead with no residual process. Every future service/socket/timer entrypoint must also have `UnitFileState=disabled`, while non-enableable helper and tenant service units must be exactly `static`; an inactive but enabled unit is unsafe because it could start after a reboot outside the activation journal. A foreign or missing tenant instance blocks recovery.

```bash
/opt/workagent/control/bin/workagent-backup restore \
  --archive /mnt/workagent-backup/off-host/ARCHIVE \
  --receipt /mnt/workagent-backup/off-host/RECEIPT \
  --target /var/lib/workagent-backup/restore-RESTORE_ID

/opt/workagent/control/bin/workagent-backup restore \
  --archive /mnt/workagent-backup/off-host/ARCHIVE \
  --receipt /mnt/workagent-backup/off-host/RECEIPT \
  --target /var/lib/workagent-backup/restore-install-RESTORE_ID \
  --install \
  --confirm INSTALL-RESTORED-WORKAGENT
```

The installer never overwrites conflicting state. It recreates exact tenant UID/GID accounts, locked/nologin/group shape, capacity leases, ACLs, systemd drop-ins and XFS quotas, while normalizing archived Portal, notification, ChatForward and CLIProxy ownership to their package-created identities. It restores the encrypted-backup copy of the CLIProxy tenant-key/quota/usage policy while holding the exclusive CLIProxy lifecycle lock. Backup holds every Portal/tenant runtime lock, the CLIProxy migration lock and shared locks on all canonical release pointers; one shared runtime pointer is archived once, and the independent Renderer pointer is always included. Both current and previous Renderer/tenant releases are verified before backup and again before recovered services start.

Activation is crash-recoverable. Before it may record intent or publish a permit, recovery authenticates the fixed-control manifest and the entire installed systemd fleet: the mount, every core/cutover unit, every timer/target and the exact restored tenant service/socket set. Every fragment and drop-in must be the exact release or canonically derived bytes at its one allowed `FragmentPath` or complete `DropInPaths` set, as a root-owned, single-link `0644` file; every invoked WorkAgent admission/lifecycle helper must be the exact release bytes at its fixed `/usr/libexec` path as a root-owned, single-link `0555` file. Those paths and every ancestor are descriptor-bound, non-linked, root-owned and not group/world-writable. The manager must report `NeedDaemonReload=no`, the required baseline `UnitFileState`, the mount's exact `What`/`Where`/`Type`/`Options`, each socket's exact listen address, owner/group, modes, backlog, remove-on-stop, `Accept=no` and triggered service, the exact service `Type`/`User`/`Group`, and the complete ordered `ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecStop`, `ExecStopPost` and `ExecReload` vectors, including the ordinary and extended privileged/ignore-failure forms. Manager properties, source digests, file identities and ancestor identities are read twice and must remain identical. The same full proof is repeated after the durable journal, after permit publication, before enablement, after exact enablement readback, around the catalog-ready target, immediately before and after every individual start, and once more both before and after permit revocation. A successful `systemctl` exit alone is never considered durable proof.

The exclusive install lock is `/run/workagent-backup/recovery-install.lock`; recovery persists the exact allow-listed activation/rollback set to root-only `/var/lib/workagent-backup/recovery-activation.json`, including both tenant sockets and the services that socket or Portal traffic may activate. It then atomically publishes and exclusively holds `/run/workagent-backup/recovery-activation.permit`, whose canonical schema-v2 content binds this boot ID, the durable journal inode and the exact held recovery-install lock inode. Every recovery-activated service runs `/usr/libexec/workagent-core-activation-admission-v1` first and `/usr/libexec/workagent-recovery-activation-admission-v1` second as privileged pre-start boundaries. With no recovery journal the recovery helper admits ordinary startup; with a journal it requires the safe matching permit plus conflicting exclusive owners of that permit, its bound recovery-install lock and the global activation lock. A generic administrator holding only the activation lock—or relocking a stale same-boot permit while substituting another install-lock inode—is therefore not recovery authorization. Reboot removes the volatile permit while retaining the journal, and SIGKILL leaves an unlocked same-boot permit; both states block every partial-recovery entrypoint. Tenant sockets additionally require and follow `workagent-tenant-catalog-ready.target`, so they cannot listen or socket-activate UserHost before that same admission and reconciliation boundary.

On the next serialized invocation, crash replay first disables every journaled enableable unit, stops sockets before services, stops the catalog-ready target, and explicitly stops and proves the reconcile oneshot inactive. It then reconstructs the contract from the control release assets plus the installed Portal/tenant catalog and must prove the complete baseline manager/source contract before re-reading the unchanged journal and removing it. Any stop, disable, release-source, manager-cache, topology or journal-identity failure retains the journal and therefore keeps partial-recovery entrypoints blocked. Restore the exact package files, run the controlled daemon reload, and rerun authenticated recovery; never manually delete the journal. The normal commit revokes the permit before removing the journal and syncing its persistent parent, only after CLIProxy, notification, ChatForward, every enabled tenant socket, the ChatForward browser and Portal have passed their systemd/readiness gates and the final commit checks. Production preflight blocks whenever either recovery artifact or the tenant-activation transaction journal is present or cannot be proved absent. The JSON result reports each internal component that started. Caddy and the backup/health services and timers deliberately remain stopped and disabled: internal restoration is not permission to publish traffic or declare external production readiness before new-host authentication and acceptance.

Immutable release trees and the offline backup-encryption key are intentionally not restored from application state. Before the install pass, run the three `workagent-secret generate-install` commands on the blank host; their systemd ciphertext is host-bound and absent from the backup. CLIProxy provider OAuth files, both parent/child paths that could capture them, the ChatForward browser profile/cache, systemd credential ciphertext and the systemd host key are all excluded. Re-run provider OAuth with the fixed transient-unit procedure in `docs/CLIPROXY_OAUTH_LINUX.md` and perform the one-time ChatGPT login in `docs/CHATFORWARD_LINUX.md` after internal recovery.

## 8. Start and verify

```bash
/opt/workagent/control/bin/workagent-admin verify-host
/opt/workagent/control/bin/workagent-admin verify-tenant --tenant-id TENANT_UUID
# Complete docs/CLIPROXY_OAUTH_LINUX.md and docs/CHATFORWARD_LINUX.md first.
# Only after local/provider acceptance and approved edge-gate authorization:
/opt/workagent/control/bin/workagent-admin service-action --action enable-now --unit caddy.service \
  --confirm PUBLISH-WORKAGENT-EDGE
/opt/workagent/control/bin/workagent-admin service-action --action enable-now --unit workagent-backup.timer
/opt/workagent/control/bin/workagent-admin service-action --action enable-now --unit workagent-healthcheck.timer
```

The Caddy command is an explicit edge-publication commit, not a convenience
start. It requires the exact Portal listener/origin represented by the release
Caddyfile, performs a controlled systemd manager reload, authenticates the
manager-loaded Caddy and Portal unit definitions plus their exact release
fragments/drop-ins, and binds the protected policy/brand IDs and the complete
tenant activation catalog to one unchanged Portal generation. Under the
exclusive global activation lock it first reconciles only canonical stale edge
evidence, then publishes cross-inode, current-boot evidence at root-only
`/var/lib/workagent-edge/publication.json` and
`/run/workagent-edge/publication.permit` while retaining an exclusive permit
lock. It synchronously enables Caddy, proves it is enabled but inactive, and
issues exactly one nonblocking start; it never uses `enable --now`, restart, or
a background watcher.

Caddy's first privileged
`ExecStartPre=+/usr/libexec/workagent-edge-publication-admission-v1` command
authenticates those exact evidence inodes and both exclusive locks. Its
synchronous privileged
`ExecStartPost=+/usr/libexec/workagent-edge-publication-admission-v1 --watch $MAINPID`
command then remains the systemd start control process while the publisher
proves the unit is exactly `activating/start-post`, with one unchanged
invocation, MainPID, executable and start timestamp. The publisher compares the
running Caddy admin-API configuration with the same release Caddyfile through the
protected Unix socket both before and after an actual trusted-TLS `/readyz`
request dialed to loopback TCP 443 with the production SNI; the Portal
generation, Caddy generation, policy/brand IDs, provider readiness,
ChatForward, notifications and every enabled tenant must remain exact across
that proof. Reaching `active` before commit is a failure, because it would mean
the blocking watcher was bypassed.

Commit removes and fsyncs the durable journal first, then unlinks the volatile
permit as its final nonblocking mutation and releases the permit lock. The
post-start watcher succeeds only after both names are absent, both pinned
inodes and payloads remain exact, the activation authority remains held, and
the permit is unlocked. A publisher crash or evidence/lock change makes the
post-start command fail, so systemd fails the start and cleans the Caddy
cgroup. `TimeoutStartSec=6min` bounds a stopped publisher; the publisher's
five-minute deadline expires first. After commit, the command accepts only
the same generation becoming `active/running`. Any proof or commit failure is
compensated with a proved `disable --now`; the exact enablement-symlink
directory is fsynced and rechecked before canonical crash evidence is cleared,
so a power loss cannot resurrect an unproved edge. Backup and health timer
`enable-now` failures retain their
separate idempotent durable roll-forward semantics: if persistent timer
enablement committed but activation did not, rerun the exact command before
cutover.

Ordinary `verify-tenant` is the online account, release, configuration and loaded-unit verification used after activation; it deliberately accepts the tenant's expected running service. Only the exact systemd `ExecStartPre` command adds `--require-quiescent`, which enables the root-only process boundary before UserHost starts. Its executable retains the systemd `+` prefix: on the production systemd 255 host this was verified to run the pre-start check with host-root process visibility even though the main service uses a non-root `User=`, `ProtectProc=invisible` and `ProcSubset=pid`; the same read of another UID's `/proc/PID/status` fails without `+`. Quiescent mode scans the complete process table twice with stable PID start-time evidence and rejects startup if the tenant's dedicated runtime UID appears as any process real, effective, saved or filesystem UID. Unreadable or malformed process evidence, excessive process-table size, persistent PID churn or exhausted bounded rescans fail closed; ordinary processes that disappear during a scan trigger a fresh scan instead of a permanent false failure. The locked runtime UID must not be reused outside its one tenant service, and `workagent-userhost@.service` must retain `KillMode=control-group` so a stopped activation cannot deliberately leave same-UID descendants behind. The check reports no process command line or environment content.

The recovery installer starts `cliproxyapi.service` first; its startup renders only a bcrypt management hash, verifies the exact loopback/build/plugin/state contract, reconciles the 16 Windows-managed aliases, and read-verifies them before systemd declares startup complete. Install the tracked Caddyfile and publish only shared HTTPS 443 through the approved reverse proxy, forwarding to Portal's cleartext loopback TCP listener. TCP 80 remains untouched; ACME must use TLS-ALPN-01 and fails closed when public 443 is unavailable. Portal rejects non-loopback listeners, direct production TLS, untrusted proxy CIDRs and missing forwarded HTTPS. UserHost, backend, CLIProxy, and integration endpoints remain loopback/UDS-only. Install the health timer, monitoring rules, bounded journald policy, and Caddy rolling-log directory. A green local `/readyz`, fresh provider OAuth, successful ChatGPT login, independent external TLS/WebSocket evidence, fresh verified off-host backup metric and successful two-tenant browser/provider acceptance are mandatory before traffic cutover is declared complete.

The CLIProxy service holds a nonblocking shared `flock` on the root-owned `/run/workagent/cliproxy-migration.lock` for its full process lifetime. Offline migrated quota-state installation takes the exclusive lock and rechecks that the service is inactive before replacing state; never remove, relax or bypass this lock to force a cutover.

Codex and Kimi provider-login transient units receive
`/run/workagent/cliproxy-oauth.lock` only as the exact named read-only fd 7,
after the catalog, control, shared, and migration descriptors. The immutable
fixed-root supervisor validates its `root:cliproxyapi` mode-`0640`, empty,
single-link inode and unchanged path identity, then takes a nonblocking
exclusive lock after the migration shared lock and retains it until the login
child exits. A duplicate or cross-provider login fails with status 75; never
unlink, replace, chmod, hard-link, populate, reorder, or bypass this writer
gate.

## Socket activation identity

The socket is created by systemd with owner `workagent` and mode 0600. Each UserHost service is assigned a dedicated tenant account by a root-owned drop-in. The template defaults to `workagent-disabled`, so a missing identity override fails closed.

The UserHost template intentionally does not set `RestrictSUIDSGID=yes`: on the audited systemd build that directive blocked `openat2`, removing the stronger path-confinement primitive. `NoNewPrivileges`, an empty capability set, read-only system hierarchy and a dedicated UID remain enabled.
