# Production deployment runbook

The templates install the WorkAgent2 control plane under `/opt/workagent`, `/etc/workagent`, `/var/lib/workagent`, `/srv/workagent` and `/run/workagent`. Commands below never place a password or API key in an argument.

## 1. Build and approve

Run the checksum-pinned source gate from a clean committed revision:

```bash
scripts/install-ci-tools.sh /absolute/private/tool-dir
GO_BIN=/absolute/go1.26.5/bin/go \
GITLEAKS_BIN=/absolute/private/tool-dir/gitleaks \
SYFT_BIN=/absolute/private/tool-dir/syft \
GOVULNCHECK_BIN=/absolute/private/tool-dir/govulncheck \
SHELLCHECK_BIN=/absolute/private/tool-dir/shellcheck \
scripts/source-gate.sh /absolute/empty/artifact-dir
```

The source gate produces ten online control-plane binaries (`portal`, `userhost`, `admin`, `provision`, `import-stage`, `release`, `backup`, `secret`, `cliproxy`, `notification`), the health helper, protected host-preparation/preflight helpers and the exact non-secret configuration/deployment/docs tree under `control-plane`. The root-only `workagent-import-stage` publisher is part of the signed online control root but never runs as a service. It packages `workagent-migrate-windows` separately as an offline tool; never install that offline reader on the production service path. Build the shared payload with `scripts/assemble-shared-linux.sh`, which accepts only the exact CLIProxyAPI `7.2.81 / per-key-models.4`, `cpa-key-policy 0.4.5`, ChatForward, Node.js and `ws` hashes.

Do not assume that an RPM pipeline supplies missing evidence. Follow `docs/RELEASE_EVIDENCE.md` to create SPDX, reproducible provenance and an authorized license report, then sign the complete control payload with scope `portal` and the complete shared payload with scope `shared`. `workagent-smoke` and `workagent-synthetic-runtime` are acceptance fixtures and must not enter any production release. Never copy an uncommitted developer build over a running binary. Production release remains blocked while `LICENSE_STATUS.md` is unresolved.

## 2. Prepare the host

Install the complete immutable signed control root at `/opt/workagent/control` and shared root at `/opt/workagent/shared`; each tree must be root-owned, non-writable and verify against `/etc/workagent/trust/release-signing.pub`. Stop every consumer, verify a staged sibling tree, preserve the previous signed tree, and atomically rename the new tree into place. Never edit an installed signed tree. Install the files in this directory into their normal systemd, sysusers.d and tmpfiles.d locations, then run:

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
systemctl daemon-reload
```

Install the OS package that provides `setfacl`; tenant configuration delivery fails closed without POSIX ACL support. Before provisioning any tenant, follow `docs/PRODUCTION_HOST.md`: run `scripts/production-host-prepare.sh --check`, archive the old synthetic deployment separately, and only then explicitly apply the dedicated 192 GiB sparse XFS image/mount contract. Never mount over a non-empty directory. The script verifies `prjquota`, POSIX ACLs, cgroup v2, systemd and `kernel.yama.ptrace_scope >= 2`, and preserves a 32 GiB backing-filesystem reserve. The ptrace restriction is mandatory because tenant supervisors retain an in-memory request verifier that must not be readable by same-UID agent subprocesses. `/opt/workagent/control/bin/workagent-admin verify-host` checks both the host and the exact loaded Portal service sandbox; startup rejects Portal file ownership, mode, ACL, signature or unit-property drift.

For the initial Windows migration, do not recreate the reported tenants one at a time with `workagent-provision` and do not copy stage paths by hand. Keep every WorkAgent service/socket/timer, Caddy and CLIProxy stopped, retain the separately verified synthetic archive, and use the signed `workagent-import-stage --check` followed by explicit `--apply --confirm PUBLISH-WORKAGENT-MIGRATION` procedure in `docs/WINDOWS_DATA_MIGRATION.md`. The publisher creates/verifies all tenant accounts, configuration, drop-ins and XFS quotas before its first no-replace rename, publishes only the staged Portal database and tenant trees, creates the protected CLIProxy backup directory without touching backup files, records a durable resume journal, and starts nothing. Its `rollback_destination` is merely a reserved no-replace destination; it is not a backup receipt.

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

Production schema v5 requires both integrations: ChatForward must be the loopback service at `127.0.0.1:3210`, and the notification source must be an approved HTTPS or loopback endpoint. Optional Windows-parity administrator impersonation accepts only an Argon2id hash loaded as the `admin-master-password-hash` encrypted systemd credential; set `admin_master_password_hash_file` to its canonical `/run/credentials/...` path. It is disabled when the field is absent.

The backup destination must be a mounted NFS/NFS4/CIFS/SMB3/Ceph/approved remote FUSE filesystem rooted at `/mnt/workagent-backup` and distinct from the local backup filesystem. The service assertion, strict configuration, and backup implementation fail closed when the mount is absent, `require_remote_filesystem` is not true, or the path is merely another local directory. The current host has no approved remote mount, so production activation remains blocked. Quiesced backup writes the previously active WorkAgent unit list to root-only `/run/workagent-backup/quiesce.json`; the service's `ExecStopPost` resumes it after normal failure or forced termination, and the next backup also recovers a stale journal before stopping anything.

## 4. Publish signed releases

Keep the Ed25519 private key offline. The public key is installed at `/etc/workagent/trust/release-signing.pub`. Every release root must be immutable, root-owned and contain its SPDX, provenance, approved license report and component revision list before manifest creation.

Example runtime manifest invocation (schema numbers are release-specific and must come from the migration owner):

```bash
/opt/workagent/control/bin/workagent-release manifest \
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
  --private-key /absolute/offline/release-signing.key \
  --public-key /etc/workagent/trust/release-signing.pub
```

Portal's Renderer and every UserHost resolve the signed JSON pointer at startup. The production runtime lock is AionUi `2.1.0-beta.editfork.21`, whose static/assistant payload is byte-verified against the read-only Windows `.20` reference and whose Linux host adds the fd3 possession-channel boundary, plus the Linux compatibility upgrade AionCore `v0.1.42-editfork.10`, `@noble/hashes` 2.2.0, Codex 0.144.4, Kimi Code `0.29.1-fork-steer.1`, and Python 3.13.13. The `.21` Renderer must contain the locked pure-JS SHA-256 upload path and must not depend on `crypto.subtle`; `.21/.10` must pass the 1 GiB limit, 16 MiB chunk, three-concurrent-upload, SHA/offset, 24-hour resume, idempotent init/complete and no-overwrite acceptance suite. A version string alone is not browser evidence. The shared lock also covers CLIProxyAPI 7.2.81, `per-key-models.4`, `cpa-key-policy` 0.4.5, ChatForward `zombie-reap-20260725-2329`, extension 0.16.0, Node.js 24.15.0 and ws 8.21.1. Do not claim production activation until every required signed component and external login prerequisite is present at its approved version.

## 5. Provision tenants and users

Create a canonical UUID, a unique locked account and an unused XFS project ID for each tenant:

```bash
/opt/workagent/control/bin/workagent-provision tenant \
  --tenant-id TENANT_UUID \
  --runtime-user workagent_tenant_NAME \
  --project-id UNIQUE_PROJECT_ID \
  --disk-hard-limit-bytes BYTES
```

The command creates and locks a same-name, nologin account; rejects unexpected supplementary groups; creates any missing global capacity leases; assigns/read-verifies the hard quota; writes the root-owned schema v5 tenant configuration with a read-only ACL for exactly that runtime UID; writes identity and resource-limit drop-ins; reloads systemd; and verifies the signed release plus the exact loaded socket/service sandbox. Add `--start` only after all verification passes. `--memory-bytes`, `--cpu-percent` and `--active-processes` default to the Windows parity values of 6 GiB, 50% and 64.

Create the first Portal administrator from a protected password file:

```bash
/opt/workagent/control/bin/workagent-admin init-admin \
  --tenant-config /etc/workagent/users/TENANT_UUID.json \
  --username USERNAME \
  --password-file /absolute/root-only/password.input
```

Use `create-user`, `set-password`, `set-enabled`, `set-limits`, `runtime-status`, `runtime-start`, `runtime-stop`, `runtime-restart` and `set-chatgpt-pro-limit` for later lifecycle operations. Disablement revokes sessions before the socket/service is stopped; re-enablement verifies identity, ACL, release, drop-ins and socket state before committing the database change.

## 6. Initial activation and upgrades

Generate a preflight report while the target and all configuration are stable. A first activation uses `--initial`; later activations additionally require a fully decrypted and verified backup no older than four hours. The exact `--required` paths must include the Renderer index, AionUi/AionCore executables and all three Agent CLI executables for their consumer.

For every upgrade, make the configured `/notification` source return a new notice whose ID is `workagent-upgrade-RELEASE_ID`, message is exactly `系统正在升级，正在进行的任务可能会中断`, and `published_at` is RFC3339. Publish it at least 60 seconds before preflight/cutover. Put only the value of a currently authenticated administrator's `__Host-aionui-portal` cookie in a temporary root-owned 0600 file. Preflight fetches `/api/portal/me/notifications` over the local trusted Portal boundary, requires that exact notice, and binds its ID, publication time and observation time into the protected report. Remove the temporary session file through the approved secret-disposal procedure after preflight.

```bash
/opt/workagent/control/bin/workagent-release preflight [channel and release options] \
  --portal-config /etc/workagent/portal.json \
  --backup-config /etc/workagent/backup.json \
  --maintenance-session-file /absolute/root-only/portal-session.input \
  --output /var/lib/workagent/preflight.json

/opt/workagent/control/bin/workagent-backup create --quiesce-systemd

/opt/workagent/control/bin/workagent-release activate [same channel and release options] \
  --preflight /var/lib/workagent/preflight.json \
  --backup-archive /absolute/verified/archive \
  --backup-receipt /absolute/verified/receipt
```

For the first activation, omit `--maintenance-session-file` and pass `--initial` to `activate`; there is no existing user session to notify.

Activation uses compare-and-swap on the current pointer and rejects a target that cannot read the active data schema. Affected Portal, sockets and UserHost services must be inactive before the pointer moves. Shared or combined activation additionally requires `workagent-chatforward-browser.service` to be stopped first and `workagent-chatforward.service` second; the activation drain gate checks both in that order and refuses to move the pointer while either is active. Rollback applies the same drain gate, re-verifies both releases, and is allowed only when the previous release can read the schema the active release may have written; otherwise restore the verified pre-upgrade backup onto a blank host.

## 7. Verify and rehearse recovery

A validation-only recovery target must not already exist. The install pass normally uses a different fresh target. If an install is killed after the target was published, repeat the exact same archive, receipt and target: recovery accepts it only after proving every byte, entry, mode and archived UID/GID against the authenticated manifest. It never adopts a changed or extra entry. Installation is allowed only on a blank, package-prepared host where the production binaries, unit templates, trust public key and every immutable signed release named as either `current` or `previous` already exist. `mihomo.service` must be active/running; Caddy, the backup and health services/timers, every WorkAgent application service and the exact restored tenant service/socket set must be loaded and inactive/dead with no residual process. Every future service/socket/timer entrypoint must also have `UnitFileState=disabled`, while non-enableable helper and tenant service units must be exactly `static`; an inactive but enabled unit is unsafe because it could start after a reboot outside the activation journal. A foreign or missing tenant instance blocks recovery.

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

The installer never overwrites conflicting state. It recreates exact tenant UID/GID accounts, locked/nologin/group shape, capacity leases, ACLs, systemd drop-ins and XFS quotas, while normalizing archived Portal, notification, ChatForward and CLIProxy ownership to their package-created identities. It restores the encrypted-backup copy of the CLIProxy tenant-key/quota/usage policy while holding the exclusive CLIProxy lifecycle lock. Backup holds every Portal/tenant runtime lock, the CLIProxy migration lock and shared locks on all canonical release pointers; one shared runtime pointer is archived once, and the independent Renderer pointer is always included. Both current and previous Renderer/tenant signed releases are verified before backup and again before recovered services start.

Activation is crash-recoverable. The exclusive install lock is `/run/workagent-backup/recovery-install.lock`; before starting anything, recovery persists the exact allow-listed activation/rollback set to root-only `/var/lib/workagent-backup/recovery-activation.json`, including both tenant sockets and the services that socket or Portal traffic may activate. A kill or power loss is reconciled on the next invocation by disabling enableable units and stopping sockets before services. Disable/enable operations are followed by exact `UnitFileState` readback, so a successful `systemctl` exit alone is never considered durable proof. The journal is removed and its persistent parent synced only after CLIProxy, notification, ChatForward, every enabled tenant socket, the ChatForward browser and Portal have passed their systemd/readiness gates, been enabled and passed a final commit recheck. Production preflight blocks whenever the persistent journal is present or cannot be proved absent. The JSON result reports each internal component that started. Caddy and the backup/health services and timers deliberately remain stopped and disabled: internal restoration is not permission to publish traffic or declare external production readiness before new-host authentication and acceptance.

Immutable signed release trees and the offline backup-encryption key are intentionally not restored from application state. Before the install pass, run the three `workagent-secret generate-install` commands on the blank host; their systemd ciphertext is host-bound and absent from the backup. CLIProxy provider OAuth files, both parent/child paths that could capture them, the ChatForward browser profile/cache, systemd credential ciphertext and the systemd host key are all excluded. Re-run provider OAuth with the fixed transient-unit procedure in `docs/CLIPROXY_OAUTH_LINUX.md` and perform the one-time ChatGPT login in `docs/CHATFORWARD_LINUX.md` after internal recovery.

## 8. Start and verify

```bash
/opt/workagent/control/bin/workagent-admin verify-host
/opt/workagent/control/bin/workagent-admin verify-tenant --tenant-id TENANT_UUID
# Complete docs/CLIPROXY_OAUTH_LINUX.md and docs/CHATFORWARD_LINUX.md first.
# Only after local/provider acceptance and approved edge-gate authorization:
systemctl enable --now caddy.service workagent-backup.timer workagent-healthcheck.timer
```

Ordinary `verify-tenant` is the online account, release, configuration and loaded-unit verification used after activation; it deliberately accepts the tenant's expected running service. Only the exact systemd `ExecStartPre` command adds `--require-quiescent`, which enables the root-only process boundary before UserHost starts. Its executable retains the systemd `+` prefix: on the production systemd 255 host this was verified to run the pre-start check with host-root process visibility even though the main service uses a non-root `User=`, `ProtectProc=invisible` and `ProcSubset=pid`; the same read of another UID's `/proc/PID/status` fails without `+`. Quiescent mode scans the complete process table twice with stable PID start-time evidence and rejects startup if the tenant's dedicated runtime UID appears as any process real, effective, saved or filesystem UID. Unreadable or malformed process evidence, excessive process-table size, persistent PID churn or exhausted bounded rescans fail closed; ordinary processes that disappear during a scan trigger a fresh scan instead of a permanent false failure. The locked runtime UID must not be reused outside its one tenant service, and `workagent-userhost@.service` must retain `KillMode=control-group` so a stopped activation cannot deliberately leave same-UID descendants behind. The check reports no process command line or environment content.

The recovery installer starts `cliproxyapi.service` first; its startup renders only a bcrypt management hash, verifies the exact loopback/build/plugin/state contract, reconciles the 16 Windows-managed aliases, and read-verifies them before systemd declares startup complete. Install the tracked Caddyfile and publish only shared HTTPS 443 through the approved reverse proxy, forwarding to Portal's cleartext loopback TCP listener. TCP 80 remains untouched; ACME must use TLS-ALPN-01 and fails closed when public 443 is unavailable. Portal rejects non-loopback listeners, direct production TLS, untrusted proxy CIDRs and missing forwarded HTTPS. UserHost, backend, CLIProxy, and integration endpoints remain loopback/UDS-only. Install the health timer, monitoring rules, bounded journald policy, and Caddy rolling-log directory. A green local `/readyz`, fresh provider OAuth, successful ChatGPT login, independent external TLS/WebSocket evidence, fresh verified off-host backup metric and successful two-tenant browser/provider acceptance are mandatory before traffic cutover is declared complete.

The CLIProxy service holds a nonblocking shared `flock` on the root-owned `/run/workagent/cliproxy-migration.lock` for its full process lifetime. Offline migrated quota-state installation takes the exclusive lock and rechecks that the service is inactive before replacing state; never remove, relax or bypass this lock to force a cutover.

## Socket activation identity

The socket is created by systemd with owner `workagent` and mode 0600. Each UserHost service is assigned a dedicated tenant account by a root-owned drop-in. The template defaults to `workagent-disabled`, so a missing identity override fails closed.

The UserHost template intentionally does not set `RestrictSUIDSGID=yes`: on the audited systemd build that directive blocked `openat2`, removing the stronger path-confinement primitive. `NoNewPrivileges`, an empty capability set, read-only system hierarchy and a dedicated UID remain enabled.
