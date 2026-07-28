# CLIProxyAPI Linux provider OAuth runbook

CLIProxyAPI provider credentials are host-local authentication material. They
are intentionally excluded from Windows migration and blank-host recovery, so
the approved Codex and Kimi accounts must each be authorized once on the new
Linux host. This is an activation step, not a data-copy step.

The production CLIProxy service may start before provider OAuth. Its
`ExecStartPre` creates and verifies the protected runtime configuration,
starts the locked loopback core/plugin/policy contract, and reconciles the
managed aliases. Portal and the full CLIProxy doctor remain not ready until
both a usable file-backed Codex credential and a usable file-backed Kimi
credential are reported by the authenticated management API.

## Preconditions

Complete these checks from a trusted root console:

```bash
/opt/workagent/control/bin/workagent-admin service-action \
  --action start --unit cliproxyapi.service
/usr/bin/systemctl show cliproxyapi.service \
  --property=ActiveState --property=SubState --property=MainPID
/usr/bin/test -x /usr/libexec/workagent-fixed-root-exec-v1
/usr/bin/test -x /opt/workagent/shared/cliproxyapi/bin/cli-proxy-api
/usr/bin/test -r /var/lib/cliproxyapi/config.yaml
```

Require exactly `ActiveState=active`, `SubState=running`, and a positive
`MainPID`. The binary must come from the verified shared release, and
the service must already have passed its pre-OAuth startup contract. Do not
copy an auth directory from Windows or another Linux host, and do not run the
OAuth binary as root.

Each invocation below reads a fresh non-secret kernel UUID into a task-specific
unit name. This makes concurrent or stale attempts visible without reusing a
transient unit identity. `--collect` removes the stopped unit after the command
completes. The fixed supervisor enforces one authorization flow at a time; a
second Codex or Kimi flow fails immediately with status 75 instead of sharing
the writable auth directory.

Every transient unit receives the catalog, control, shared, and CLIProxy
migration locks as named read-only descriptors 3, 4, 5, and 6. Codex and Kimi
authorization units additionally receive the dedicated CLIProxy OAuth writer
lock as descriptor 7. The immutable installed
`/usr/libexec/workagent-fixed-root-exec-v1` validates the exact descriptor
names, paths, inodes, modes, and read-only access plus the closed profile's
complete command arguments. It acquires the three release locks shared in
order, acquires the migration lock shared and nonblockingly, then acquires the
OAuth writer lock exclusively and nonblockingly for authorization profiles.
Every OAuth and doctor profile retains its complete lock set through child
exit. This is deliberately
stricter than relying on the operator's active-service check: the login
children read the catalog-derived runtime configuration, while
`workagent-cliproxy doctor` reads the protected Portal and policy catalog
directly. Therefore fixed-root switching and catalog publication cannot
overlap any OAuth/doctor command, and the CLIProxy migration writer cannot
change policy state underneath any flow. The OAuth writer gate also prevents
two provider login children from concurrently changing host-local credential
files. Do not remove or reorder these `OpenFile` properties or bypass the
versioned supervisor.

## Authorize Codex

```bash
read -r workagent_codex_oauth_run_id < /proc/sys/kernel/random/uuid
/usr/bin/systemd-run --quiet --wait --pty --collect --service-type=exec \
  --unit="workagent-cliproxy-oauth-codex-${workagent_codex_oauth_run_id}.service" \
  --uid=cliproxyapi --gid=cliproxyapi \
  --working-directory=/var/lib/cliproxyapi \
  --setenv=HOME=/var/lib/cliproxyapi \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=PrivateTmp=yes \
  --property='ReadWritePaths=/var/lib/cliproxyapi' \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
  --property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only' \
  --property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only' \
  --property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only' \
  --property='OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only' \
  --property='OpenFile=/run/workagent/cliproxy-oauth.lock:workagent-cliproxy-oauth-lock:read-only' \
  /usr/libexec/workagent-fixed-root-exec-v1 cliproxy-oauth-codex \
  /opt/workagent/shared/cliproxyapi/bin/cli-proxy-api \
  --config /var/lib/cliproxyapi/config.yaml \
  --codex-device-login --no-browser
```

Follow the displayed device authorization instructions in the trusted
terminal and browser. Do not paste the authorization URL, device code, account
identifier, token, or resulting auth filename into logs, tickets, or chat.

## Authorize Kimi

```bash
read -r workagent_kimi_oauth_run_id < /proc/sys/kernel/random/uuid
/usr/bin/systemd-run --quiet --wait --pty --collect --service-type=exec \
  --unit="workagent-cliproxy-oauth-kimi-${workagent_kimi_oauth_run_id}.service" \
  --uid=cliproxyapi --gid=cliproxyapi \
  --working-directory=/var/lib/cliproxyapi \
  --setenv=HOME=/var/lib/cliproxyapi \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=PrivateTmp=yes \
  --property='ReadWritePaths=/var/lib/cliproxyapi' \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
  --property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only' \
  --property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only' \
  --property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only' \
  --property='OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only' \
  --property='OpenFile=/run/workagent/cliproxy-oauth.lock:workagent-cliproxy-oauth-lock:read-only' \
  /usr/libexec/workagent-fixed-root-exec-v1 cliproxy-oauth-kimi \
  /opt/workagent/shared/cliproxyapi/bin/cli-proxy-api \
  --config /var/lib/cliproxyapi/config.yaml \
  --kimi-login --no-browser
```

Follow the displayed authorization instructions with the approved Kimi
account and apply the same confidentiality rules.

The fixed CLIProxyAPI login commands may return a zero process status even
when some authorization failures were printed. Never treat their exit status
or a success-looking line as readiness evidence.

## Enforce full readiness

After both flows finish, restart CLIProxy so the production process reloads
the host-local auth directory, then run the full authenticated doctor inside a
separate credential namespace:

```bash
/opt/workagent/control/bin/workagent-admin service-action \
  --action restart --unit cliproxyapi.service

read -r workagent_oauth_doctor_run_id < /proc/sys/kernel/random/uuid
/usr/bin/systemd-run --quiet --wait --pipe --collect --service-type=exec \
  --unit="workagent-cliproxy-oauth-doctor-${workagent_oauth_doctor_run_id}.service" \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=PrivateTmp=yes \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
  --property=LoadCredentialEncrypted=cliproxy-management-key:/etc/credstore.encrypted/workagent/cliproxy-management-key.cred \
  --property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only' \
  --property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only' \
  --property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only' \
  --property='OpenFile=/run/workagent/cliproxy-migration.lock:workagent-cliproxy-migration-lock:read-only' \
  /usr/libexec/workagent-fixed-root-exec-v1 cliproxy-oauth-doctor \
  /opt/workagent/control/bin/workagent-cliproxy doctor \
  --portal-config /etc/workagent/portal.json \
  --credential %d/cliproxy-management-key \
  --wait 30s
```

The doctor accepts only the locked core build/patch, runtime configuration,
plugin, policy/catalog state, and at least one active, available, non-disabled,
non-runtime-only, file-backed credential for each of `codex` and `kimi` under
the canonical auth directory. It does not print account identifiers, auth
filenames, paths, or tokens. A host shell cannot read
`/run/credentials/cliproxyapi.service/...`; systemd exposes the encrypted
management key only as `%d/cliproxy-management-key` inside this fixed
transient unit. Never decrypt it to a temporary file, argument, environment
value, or shell variable.

A green doctor proves the protected local contract and usable credential
inventory, not provider entitlement or successful inference. Before cutover,
also require real Codex and Kimi requests through two distinct Portal tenants,
including streaming/tool behavior, usage/quota settlement, restart behavior,
failure handling, and cross-tenant rejection. Portal/full readiness must stay
red while either provider credential is absent or unusable, and cutover must
not proceed until the doctor passes. ChatGPT/ChatForward login and browser
acceptance remain the separate procedure in `docs/CHATFORWARD_LINUX.md`.
