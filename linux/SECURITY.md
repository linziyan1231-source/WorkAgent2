# Security policy

## Trust boundary

The browser authenticates only to the Portal. Tenant identity is assigned by the server and must never be accepted from browser paths, headers, cookies, query parameters, or request bodies.

Each tenant has a canonical UUID, a dedicated locked `nologin` Linux account, a private data root, a dedicated Unix-domain socket, a dedicated cgroup and an XFS project quota. The Portal account has no direct access to tenant data or the Docker socket. Startup and administrative verification reject identity, ownership, ACL, quota, socket, cgroup or release drift.

## Files and service identity

- Portal configuration, policy, branding and trust material are canonical root-owned, non-symlink files and directories with no unintended write access.
- A tenant configuration is root-owned and grants read access to exactly one named ACL principal: that tenant's runtime UID. Configuration-directory ACLs grant only the traversal needed by provisioned tenant UIDs.
- Tenant data roots are owned by the matching runtime UID with mode 0700. Runtime accounts have a same-name primary group and only the approved capacity group as a supplementary group.
- Portal and tenant startup verify the loaded systemd unit properties, including user/group, capabilities, address families, writable/inaccessible paths, process cleanup, resource limits and sandbox controls. Template or drop-in drift fails closed.

## Secrets and logs

Long-lived secrets must not be stored in Git, command arguments, environment variables, shared release trees, logs, crash dumps or browser-visible configuration. Provision them through root-owned credential files or encrypted systemd credentials with the narrowest possible reader. The sole runtime bootstrap exception is a fresh per-service AionUi/AionCore transport credential: UserHost passes it only to those two child boundaries, each child validates and overwrites its Linux initial-environment bytes before binding, it is never inherited by Agent CLIs, and UserHost zeroes its copy after all request/tunnel users stop. The optional administrator master-password value is an Argon2id hash, never a plaintext password.

Control-plane logs use structured redaction. Child-process output is line-buffered, size-bounded, rotated and redacted; an oversized unterminated line is discarded rather than emitted. Browser credentials and upstream authorization state are stripped at both reverse-proxy boundaries.

## Network exposure

Production exposes only shared HTTPS 443. The approved reverse proxy forwards to a cleartext loopback TCP Portal listener; production configuration rejects direct Portal TLS, non-loopback listeners, Unix Portal listeners, non-loopback trusted-proxy CIDRs and requests without trusted forwarded HTTPS. Direct TLS on loopback is a staging-only exception.

UserHost starts only from systemd socket activation and verifies that the inherited file descriptor is the exact configured 0600 Unix socket. Portal and UserHost independently enforce peer credentials. AionUi, AionCore, model proxies and integrations remain loopback/UDS-only and are never publicly published. Because another local UID can still reach a loopback port, AionUi and AionCore also require the memory-only per-service runtime credential on every transport path; application JWT/session checks continue after that gate.

When an outbound HTTP/HTTPS proxy is approved, Portal copies one root-controlled policy into every tenant. User configuration cannot override `HTTP_PROXY`, `HTTPS_PROXY` or the fixed loopback bypass; OAuth targets are still restricted to allow-listed public HTTPS destinations.

## Fail-closed requirements

- Missing or malformed branding, policy, tenant identity, release manifest, credential, trusted-proxy configuration or systemd property prevents startup/readiness.
- A release hash, provenance, license approval, component version or data-schema mismatch prevents readiness and launch.
- An upgrade cannot pass preflight until the exact per-release maintenance notice has been visible for at least 60 seconds through the authenticated Portal notification endpoint; the protected preflight report binds that evidence to the target release.
- Enabled ChatForward readiness requires the exact three-pair cap, `quota-v1` protection and source-asset proxy health contract; a listening TCP port or an older partial health response is not sufficient.
- Unknown models, tenants, forwarded headers, origins and WebSocket upgrades are denied.
- Browser Cookie, Authorization and CSRF values never enter a tenant backend, and tenant responses cannot set Portal-origin cookies.
- Database migration validates the complete target schema inside the same transaction; a malformed legacy schema is rolled back without advancing `user_version`.
- Backup requires a verified remote filesystem copy. Quiesced-service state is journaled in root-only `/run` storage, and systemd runs an idempotent exit hook so an interrupted backup does not leave Portal/UserHost services stopped.
- Restore never overwrites conflicting host state and re-verifies accounts, ACLs, quotas, units, releases and database integrity before activation.

## Reporting

Security contacts and an incident-response channel must be supplied by the WorkAgent2 production owner before release.
