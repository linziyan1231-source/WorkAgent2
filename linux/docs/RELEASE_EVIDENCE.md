# Release and evidence runbook

Production code is split into three independently verified roots:

| Scope | Installed root | Component contract |
|---|---|---|
| `portal` | `/opt/workagent/control` | `control-plane/components.portal.json` |
| `shared` | `/opt/workagent/shared` | `components/shared/components.json` |
| `runtime` | an immutable release below the configured runtime releases directory | `components/runtime/components.json` |

The control and shared roots are fixed paths so systemd can start without a
pointer lookup. They are immutable hash-verified releases: every service
verifies the relevant root, its `manifest.json`, the complete per-file SHA-256
inventory, ownership, modes and required executable set before it performs
preparation or starts the workload. Manifests are unsigned; integrity comes
from the root-owned, non-writable release tree and the hash-locked source-gate
evidence that produced it, not from a signature. A root or operating-system
administrator remains inside the trusted computing base because root can
replace both a unit and a release tree; the startup verifier prevents partial
installs and non-privileged tampering, not a compromised host administrator.

## 1. Create payloads only from a clean revision

Run `scripts/source-gate.sh` with the pinned Go, Gitleaks, govulncheck and
ShellCheck executables. Its default `quality` mode performs tests and analysis
but deliberately publishes no payload. Production evidence comes only from the
fresh, cache-free `verify` CI job, which invokes the separate `artifact` mode
after the quality job passed the identical revision. That artifact records the
exact source revision, tool versions, scans, checksums, nine online
control-plane binaries and the health helper. A loose local
artifact-mode directory is rehearsal output, not production authorization.

The gate locks one commit and tree in a sanitized object repository, rejects a
dirty invoking worktree, and materializes separate test and build snapshots
directly from the locked Git blobs. Binaries are built with `CGO_ENABLED=0`,
`-trimpath` and `-ldflags=-buildid=`; every binary must embed exactly one clean
`vcs.revision` matching the locked commit, so an identical toolchain and source
revision reproduce identical bytes. Before the final Gitleaks scans, the
control payload is frozen to mode `0555` for its root, directories and exact
executable allow-list and `0444` for every other regular file. A symlink, special or
multiply-linked file, any setuid/setgid/sticky bit, non-canonical path or
unlisted executable fails the gate. `workagent-release validate-layout` then
independently rejects extended/default POSIX ACLs, Linux file capabilities and
every unbound extended attribute except the host-managed `security.selinux`
label.

`control-plane.tree-modes.tsv` records the
deterministic entry type, mode and relative path; it deliberately omits
builder UID/GID, while the installed release still requires production
`root:root` ownership. The payload's inner `SHA256SUMS` must exactly equal the
complete regular-file inventory; it is regenerated and compared after freezing
and again after the final scan phase. The outer `EVIDENCE.sha256` binds the
inner inventory, the mode manifest and `source-gate.json`. Verify all
layers after any root-only, mode-preserving cross-host transfer; never upload
or copy the evidence tree with a tool that normalizes modes — CI publishes only
the mode-preserving `workagent-source-gate.tar` plus its SHA-256 sidecar, which
is a transport envelope, not authorization to deploy.

Build the runtime and shared payloads with the checked-in assemblers. A shared
payload is accepted only when CLIProxyAPI, its policy plugin, ChatForward,
Node.js and `ws` match the exact checked-in hashes and version probes. Perform
independent clean builds for every component whose build contract requires
reproducibility and retain both outputs and their comparison record. A matching
version string is not a substitute for matching bytes.

## 2. Create the unsigned manifest

Stage the complete release root as `root:root`: directories and allow-listed
executables `0555`, every other regular file `0444`. `workagent-release
manifest` records and later verifies the supplied modes; it does not repair a
badly staged tree. The executing binary must contain
`vcs.revision=<40 lowercase hex>` and `vcs.modified=false` in `go version -m`,
and `--source-revision` must equal that embedded clean revision:

```bash
/absolute/verified/final-source-gate/control-plane/bin/workagent-release manifest \
  --root /absolute/new-release-root \
  --release-id RELEASE_ID \
  --source-revision CLEAN_SOURCE_REVISION \
  --branding-version APPROVED_BRAND_VERSION \
  --policy-version APPROVED_POLICY_VERSION \
  --scope portal \
  --data-schema-version WRITE_SCHEMA \
  --minimum-readable-data-schema MIN_READ_SCHEMA \
  --maximum-readable-data-schema MAX_READ_SCHEMA \
  --components /absolute/components.portal.json \
  --required share/deploy/caddy/Caddyfile \
  --required-executable admin/install-edge-publication-admission-v1 \
  --required-executable bin/workagent-release \
  --required-executable share/deploy/libexec/workagent-edge-publication-admission-v1
```

Every manifest invocation must assert a non-empty consumer contract. The portal
example above is abbreviated; the real control contract lists every edge and
lifecycle data file and the complete executable allow-list. For the shared
root, assert data files `chatforward/app/src/server.js` and
`chatforward/app/extension/manifest.json`, plus executables
`cliproxyapi/bin/cli-proxy-api`,
`cliproxyapi/plugins/cpa-key-policy-v0.4.5.so`,
`chatforward/integration/run-server.sh`,
`chatforward/integration/run-browser.sh`,
`chatforward/integration/readiness.mjs`,
`chatforward/integration/login.sh`, and `chatforward/node/bin/node`. For a
runtime release, assert the four builtin-assistant data files,
`static/index.html`, and executables `bin/aioncore`, `bin/aionui-web`,
`bin/codex`, `bin/kimi`, and `bin/python3`. Use `--scope shared` and
`components.shared.json` for the shared root, and `--scope runtime` plus the
runtime component list for each runtime release. Never reuse a release ID for
different bytes.

## 3. Verify, install, activate and roll back

`workagent-release verify` re-checks the manifest, scope, exact consumer
contract, `root:root` ownership, frozen modes and every file's SHA-256 without
any public key. New candidates additionally pass `--admission-baseline`;
installed service startup and historical rollback verification deliberately
omit it so today's component versions are not imposed retroactively. Fixed
control and shared roots may omit `--release-id` during direct historical
verification; the manifest supplies the ID, while a supplied ID must match
exactly.

Install only through the fixed-root journal. Stop the affected fleet, stage the
complete root-owned mode-`0555` tree on the same filesystem at
`.control.stage-RELEASE_ID` or `.shared.stage-RELEASE_ID`, and run
`fixed-install`, then `fixed-reconcile`; `fixed-rollback` restores the durably
preserved previous tree. Every candidate install uses the separately hash- and
VCS-verified final source-gate binary from that candidate's exact revision,
never an older installed binary. Never rename, delete, or edit an installed
tree by hand.

Only the configured `runtime` channel uses a mutable pointer. Runtime
`preflight`, `activate` and `rollback` always require an explicit release ID,
bind the protected root/pointer identity and the protected-config-derived
consumer contract, require a recent verified backup, and move the pointer by
compare-and-swap only while the affected consumers are drained.

## 4. Evidence required for authorization

Retain the clean source-gate output, its `EVIDENCE.sha256` and the tree-mode
manifest, build logs, independent-build comparison, component input hashes,
each `manifest.json`, the preflight report, a verified backup receipt and the
activation/rollback rehearsal. Production traffic additionally requires the
host, external TLS/WebSocket, two-tenant browser/provider, OAuth, ChatForward
login, quota, monitoring and blank-host recovery evidence described by the
deployment guide and `SECURITY.md`.
