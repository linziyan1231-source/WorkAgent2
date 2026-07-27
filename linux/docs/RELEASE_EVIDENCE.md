# Signed release and evidence runbook

Production code is split into three independently verified roots:

| Scope | Installed root | Component contract |
|---|---|---|
| `portal` | `/opt/workagent/control` | `control-plane/components.portal.json` |
| `shared` | `/opt/workagent/shared` | `components/shared/components.json` |
| `runtime` | an immutable release below the configured runtime releases directory | `components/runtime/components.json` |

The control and shared roots are fixed paths so systemd can start without an
unsigned pointer lookup. They are still immutable signed releases: every
service verifies the relevant root, manifest signature, evidence, complete file
inventory and required executable set before it performs preparation or starts
the workload. A root or operating-system administrator remains inside the
trusted computing base because root can replace both a unit and its trust key;
the startup verifier prevents partial installs, unsigned updates and
non-privileged tampering, not a compromised host administrator.

## 1. Create payloads only from a clean revision

Run `scripts/source-gate.sh` with the pinned Go, Gitleaks, Syft,
govulncheck and ShellCheck executables. Its default `quality` mode performs
tests and analysis but deliberately publishes no payload. Production evidence
comes only from the fresh, cache-free `verify` CI job, which invokes the
separate `artifact` mode after the quality job passed the identical revision.
That artifact records the exact source revision, tool versions, source SBOM,
scans, checksums, ten online control-plane binaries (including the root-only
signed `workagent-import-stage` publisher), the health helper, and the
separately packaged offline `workagent-capture-windows` and
`workagent-migrate-windows` commands. Neither offline command is ever
installed as an online service. A loose local artifact-mode directory is
rehearsal output, not production authorization.

The payload build and scans run as the invoking builder. On an unprivileged CI
runner, the gate additionally requires passwordless non-interactive `sudo` only
for the ordinary and race Go test suites that exercise the real production
`root:root` manifest contract. Their Go build and module caches are copied into
an isolated root-owned temporary directory, reverified with network module
resolution disabled, and removed at exit. Every package other than the
deliberately root-owned release fixture is also run uncached, both normally and
with the race detector, as the runner identity. This preserves non-root service
coverage and genuinely tests the `0500`/`0400` cleanup path. No payload build or
scanner runs through sudo. The gate locks one commit and tree in a sanitized
object repository, rejects a dirty invoking worktree, and materializes separate
test and build snapshots directly from the locked Git blobs. It never invokes
checkout filters or archive attributes. Ignored or test-created files in the
invoking checkout therefore cannot enter the tested or published binaries.

Source-gate evidence schema v2 is independent of the invoking shell's umask.
Before the final payload SBOM and Gitleaks scans, the control payload is frozen
to mode `0555` for its root and every directory, `0555` for the exact executable
allow-list, and `0444` for every other regular file. The separate offline
migration-tools payload is deliberately root-only: its root and directories are
`0500`, its two allow-listed commands are `0500`, and its other regular files
are `0400`. A symlink, special or multiply-linked file, any setuid/setgid/sticky
mode bit, non-canonical path, unlisted executable, duplicate executable, or
missing/non-executable allow-list entry fails the gate before a manifest is
published.

After the mode freeze, the source-gated `workagent-release validate-layout`
command independently walks both payloads. It rejects extended/default POSIX
ACLs, Linux file capabilities, and every other unbound extended attribute
except the host-managed `security.selinux` label. That sole exception is not
release evidence: an enforcing host still requires the separate SELinux policy
and denial review called out by production preflight.

`control-plane.tree-modes.tsv` and `migration-tools.tree-modes.tsv` record the
deterministic entry type, mode and relative path, including the payload root as
`.`. They deliberately omit builder UID/GID so independent unprivileged and
root builders can compare the same pre-install contract; the final signed
release manifest still requires and binds production `root:root` ownership.
Both tree-mode manifests are covered by `EVIDENCE.sha256`. Each payload's inner
`SHA256SUMS` must exactly equal the complete regular-file inventory other than
`SHA256SUMS` itself; it is regenerated and compared after freezing and again
after the final SBOM/Gitleaks phase, so an extra ordinary file is not merely
recorded by name without a bound content hash. The outer evidence hashes bind
the inner inventories and mode manifests. Verify all three layers after any
root-only, mode-preserving cross-host transfer. Do not copy a payload with a
tool that silently widens or discards its modes.

GitHub artifact upload normalizes loose directory and file permissions, so CI
must never upload the evidence directory directly. After terminating the
isolated build UID, the pinned workflow copies the result without reflinks into
a private root-owned tree, regenerates the exact outer evidence inventory and
source-gate metadata, round-trips it, then creates `workagent-source-gate.tar`
and its SHA-256 sidecar beneath a non-writable root-owned `/opt` directory. It
uploads only those two mode-`0444` ordinary files. After download, verify the sidecar before extraction;
extract as root with ownership and permissions preserved into a new empty
directory, then verify `EVIDENCE.sha256`, both complete `SHA256SUMS` inventories,
both tree-mode manifests and both `validate-layout` profiles again. The tar is a
transport envelope, not a signed release and not authorization to deploy.

Build the runtime and shared payloads with the checked-in assemblers. A shared
payload is accepted only when CLIProxyAPI, its policy plugin, ChatForward,
Node.js and `ws` match the exact checked-in hashes and version probes. Perform
independent clean builds for every component whose build contract requires
reproducibility and retain both outputs and their comparison record. A matching
version string is not a substitute for matching bytes or an approved
reproducibility exception.

The runtime assembler must also accept the checked-in pre-sign payload manifest
and canonical tree pins before any evidence is generated. Never weaken or
temporarily bypass that production check to qualify an upgrade. A legitimate
future payload change must be built and compared in an isolated, non-production
qualification workflow, reviewed from the resulting candidate hashes, and only
then update the checked-in pins through the normal clean-source review process.
Retain both candidate hashes, the reproducibility comparison and reviewer
approval, then rerun the complete source gate, clean assembly and signed
evidence pipeline after the pin update.

## 2. Generate evidence outside the payload

For each payload, invoke:

```bash
WORKAGENT_RELEASE_BIN=/absolute/workagent-release \
SYFT_BIN=/absolute/syft \
scripts/prepare-release-evidence.sh \
  /absolute/payload \
  /absolute/components.json \
  RELEASE_ID \
  CLEAN_SOURCE_REVISION \
  SOURCE_URI \
  APPROVED_BUILDER_ID \
  APPROVED_BUILD_TYPE \
  UNIQUE_INVOCATION_ID \
  /absolute/new-evidence-directory
```

The output contains `sbom.spdx.json`, reproducible `provenance.json`, a private
mode-0600 `licenses.review.json` draft and `SHA256SUMS`. The provenance includes
the source revision and every component revision. The license draft is
deliberately `approved: false`; do not place it in a release or change that
field merely to satisfy the verifier.

The evidence directory is private (`0700`); Syft output and its checksum list
may therefore be `0600` without obstructing root signing or root-to-root
delivery. Those are evidence-storage modes, not final release-tree modes.

An authorized legal/release reviewer must inspect the payload and SBOM, fill
one non-placeholder SPDX expression and copyright entry for every component,
include every required NOTICE/license file inside the payload, record the
actual UTC review time, set `approved: true`, and attach the organization's
external approval reference to the release record. `NONE`, `NOASSERTION`,
`unknown`, `TODO`, `TBD`, `review_required` and unresolved entries are not
approval. `LICENSE_STATUS.md` remains a repository-wide release blocker until
the same authorized owner records the source, dependency, asset, NOTICE and
brand decisions; repository maintainers must not self-approve it.

## 3. Sign the complete immutable tree

Copy the reviewed files into the new payload as `sbom.spdx.json`,
`provenance.json` and `licenses.json`, each `root:root` mode `0444`. Install any
referenced NOTICE files as `0444`. Before manifest creation, require the release
root and every directory to be `root:root` mode `0555`, every executable in the
scope's exact allow-list to be `root:root` mode `0555`, and every other regular
file to be `root:root` mode `0444`. Do not treat a recursive "remove write bits"
operation as normalization: it can preserve an unusable `0500`/`0700`
executable or directory. `workagent-release manifest` records and later verifies
the supplied modes; it does not repair a badly staged tree. The same validation
rejects setuid, setgid and sticky bits, extended/default POSIX ACLs, file
capabilities, and unbound `user.*`, `trusted.*` or `security.*` metadata. Only
`security.selinux` may remain for host-managed labeling, and its policy/label
evidence is reviewed separately. Only after the exact mode, ownership and
extended-metadata contract is checked should the offline Ed25519 private key be
used:

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
  --sbom sbom.spdx.json \
  --provenance provenance.json \
  --licenses licenses.json \
  --required share/deploy/caddy/Caddyfile \
  --required share/deploy/systemd/caddy.service \
  --required share/deploy/systemd/caddy.service.d/workagent.conf \
  --required share/deploy/systemd/cliproxyapi.service \
  --required share/deploy/systemd/workagent-backup.service \
  --required share/deploy/systemd/workagent-backup.timer \
  --required share/deploy/systemd/workagent-healthcheck.service \
  --required share/deploy/systemd/workagent-healthcheck.timer \
  --required share/deploy/systemd/workagent-portal.service \
  --required share/deploy/systemd/workagent-portal.service.d/chatforward.conf \
  --required share/deploy/systemd/workagent-portal.service.d/credentials.conf.example \
  --required-executable admin/install-core-activation-admission-v1 \
  --required-executable admin/install-edge-publication-admission-v1 \
  --required-executable admin/install-fixed-root-exec-v1 \
  --required-executable admin/install-recovery-activation-admission-v1 \
  --required-executable admin/production-host-prepare \
  --required-executable admin/production-preflight \
  --required-executable admin/smoke-chatforward-browser-sandbox \
  --required-executable admin/verify-host-rpms \
  --required-executable bin/workagent-admin \
  --required-executable bin/workagent-backup \
  --required-executable bin/workagent-cliproxy \
  --required-executable bin/workagent-healthcheck \
  --required-executable bin/workagent-import-stage \
  --required-executable bin/workagent-notification \
  --required-executable bin/workagent-portal \
  --required-executable bin/workagent-provision \
  --required-executable bin/workagent-release \
  --required-executable bin/workagent-secret \
  --required-executable bin/workagent-userhost \
  --required-executable share/deploy/libexec/workagent-core-activation-admission-v1 \
  --required-executable share/deploy/libexec/workagent-edge-publication-admission-v1 \
  --required-executable share/deploy/libexec/workagent-fixed-root-exec-v1 \
  --required-executable share/deploy/libexec/workagent-recovery-activation-admission-v1 \
  --private-key /absolute/offline/release-signing.key \
  --public-key /etc/workagent/trust/release-signing.pub
```

Every manifest invocation must assert a non-empty consumer contract. The portal
example lists the exact edge/lifecycle data and executable allow-lists for the control payload. For the
shared root, assert data files `chatforward/app/src/server.js` and
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
runtime component list for each runtime release.
Never reuse a release ID for different bytes. Keep the private key offline; the
production host receives only the root-owned public key at
`/etc/workagent/trust/release-signing.pub`.

Strict admission is external to the candidate manifest. The executing trusted
`workagent-release` binary must contain `vcs.revision=<40 lowercase hex>` and
`vcs.modified=false` in `go version -m`; manifest generation, explicit
`verify --admission-baseline`, fixed-root candidate install, runtime preflight,
and runtime activation all require the manifest source revision to equal that
embedded clean revision. A manifest cannot authorize itself by choosing its
own `source_revision`. Source-gate builds retain the normal Go VCS settings;
do not strip or override them with linker flags.

Fixed control and shared roots may omit `--release-id` during direct historical
verification; the signed manifest supplies the ID, while a supplied ID must
match exactly. Installed service startup and historical rollback verification
deliberately omit `--admission-baseline`: they still require the signature,
scope, exact consumer contract, ownership, and complete bytes without
retroactively imposing today's component versions.

Install only through the fixed-root journal. Stop the affected fleet without
asking the command to stop it, stage the complete root-owned mode-`0555` tree
on the same filesystem at `.control.stage-RELEASE_ID` or
`.shared.stage-RELEASE_ID`, and run:

```bash
/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-install \
  --destination /opt/workagent/control \
  --staged-root /opt/workagent/.control.stage-NEW_RELEASE_ID \
  --expected-current-release CURRENT_RELEASE_ID

/absolute/verified/final-source-gate/control-plane/bin/workagent-release fixed-reconcile \
  --destination /opt/workagent/control

/opt/workagent/control/bin/workagent-release fixed-rollback \
  --destination /opt/workagent/control \
  --expected-current-release CURRENT_RELEASE_ID \
  --expected-previous-release PREVIOUS_RELEASE_ID
```

Use `/opt/workagent/shared` and its reserved sibling names for shared releases.
Omit `--expected-current-release` only for a first install. Every candidate
install and pending-journal reconciliation uses the separately hash- and
VCS-verified final source-gate binary from that candidate's exact revision,
never an older installed binary or a binary trusted only because it is inside
the candidate. Add `--initial` to `fixed-reconcile` only for a genuinely
pending first control-root journal before Portal and tenant configuration
exists; it is rejected for shared, upgrade, completed, or absent journals. The
installer holds the catalog and fixed-channel locks, applies strict admission
only to the journal candidate wherever its device/inode moved after a crash,
keeps historical current/previous/archive trees on signature verification,
uses exact compare-and-swap release IDs, and durably preserves the previous
tree. Never rename, delete, or edit an installed tree by hand. Reload and start
services only after reconciliation and direct post-install verification pass.
Named runtime preflight and activation always require an explicit release ID.

## 4. Evidence required for authorization

Retain the clean source-gate output, its `EVIDENCE.sha256` and both tree-mode
manifests, build logs, independent-build comparison, component input hashes,
SPDX files, completed license report and approval reference, provenance,
`manifest.json`, `manifest.sig`, public-key fingerprint, preflight report,
verified backup receipt and activation/rollback rehearsal.
Production traffic additionally requires the host, external TLS/WebSocket,
two-tenant browser/provider, OAuth, ChatForward login, quota, monitoring and
blank-host recovery evidence listed in `docs/PRODUCTION_PARITY.md`.
