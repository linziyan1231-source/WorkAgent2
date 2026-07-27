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
govulncheck and ShellCheck executables. Preserve its complete output directory
and CI artifact. It records the exact source revision, tool versions, source
SBOM, scans, checksums, ten online control-plane binaries (including the
root-only signed `workagent-import-stage` publisher), the health helper,
and a separately packaged offline `workagent-migrate-windows` command. The
migration command is never installed as an online service.

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
`provenance.json` and `licenses.json`. Install any referenced NOTICE files,
make the complete tree root-owned and non-writable, and create the manifest with
the offline Ed25519 private key:

```bash
workagent-release manifest \
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
  --private-key /absolute/offline/release-signing.key \
  --public-key /etc/workagent/trust/release-signing.pub
```

Use `--scope shared` and `components.shared.json` for the shared root, and
`--scope runtime` plus the runtime component list for each runtime release.
Never reuse a release ID for different bytes. Keep the private key offline; the
production host receives only the root-owned public key at
`/etc/workagent/trust/release-signing.pub`.

Before installation, run `workagent-release verify` against the staged root and
the production public key. Install control or shared releases by stopping their
consumers, verifying a complete root-owned sibling directory on the same
filesystem, preserving the previous signed root under an explicit rollback
name, and atomically renaming the new directory to `/opt/workagent/control` or
`/opt/workagent/shared`. Never edit either installed tree in place. Reload
systemd and start services only after the post-install verification succeeds.

## 4. Evidence required for authorization

Retain the clean source-gate output, build logs, independent-build comparison,
component input hashes, SPDX files, completed license report and approval
reference, provenance, `manifest.json`, `manifest.sig`, public-key fingerprint,
preflight report, verified backup receipt and activation/rollback rehearsal.
Production traffic additionally requires the host, external TLS/WebSocket,
two-tenant browser/provider, OAuth, ChatForward login, quota, monitoring and
blank-host recovery evidence listed in `docs/PRODUCTION_PARITY.md`.
