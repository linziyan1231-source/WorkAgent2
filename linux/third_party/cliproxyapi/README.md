# CLIProxyAPI production source lock

This directory records the exact, non-secret customization inputs observed on
the Windows WorkAgent2 host in read-only mode on 2026-07-27. It does not contain
a prebuilt binary, OAuth token, provider key, downstream `cpa_` key, management
credential, or policy state.

The locked runtime identity is:

- CLIProxyAPI `7.2.81`, built with `Commit=per-key-models.4` and CGO plugin support.
- `cpa-key-policy` `0.4.5`, ABI 1.
- listener `127.0.0.1:8317`; `remote-management.allow-remote=false`.

The first two files under `patches/` are byte-for-byte copies of:

- `C:\projects\WorkAgent2\scripts\remote\cliproxyapi-per-key-models.patch`
- `C:\projects\WorkAgent2\scripts\patches\cpa-key-policy-0.4.4-state-concurrency.patch`

Their hashes, the two source-archive hashes, the candidate manifest hash, and
the inspected Windows administration helper hash are recorded in
`SHA256SUMS.sources`. The Windows helper was not installed on Linux: it assumes
`/root/cliproxyapi`, edits root SSH authorization, and restarts the service. Its
required non-secret operations are provided by the native
`workagent-cliproxy prepare|bootstrap|doctor` helper, the Portal provisioner,
and the authenticated management client in this repository. Bootstrap
reconciles and read-verifies the exact 16-entry Windows managed-alias catalog
only after the authenticated build/plugin/listener contract passes; it
preserves non-managed operator aliases.

`cpa-key-policy-0.4.5-linux-directory-fsync.patch` is an auditable Linux-only
durability layer authored for this migration. It preserves the Windows patch
unchanged, then makes a successful state-file rename durable by fsyncing the
destination parent directory. Its unit tests verify rename-before-sync order,
destination-parent selection, sync-error propagation, and real replacement on
Linux. Its repository hash is recorded separately in `SHA256SUMS.sources`.

`cliproxyapi-go1.26-hardening.patch` is a Linux-build compatibility layer for
findings surfaced by the pinned Go 1.26.5 vet tool. It keeps protocol behavior
unchanged while giving `FileBodySource.WriteTo` the standard byte-counting
signature, removing an unreachable post-loop block, and making transfer of two
stream cancellation functions to their registries explicit. It also skips
no-op writes to an already initialized returned stream-header map, eliminating
a real read/write race without changing header values. Full upstream tests,
focused race tests, and full vet run after this patch is applied.

An approved Linux amd64 build must start from the two recorded source archives,
apply the two Windows-derived patches byte-for-byte and then the recorded
Linux-only durability and compatibility patches, run both upstream test suites
(including focused race tests and full vet), set the core linker
identities to `7.2.81` and `per-key-models.4`, and emit a root-owned immutable
`cli-proxy-api` plus `cpa-key-policy-v0.4.5.so`. Packaging must record fresh
Linux artifact hashes, SBOM, provenance, license approval, and the three shared
release components `cliproxyapi=7.2.81`,
`cliproxyapi-patch=per-key-models.4`, and `cpa-key-policy=0.4.5`.

`windows-candidate-manifest.json` is byte-preserved historical Windows
evidence. Its `migration_contract` describes the candidate evaluated on
Windows; it is not a Linux cutover instruction. Linux migration must generate
a new management key, invalidate copied OAuth state, and rotate/reprovision
every tenant downstream key. The historical `copy_existing_management_key`,
`copy_existing_oauth_auth_dir`, and `rotate_downstream_keys` values must never
be applied to Linux.
