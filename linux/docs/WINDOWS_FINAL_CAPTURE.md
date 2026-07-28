# Windows final read-only capture

The final Windows data acquisition is a separate, offline cutover tool. It is
not an online WorkAgent service and it has no Windows mutation capability.

## Non-negotiable consistency boundary

`workagent-capture-windows` cannot stop a Windows service, checkpoint SQLite,
create a Volume Shadow Copy, or write a temporary file on Windows. An
authorized operator must freeze every Windows writer from outside this tool.
Until that freeze exists, only `--check` is permitted and its result is always
reported as `rehearsal-only-not-frozen`. A successful rehearsal is not a final
snapshot and does not prove transactionally consistent SQLite state.

The frozen interval must cover the complete sequence:

1. before inventories of every bound source and anonymous OAuth evidence;
2. all stdout-only tar streams;
3. after inventories and anonymous OAuth evidence.

Any path, metadata, inode, content, approved-exclusion, or OAuth-evidence drift
fails the run. The unpublished `.partial-*` directory is retained as private
failure evidence.

For every source—including Portal DB, WAL, and SHM separately—the private
completion manifest binds the before content/archive projection, the
tar-derived content/archive projection, and the after content/archive
projection. All three must be identical; an empty WAL is still a required,
hashed file rather than an omitted optional sidecar.

## Private capture spec

The spec is operator-owned input, not source code. It must be a real,
root-owned, single-link `0600` regular file at a clean absolute Linux path
below a root-owned `0700` directory, with no symbolic-link ancestor. Do
not commit it, paste it into tickets, or pass its contents on a command line.
It binds:

- one exact direct Windows SSH endpoint: canonical IPv4 address, port, login
  user, opaque host-key alias, Ed25519 host key, and an exact Ed25519 client
  identity;
- exactly one Portal database, WAL, SHM, and Portal configuration file;
- the notification state and non-browser ChatForward shared state;
- exactly eight complete tenant roots;
- the CLIProxy configuration, management state, and policy-state file;
- every admitted external workspace;
- one OAuth auth directory for anonymous evidence only;
- the private, digest-pinned `external-workspaces.json` migration mapping;
- optional non-overlapping supplemental trees needed to preserve configuration,
  logs, source, CLI state, workspace data, and unknown user data.

Destinations follow the existing migration snapshot contract. Source paths and
tenant leaves exist only in the private spec. The program rejects overlapping
source/destination roots, duplicate IDs, unsafe paths, links in the spec, and
unknown JSON fields.

Every source has explicit file, byte, tar-stream, and entry limits. Aggregate
limits include local inputs and conservative filesystem overhead. The final
destination parent must already be a real root-owned `0700` directory with the
configured free-space reserve.

### Private SSH transport approval

Schema-v1 capture specs and SSH aliases are not production inputs. The
schema-v2 spec requires a separate canonical, root-owned, single-link `0600`
SSH transport profile below a root-owned `0700` directory. The profile binds
one canonical public or management IPv4 literal, a port and login user, an
opaque alias of the form `workagent-windows-` plus 32 lowercase hexadecimal
characters, the exact `ssh-ed25519` host-key algorithm, and absolute paths plus
operator-approved SHA-256 digests for two dedicated files:

- a one-record known-hosts file whose exact canonical line is
  `<opaque-alias> ssh-ed25519 <base64-key>` followed by one newline; and
- one unencrypted Ed25519 private identity file encoded as exactly one
  canonical PEM block.

The profile, known-hosts file and identity must each be a real root-owned,
single-link `0600` file with a real root-owned `0700` parent and no symbolic
link ancestor. They must be dedicated to this capture and must not be the
normal root SSH configuration, normal `known_hosts`, an agent, or a default
identity below `~/.ssh`.

Obtain and verify the Windows OpenSSH host public key through the Windows
console or an independent management plane. First-use acceptance and an
unauthenticated `ssh-keyscan` result are not approval. Confirm that the host
private key is unique and has not been cloned. The IPv4 address must route
directly to this one Windows host; a DNS name, VIP, load balancer, transparent
failover, `ProxyCommand`, `ProxyJump`, or SSH bastion is not admitted by this
schema. If a jump path is unavoidable, it must be explicitly modeled and
pinned in a future schema before production use.

The canonical profile has this exact field order and indentation; replace the
illustrative values and digests with independently approved private values:

```json
{
  "schema_version": 1,
  "ssh_transport": {
    "connect_address": "198.51.100.10",
    "port": 22,
    "user": "capture-operator",
    "host_key_alias": "workagent-windows-11111111111111111111111111111111",
    "host_key_algorithm": "ssh-ed25519",
    "known_hosts": {
      "path": "/root/private/windows-capture-known-hosts",
      "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
    },
    "identity": {
      "path": "/root/private/windows-capture-identity",
      "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
    }
  }
}
```

The example is structural only and is not an approved endpoint or key.

### Trust and authorization boundary

This evidence model trusts the Linux kernel, root account, release operator,
and the independent management-plane host-key verification. The private
spec, receipts, gate, sealed transport inputs, and capture manifest provide
integrity and durable binding inside that trust boundary; they are not
authenticity proof against a malicious or compromised root account. A threat
model that includes hostile root requires an external signer or immutable
audit service before production cutover.

The three-rehearsal gate qualifies one exact spec, executable, revision, and
SSH transport binding. It deliberately has no expiry, planned capture ID, or
single-use token, so it is not by itself a fresh cutover authorization.
Release/legal approval, the authorized Windows writer freeze, and the final
delta result remain separate external cutover gates. If policy requires a
time-limited or one-shot authorization, issue and verify that approval outside
this tool rather than treating an older 3/3 gate as sufficient.

The bootstrap helper derives this private input only from the protected legacy
snapshot and its completed migration report; it never contacts Windows:

```bash
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --init-spec \
  --legacy-snapshot /root/private/protected-legacy-snapshot \
  --migration-report /root/private/completed-stage/report.json \
  --ssh-transport-profile /root/private/windows-capture-ssh-transport.json \
  --spec-output /root/private/workagent-final-capture.json
```

The helper publishes the digest-pinned external-workspace companion first and
the spec second. Both use descriptor-relative temporary files, file and parent
directory syncs, and `RENAME_NOREPLACE`. If execution stops between those two
renames, rerunning converges only when the existing file has exactly the
expected bytes and private ownership/mode; a different or unsafe collision
fails closed.

## Exact exclusions only

An exclusion is bound to one source ID and one exact root-relative path. There
is no recursive same-name filter. The only admitted types are:

- an exact `node_modules` tree;
- a positively identified Python environment with `pyvenv.cfg` and a real
  `Scripts` or `bin` directory;
- individually enumerated `__pycache__`, `.pytest_cache`, `.mypy_cache`, and
  `.ruff_cache` directories;
- individually enumerated `.cache`, `.npm`, and `.pnpm-store` download caches;
- the exact external `backend/.venv`, with the same positive Python-environment
  checks.

Each exclusion must exist and pass its type check both before and after the tar
window. Logs, SQLite files and sidecars, configuration, CLI state, source,
workspaces, and unknown user data remain included by default.
The inventory escapes GNU `find -path` pattern metacharacters in the complete
source-plus-relative path, and tar applies `--no-wildcards` before every
`--exclude`, so an approved exclusion is always interpreted literally.
Bound source and exclusion paths reject carriage returns and newlines; legal
newline-bearing filenames below a source remain supported because discovery
and the inventory protocol are NUL-delimited.

## Read-only rehearsal

Every rehearsal requires an operator-established temporary quiescence window
covering the complete invocation. The tool cannot establish or verify that
window; `--writers-quiesced` plus the exact confirmation token is an explicit
operator declaration that the external action has already happened. It is not
the final continuous cutover freeze and must not be replaced with
`--windows-frozen`.

Run from the Linux migration host as root, using a fresh ID and an absent
receipt path below a real root-owned `0700` directory:

```bash
rehearsal_id=rehearsal-20260727t090000z-01
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --spec /root/private/workagent-final-capture.json \
  --check \
  --rehearsal-id "$rehearsal_id" \
  --receipt-output "/root/private/windows-rehearsals/$rehearsal_id.json" \
  --writers-quiesced \
  --confirm "REHEARSAL-WRITERS-QUIESCED:$rehearsal_id"
```

The output parent is opened once and its exact directory descriptor is held
with a nonblocking exclusive advisory lock for the complete attempt. Temporary
file creation, no-replace rename, and directory sync all use that same
descriptor. Immediately before and after publication, the original path must
still resolve to the same private directory device/inode; namespace rotation
or replacement fails closed. The invocation has a conservative 24-hour
run-level timeout; this is in addition to each remote command's 12-hour
deadline and applies only
to `--check`, not to final capture. Missing declaration, a wrong token, an
unsafe or colliding output, private-input failure, or executable-identity
failure is rejected before the first SSH call.

Success atomically publishes one strict canonical, root-owned, single-link
`0600` receipt. A partial file is synced, the parent is synced, publication
uses `RENAME_NOREPLACE`, and the parent is synced again. Existing output always
fails closed—even when its bytes match—so every counted attempt is fresh. The
receipt, rather than the anonymous stdout convenience report, is the durable
success boundary. A later stdout encoding or broken-pipe failure does not
invalidate an already published receipt; gate sealing consumes receipts only.
If a command reports an error after the no-replace rename because a durability
sync could not be confirmed, do not count stdout and do not reuse that path.
The sealer's later canonical, descriptor-stable read plus file-and-parent sync
is the only recovery path that can establish whether the named receipt is
durable and admissible.

The receipt binds the fresh rehearsal ID, the external-quiescence declaration
class (not an unverifiable window name), private-spec digest, source count,
and actual UTC remote-window start/end (the start is sampled immediately before
the first collection after all local preflight checks). It also binds exactly
two complete anonymous collection-evidence
objects and their recomputed digests, and an executable identity. That identity
requires clean Go VCS metadata (`vcs.modified=false`), its exact Git revision,
the exact capture-command Go main path, and a stable SHA-256/build-info read
through one `/proc/self/exe` descriptor. The executable must be the root-owned,
single-link `0500` release file and is checked before and after the remote
work. Each collection includes every anonymous source slot's content,
archive, inventory-identity and approved-exclusion evidence, plus anonymous
OAuth evidence and a recomputed aggregate. The receipt is written only after
the two collections match and the spec, pinned local inputs, and executable
identity pass their ending revalidation.

Run exactly three separate successful attempts with distinct IDs and
nonoverlapping intervals, restoring writers only outside each operator-managed
temporary quiescence as appropriate. Evidence may legitimately change between
attempts. Seal the three receipts locally; sealing never constructs a Windows
transport and its output path must also be new:

```bash
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --seal-rehearsal-gate \
  --spec /root/private/workagent-final-capture.json \
  --rehearsal-receipt /root/private/windows-rehearsals/rehearsal-20260727t090000z-01.json \
  --rehearsal-receipt /root/private/windows-rehearsals/rehearsal-20260727t110000z-02.json \
  --rehearsal-receipt /root/private/windows-rehearsals/rehearsal-20260727t130000z-03.json \
  --gate-output /root/private/windows-rehearsals/three-of-three.gate.json
```

The sealer strictly and canonically rereads all three private `0600` receipts,
the current private spec and its pinned local inputs, and the current
root-owned `0500` capture executable. It recomputes collection digests and
aggregates, and requires unique receipt paths, IDs and file digests;
nonoverlapping intervals; and one binary SHA, clean VCS revision, current spec
digest, and source count. It does not require mutable Windows evidence to be
equal across attempts. The gate embeds all three complete canonical receipts
and their file digests, so it remains independently revalidatable without the
external receipt files. It records the factual `cross_run_state` value
`identical` or `varied`; validation recomputes that fact from the embedded
evidence. Receipt and gate errors and stdout reports remain anonymous.
The gate output parent is likewise held by one directory descriptor from
preflight through publication and must retain the same path device/inode.
At both ends of sealing, the sealer also reopens and validates the exact
content-pinned SSH known-hosts and identity inputs, but it never constructs an
SSH session or contacts Windows.

A failed or drifted attempt produces no receipt and cannot count. One failure
reports every detected anonymous drift class: OAuth file-count,
aggregate-byte, and digest changes plus source and approved-exclusion slot
numbers. It never emits a Windows path, tenant leaf, OAuth filename, digest
value, or content. A rehearsal and its 3/3 gate are still not a snapshot and
must never be substituted for the frozen final capture.

The command constructs exactly one immutable SSH transport session from the
schema-v2 binding for the complete invocation. It securely reads and hashes
the dedicated inputs, validates the one canonical known-host record and
Ed25519 identity, and places their exact bytes in sealed Linux memory files.
Every SSH child uses those same sealed bytes; the mutable source files are
reopened and revalidated before any success receipt or manifest is published.
The sealed files are closed before success publication.

SSH reads no user or system configuration (`-F none`), normal identity files
are cleared before the one sealed identity is added, normal and global
known-host files are disabled, and agents, certificates, password,
keyboard-interactive, GSSAPI, host-based authentication, multiplexing, DNS,
canonicalization, host-key updates, proxy commands and jump hosts are all
disabled. Strict host-key checking uses only the sealed one-record file and
the exact opaque alias and Ed25519 algorithm. The local SSH child receives a
minimal fixed environment with askpass disabled. All data arguments are
lowercase hex, SSH is batch-only with TTY and forwarding disabled, and the
remote external programs are fixed to
`/usr/bin/bash`, `/usr/bin/find`, `/usr/bin/stat`, `/usr/bin/sha256sum`, and
`/usr/bin/tar`.
Remote stderr and stdout are hard bounded. Stderr text is never returned or
stored. Every remote read-only command has a 12-hour wall-clock deadline and a
bounded post-cancellation wait; the complete rehearsal has the separate
24-hour ceiling described above. Inventory and OAuth walks enforce their entry
and byte ceilings incrementally, before hashing the next admitted file, and
the Linux parser independently rechecks the same limits. Inventory collection
uses at most four concurrent read-only SSH
channels to bound Windows load and shorten the consistency window; tar payloads
remain single-stream and source ordered.

The OAuth auth directory is never archived. Its filenames and contents are not
emitted; the final evidence contains only count, aggregate bytes, and a digest
of anonymous per-file records. Provider OAuth must be completed again on Linux.
The CLIProxy policy state is copied because it is required for tenant key,
quota, and usage continuity.

## Frozen final capture

Choose a new capture ID for every attempt. The destination basename must equal
that ID and an existing completed capture is never overwritten:

```bash
capture_id=cutover-20260727t120000z
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --spec /root/private/workagent-final-capture.json \
  --rehearsal-gate /root/private/windows-rehearsals/three-of-three.gate.json \
  --capture \
  --capture-id "$capture_id" \
  --destination "/root/private/windows-captures/$capture_id" \
  --windows-frozen \
  --confirm "FINAL-WINDOWS-CAPTURE:$capture_id"
```

`--windows-frozen` is a declaration of an already-established external freeze;
it does not perform one. Keep the freeze in place until the command reports
`complete-frozen-capture`.

Before opening SSH or creating a destination partial, capture strictly verifies
the canonical gate and requires its spec digest, source count, executable
SHA-256, and clean Git revision to match the current capture invocation. The
exact gate bytes are copied into the partial. Their SHA-256 is bound by the
schema-v2 start journal and schema-v2 completion manifest. A completed-capture
replay must supply that same gate; a different gate fails before remote access.

Files are streamed directly to a sibling private `.partial-*` directory.
Archive traversal, duplicate names, unapproved symlinks, hardlinks, devices,
sparse or special files, mount crossings, and destination symlink races fail
closed. The sole symlink contract matches the existing offline migrator: a
safe tenant-relative link may target an existing path inside that same
tenant's `data/builtin-skills` tree. The link is retained in the private
snapshot for the migrator's bounded in-tenant rewrite; cross-tenant, external,
missing-target, relative-target, and arbitrary links remain rejected.
Captured files are `0600`, or `0700` only when the Windows inventory marked
the owner-executable bit; directories are `0700`. This preserves executable
semantics without retaining group/world access. File, directory, and approved
symlink modification times are restored at the inventoried second and are part
of the stored semantic hash. Every file and directory is synced, the complete
stored content plus start/before/after evidence is
reopened and rehashed before publication, and publication uses
`renameat2(RENAME_NOREPLACE)` followed by a parent directory sync.

Replaying the same completed request does not contact Windows. It reopens the
private spec, traverses every captured destination without following links,
rehashes all files and pinned local inputs, validates the start journal and
both evidence documents and the preserved canonical rehearsal gate against the
completion manifest, rejects unexpected entries, and matches the complete
manifest before returning success.
Because this path is deliberately local-only, it does not open or require the
live SSH identity or known-hosts files. It verifies their binding transitively
through the exact schema-v2 spec digest already preserved by the gate and
manifest.

## Separate final-delta check

After capture, keep Windows frozen while the offline migration dry run and
completed stage verification consume this exact immutable snapshot. Then run
the separate final-delta mode against that same capture ID and destination:

```bash
capture_id=cutover-20260727t120000z
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --spec /root/private/workagent-final-capture.json \
  --verify-final-delta \
  --capture-id "$capture_id" \
  --destination "/root/private/windows-captures/$capture_id" \
  --windows-frozen \
  --confirm "FINAL-WINDOWS-DELTA:$capture_id"
```

This is an independent read-only check, not a replay of `--capture` and not a
substitute for the external freeze. Before opening any SSH channel, it:

1. reopens the strict private spec and rehashes every pinned local input;
2. requires the capture parent and completed capture to remain real,
   root-owned private directories;
3. strictly decodes and stably hashes the exact `capture-manifest.json` bytes;
4. revalidates the start journal, before/after evidence, every captured file,
   directory and admitted symbolic link, the preserved canonical rehearsal
   gate, the complete stored layout, and the aggregate; and
5. rereads the spec, local inputs, and manifest so a change during local
   verification fails before Windows is contacted; and
6. requires the current root-owned `0500` executable SHA-256 and clean Git
   revision to match the executable embedded in that preserved gate, then
   rereads the executable identity immediately before the first SSH call.

Only after all local checks pass does it collect two new Windows inventories
and anonymous OAuth evidence sets through the fixed read-only SSH protocol.
The two collections must match each other and must exactly equal both the
capture's before and after evidence, including source identity/content/archive
projections, each approved-exclusion digest, OAuth count/bytes/digest, source
cardinality, and aggregate. It then repeats the complete local capture gate and
requires the exact same binding before reporting success, so local capture or
input drift during the remote window also fails closed. It then rereads the
current executable identity; any binary drift during the final-delta window
suppresses success. The mode never streams tar data and has no Windows mutation
capability.

Success is the anonymous `complete-frozen-final-delta` JSON report. It binds
the capture ID, private spec digest, exact completion-manifest digest, original
capture completion time, verification completion time, source count,
aggregate, and anonymous OAuth summary; it contains no Windows paths, tenant
leaves, exclusion paths, or OAuth filenames. Re-running the command performs a
new offline verification and two new Windows reads; a previous success is
never treated as cached evidence.

The local-only Go API
`wincapture.VerifyCompletedCapture(wincapture.CompletedCaptureOptions{...})`
exposes the verified capture ID, spec digest, exact manifest digest, original
completion time, and aggregate for later private migration evidence. It
performs the same complete local integrity gate and cannot contact Windows.
Its binding schema remains version 1: the exact schema-v2 manifest digest is
the transitive binding to the preserved rehearsal-gate digest and bytes.

Any change to the approved address, port, user, host key, known-hosts bytes,
or identity bytes requires a new no-replace schema-v2 spec path and three new
rehearsal receipts and gate. Existing schema-v1 specs, binaries, receipts and
gates are historical evidence only and cannot count toward this cutover.
This deliberately local-only verifier validates the stored gate but does not
require the original capture executable to remain installed; only operations
that can contact Windows enforce the live executable identity.

Do not activate Linux production or describe the cutover as final until the
offline migration gates and this separate final-delta check pass while the
Windows freeze is still in force.
