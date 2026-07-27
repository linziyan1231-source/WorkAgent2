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

The bootstrap helper derives this private input only from the protected legacy
snapshot and its completed migration report; it never contacts Windows:

```bash
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --init-spec \
  --legacy-snapshot /root/private/protected-legacy-snapshot \
  --migration-report /root/private/completed-stage/report.json \
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

Run from the Linux migration host as root:

```bash
/opt/workagent/migration-tools/bin/workagent-capture-windows \
  --spec /root/private/workagent-final-capture.json \
  --check
```

Although this mode cannot declare or produce a final frozen capture, a useful
rehearsal still needs an operator-established temporary quiescence window. Stop
or otherwise fence every WorkAgent writer outside this tool, including
CLIProxyAPI OAuth refreshes, for the complete invocation. Do not pass
`--windows-frozen`: temporary rehearsal quiescence is not the final continuous
cutover freeze and the tool remains strictly read-only.

Run at least three separate successful rehearsals before establishing the
final external freeze. Each successful invocation independently proves that
its own before/after source, approved-exclusion, and anonymous OAuth evidence
converged. If production writers resume between separate rehearsal windows,
the anonymous aggregate and OAuth summaries may legitimately differ across
their reports; do not reject those successes merely because the reports are
not byte-identical. If all three invocations run inside one continuous
quiescence window, their summaries must remain identical. Preserve each JSON
report together with its UTC start/end, exit status, source revision, and the
binary and private-spec SHA-256 values in a root-only evidence directory. The
report's `completed_at` is the tool-recorded successful completion time.

Any nonzero invocation is a failed attempt and does not count toward the three
successes. One failure reports every detected anonymous drift class: OAuth
file-count, aggregate-byte, and digest changes plus source and
approved-exclusion slot numbers. It never emits a Windows path, tenant leaf,
OAuth filename, digest value, or content. Do not immediately repeat a drift
failure while known writers remain active. All three successes must bind the
same binary, private-spec digest, and source count. A rehearsal still is not a
snapshot and must never be substituted for the frozen final capture.

The command invokes only the fixed SSH target and a static `bash -s` program.
All data arguments are lowercase hex, SSH is batch-only with TTY and forwarding
disabled, and the remote external programs are fixed to
`/usr/bin/bash`, `/usr/bin/find`, `/usr/bin/stat`, `/usr/bin/sha256sum`, and
`/usr/bin/tar`.
Remote stderr and stdout are hard bounded. Stderr text is never returned or
stored. Every remote read-only command has a 12-hour wall-clock deadline and a
bounded post-cancellation wait. Inventory and OAuth walks enforce their entry
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
  --capture \
  --capture-id "$capture_id" \
  --destination "/root/private/windows-captures/$capture_id" \
  --windows-frozen \
  --confirm "FINAL-WINDOWS-CAPTURE:$capture_id"
```

`--windows-frozen` is a declaration of an already-established external freeze;
it does not perform one. Keep the freeze in place until the command reports
`complete-frozen-capture`.

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
both evidence documents against the completion manifest, rejects unexpected
entries, and matches the complete manifest before returning success.

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
   directory and admitted symbolic link, the complete stored layout, and the
   aggregate; and
5. rereads the spec, local inputs, and manifest so a change during local
   verification fails before Windows is contacted.

Only after all local checks pass does it collect two new Windows inventories
and anonymous OAuth evidence sets through the fixed read-only SSH protocol.
The two collections must match each other and must exactly equal both the
capture's before and after evidence, including source identity/content/archive
projections, each approved-exclusion digest, OAuth count/bytes/digest, source
cardinality, and aggregate. It then repeats the complete local capture gate and
requires the exact same binding before reporting success, so local capture or
input drift during the remote window also fails closed. The mode never streams
tar data and has no Windows mutation capability.

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

Do not activate Linux production or describe the cutover as final until the
offline migration gates and this separate final-delta check pass while the
Windows freeze is still in force.
