# Encrypted off-host backup gate

`config/backup.example.json` is the production policy template. Its local
directory is only encrypted staging; its off-host directory must be beneath the
separately mounted `/mnt/workagent-backup` remote filesystem. The systemd unit
uses `AssertPathIsMountPoint=/mnt/workagent-backup`, and the backup binary then
verifies the filesystem type and that the remote destination is on a different
filesystem from local staging.

This repository intentionally contains no server name, share, username,
password, or mount credential. Install an organization-approved NFS/NFS4,
CIFS/SMB3, Ceph, or remote-FUSE mount through its protected credential flow.
Until that mount exists and a read-after-write-verified encrypted backup plus a
blank-host restore rehearsal succeeds, backup and production preflight must
fail. Never point `off_host_directory` at another local directory, the sparse
tenant image, or a bind mount of `/`.

Encrypted systemd credentials under `/etc/credstore.encrypted` are deliberately
excluded. `workagent-secret` binds them to the current OS installation's host
key; copying only their ciphertext to a blank host is neither recoverable nor a
secret escrow. Before a blank-host install, use `workagent-secret
generate-install` to create fresh CLIProxy management, ChatForward and
notification values directly in memory and install fresh host-bound
ciphertexts; then repeat OAuth and chat login. Never back up
`/var/lib/systemd/credential.secret` as a portability workaround.

The encrypted application archive always includes the single canonical
CLIProxy policy file
`/var/lib/cliproxyapi/policy/cpa-key-policy-state.json`. That file contains the
new tenant key hashes, quota limits and usage windows needed for a usable
blank-host restore; it does not contain provider OAuth tokens. Backup stops
CLIProxy and holds the same exclusive migration lock used by the offline quota
importer until the archive is complete. `/var/lib/cliproxyapi/auth` and every
parent or child source that could include it are rejected. Recovery restores
the policy file to the package-created `cliproxyapi` identity before starting
CLIProxy; provider OAuth is intentionally performed again on the new host.

The canonical application-state source set is `/etc/workagent`, the Portal
state root, every tenant data root, the CLIProxy policy file, every tenant
systemd identity drop-in, the independent Renderer release pointer and one
copy of each distinct tenant runtime pointer. Release trees themselves remain
immutable package artifacts. Snapshot discovery rejects unexpected tenant
configuration entries, proves Portal and tenant state-root/lock ownership,
checks SQLite, quota and signed current/previous releases, and holds all
runtime, CLIProxy and shared release-pointer locks until the encrypted local
and remote copies have completed. Archive construction rechecks file bytes,
metadata, namespace identity, symbolic-link targets and directory membership
for drift.

Additional sources may not equal, contain, or be contained by the CLIProxy
OAuth directory, `/etc/credstore.encrypted`, the systemd host key, or either
the persistent or cache ChatForward Chromium profile. The same overlap rule
prevents a broad parent directory from capturing host-bound material by
accident. The offline encryption key must also remain outside every source.

Blank-host installation is resumable only with the same authenticated
archive, receipt and staging target; all bytes, metadata and the exact entry
set are reverified before an existing target is accepted. The package and
production preflight create and verify the cross-process install lock at
`/run/workagent-backup/recovery-install.lock` as `0600 root:root`. Activation
itself is recorded, without replacement, in the persistent root-only
`/var/lib/workagent-backup/recovery-activation.json`; this journal is absent in
normal state and must never be created by tmpfiles. A subsequent invocation
after SIGKILL or reboot disables the enableable set and stops tenant sockets
before their possibly socket-activated services. Recovery requires every
future entrypoint to be both inactive and `UnitFileState=disabled`, requires
non-enableable helpers to remain `static`, and reads those exact states back
after every enable or rollback; this prevents a reboot from escaping the
activation journal. Production preflight blocks
unless the protected journal parent is valid and this file is provably absent.

Recovery deliberately has two gates. It requires Caddy and the backup/health
services and timers to be inactive, but its activation transaction starts and
enables only CLIProxy, notification, ChatForward, enabled tenant sockets, the
ChatForward browser and Portal. Caddy and both timers stay stopped until fresh
provider OAuth, the one-time ChatGPT login, local/provider checks and the
approved external edge gate are complete. This prevents a technically restored
host from publishing traffic or emitting production health/backup claims too
early.
