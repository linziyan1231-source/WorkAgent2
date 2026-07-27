# Journal retention boundary

All WorkAgent services write to the systemd journal and apply per-unit rate
limits. `99-workagent-production.conf` adds a bounded, compressed, sealed
30-day persistent journal policy: at most 4 GiB, files no larger than 256 MiB,
and at least 16 GiB left free on the root filesystem.

Journald settings are host-wide, not service-scoped. Before installation,
compare this template with every existing file under
`/etc/systemd/journald.conf.d`. Back up any differing file and install this one
atomically as root-owned mode `0644`; never overwrite an organization policy
without approval. Validate with `systemd-analyze cat-config systemd/journald.conf`
and restart `systemd-journald` only during an approved maintenance window.

Caddy access events do not use the journal: the tracked Caddyfile rotates them
at 100 MiB while deleting request URIs and headers before encoding. CLIProxy
file logging is disabled; application and browser logs remain journal-only.
