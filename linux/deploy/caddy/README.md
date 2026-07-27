# Public TLS boundary

`Caddyfile` is the production HTTPS boundary for this migrated host. The
`nip.io` hostname resolves directly to the server's public IPv4 address.
Automatic HTTP redirects and the ACME HTTP-01 challenge are disabled because
TCP port 80 belongs to an unrelated Docker workload; certificate issuance must
therefore succeed through TLS-ALPN-01 on public TCP 443. There is deliberately
no internal/self-signed certificate fallback. If ACME or public ingress fails,
the deployment remains unavailable rather than silently serving untrusted TLS.
Only the Portal loopback listener is proxied. CLIProxy, ChatForward, the local
notification source, AionCore, Portal `/internal/*`, and UserHost sockets remain
private.

Tenant runtimes are allowed loopback TCP for provider and Portal integration,
so Caddy's administrative API must never listen on `127.0.0.1:2019`. The
tracked service drop-in creates `/run/caddy-admin` as mode `0700` owned by the
Caddy account, and the Caddyfile places the admin Unix socket inside it. The
packaged `ExecReload` reads the admin address from the same Caddyfile.

The access log is rotated internally at 100 MiB, retains at most ten files for
30 days, and drops request URIs and headers so OAuth codes, cookies, prompts,
and authorization values are not persisted. Caddy's own service user must have
write access to `/var/log/caddy`; the OS Caddy package normally creates it.

Before activation, run `caddy validate --config /etc/caddy/Caddyfile`, confirm
that the tracked file is the installed file, and test the certificate chain,
hostname, HTTPS `/readyz`, and WebSocket proxying from a genuinely external
network. A successful localhost check is not public-ingress evidence. The
current cloud security-group/NAT path is a known blocker until an external
client can reach TCP 443. Replacing this temporary address-derived hostname
with an organization-owned DNS name is a normal certificate/configuration
change and does not alter tenant data.
