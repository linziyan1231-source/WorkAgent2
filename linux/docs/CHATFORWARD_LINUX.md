# ChatForward Linux production runbook

ChatForward uses the exact Windows server release `zombie-reap-20260725-2329`, extension version `0.16.0`, three-pair limit, `quota-v1` gate and source-asset allow-list from the read-only production snapshot. Linux replaces the Windows launcher and Chrome profile discovery with a dedicated locked account, an immutable packaged Node runtime, a private Xvfb display and a persistent Chromium profile. Windows Chrome cookies are deliberately not copied because they are DPAPI-bound and because browser authentication material must not cross hosts.

After the normal WorkAgent host package is installed, the only interactive ChatForward action is one ChatGPT login in the dedicated profile. The unpacked extension is loaded by the managed Chromium command line on every start; no later extension installation is required.

## 1. Build a reproducible package

Inputs are the copied source snapshot, the checksum-verified official Node.js archive, and the exact `ws` tarball named by `package-lock.json`. The build does not modify the source directory. It verifies the complete file set and hashes, seeds an isolated npm cache from that pinned tarball, installs dependencies offline with lifecycle scripts disabled, runs the original ChatForward tests and the Linux integration tests, packages only the Node runtime binary/license needed in production, adds the Linux integration, normalizes metadata, and emits a deterministic tarball plus `SHA256SUMS`.

```bash
mkdir -m 0700 /absolute/empty/chatforward-output
scripts/build-chatforward.sh \
  /srv/workagent/source/.tools/sources/chatforward \
  /srv/workagent/source/.tools/downloads/node-v24.15.0-linux-x64.tar.xz \
  /srv/workagent/source/.tools/downloads/ws-8.21.1.tgz \
  /absolute/empty/chatforward-output
```

For reproducibility evidence, build twice into two new empty directories with the same `SOURCE_DATE_EPOCH` and compare both tarball SHA-256 values. Pass the approved archive and exact CLIProxy artifact root to `scripts/assemble-shared-linux.sh`, generate the evidence in `docs/RELEASE_EVIDENCE.md`, and sign the complete result with scope `shared`. Never extract an unsigned developer artifact over `/opt/workagent/shared`.

The signed shared release must:

- contain ChatForward only at `/opt/workagent/shared/chatforward`, alongside the signed CLIProxy payload, and pass the service's complete shared-root verification before start;
- install the two units, the Portal dependency drop-in, the separate sysusers/tmpfiles definitions, and `/etc/workagent/chatforward.env`;
- depend on a vendor-supported Chromium/Google Chrome version 116 or newer, Xvfb, xauth and util-linux (`runuser`);
- enable the Chromium sandbox. `--no-sandbox`, a public debugging port, and a host-network X server are forbidden.

## 2. Configure and protect credentials

Copy `config/chatforward.example.env` to `/etc/workagent/chatforward.env`, replace `CHATFORWARD_MIRROR_URL` with the public HTTPS Portal `/chatgpt/` URL, and install it as `root:workagent-chatforward` mode `0640`. Keep `CHATFORWARD_PORTAL_URL` on the Portal's exact `127.0.0.1` HTTP origin (changing only its loopback port if the approved Portal listener changes). The bridge listener is not configurable: the release wrapper always forces `127.0.0.1:3210` and exactly three pairs. If host policy requires the approved local egress proxy, set only `CHATFORWARD_OUTBOUND_PROXY_URL` to its exact `http://127.0.0.1:PORT` or `https://127.0.0.1:PORT` origin. Both Node and Chromium then use it while the Portal and bridge loopback endpoints remain bypassed; arbitrary environment proxy variables are cleared by the server wrapper.

Run `/opt/workagent/control/bin/workagent-secret generate-install --name chatforward-key`. It creates 48 random bytes in memory, base64url-encodes them and sends them only over stdin to host-bound systemd encryption; no plaintext file, argument, environment value or output is created. The resulting `/etc/credstore.encrypted/workagent/chatforward-key.cred` is loaded independently by Portal and `workagent-chatforward.service`. Use `--rotate` only in an approved coordinated restart of both consumers. The key must never appear in the environment file, a log or the Chromium profile.

Create the account and directories, then validate units without starting them:

```bash
systemd-sysusers /usr/lib/sysusers.d/workagent-chatforward.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/workagent-chatforward.conf
systemd-analyze verify \
  /usr/lib/systemd/system/workagent-chatforward.service \
  /usr/lib/systemd/system/workagent-chatforward-browser.service
systemctl daemon-reload
```

`workagent-chatforward` is locked and has `/usr/sbin/nologin`. Its profile, cache and runtime directories are mode `0700`. The Node bridge can write no application directory and uses `--jitless` so the unit can enforce `MemoryDenyWriteExecute=yes`. Chromium has only its three private write paths, a private `/tmp`, an Xvfb display with TCP disabled, no remote-debugging listener, and no sandbox-disabling flag. Its systemd boundary permits only the `user`, `pid`, and `net` namespace types required by the Chrome 150 user-namespace sandbox; a real transient-unit probe with `NoNewPrivileges=yes` and an empty capability set must pass before release, while `RestrictNamespaces=yes` is known to make the sandbox fail closed.

After the exact host RPMs and signed shared root are staged at the required
`/opt/workagent/shared/chatforward` production path, but before the
real browser service or one-time login starts, run the isolated acceptance
gate. It uses a dynamic throwaway UID, private bind-mounted profile/cache/runtime
directories, its own network namespace, and a closed private-loopback proxy,
and cleans every transient process and path; it never opens or modifies the
production ChatForward profile:

```bash
read -r workagent_chatforward_smoke_id < /proc/sys/kernel/random/uuid
sudo /usr/bin/systemd-run --quiet --wait --pipe --collect --service-type=exec \
  --unit="workagent-chatforward-smoke-${workagent_chatforward_smoke_id}.service" \
  --property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only' \
  --property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only' \
  --property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only' \
  /usr/libexec/workagent-fixed-root-exec-v1 chatforward-smoke \
  /opt/workagent/control/admin/smoke-chatforward-browser-sandbox \
  /opt/workagent/shared/chatforward \
  /usr/bin/google-chrome-stable
```

The immutable `chatforward-smoke` profile admits only that exact Chrome 150
path and command vector. While holding the catalog, control, and shared locks,
it verifies both signed roots and their complete smoke consumer contract; it
then releases only the catalog lock and supervises the smoke through exit.

## 3. One-time interactive ChatGPT login

Enable the bridge and browser units as part of normal host activation. The browser may initially show the ChatGPT login page on its private Xvfb display; its extension controller can still satisfy process readiness. From a trusted graphical console, or an SSH connection with trusted X11 forwarding, run exactly one interactive setup:

```bash
ssh -Y WORKAGENT_HOST
read -r workagent_chatforward_login_id < /proc/sys/kernel/random/uuid
workagent_chatforward_xauthority=${XAUTHORITY:-$HOME/.Xauthority}
sudo /usr/bin/systemd-run --quiet --wait --pipe --collect --service-type=exec \
  --unit="workagent-chatforward-login-${workagent_chatforward_login_id}.service" \
  --setenv="DISPLAY=${DISPLAY}" \
  --setenv="XAUTHORITY=${workagent_chatforward_xauthority}" \
  --property=UMask=0077 \
  --property=KillMode=control-group \
  --property='OpenFile=/run/workagent/activation.lock:workagent-activation-lock:read-only' \
  --property='OpenFile=/run/workagent/release-config.lock:workagent-config-lock:read-only' \
  --property='OpenFile=/opt/workagent/control.lock:workagent-control-release-lock:read-only' \
  --property='OpenFile=/opt/workagent/shared.lock:workagent-shared-release-lock:read-only' \
  /usr/libexec/workagent-fixed-root-exec-v1 chatforward-login \
  /opt/workagent/shared/chatforward/integration/login.sh
```

The closed `chatforward-login` profile requires the activation descriptor
first, acquires it exclusively, and only then acquires catalog, control and
shared locks. It verifies the signed control verifier/admin command and the
exact signed shared login/readiness/Node/extension contract while all four
lifecycle locks are held. The root supervisor retains every lock through child
exit while passing only its activation open-file description to the login
child for possession and journal-cleanliness verification. A fixed-root install,
recovery, tenant activation or second login therefore cannot overlap the
interactive browser or its managed service actions. Never run `login.sh`
directly or remove/reorder the four `OpenFile` properties.

Before touching either managed unit, the helper requires the supervisor's exact already-locked activation capability on descriptor 3 and asks the signed control command to authenticate that descriptor while proving both durable activation journals absent. It then closes its copy; the root supervisor retains the same locked open-file description through the entire interactive browser session and both service starts. The helper stops only the managed browser unit, transfers only the current X11 authorization cookie to a short-lived mode-`0600` file, and opens Chromium as `workagent-chatforward` with the production profile and extension. In that window:

1. Confirm `ChatForward Source Bridge` version `0.16.0` appears on `chrome://extensions/`.
2. Sign in to the intended ChatGPT account.
3. Confirm the configured WorkAgent project opens successfully.
4. Close every Chromium window.

The helper rejects a missing profile/cookie database, restarts the bridge and private-Xvfb browser, and waits up to 30 seconds for `controllerOnline=true`. It cannot prove account entitlement without making an unwanted chat request, so the visual project check is mandatory acceptance evidence. If ChatGPT later expires the session, repeat this same login command; no source, extension, Portal or service change is needed.

On a workstation without X11, use an approved local console or temporary, SSH-tunnel-only remote desktop attached to an operator session. Do not expose Xvfb, VNC, Chrome DevTools, port `3210`, or a login helper over the public network.

## 4. Readiness, logs and network acceptance

The bridge service start succeeds only when `/healthz` returns the full
production contract: `ok`, quota protection, `quota-v1`, source asset proxy,
exact three-pair capacity and consistent non-negative counters. The browser
service additionally requires the extension controller. Portal starts after
both managed units, and its own readiness requires `controllerOnline=true`
plus a consistent source state: `sourceOnline` must be true exactly when
`connectedPairs` is greater than zero. Zero connected pairs is valid while no
Portal user has an open B-side mirror, so an idle production system can remain
ready without fabricating a chat session.

```bash
/opt/workagent/shared/chatforward/node/bin/node \
  /opt/workagent/shared/chatforward/integration/readiness.mjs \
  --require-controller --timeout-ms 30000
ss -ltnp | grep -F '127.0.0.1:3210'
journalctl -u workagent-chatforward.service \
  -u workagent-chatforward-browser.service --since today
```

Only `127.0.0.1:3210` may listen; production users enter through the authenticated Portal `/chatgpt/` route on shared HTTPS 443. The systemd journal is the only service log destination, with per-unit rate limiting. ChatForward does not intentionally log chat prompts, responses, cookies or its HMAC key. Apply the production journald retention and off-host security-monitoring policy; do not redirect browser output into an unbounded profile log.

These local service and Portal readiness gates prove the locked bridge,
extension-controller and idle/connected state contract. They do **not** prove
that ChatGPT login is current, that the account can open the intended project,
or that a real message succeeds. Do not cite local `/readyz`, the production
preflight health section, or `controllerOnline=true` as login/entitlement
evidence. The visual project check above and the real two-tenant message
acceptance below remain mandatory and independent.

Complete browser acceptance with two distinct Portal users and include: three simultaneous A/B pairs, exact fourth-pair rejection text, source replacement after repeated failure, zombie-pair reclamation, file upload/download, quota reserve/settle, allowed static assets, denied off-list assets, restart persistence and cross-user isolation.

## 5. Recovery boundary

The Chromium profile is host-bound authentication material and is intentionally outside WorkAgent application backups. A normal service or host restart reuses `/var/lib/workagent/chatforward/chromium`. A blank-host disaster recovery restores signed packages and application state, provisions a new host-bound ChatForward credential from the approved external secret escrow, and then requires the same one-time ChatGPT login. Encrypted systemd credential ciphertext from the failed host is not portable and must not be restored. Never restore or copy the Windows profile, and never place the Linux profile in a tenant-accessible or general-purpose backup archive.
