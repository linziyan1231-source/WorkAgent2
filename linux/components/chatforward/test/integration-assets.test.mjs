import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

async function repositoryFile(relativePath) {
  return readFile(resolve(repositoryRoot, relativePath), "utf8");
}

test("bridge service uses a dedicated account, encrypted credential and loopback readiness", async () => {
  const unit = await repositoryFile("deploy/systemd/workagent-chatforward.service");
  const launcher = await repositoryFile("components/chatforward/integration/run-server.sh");
  assert.match(unit, /^User=workagent-chatforward$/m);
  assert.match(unit, /^LoadCredentialEncrypted=chatforward-key:/m);
  assert.match(unit, /^ExecStartPost=.*node --jitless .*readiness\.mjs --timeout-ms 15000$/m);
  assert.match(unit, /^ProtectSystem=strict$/m);
  assert.match(unit, /^MemoryDenyWriteExecute=yes$/m);
  assert.match(launcher, /^export CHATFORWARD_HOST=127\.0\.0\.1$/m);
  assert.match(launcher, /^export CHATFORWARD_PORT=3210$/m);
  assert.match(launcher, /^export CHATFORWARD_MAX_PAIRS=3$/m);
  assert.match(launcher, /--jitless/);
  assert.match(launcher, /--use-env-proxy/);
  assert.match(launcher, /NO_PROXY=127\.0\.0\.1,localhost/);
});

test("browser service keeps the profile private without disabling Chromium sandbox", async () => {
  const unit = await repositoryFile("deploy/systemd/workagent-chatforward-browser.service");
  const launcher = await repositoryFile("components/chatforward/integration/run-browser.sh");
  assert.match(unit, /^User=workagent-chatforward$/m);
  assert.match(unit, /^PrivateTmp=yes$/m);
  assert.match(unit, /^ProtectSystem=strict$/m);
  assert.match(unit, /^RestrictNamespaces=user pid net$/m);
  assert.match(unit, /^ReadWritePaths=\/var\/lib\/workagent\/chatforward /m);
  assert.match(unit, /readiness\.mjs --require-controller/);
  assert.match(launcher, /--user-data-dir="\$profile_directory"/);
  // Chrome 137+ ignores --load-extension outside developer mode; the
  // extension is CRX-installed through the managed policy written by
  // tmpfiles, so the launcher must not bypass that install.
  assert.doesNotMatch(launcher, /--load-extension|--disable-extensions-except/);
  assert.match(launcher, /--password-store=basic/);
  assert.match(launcher, /--disable-background-mode/);
  assert.match(launcher, /-nolisten tcp/);
  assert.match(launcher, /-auth "\$xauthority_file"/);
  assert.doesNotMatch(launcher, /(^|\s)-ac(\s|$)/m);
  assert.doesNotMatch(launcher, /--no-sandbox|--disable-web-security|--remote-debugging/);
  assert.match(launcher, /--proxy-bypass-list=localhost;127\.0\.0\.1/);
});

test("configuration contains no secret and cannot override the fixed listener", async () => {
  const configuration = await repositoryFile("config/chatforward.example.env");
  assert.match(configuration, /^CHATFORWARD_PORTAL_URL=http:\/\/127\.0\.0\.1:42580$/m);
  assert.match(configuration, /^CHATFORWARD_MIRROR_URL=http:\/\/192\.0\.2\.1:8443\/chatgpt\/$/m);
  assert.match(configuration, /^CHATFORWARD_CHROMIUM_BIN=\/usr\/bin\/google-chrome-stable$/m);
  assert.match(configuration, /^CHATFORWARD_OUTBOUND_PROXY_URL=http:\/\/127\.0\.0\.1:8118$/m);
  assert.doesNotMatch(configuration, /SECRET|CHATFORWARD_HOST|CHATFORWARD_PORT=/);
});

test("one-time login reads only the configured Chromium path and restarts managed units", async () => {
  const login = await repositoryFile("components/chatforward/integration/login.sh");
  assert.match(login, /configuration_file=\/etc\/workagent\/chatforward\.env/);
  assert.match(login, /CHATFORWARD_CHROMIUM_BIN=\*\) configured_chromium=/);
  assert.doesNotMatch(login, /source .*chatforward\.env|\. .*chatforward\.env/);
  assert.match(login, /systemctl start "\$bridge_unit"/);
  assert.match(login, /systemctl start "\$browser_unit"/);
});

test("build inputs pin the full source snapshot and Node archive", async () => {
  const sourceManifest = await repositoryFile("components/chatforward/SOURCE.sha256");
  const nodeManifest = await repositoryFile("components/chatforward/NODE.sha256");
  const dependencyManifest = await repositoryFile("components/chatforward/DEPENDENCIES.sha512");
  const version = await repositoryFile("components/chatforward/VERSION");
  const build = await repositoryFile("scripts/build-chatforward.sh");
  const entries = sourceManifest.trim().split("\n");
  assert.equal(entries.length, 27);
  assert.equal(new Set(entries.map((line) => line.slice(66))).size, entries.length);
  for (const entry of entries) assert.match(entry, /^[0-9a-f]{64}  [^/].*$/);
  assert.equal(nodeManifest.trim(), "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6  node-v24.15.0-linux-x64.tar.xz");
  assert.equal(dependencyManifest.trim(), "fb43539d6efb7c537f0e3422ea4fd2abf62f9384a06a3c3bbab5bc57e6ac8d79d1803b3d8321a475bec4ce07e10388285ec44864a136f1fcc85c11c4ce1ba25b  ws-8.21.1.tgz");
  assert.equal(version.trim(), "zombie-reap-20260725-2329");
  assert.match(build, /npm ci --offline --omit=dev --ignore-scripts --no-audit --no-fund/);
  assert.match(build, /tar --sort=name --format=gnu/);
  assert.match(build, /gzip -n -9/);
});
