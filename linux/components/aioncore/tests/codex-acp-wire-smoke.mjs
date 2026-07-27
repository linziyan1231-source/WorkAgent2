import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';

const [nodeArgument, platformRootArgument] = process.argv.slice(2);
if (nodeArgument === undefined || platformRootArgument === undefined) {
  throw new Error('usage: node codex-acp-wire-smoke.mjs /absolute/path/to/node /absolute/path/to/platform-root');
}

const nodeExecutable = resolve(nodeArgument);
const platformRoot = resolve(platformRootArgument);
const entrypoint = join(platformRoot, 'node_modules', '@agentclientprotocol', 'codex-acp', 'dist', 'index.js');
const smokeHome = await mkdtemp(join(tmpdir(), 'workagent-codex-acp-'));
const codexHome = join(smokeHome, '.codex');
await mkdir(codexHome, { mode: 0o700 });
let child;
let timer;

try {
  child = spawn(nodeExecutable, [entrypoint], {
    cwd: smokeHome,
    env: {
      HOME: smokeHome,
      CODEX_HOME: codexHome,
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      NO_COLOR: '1',
      PATH: `${join(platformRoot, 'node_modules', '.bin')}${delimiter}/usr/local/bin${delimiter}/usr/bin${delimiter}/bin`,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stdoutBuffer = '';
  let stderr = '';
  const replies = new Map();
  let wake;
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk;
    while (stdoutBuffer.includes('\n')) {
      const newline = stdoutBuffer.indexOf('\n');
      const line = stdoutBuffer.slice(0, newline).trim();
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (line !== '') {
        const message = JSON.parse(line);
        if (message.id !== undefined) replies.set(message.id, message);
      }
    }
    wake?.();
  });
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk).slice(-4096);
  });

  const waitForReply = async (id) => {
    const deadline = Date.now() + 15_000;
    while (!replies.has(id)) {
      const remaining = deadline - Date.now();
      assert.ok(remaining > 0, `timed out waiting for ACP reply ${id}: ${stderr}`);
      await new Promise((resolveWait, reject) => {
        wake = resolveWait;
        timer = setTimeout(() => {
          wake = undefined;
          reject(new Error(`timed out waiting for ACP reply ${id}: ${stderr}`));
        }, remaining);
      }).finally(() => {
        if (timer !== undefined) clearTimeout(timer);
        timer = undefined;
        wake = undefined;
      });
    }
    return replies.get(id);
  };

  const send = (id, method, params) => {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  };

  send(1, 'initialize', { protocolVersion: 1, clientCapabilities: {} });
  const initialized = await waitForReply(1);
  assert.equal(initialized.error, undefined, JSON.stringify(initialized.error));
  assert.equal(initialized.result?.protocolVersion, 1);
  assert.deepEqual(initialized.result?.agentCapabilities?.sessionCapabilities?.fork, {});
  assert.equal(initialized.result?.agentInfo?.version, '1.1.2');

  send(2, 'session/fork', {
    sessionId: 'missing',
    cwd: smokeHome,
    mcpServers: [],
    _meta: { aionui: { turnIndex: 0 } },
  });
  send(3, '_aionui/session/steer', {
    sessionId: 'missing',
    prompt: [{ type: 'text', text: 'smoke guidance' }],
  });
  send(4, '__aionui/session/steer', {
    sessionId: 'missing',
    prompt: [{ type: 'text', text: 'smoke alias guidance' }],
  });

  for (const id of [2, 3, 4]) {
    const reply = await waitForReply(id);
    assert.ok(reply.error, `ACP route ${id} unexpectedly succeeded`);
    assert.notEqual(reply.error.code, -32601, `ACP route ${id} was not registered`);
  }

  process.stdout.write('Codex ACP 1.1.2 fork/steer wire smoke: PASS\n');
} finally {
  if (timer !== undefined) clearTimeout(timer);
  if (child !== undefined) {
    child.stdin.end();
    child.kill('SIGTERM');
    await new Promise((resolveExit) => {
      if (child.exitCode !== null || child.signalCode !== null) resolveExit();
      else {
        const forceTimer = setTimeout(() => child.kill('SIGKILL'), 5_000);
        child.once('close', () => {
          clearTimeout(forceTimer);
          resolveExit();
        });
      }
    });
  }
  await rm(smokeHome, { recursive: true, force: true });
}
