import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const [nodeArgument, entrypointArgument] = process.argv.slice(2);
if (nodeArgument === undefined || entrypointArgument === undefined) {
  throw new Error('usage: node codex-acp-product-path-smoke.mjs /resolved/node /resolved/codex-acp-entrypoint');
}

const nodeExecutable = resolve(nodeArgument);
const entrypoint = resolve(entrypointArgument);
const smokeRoot = await mkdtemp(join(tmpdir(), 'workagent-codex-product-path-'));
const smokeHome = join(smokeRoot, 'home');
const codexHome = join(smokeHome, '.codex');
const capturePath = join(smokeRoot, 'fake-codex-requests.jsonl');
const fakePidPath = join(smokeRoot, 'fake-codex.pid');
const fakeCodexPath = join(smokeRoot, 'fake-codex.mjs');
await mkdir(codexHome, { recursive: true, mode: 0o700 });

const fakeCodexSource = `#!/usr/bin/env node
import { appendFileSync, writeFileSync } from 'node:fs';

const capturePath = process.env.FAKE_CODEX_CAPTURE;
const pidPath = process.env.FAKE_CODEX_PID;
if (!capturePath || !pidPath || process.argv[2] !== 'app-server') process.exit(64);
writeFileSync(pidPath, String(process.pid));

let buffer = '';
let activeThreadId = null;
let activeTurnId = null;
let steerCount = 0;
const send = (message) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...message }) + '\\n');
const result = (id, value) => send({ id, result: value });
const error = (id, code, message) => send({ id, error: { code, message } });
const capture = (message) => appendFileSync(capturePath, JSON.stringify({ method: message.method, params: message.params ?? null }) + '\\n');

const model = {
  id: 'gpt-5-codex',
  displayName: 'GPT-5-Codex',
  description: 'Product-path smoke model',
  defaultReasoningEffort: 'medium',
  supportedReasoningEfforts: [{ reasoningEffort: 'medium', description: 'Medium' }],
  inputModalities: ['text'],
  isDefault: true,
  additionalSpeedTiers: [],
};

const handle = (message) => {
  if (!message || typeof message !== 'object' || typeof message.method !== 'string') return;
  capture(message);
  if (message.id === undefined) return;
  switch (message.method) {
    case 'initialize':
      result(message.id, { userAgent: 'workagent-product-path-smoke' });
      break;
    case 'account/read':
      result(message.id, { account: null, requiresOpenaiAuth: false });
      break;
    case 'thread/read':
      result(message.id, {
        thread: {
          id: message.params.threadId,
          turns: [{ id: 'source-turn-0', items: [], status: 'completed' }],
        },
      });
      break;
    case 'thread/fork':
      result(message.id, { thread: { id: 'forked-session' } });
      break;
    case 'skills/extraRoots/set':
      result(message.id, {});
      break;
    case 'skills/list':
      result(message.id, { data: [] });
      break;
    case 'config/read':
      result(message.id, { config: {} });
      break;
    case 'thread/start':
      activeThreadId = 'live-session';
      result(message.id, {
        thread: { id: activeThreadId },
        model: model.id,
        reasoningEffort: model.defaultReasoningEffort,
        modelProvider: 'openai',
        serviceTier: null,
      });
      break;
    case 'model/list':
      result(message.id, { data: [model], nextCursor: null });
      break;
    case 'turn/start':
      activeThreadId = message.params.threadId;
      activeTurnId = 'live-turn';
      result(message.id, {
        turn: { id: activeTurnId, status: 'inProgress', items: [] },
      });
      break;
    case 'turn/steer':
      steerCount += 1;
      result(message.id, { turnId: activeTurnId });
      if (steerCount === 2) {
        setTimeout(() => send({
          method: 'turn/completed',
          params: {
            threadId: activeThreadId,
            turn: { id: activeTurnId, status: 'completed', items: [], error: null },
          },
        }), 20);
      }
      break;
    default:
      error(message.id, -32601, 'unimplemented fake Codex method: ' + message.method);
  }
};

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  while (buffer.includes('\\n')) {
    const newline = buffer.indexOf('\\n');
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (line !== '') handle(JSON.parse(line));
  }
});
`;

await writeFile(fakeCodexPath, fakeCodexSource, { mode: 0o700 });
await chmod(fakeCodexPath, 0o700);

let child;
let timer;
try {
  child = spawn(nodeExecutable, [entrypoint], {
    cwd: smokeRoot,
    env: {
      ...process.env,
      APP_SERVER_LOGS: join(smokeRoot, 'logs'),
      CODEX_HOME: codexHome,
      CODEX_PATH: fakeCodexPath,
      FAKE_CODEX_CAPTURE: capturePath,
      FAKE_CODEX_PID: fakePidPath,
      HOME: smokeHome,
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      NO_COLOR: '1',
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
    stderr = (stderr + chunk).slice(-8192);
  });

  const waitForReply = async (id) => {
    const deadline = Date.now() + 20_000;
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

  const capturedRequests = async () => {
    try {
      const contents = await readFile(capturePath, 'utf8');
      return contents.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
  };

  const waitForCapturedMethod = async (method) => {
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      const requests = await capturedRequests();
      if (requests.some((request) => request.method === method)) return requests;
      await new Promise((resolveWait) => setTimeout(resolveWait, 20));
    }
    throw new Error(`timed out waiting for fake Codex method ${method}: ${stderr}`);
  };

  const send = (id, method, params) => {
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  };

  send(1, 'initialize', { protocolVersion: 1, clientCapabilities: {} });
  const initialized = await waitForReply(1);
  assert.equal(initialized.error, undefined, JSON.stringify(initialized.error));
  assert.equal(initialized.result?.agentInfo?.version, '1.1.2');
  assert.deepEqual(initialized.result?.agentCapabilities?.sessionCapabilities?.fork, {});

  send(2, 'session/fork', {
    sessionId: 'source-session',
    cwd: smokeRoot,
    mcpServers: [],
    _meta: { aionui: { turnIndex: 0 } },
  });
  const forked = await waitForReply(2);
  assert.equal(forked.error, undefined, JSON.stringify(forked.error));
  assert.equal(forked.result?.sessionId, 'forked-session');

  send(3, 'session/new', { cwd: smokeRoot, mcpServers: [] });
  const created = await waitForReply(3);
  assert.equal(created.error, undefined, JSON.stringify(created.error));
  assert.equal(created.result?.sessionId, 'live-session');

  send(4, 'session/prompt', {
    sessionId: 'live-session',
    prompt: [{ type: 'text', text: 'initial prompt' }],
  });
  await waitForCapturedMethod('turn/start');

  send(5, '_aionui/session/steer', {
    sessionId: 'live-session',
    prompt: [{ type: 'text', text: 'first guidance' }],
  });
  send(6, '__aionui/session/steer', {
    sessionId: 'live-session',
    prompt: [{ type: 'text', text: 'alias guidance' }],
  });
  for (const id of [5, 6]) {
    const reply = await waitForReply(id);
    assert.equal(reply.error, undefined, JSON.stringify(reply.error));
    assert.equal(reply.result?.turnId, 'live-turn');
  }
  const prompted = await waitForReply(4);
  assert.equal(prompted.error, undefined, JSON.stringify(prompted.error));
  assert.equal(prompted.result?.stopReason, 'end_turn');

  const requests = await capturedRequests();
  const method = (name) => requests.filter((request) => request.method === name);
  assert.equal(method('thread/read').length, 1);
  assert.deepEqual(method('thread/read')[0].params, { threadId: 'source-session', includeTurns: true });
  assert.equal(method('thread/fork').length, 1);
  assert.deepEqual(method('thread/fork')[0].params, { threadId: 'source-session', lastTurnId: 'source-turn-0' });
  assert.equal(method('turn/start').length, 1, 'steer must not create fallback turns');
  const steers = method('turn/steer');
  assert.equal(steers.length, 2);
  assert.deepEqual(steers.map((request) => request.params), [
    {
      threadId: 'live-session',
      expectedTurnId: 'live-turn',
      input: [{ type: 'text', text: 'first guidance', text_elements: [] }],
    },
    {
      threadId: 'live-session',
      expectedTurnId: 'live-turn',
      input: [{ type: 'text', text: 'alias guidance', text_elements: [] }],
    },
  ]);

  process.stdout.write('Codex ACP resolved product path fork/live-steer smoke: PASS\n');
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
  try {
    const fakePid = Number.parseInt((await readFile(fakePidPath, 'utf8')).trim(), 10);
    if (Number.isSafeInteger(fakePid) && fakePid > 1) process.kill(fakePid, 'SIGTERM');
  } catch (error) {
    if (error?.code !== 'ENOENT' && error?.code !== 'ESRCH') throw error;
  }
  await rm(smokeRoot, { recursive: true, force: true });
}
