import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

const executable = process.argv[2];
if (executable === undefined) {
  throw new Error('usage: node native-acp-smoke.mjs /absolute/path/to/kimi');
}
const binary = resolve(executable);
const smokeHome = await mkdtemp(join(tmpdir(), 'workagent-kimi-acp-'));
let timer;

try {
  const child = spawn(binary, ['acp'], {
    env: {
      ...process.env,
      HOME: smokeHome,
      KIMI_CODE_HOME: join(smokeHome, '.kimi-code'),
      NO_COLOR: '1',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  const requests = [
    {
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: 1, clientCapabilities: {} },
    },
    {
      jsonrpc: '2.0', id: 2, method: 'session/fork',
      params: {
        sessionId: 'missing', cwd: '/tmp', mcpServers: [],
        _meta: { aionui: { turnIndex: 0 } },
      },
    },
    {
      jsonrpc: '2.0', id: 3, method: '_aionui/session/steer',
      params: {
        sessionId: 'missing',
        prompt: [{ type: 'text', text: 'smoke guidance' }],
      },
    },
  ];
  for (const request of requests) child.stdin.write(`${JSON.stringify(request)}\n`);
  child.stdin.end();

  const exit = await new Promise((resolveExit, reject) => {
    timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('Kimi ACP smoke test timed out'));
    }, 15_000);
    child.once('error', reject);
    child.once('close', (code, signal) => resolveExit({ code, signal }));
  });
  clearTimeout(timer);
  timer = undefined;
  assert.deepEqual(exit, { code: 0, signal: null }, `ACP exited unexpectedly: ${stderr}`);

  const replies = stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
  const byId = new Map(replies.map((reply) => [reply.id, reply]));
  const initialized = byId.get(1)?.result;
  assert.equal(initialized?.protocolVersion, 1);
  assert.deepEqual(initialized?.agentCapabilities?.sessionCapabilities?.fork, {});
  assert.equal(initialized?.agentInfo?.version, '0.29.1');
  assert.equal(byId.get(2)?.error?.code, -32000, 'fork must retain the auth gate');
  assert.equal(byId.get(3)?.error?.code, -32602, 'steer must reject an unknown session');
  process.stdout.write('Kimi native ACP fork/steer smoke: PASS\n');
} finally {
  if (timer !== undefined) clearTimeout(timer);
  await rm(smokeHome, { recursive: true, force: true });
}
