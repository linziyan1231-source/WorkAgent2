import { describe, expect, it, vi } from 'vitest';

import type { AgentSideConnection } from '@agentclientprotocol/sdk';
import type { KimiHarness, Session } from '@moonshot-ai/kimi-code-sdk';

import { AcpServer } from '../src/server';
import { AcpSession } from '../src/session';
import { AUTHED_STATUS, UNAUTHED_STATUS } from './_helpers/harness-stubs';

function makeHarness(options: {
  authenticated?: boolean;
  forkSession?: KimiHarness['forkSession'];
} = {}): KimiHarness {
  return {
    auth: {
      status: async () => options.authenticated === false ? UNAUTHED_STATUS : AUTHED_STATUS,
    },
    forkSession: options.forkSession,
  } as unknown as KimiHarness;
}

describe('AionUI ACP fork/steer patch', () => {
  it('advertises the ACP fork capability', async () => {
    const response = await new AcpServer(makeHarness()).initialize({ protocolVersion: 1 });
    expect(response.agentCapabilities?.sessionCapabilities?.fork).toEqual({});
  });

  it('forks the requested persisted turn with AionUI metadata', async () => {
    const forkSession = vi.fn(async () => ({ id: 'session-forked' }) as Session);
    const server = new AcpServer(makeHarness({ forkSession }));

    await expect(server.unstable_forkSession({
      sessionId: 'session-source',
      cwd: '/srv/workagent/users/example/workspace',
      mcpServers: [],
      _meta: { aionui: { turnIndex: 4 } },
    })).resolves.toEqual({ sessionId: 'session-forked' });
    expect(forkSession).toHaveBeenCalledExactlyOnceWith({
      id: 'session-source',
      turnIndex: 4,
      metadata: { source: 'aionui' },
    });
  });

  it.each([
    undefined,
    null,
    -1,
    1.5,
    '2',
  ])('rejects invalid AionUI turnIndex %j', async (turnIndex) => {
    const forkSession = vi.fn();
    const server = new AcpServer(makeHarness({ forkSession }));
    await expect(server.unstable_forkSession({
      sessionId: 'session-source',
      cwd: '/srv/workagent/users/example/workspace',
      mcpServers: [],
      _meta: { aionui: { turnIndex } },
    })).rejects.toMatchObject({ code: -32602 });
    expect(forkSession).not.toHaveBeenCalled();
  });

  it('keeps the authentication gate in front of fork', async () => {
    const forkSession = vi.fn();
    const server = new AcpServer(makeHarness({ authenticated: false, forkSession }));
    await expect(server.unstable_forkSession({
      sessionId: 'session-source',
      cwd: '/srv/workagent/users/example/workspace',
      mcpServers: [],
      _meta: { aionui: { turnIndex: 0 } },
    })).rejects.toMatchObject({ code: -32000 });
    expect(forkSession).not.toHaveBeenCalled();
  });

  it('maps a missing source session to ACP invalid_params', async () => {
    const server = new AcpServer(makeHarness({
      forkSession: async () => {
        throw Object.assign(new Error('missing'), { code: 'session.not_found' });
      },
    }));
    await expect(server.unstable_forkSession({
      sessionId: 'session-missing',
      cwd: '/srv/workagent/users/example/workspace',
      mcpServers: [],
      _meta: { aionui: { turnIndex: 0 } },
    })).rejects.toMatchObject({ code: -32602 });
  });

  it('converts ACP content blocks and steers the matching live session', async () => {
    const steer = vi.fn(async () => undefined);
    const session = { id: 'session-live', steer } as unknown as Session;
    const acpSession = new AcpSession({} as AgentSideConnection, session);
    const server = new AcpServer(makeHarness());
    const internals = server as unknown as { sessions: Map<string, AcpSession> };
    internals.sessions.set(session.id, acpSession);

    await expect(server.extMethod('_aionui/session/steer', {
      sessionId: session.id,
      prompt: [{ type: 'text', text: 'Use the smaller migration step.' }],
    })).resolves.toEqual({});
    expect(steer).toHaveBeenCalledExactlyOnceWith([
      { type: 'text', text: 'Use the smaller migration step.' },
    ]);
  });

  it('rejects malformed or unknown steer targets before calling the SDK', async () => {
    const server = new AcpServer(makeHarness());
    await expect(server.extMethod('_aionui/session/steer', {
      sessionId: 'session-missing',
      prompt: [],
    })).rejects.toMatchObject({ code: -32602 });
    await expect(server.extMethod('_aionui/session/steer', {
      sessionId: 7,
      prompt: 'not-an-array',
    })).rejects.toMatchObject({ code: -32602 });
  });
});
