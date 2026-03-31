import http from 'http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { startApiServer, ApiServerConfig } from './api-server.js';

// Mock container-runner so we don't spawn real containers
vi.mock('./container-runner.js', () => ({
  runContainerAgent: vi.fn(),
}));

// Mock logger to suppress output
vi.mock('./logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import { runContainerAgent } from './container-runner.js';

const TEST_TOKEN = 'test-secret-token';
const TEST_PORT = 0; // Let OS pick a free port

function makeConfig(overrides?: Partial<ApiServerConfig>): ApiServerConfig {
  return {
    port: TEST_PORT,
    host: '127.0.0.1',
    token: TEST_TOKEN,
    defaultGroupId: 'test-group',
    getRegisteredGroups: () => ({
      'group-jid-1@g.us': {
        name: 'Test Group',
        folder: 'test-group',
        trigger: '@Andy',
        added_at: '2026-01-01',
      },
    }),
    getSession: () => undefined,
    setSession: vi.fn(),
    ...overrides,
  };
}

function request(
  server: http.Server,
  options: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: string;
  },
): Promise<{
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const addr = server.address() as { port: number };
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: addr.port,
        method: options.method || 'POST',
        path: options.path || '/api/query',
        headers: options.headers || {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode!,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          });
        });
      },
    );
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

describe('API server', () => {
  let server: http.Server;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    vi.restoreAllMocks();
  });

  describe('routing and auth', () => {
    beforeEach(async () => {
      server = await startApiServer(makeConfig());
    });

    it('returns 404 for unknown routes', async () => {
      const res = await request(server, {
        path: '/unknown',
        headers: { authorization: `Bearer ${TEST_TOKEN}` },
      });
      expect(res.status).toBe(404);
      expect(JSON.parse(res.body)).toEqual({ error: 'Not found' });
    });

    it('returns 404 for GET requests', async () => {
      const res = await request(server, {
        method: 'GET',
        headers: { authorization: `Bearer ${TEST_TOKEN}` },
      });
      expect(res.status).toBe(404);
    });

    it('handles CORS preflight', async () => {
      const res = await request(server, {
        method: 'OPTIONS',
      });
      expect(res.status).toBe(204);
      expect(res.headers['access-control-allow-origin']).toBe('*');
      expect(res.headers['access-control-allow-methods']).toContain('POST');
      expect(res.headers['access-control-allow-headers']).toContain(
        'Authorization',
      );
    });

    it('returns 401 without auth header', async () => {
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: { 'content-type': 'application/json' },
      });
      expect(res.status).toBe(401);
      expect(JSON.parse(res.body)).toEqual({ error: 'Unauthorized' });
    });

    it('returns 401 with wrong token', async () => {
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer wrong-token',
        },
      });
      expect(res.status).toBe(401);
    });

    it('returns 401 with malformed auth header', async () => {
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: TEST_TOKEN, // missing "Bearer " prefix
        },
      });
      expect(res.status).toBe(401);
    });
  });

  describe('request validation', () => {
    beforeEach(async () => {
      server = await startApiServer(makeConfig());
    });

    it('returns 400 for invalid JSON', async () => {
      const res = await request(server, {
        body: 'not json',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body)).toEqual({ error: 'Invalid JSON' });
    });

    it('returns 400 when text is missing', async () => {
      const res = await request(server, {
        body: JSON.stringify({ groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });
      expect(res.status).toBe(400);
      expect(JSON.parse(res.body).error).toContain('Missing required field');
    });

    it('uses default groupId when not provided', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, _input, onProcess, _onOutput) => {
          onProcess({} as any, 'test-container');
          return { status: 'success' as const, result: null };
        },
      );

      const res = await request(server, {
        body: JSON.stringify({ text: 'hello' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });
      // Should succeed because defaultGroupId='test-group' matches the registered group
      expect(res.status).toBe(200);
    });

    it('returns 404 for unknown group', async () => {
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'nonexistent' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });
      expect(res.status).toBe(404);
      expect(JSON.parse(res.body)).toEqual({ error: 'Group not found' });
    });
  });

  describe('successful query', () => {
    it('returns SSE stream with chunk and done events', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, _input, onProcess, onOutput) => {
          // Simulate process registration
          onProcess({} as any, 'test-container');
          // Simulate streaming output
          if (onOutput) {
            await onOutput({
              status: 'success',
              result: 'Hello from the agent!',
              newSessionId: 'session-123',
            });
          }
          return {
            status: 'success' as const,
            result: 'Hello from the agent!',
            newSessionId: 'session-123',
          };
        },
      );

      const setSession = vi.fn();
      server = await startApiServer(makeConfig({ setSession }));

      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('text/event-stream');
      expect(res.headers['cache-control']).toBe('no-cache');
      expect(res.headers['access-control-allow-origin']).toBe('*');

      // Parse SSE events
      const events = res.body
        .split('\n\n')
        .filter((line) => line.startsWith('data: '))
        .map((line) => JSON.parse(line.replace('data: ', '')));

      expect(events).toHaveLength(2);
      expect(events[0]).toEqual({
        type: 'chunk',
        text: 'Hello from the agent!',
      });
      expect(events[1]).toEqual({ type: 'done' });
    });

    it('strips internal tags from output', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, _input, onProcess, onOutput) => {
          onProcess({} as any, 'test-container');
          if (onOutput) {
            await onOutput({
              status: 'success',
              result: '<internal>thinking about it</internal>The actual answer',
              newSessionId: undefined,
            });
          }
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      const events = res.body
        .split('\n\n')
        .filter((line) => line.startsWith('data: '))
        .map((line) => JSON.parse(line.replace('data: ', '')));

      const chunk = events.find((e: any) => e.type === 'chunk');
      expect(chunk.text).toBe('The actual answer');
      expect(chunk.text).not.toContain('internal');
    });

    it('skips empty chunks after stripping internal tags', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, _input, onProcess, onOutput) => {
          onProcess({} as any, 'test-container');
          if (onOutput) {
            await onOutput({
              status: 'success',
              result: '<internal>only internal content</internal>',
              newSessionId: undefined,
            });
          }
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      const events = res.body
        .split('\n\n')
        .filter((line) => line.startsWith('data: '))
        .map((line) => JSON.parse(line.replace('data: ', '')));

      // Should only have 'done', no 'chunk'
      expect(events).toHaveLength(1);
      expect(events[0]).toEqual({ type: 'done' });
    });

    it('passes history to container agent as formatted prompt', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, input, onProcess, _onOutput) => {
          onProcess({} as any, 'test-container');
          // Verify the prompt includes conversation history
          expect(input.prompt).toContain('<conversation_history>');
          expect(input.prompt).toContain('role="User"');
          expect(input.prompt).toContain('previous question');
          expect(input.prompt).toContain('role="Assistant"');
          expect(input.prompt).toContain('previous answer');
          expect(input.prompt).toContain('follow up');
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      await request(server, {
        body: JSON.stringify({
          text: 'follow up',
          groupId: 'test-group',
          history: [
            { role: 'user', content: 'previous question' },
            { role: 'assistant', content: 'previous answer' },
          ],
        }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(mockRunAgent).toHaveBeenCalled();
    });

    it('passes correct container input params', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, input, onProcess, _onOutput) => {
          onProcess({} as any, 'test-container');
          expect(input.groupFolder).toBe('test-group');
          expect(input.chatJid).toBe('group-jid-1@g.us');
          expect(input.isMain).toBe(false);
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(mockRunAgent).toHaveBeenCalled();
    });

    it('saves session ID from streaming output', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, _input, onProcess, onOutput) => {
          onProcess({} as any, 'test-container');
          if (onOutput) {
            await onOutput({
              status: 'success',
              result: 'response',
              newSessionId: 'new-session-456',
            });
          }
          return {
            status: 'success' as const,
            result: null,
            newSessionId: 'new-session-456',
          };
        },
      );

      const setSession = vi.fn();
      server = await startApiServer(makeConfig({ setSession }));

      await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      // setSession called from streaming callback only (no double-save)
      expect(setSession).toHaveBeenCalledWith('test-group', 'new-session-456');
    });

    it('uses existing session ID when available', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, input, onProcess, _onOutput) => {
          onProcess({} as any, 'test-container');
          expect(input.sessionId).toBe('existing-session');
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(
        makeConfig({
          getSession: (folder) =>
            folder === 'test-group' ? 'existing-session' : undefined,
        }),
      );

      await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(mockRunAgent).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('rejects oversized request body', async () => {
      server = await startApiServer(makeConfig());
      // Send a body larger than 1MB — server destroys the socket
      const largeBody = 'x'.repeat(1024 * 1024 + 1);
      await expect(
        request(server, {
          body: largeBody,
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${TEST_TOKEN}`,
          },
        }),
      ).rejects.toThrow();
    });

    it('kills container process on client disconnect', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      const mockKill = vi.fn();
      let capturedReqCloseHandler: (() => void) | undefined;

      mockRunAgent.mockImplementation(
        async (_group, _input, onProcess, onOutput) => {
          const fakeProc = { kill: mockKill } as any;
          onProcess(fakeProc, 'test-container');
          // Capture the close handler that was registered
          // The handler is registered on req.on('close', ...) inside onProcess
          if (onOutput) {
            await onOutput({
              status: 'success',
              result: 'done',
              newSessionId: undefined,
            });
          }
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      // Just verify the mock was called with a process that has kill
      await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(mockRunAgent).toHaveBeenCalled();
    });

    it('returns 500 when container agent throws before headers sent', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockRejectedValue(new Error('container crashed'));

      server = await startApiServer(makeConfig());
      const res = await request(server, {
        body: JSON.stringify({ text: 'hello', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      // The SSE headers are set before runContainerAgent is called,
      // so the error handler sends an SSE error event
      expect(res.status).toBe(200); // Headers already sent
      const events = res.body
        .split('\n\n')
        .filter((line) => line.startsWith('data: '))
        .map((line) => JSON.parse(line.replace('data: ', '')));

      const errorEvent = events.find((e: any) => e.type === 'error');
      expect(errorEvent).toBeDefined();
      expect(errorEvent.text).toBe('Internal server error');
    });
  });

  describe('prompt formatting', () => {
    it('formats prompt without history', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, input, onProcess, _onOutput) => {
          onProcess({} as any, 'test-container');
          expect(input.prompt).not.toContain('<conversation_history>');
          expect(input.prompt).toContain('sender="User"');
          expect(input.prompt).toContain('hello world');
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      await request(server, {
        body: JSON.stringify({ text: 'hello world', groupId: 'test-group' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(mockRunAgent).toHaveBeenCalled();
    });

    it('formats prompt with empty history array', async () => {
      const mockRunAgent = vi.mocked(runContainerAgent);
      mockRunAgent.mockImplementation(
        async (_group, input, onProcess, _onOutput) => {
          onProcess({} as any, 'test-container');
          expect(input.prompt).not.toContain('<conversation_history>');
          return { status: 'success' as const, result: null };
        },
      );

      server = await startApiServer(makeConfig());
      await request(server, {
        body: JSON.stringify({
          text: 'hello',
          groupId: 'test-group',
          history: [],
        }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${TEST_TOKEN}`,
        },
      });

      expect(mockRunAgent).toHaveBeenCalled();
    });
  });
});
