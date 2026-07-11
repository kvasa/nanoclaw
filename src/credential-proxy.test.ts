import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';

const mockEnv: Record<string, string> = {};
vi.mock('./env.js', () => ({
  // Honor the requested-keys contract of the real readEnvFile — the
  // /mcp-creds filtering tests depend on it.
  readEnvFile: vi.fn((keys: string[]) =>
    Object.fromEntries(
      keys.filter((k) => k in mockEnv).map((k) => [k, mockEnv[k]]),
    ),
  ),
}));

vi.mock('./logger.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
}));

import { startCredentialProxy } from './credential-proxy.js';
import { issueCredsToken, _resetCredsTokens } from './creds-token.js';

function makeRequest(
  port: number,
  options: http.RequestOptions,
  body = '',
): Promise<{
  statusCode: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { ...options, hostname: '127.0.0.1', port },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode!,
            body: Buffer.concat(chunks).toString(),
            headers: res.headers,
          });
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

describe('credential-proxy', () => {
  let proxyServer: http.Server;
  let upstreamServer: http.Server;
  let proxyPort: number;
  let upstreamPort: number;
  let lastUpstreamHeaders: http.IncomingHttpHeaders;
  let upstreamCalls: number;

  beforeEach(async () => {
    lastUpstreamHeaders = {};
    upstreamCalls = 0;

    upstreamServer = http.createServer((req, res) => {
      upstreamCalls++;
      lastUpstreamHeaders = { ...req.headers };
      req.resume();
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) =>
      upstreamServer.listen(0, '127.0.0.1', resolve),
    );
    upstreamPort = (upstreamServer.address() as AddressInfo).port;
  });

  afterEach(async () => {
    await new Promise<void>((r) => proxyServer?.close(() => r()));
    await new Promise<void>((r) => upstreamServer?.close(() => r()));
    for (const key of Object.keys(mockEnv)) delete mockEnv[key];
    _resetCredsTokens();
  });

  async function startProxy(env: Record<string, string>): Promise<number> {
    Object.assign(mockEnv, env, {
      ANTHROPIC_BASE_URL: `http://127.0.0.1:${upstreamPort}`,
    });
    proxyServer = await startCredentialProxy(0);
    return (proxyServer.address() as AddressInfo).port;
  }

  /** Issue a valid passthrough token, as buildContainerArgs does per spawn. */
  function passthroughToken(): string {
    return issueCredsToken({ groupFolder: 'test', enabledMcpServers: [] });
  }

  it('API-key mode injects x-api-key and strips placeholder', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'placeholder',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      '{}',
    );

    expect(lastUpstreamHeaders['x-api-key']).toBe('sk-ant-real-key');
  });

  it('OAuth mode replaces Authorization when container sends one', async () => {
    proxyPort = await startProxy({
      CLAUDE_CODE_OAUTH_TOKEN: 'real-oauth-token',
    });

    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/api/oauth/claude_cli/create_api_key',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer placeholder',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      '{}',
    );

    expect(lastUpstreamHeaders['authorization']).toBe(
      'Bearer real-oauth-token',
    );
  });

  it('OAuth mode does not inject Authorization when container omits it', async () => {
    proxyPort = await startProxy({
      CLAUDE_CODE_OAUTH_TOKEN: 'real-oauth-token',
    });

    // Post-exchange: container uses x-api-key only, no Authorization header
    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'temp-key-from-exchange',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      '{}',
    );

    expect(lastUpstreamHeaders['x-api-key']).toBe('temp-key-from-exchange');
    expect(lastUpstreamHeaders['authorization']).toBeUndefined();
  });

  it('strips hop-by-hop headers and the proxy token', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          connection: 'keep-alive',
          'keep-alive': 'timeout=5',
          'transfer-encoding': 'chunked',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      '{}',
    );

    // Proxy strips client hop-by-hop headers. Node's HTTP client may re-add
    // its own Connection header (standard HTTP/1.1 behavior), but the client's
    // custom keep-alive and transfer-encoding must not be forwarded.
    expect(lastUpstreamHeaders['keep-alive']).toBeUndefined();
    expect(lastUpstreamHeaders['transfer-encoding']).toBeUndefined();
    // The host-internal proxy token must never reach the upstream API.
    expect(lastUpstreamHeaders['x-nanoclaw-token']).toBeUndefined();
  });

  // --- passthrough authentication ---

  it('passthrough without a token gets 401 and no upstream request', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    const res = await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'placeholder',
        },
      },
      '{}',
    );

    expect(res.statusCode).toBe(401);
    expect(upstreamCalls).toBe(0);
  });

  it('passthrough with an unknown token gets 401 and no upstream request', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    const res = await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-api-key': 'placeholder',
          'x-nanoclaw-token': '0'.repeat(64),
        },
      },
      '{}',
    );

    expect(res.statusCode).toBe(401);
    expect(upstreamCalls).toBe(0);
  });

  it('passthrough with a valid token is forwarded with the credential', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    const res = await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      '{}',
    );

    expect(res.statusCode).toBe(200);
    expect(upstreamCalls).toBe(1);
    expect('x-api-key' in lastUpstreamHeaders).toBe(true);
  });

  it('oversized body gets 413 and no upstream request', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    const oversized = Buffer.alloc(64 * 1024 * 1024 + 1, 'a');
    // The proxy destroys the socket mid-upload; depending on timing the
    // client sees the 413 or a reset connection. Either way: no upstream.
    try {
      const res = await makeRequest(
        proxyPort,
        {
          method: 'POST',
          path: '/v1/messages',
          headers: {
            'content-type': 'application/json',
            'x-nanoclaw-token': passthroughToken(),
          },
        },
        oversized.toString(),
      );
      expect(res.statusCode).toBe(413);
    } catch (err) {
      expect((err as NodeJS.ErrnoException).code).toMatch(/ECONNRESET|EPIPE/);
    }
    expect(upstreamCalls).toBe(0);
  });

  it('body under the limit is forwarded normally', async () => {
    proxyPort = await startProxy({ ANTHROPIC_API_KEY: 'sk-ant-real-key' });

    const res = await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      Buffer.alloc(1024 * 1024, 'a').toString(),
    );

    expect(res.statusCode).toBe(200);
    expect(upstreamCalls).toBe(1);
  });

  // --- /mcp-creds endpoint ---

  // Every third-party credential the proxy can serve; the filtering tests
  // populate all of them so a leak of any unentitled key is caught.
  const ALL_MCP_ENV = {
    RHL_EMAIL: 'rhl-email-value',
    RHL_PASS: 'rhl-pass-value',
    APPLE_ID: 'apple-id-value',
    APPLE_APP_PASSWORD: 'apple-pass-value',
    CALDAV_BASE_URL: 'caldav-url-value',
    GARMIN_EMAIL: 'garmin-email-value',
    GARMIN_PASSWORD: 'garmin-pass-value',
    GEMINI_API_KEY: 'gemini-key-value',
  };

  async function fetchCreds(
    token: string,
  ): Promise<{ statusCode: number; keys: string[] }> {
    const res = await makeRequest(proxyPort, {
      method: 'GET',
      path: '/mcp-creds',
      headers: { authorization: `Bearer ${token}` },
    });
    return {
      statusCode: res.statusCode,
      keys:
        res.statusCode === 200 ? Object.keys(JSON.parse(res.body)).sort() : [],
    };
  }

  it('/mcp-creds rejects requests without the bearer token', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });

    const res = await makeRequest(proxyPort, {
      method: 'GET',
      path: '/mcp-creds',
    });

    expect(res.statusCode).toBe(401);
    expect(res.body).toBe('Unauthorized');
  });

  it('/mcp-creds rejects a token that was never issued', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });

    const res = await makeRequest(proxyPort, {
      method: 'GET',
      path: '/mcp-creds',
      headers: { authorization: `Bearer ${'0'.repeat(64)}` },
    });

    expect(res.statusCode).toBe(401);
    expect(res.body).toBe('Unauthorized');
  });

  it('group with no MCP servers gets only the universal keys', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });
    const token = issueCredsToken({
      groupFolder: 'skolka',
      enabledMcpServers: [],
    });

    const { statusCode, keys } = await fetchCreds(token);

    expect(statusCode).toBe(200);
    expect(keys).toEqual(['GEMINI_API_KEY']);
  });

  it('group with rohlik gets Rohlik keys and not Garmin/Apple ones', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });
    const token = issueCredsToken({
      groupFolder: 'rohlik',
      enabledMcpServers: ['rohlik'],
    });

    const { keys } = await fetchCreds(token);

    expect(keys).toEqual(['GEMINI_API_KEY', 'RHL_EMAIL', 'RHL_PASS']);
  });

  it('group with rohlik and garmin gets the union', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });
    const token = issueCredsToken({
      groupFolder: 'multi',
      enabledMcpServers: ['rohlik', 'garmin'],
    });

    const { keys } = await fetchCreds(token);

    expect(keys).toEqual([
      'GARMIN_EMAIL',
      'GARMIN_PASSWORD',
      'GEMINI_API_KEY',
      'RHL_EMAIL',
      'RHL_PASS',
    ]);
  });

  it('an unknown server name in the grant contributes no keys', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });
    const token = issueCredsToken({
      groupFolder: 'main',
      enabledMcpServers: ['gmail', 'does-not-exist'],
    });

    const { statusCode, keys } = await fetchCreds(token);

    expect(statusCode).toBe(200);
    expect(keys).toEqual(['GEMINI_API_KEY']);
  });

  it('two tokens are isolated: an empty grant gets nothing extra', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });
    const rohlikToken = issueCredsToken({
      groupFolder: 'rohlik',
      enabledMcpServers: ['rohlik'],
    });
    const emptyToken = issueCredsToken({
      groupFolder: 'skolka',
      enabledMcpServers: [],
    });

    const rohlik = await fetchCreds(rohlikToken);
    const empty = await fetchCreds(emptyToken);

    expect(rohlik.keys).toEqual(['GEMINI_API_KEY', 'RHL_EMAIL', 'RHL_PASS']);
    expect(empty.keys).toEqual(['GEMINI_API_KEY']);
  });

  it('a calendar grant gets the Apple/CalDAV keys only', async () => {
    proxyPort = await startProxy({
      ANTHROPIC_API_KEY: 'sk-ant',
      ...ALL_MCP_ENV,
    });
    const token = issueCredsToken({
      groupFolder: 'cal',
      enabledMcpServers: ['calendar'],
    });

    const { keys } = await fetchCreds(token);

    expect(keys).toEqual([
      'APPLE_APP_PASSWORD',
      'APPLE_ID',
      'CALDAV_BASE_URL',
      'GEMINI_API_KEY',
    ]);
  });

  it('returns 502 when upstream is unreachable', async () => {
    Object.assign(mockEnv, {
      ANTHROPIC_API_KEY: 'sk-ant-real-key',
      ANTHROPIC_BASE_URL: 'http://127.0.0.1:59999',
    });
    proxyServer = await startCredentialProxy(0);
    proxyPort = (proxyServer.address() as AddressInfo).port;

    const res = await makeRequest(
      proxyPort,
      {
        method: 'POST',
        path: '/v1/messages',
        headers: {
          'content-type': 'application/json',
          'x-nanoclaw-token': passthroughToken(),
        },
      },
      '{}',
    );

    expect(res.statusCode).toBe(502);
    expect(res.body).toBe('Bad Gateway');
  });
});
