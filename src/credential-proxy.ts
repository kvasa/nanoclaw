/**
 * Credential proxy for container isolation.
 * Containers connect here instead of directly to the Anthropic API.
 * The proxy injects real credentials so containers never see them.
 *
 * Two auth modes:
 *   API key:  Proxy injects x-api-key on every request.
 *   OAuth:    Container CLI exchanges its placeholder token for a temp
 *             API key via /api/oauth/claude_cli/create_api_key.
 *             Proxy injects real OAuth token on that exchange request;
 *             subsequent requests carry the temp key which is valid as-is.
 */
import { createServer, Server } from 'http';
import { request as httpsRequest } from 'https';
import { request as httpRequest, RequestOptions } from 'http';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';
import { resolveCredsToken } from './creds-token.js';

/**
 * Which env keys each MCP server is entitled to. A container only ever
 * receives the union of the entries for the servers its group enabled, so a
 * prompt-injected agent in one group cannot read another integration's
 * credentials out of its own environment.
 *
 * This mapping is a security boundary: adding a new MCP server means adding
 * its entry here — otherwise its credentials will not reach any container,
 * and the failure will look like a broken integration rather than a policy
 * decision.
 */
const MCP_SERVER_CREDENTIALS: Record<string, string[]> = {
  rohlik: ['RHL_EMAIL', 'RHL_PASS'],
  calendar: ['APPLE_ID', 'APPLE_APP_PASSWORD', 'CALDAV_BASE_URL'],
  garmin: ['GARMIN_EMAIL', 'GARMIN_PASSWORD'],
};

/**
 * Credentials every container gets regardless of enabled servers.
 * GEMINI_API_KEY backs the generate_image tool, which is part of the agent
 * runner itself and available to all groups. Routed through the proxy so it
 * never appears in `docker inspect` output.
 */
const UNIVERSAL_CREDENTIALS = ['GEMINI_API_KEY'];

/**
 * Upper bound on a passthrough request body. This proxy carries full Claude
 * API conversations — long transcripts plus base64-encoded images — so the
 * limit must sit comfortably above the API's own ~32MB request ceiling.
 * 64MB rejects nothing legitimate while still bounding memory per request
 * (the whole body is buffered before forwarding).
 */
const MAX_BODY_SIZE = 64 * 1024 * 1024;

export type AuthMode = 'api-key' | 'oauth';

export interface ProxyConfig {
  authMode: AuthMode;
}

export function startCredentialProxy(
  port: number,
  host = '127.0.0.1',
): Promise<Server> {
  const secrets = readEnvFile([
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
  ]);

  // Prefer OAuth token (Claude Code token) over API key when both are present
  const oauthAvailable = !!(
    secrets.CLAUDE_CODE_OAUTH_TOKEN || secrets.ANTHROPIC_AUTH_TOKEN
  );
  const authMode: AuthMode = oauthAvailable
    ? 'oauth'
    : secrets.ANTHROPIC_API_KEY
      ? 'api-key'
      : 'oauth';
  const oauthToken =
    secrets.CLAUDE_CODE_OAUTH_TOKEN || secrets.ANTHROPIC_AUTH_TOKEN;

  const upstreamUrl = new URL(
    secrets.ANTHROPIC_BASE_URL || 'https://api.anthropic.com',
  );
  const isHttps = upstreamUrl.protocol === 'https:';
  const makeRequest = isHttps ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    // Trust rule for every endpoint on this server: a request is only
    // credentialed if it presents a token this host issued to a container it
    // spawned (resolveCredsToken). The proxy listens on the Docker bridge,
    // where unrelated containers can reach it — nothing may be injected or
    // served without that token. Any new endpoint must apply the same check.
    const server = createServer((req, res) => {
      // Serve MCP credentials to containers so they are never passed as docker -e flags.
      // Token auth prevents rogue processes on the docker bridge from reading credentials.
      if (req.method === 'GET' && req.url === '/mcp-creds') {
        const auth = req.headers['authorization'];
        const token = auth?.startsWith('Bearer ')
          ? auth.slice('Bearer '.length)
          : undefined;
        const grant = token ? resolveCredsToken(token) : undefined;
        if (!grant) {
          res.writeHead(401, { 'Content-Type': 'text/plain' });
          res.end('Unauthorized');
          return;
        }
        // Union of the entitlements for this group's enabled servers.
        // Unknown server names contribute nothing.
        const allowedKeys = [
          ...UNIVERSAL_CREDENTIALS,
          ...grant.enabledMcpServers.flatMap(
            (server) => MCP_SERVER_CREDENTIALS[server] ?? [],
          ),
        ];
        const mcpCreds = readEnvFile(allowedKeys);
        logger.info(
          { group: grant.groupFolder, servers: grant.enabledMcpServers },
          'Served MCP credentials',
        );
        const body = Buffer.from(JSON.stringify(mcpCreds));
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': body.length,
        });
        res.end(body);
        return;
      }

      // Passthrough: authenticate before anything else. The Claude Agent SDK
      // attaches the per-container token as x-nanoclaw-token (via
      // ANTHROPIC_CUSTOM_HEADERS, set in buildContainerArgs); the SDK owns
      // the Authorization header, so it cannot carry this token. Unknown or
      // missing token -> 401, no upstream request, no credential injected.
      // (Map lookup by token; no string comparison against a secret.)
      const passthroughToken = req.headers['x-nanoclaw-token'];
      const passthroughGrant =
        typeof passthroughToken === 'string'
          ? resolveCredsToken(passthroughToken)
          : undefined;
      if (!passthroughGrant) {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        res.end('Unauthorized');
        return;
      }

      const chunks: Buffer[] = [];
      let size = 0;
      let rejected = false;
      req.on('data', (c: Buffer) => {
        size += c.length;
        if (size > MAX_BODY_SIZE) {
          rejected = true;
          logger.warn(
            { group: passthroughGrant.groupFolder, size },
            'Credential proxy request body too large',
          );
          res.writeHead(413, { 'Content-Type': 'text/plain' });
          res.end('Payload Too Large');
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        if (rejected) return;
        const body = Buffer.concat(chunks);
        const headers: Record<string, string | number | string[] | undefined> =
          {
            ...(req.headers as Record<string, string>),
            host: upstreamUrl.host,
            'content-length': body.length,
          };

        // Strip hop-by-hop headers that must not be forwarded by proxies
        delete headers['connection'];
        delete headers['keep-alive'];
        delete headers['transfer-encoding'];
        // The proxy token is host-internal; never forward it upstream.
        delete headers['x-nanoclaw-token'];

        if (authMode === 'api-key') {
          // API key mode: inject x-api-key on every request
          delete headers['x-api-key'];
          headers['x-api-key'] = secrets.ANTHROPIC_API_KEY;
        } else {
          // OAuth mode: replace placeholder Bearer token with the real one
          // only when the container actually sends an Authorization header
          // (exchange request + auth probes). Post-exchange requests use
          // x-api-key only, so they pass through without token injection.
          if (headers['authorization']) {
            delete headers['authorization'];
            if (oauthToken) {
              headers['authorization'] = `Bearer ${oauthToken}`;
            }
          }
        }

        const upstream = makeRequest(
          {
            hostname: upstreamUrl.hostname,
            port: upstreamUrl.port || (isHttps ? 443 : 80),
            path: req.url,
            method: req.method,
            headers,
          } as RequestOptions,
          (upRes) => {
            res.writeHead(upRes.statusCode!, upRes.headers);
            upRes.pipe(res);
          },
        );

        upstream.on('error', (err) => {
          logger.error(
            { err, url: req.url },
            'Credential proxy upstream error',
          );
          if (!res.headersSent) {
            res.writeHead(502);
            res.end('Bad Gateway');
          }
        });

        upstream.write(body);
        upstream.end();
      });
    });

    server.listen(port, host, () => {
      logger.info({ port, host, authMode }, 'Credential proxy started');
      resolve(server);
    });

    server.on('error', reject);
  });
}

/** Detect which auth mode the host is configured for. */
export function detectAuthMode(): AuthMode {
  const secrets = readEnvFile([
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'ANTHROPIC_AUTH_TOKEN',
  ]);
  const oauthAvailable = !!(
    secrets.CLAUDE_CODE_OAUTH_TOKEN || secrets.ANTHROPIC_AUTH_TOKEN
  );
  return oauthAvailable
    ? 'oauth'
    : secrets.ANTHROPIC_API_KEY
      ? 'api-key'
      : 'oauth';
}
