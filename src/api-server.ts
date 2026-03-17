/**
 * HTTP API server for direct client access (e.g. pi-assistant).
 * Replaces the Slack relay with a direct HTTP + SSE streaming interface.
 *
 * POST /api/query — accepts a JSON body with text, groupId, and optional history.
 * Returns SSE stream with chunks and a done marker.
 */
import crypto from 'crypto';
import { createServer, Server, IncomingMessage, ServerResponse } from 'http';

import { ContainerOutput, runContainerAgent } from './container-runner.js';
import { logger } from './logger.js';
import { RegisteredGroup } from './types.js';

const MAX_BODY_SIZE = 1024 * 1024; // 1MB

export interface ApiServerConfig {
  port: number;
  token: string;
  defaultGroupId: string;
  getRegisteredGroups: () => Record<string, RegisteredGroup>;
  getSession: (groupFolder: string) => string | undefined;
  setSession: (groupFolder: string, sessionId: string) => void;
}

interface QueryRequest {
  text: string;
  groupId?: string;
  history?: Array<{ role: 'user' | 'assistant'; content: string }>;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_SIZE) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendSSE(res: ServerResponse, data: object): void {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function formatPrompt(
  text: string,
  history?: Array<{ role: 'user' | 'assistant'; content: string }>,
): string {
  let prompt = '';
  if (history && history.length > 0) {
    prompt += '<conversation_history>\n';
    for (const entry of history) {
      const role = entry.role === 'user' ? 'User' : 'Assistant';
      prompt += `<message role="${role}">${entry.content}</message>\n`;
    }
    prompt += '</conversation_history>\n\n';
  }
  prompt += `<message sender="User" time="${new Date().toISOString()}">${text}</message>`;
  return prompt;
}

export function startApiServer(config: ApiServerConfig): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = createServer(async (req, res) => {
      // CORS preflight
      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        });
        res.end();
        return;
      }

      if (req.method !== 'POST' || req.url !== '/api/query') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
        return;
      }

      // Auth check (timing-safe comparison to prevent timing attacks)
      const authHeader = req.headers.authorization ?? '';
      const expected = `Bearer ${config.token}`;
      const isAuthorized =
        authHeader.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(authHeader), Buffer.from(expected));
      if (!isAuthorized) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      try {
        const body = await readBody(req);
        let parsed: QueryRequest;
        try {
          parsed = JSON.parse(body.toString());
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
          return;
        }

        if (!parsed.text) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing required field: text' }));
          return;
        }

        // Fall back to default group when groupId is not provided
        const groupId = parsed.groupId || config.defaultGroupId;

        // Find the registered group by folder name
        const groups = config.getRegisteredGroups();
        const groupEntry = Object.entries(groups).find(
          ([, g]) => g.folder === groupId,
        );

        if (!groupEntry) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Group not found' }));
          return;
        }

        const [chatJid, group] = groupEntry;

        // Set up SSE response
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'Access-Control-Allow-Origin': '*',
        });

        const prompt = formatPrompt(parsed.text, parsed.history);
        const sessionId = config.getSession(group.folder);

        logger.info(
          { group: group.name, textLength: parsed.text.length },
          'API query received',
        );

        const output = await runContainerAgent(
          group,
          {
            prompt,
            sessionId,
            groupFolder: group.folder,
            chatJid,
            isMain: false,
          },
          (proc, containerName) => {
            // Kill the container process when client disconnects
            req.on('close', () => {
              logger.debug(
                { containerName },
                'API client disconnected, killing container',
              );
              proc.kill('SIGTERM');
            });
          },
          async (result: ContainerOutput) => {
            if (result.newSessionId) {
              config.setSession(group.folder, result.newSessionId);
            }
            if (result.result) {
              const text = result.result
                .replace(/<internal>[\s\S]*?<\/internal>/g, '')
                .trim();
              if (text) {
                sendSSE(res, { type: 'chunk', text });
              }
            }
          },
        );

        sendSSE(res, { type: 'done' });
        res.end();
      } catch (err) {
        logger.error({ err }, 'API query error');
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        } else {
          sendSSE(res, { type: 'error', text: 'Internal server error' });
          res.end();
        }
      }
    });

    server.listen(config.port, () => {
      logger.info({ port: config.port }, 'API server started');
      resolve(server);
    });

    server.on('error', reject);
  });
}
