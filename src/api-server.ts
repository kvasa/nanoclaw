/**
 * HTTP API server for direct client access (e.g. pi-assistant).
 * Replaces the Slack relay with a direct HTTP + SSE streaming interface.
 *
 * POST /api/query — accepts a JSON body with text, groupId, and optional history.
 * Returns SSE stream with chunks and a done marker.
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { createServer, Server, IncomingMessage, ServerResponse } from 'http';

import { ContainerOutput, runContainerAgent } from './container-runner.js';
import { DATA_DIR } from './config.js';
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
}

/**
 * Tracks an active container for a group.
 * The onResult callback is swapped on each new HTTP request so that
 * output from piped messages routes to the correct response.
 */
interface ActiveContainer {
  groupFolder: string;
  /** Mutable callback — points to the current HTTP response handler. */
  onResult: ((result: ContainerOutput) => void) | null;
  /** Resolves the current HTTP request's promise. */
  resolveRequest: (() => void) | null;
  /** True while runContainerAgent hasn't resolved yet (container alive). */
  alive: boolean;
}

/** Per-group active container map, keyed by groupFolder. */
const activeContainers = new Map<string, ActiveContainer>();

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

function formatPrompt(text: string): string {
  return `<message sender="User" time="${new Date().toISOString()}">${text}</message>`;
}

/**
 * Write a follow-up message to the container via IPC input directory.
 * Same mechanism as GroupQueue.sendMessage.
 */
function pipeViaIpc(groupFolder: string, prompt: string): boolean {
  const inputDir = path.join(DATA_DIR, 'ipc', groupFolder, 'input');
  try {
    fs.mkdirSync(inputDir, { recursive: true });
    const filename = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}.json`;
    const filepath = path.join(inputDir, filename);
    const tempPath = `${filepath}.tmp`;
    fs.writeFileSync(
      tempPath,
      JSON.stringify({ type: 'message', text: prompt }),
    );
    fs.renameSync(tempPath, filepath);
    return true;
  } catch (err) {
    logger.debug({ groupFolder, err }, 'Failed to write IPC message for API');
    return false;
  }
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

        const prompt = formatPrompt(parsed.text);

        logger.info(
          { group: group.name, textLength: parsed.text.length },
          'API query received',
        );

        const existing = activeContainers.get(group.folder);

        if (existing?.alive) {
          // Reuse existing container — pipe via IPC
          logger.info(
            { group: group.name },
            'Piping API query to existing container',
          );

          await new Promise<void>((resolveRequest) => {
            // Swap the output handler to this HTTP response
            existing.onResult = (result: ContainerOutput) => {
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
              if (result.result) {
                existing.onResult = null;
                existing.resolveRequest = null;
                resolveRequest();
              }
            };
            existing.resolveRequest = resolveRequest;

            pipeViaIpc(group.folder, prompt);
          });
        } else {
          // Spawn new container
          const sessionId = config.getSession(group.folder);
          const tracker: ActiveContainer = {
            groupFolder: group.folder,
            onResult: null,
            resolveRequest: null,
            alive: true,
          };
          activeContainers.set(group.folder, tracker);

          await new Promise<void>((resolveRequest, rejectRequest) => {
            tracker.onResult = (result: ContainerOutput) => {
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
              // Resolve HTTP response after first output with a result
              if (result.result && tracker.resolveRequest) {
                const r = tracker.resolveRequest;
                tracker.onResult = null;
                tracker.resolveRequest = null;
                r();
              }
            };
            tracker.resolveRequest = resolveRequest;

            runContainerAgent(
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
                // Delegate to the mutable handler — routes to whichever
                // HTTP response is currently waiting.
                if (tracker.onResult) {
                  tracker.onResult(result);
                }
              },
            )
              .then(() => {
                // Container exited — clean up tracker
                tracker.alive = false;
                activeContainers.delete(group.folder);
                // Resolve any pending request
                if (tracker.resolveRequest) {
                  tracker.resolveRequest();
                  tracker.resolveRequest = null;
                }
              })
              .catch((err) => {
                tracker.alive = false;
                activeContainers.delete(group.folder);
                if (tracker.resolveRequest) {
                  tracker.resolveRequest = null;
                  rejectRequest(err);
                }
              });
          });
        }

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
