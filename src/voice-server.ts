/**
 * Voice server for NanoClaw.
 * Pipeline: Browser mic → WebSocket → Whisper STT → Claude → OpenAI TTS → Browser
 *
 * Endpoints (bound to 127.0.0.1, proxied by nginx at /api/voice/):
 *   GET  /auth/google          — redirect to Google OAuth consent screen
 *   GET  /auth/callback        — OAuth callback, issues signed token, redirects to frontend
 *   GET  /ws                   — WebSocket voice session (first msg must be { type:"auth", token })
 *
 * Config (.env):
 *   VOICE_PORT             — port to listen on (default: 3003)
 *   VOICE_SECRET           — HMAC secret for tokens
 *   VOICE_TTS_VOICE        — TTS voice name (default: ash)
 *   VOICE_GROUP            — group folder to use for Claude memory (default: main)
 *   GOOGLE_CLIENT_ID       — Google OAuth2 client ID
 *   GOOGLE_CLIENT_SECRET   — Google OAuth2 client secret
 *   GOOGLE_REDIRECT_URI    — OAuth2 redirect URI (default: https://jarmil.eu/api/voice/auth/callback)
 *   VOICE_ALLOWED_EMAILS   — comma-separated allowed emails (default: j.kv@snicka.cz)
 */
import crypto from 'crypto';
import http from 'http';

import { WebSocket, WebSocketServer } from 'ws';

import { readEnvFile } from './env.js';
import { logger } from './logger.js';
import { transcribeBuffer } from './transcription.js';
import { synthesizeSpeech, TtsVoice } from './tts.js';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const envConfig = readEnvFile([
  'API_TOKEN',
  'API_GROUP_ID',
  'VOICE_SECRET',
  'VOICE_PORT',
  'VOICE_GROUP',
  'VOICE_TTS_VOICE',
  'API_PORT',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_REDIRECT_URI',
  'VOICE_ALLOWED_EMAILS',
]);

const VOICE_PORT = parseInt(
  process.env.VOICE_PORT || envConfig.VOICE_PORT || '3003',
  10,
);
const VOICE_SECRET =
  process.env.VOICE_SECRET ||
  envConfig.VOICE_SECRET ||
  crypto.randomBytes(32).toString('hex');
// Default to API_GROUP_ID (typically 'main') so voice uses the same registered group
const VOICE_GROUP =
  process.env.VOICE_GROUP ||
  envConfig.VOICE_GROUP ||
  envConfig.API_GROUP_ID ||
  'main';
const VOICE_TTS_VOICE: TtsVoice = (process.env.VOICE_TTS_VOICE ||
  envConfig.VOICE_TTS_VOICE ||
  'ash') as TtsVoice;
const NANOCLAW_API_PORT = parseInt(
  process.env.API_PORT || envConfig.API_PORT || '3002',
  10,
);
const NANOCLAW_API_TOKEN = process.env.API_TOKEN || envConfig.API_TOKEN || '';

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || envConfig.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET || envConfig.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  envConfig.GOOGLE_REDIRECT_URI ||
  'https://jarmil.eu/api/voice/auth/callback';

const VOICE_ALLOWED_EMAILS_RAW =
  process.env.VOICE_ALLOWED_EMAILS ||
  envConfig.VOICE_ALLOWED_EMAILS ||
  'j.kv@snicka.cz';
const VOICE_ALLOWED_EMAILS = new Set(
  VOICE_ALLOWED_EMAILS_RAW.split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean),
);

// ---------------------------------------------------------------------------
// Auth — JWT tokens
// ---------------------------------------------------------------------------

function signToken(userId: string): string {
  const expires = (Date.now() + 24 * 60 * 60 * 1000).toString();
  const payload = `${userId}:${expires}`;
  const sig = crypto
    .createHmac('sha256', VOICE_SECRET)
    .update(payload)
    .digest('hex');
  return Buffer.from(`${payload}:${sig}`).toString('base64url');
}

function verifyToken(token: string): string | null {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf-8');
    const parts = decoded.split(':');
    if (parts.length < 3) return null;
    const sig = parts[parts.length - 1];
    const expires = parseInt(parts[parts.length - 2]);
    const userId = parts.slice(0, parts.length - 2).join(':');
    const payload = `${userId}:${expires}`;

    if (Date.now() > expires) return null;

    const expectedSig = crypto
      .createHmac('sha256', VOICE_SECRET)
      .update(payload)
      .digest('hex');

    if (sig.length !== expectedSig.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig)))
      return null;

    return userId;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Google OAuth2 — pending states (CSRF protection, 10 min TTL)
// ---------------------------------------------------------------------------

const pendingStates = new Map<string, number>(); // state → expires

function createOAuthState(): string {
  const state = crypto.randomBytes(16).toString('hex');
  pendingStates.set(state, Date.now() + 10 * 60 * 1000);
  return state;
}

function consumeOAuthState(state: string): boolean {
  const expires = pendingStates.get(state);
  if (!expires) return false;
  pendingStates.delete(state);
  if (Date.now() > expires) return false;
  return true;
}

// Periodically clean up expired states
setInterval(
  () => {
    const now = Date.now();
    for (const [state, expires] of pendingStates) {
      if (now > expires) pendingStates.delete(state);
    }
  },
  5 * 60 * 1000,
);

// ---------------------------------------------------------------------------
// Google OAuth2 — HTTP helpers
// ---------------------------------------------------------------------------

async function exchangeCodeForEmail(code: string): Promise<string | null> {
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
    }).toString(),
  });

  if (!tokenRes.ok) {
    const body = await tokenRes.text();
    logger.warn(
      { status: tokenRes.status, body },
      'Google token exchange failed',
    );
    return null;
  }

  const tokens = (await tokenRes.json()) as { access_token?: string };
  if (!tokens.access_token) return null;

  const userRes = await fetch(
    'https://openidconnect.googleapis.com/v1/userinfo',
    {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    },
  );

  if (!userRes.ok) return null;
  const user = (await userRes.json()) as {
    email?: string;
    email_verified?: boolean;
  };
  if (!user.email || !user.email_verified) return null;

  return user.email.toLowerCase();
}

// ---------------------------------------------------------------------------
// NanoClaw API — SSE stream → full text
// ---------------------------------------------------------------------------

async function callNanoClaw(text: string, groupId: string): Promise<string> {
  const res = await fetch(`http://127.0.0.1:${NANOCLAW_API_PORT}/api/query`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${NANOCLAW_API_TOKEN}`,
    },
    body: JSON.stringify({ text, groupId }),
  });

  if (!res.ok) throw new Error(`NanoClaw API error: ${res.status}`);

  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let fullText = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      try {
        const data = JSON.parse(line.slice(6)) as {
          type: string;
          text?: string;
        };
        if (data.type === 'chunk' && data.text) fullText += data.text;
      } catch {
        // ignore malformed line
      }
    }
  }

  return fullText;
}

// ---------------------------------------------------------------------------
// WebSocket session
// ---------------------------------------------------------------------------

function mimeToFilename(mime: string): string {
  if (mime.includes('mp4')) return 'audio.m4a';
  if (mime.includes('ogg')) return 'audio.ogg';
  return 'audio.webm';
}

function handleVoiceSession(ws: WebSocket): void {
  let userId: string | null = null;
  const groupId: string = VOICE_GROUP;
  let busy = false;
  let sessionMime = 'audio/webm';
  let pendingFilename: string | null = null;
  let pendingMime: string | null = null;

  const send = (data: object): void => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
    }
  };

  ws.on('message', (data: Buffer | string, isBinary: boolean) => {
    void (async () => {
      try {
        // ── Text: auth ───────────────────────────────────────────────────────
        if (!isBinary) {
          const msg = JSON.parse(data.toString()) as {
            type: string;
            token?: string;
          };
          if (msg.type === 'auth') {
            const verified = msg.token ? verifyToken(msg.token) : null;
            if (!verified) {
              send({ type: 'error', message: 'Neautorizováno' });
              ws.close(1008, 'Unauthorized');
              return;
            }
            userId = verified;
            if ((msg as { mimeType?: string }).mimeType) {
              sessionMime = (msg as { mimeType?: string }).mimeType!;
            }
            send({ type: 'ready', userId });
            logger.info(
              { userId, groupId, mimeType: sessionMime },
              'Voice session authenticated',
            );
          } else if (msg.type === 'audio_meta') {
            pendingFilename = (msg as { filename?: string }).filename ?? null;
            pendingMime = (msg as { mimeType?: string }).mimeType ?? null;
          } else if (msg.type === 'client_error') {
            logger.warn(
              { userId, error: (msg as { message?: string }).message },
              'Browser audio error',
            );
          }
          return;
        }

        // ── Binary: audio blob ───────────────────────────────────────────────
        if (!userId) {
          send({ type: 'error', message: 'Nejprve se přihlaste' });
          return;
        }
        if (busy) {
          send({ type: 'busy' });
          return;
        }

        const audioBuffer = data as Buffer;
        if (audioBuffer.length < 200) return;

        busy = true;
        try {
          send({ type: 'status', stage: 'transcribing' });

          const useMime = pendingMime ?? sessionMime;
          const useFilename = pendingFilename ?? mimeToFilename(useMime);
          pendingFilename = null;
          pendingMime = null;

          const transcript = await transcribeBuffer(
            audioBuffer,
            useFilename,
            useMime,
          );
          if (!transcript) {
            send({ type: 'status', stage: 'idle' });
            return;
          }

          send({ type: 'transcript', text: transcript });
          send({ type: 'status', stage: 'thinking' });

          const response = await callNanoClaw(transcript, groupId!);
          const responseTrimmed = response.trim();
          if (!responseTrimmed) {
            send({ type: 'status', stage: 'idle' });
            return;
          }

          send({ type: 'response', text: responseTrimmed });
          send({ type: 'status', stage: 'speaking' });

          const audioOut = await synthesizeSpeech(
            responseTrimmed,
            VOICE_TTS_VOICE,
          );
          if (audioOut && ws.readyState === WebSocket.OPEN) {
            ws.send(audioOut);
          }

          send({ type: 'status', stage: 'idle' });
        } finally {
          busy = false;
        }
      } catch (err) {
        busy = false;
        logger.error({ err, userId }, 'Voice pipeline error');
        send({ type: 'error', message: 'Chyba zpracování' });
        send({ type: 'status', stage: 'idle' });
      }
    })();
  });

  ws.on('close', () => logger.info({ userId }, 'Voice session closed'));
  ws.on('error', (err) => logger.error({ err, userId }, 'Voice WS error'));
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

function setCorsHeaders(res: http.ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', 'https://jarmil.eu');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function handleAuthGoogle(res: http.ServerResponse): void {
  const state = createOAuthState();
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email',
    state,
    access_type: 'online',
    prompt: 'select_account',
  });
  res.writeHead(302, {
    Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}`,
  });
  res.end();
}

function handleAuthCallback(
  req: http.IncomingMessage,
  res: http.ServerResponse,
): void {
  const url = new URL(req.url!, `http://localhost`);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error || !code || !state) {
    res.writeHead(302, { Location: 'https://jarmil.eu/?auth=error' });
    res.end();
    return;
  }

  if (!consumeOAuthState(state)) {
    res.writeHead(302, { Location: 'https://jarmil.eu/?auth=error' });
    res.end();
    return;
  }

  void (async () => {
    try {
      const email = await exchangeCodeForEmail(code);

      if (!email || !VOICE_ALLOWED_EMAILS.has(email)) {
        logger.warn({ email }, 'Google OAuth: email not allowed');
        res.writeHead(302, { Location: 'https://jarmil.eu/?auth=denied' });
        res.end();
        return;
      }

      const token = signToken(email);
      logger.info({ email }, 'Google OAuth: login successful');
      res.writeHead(302, {
        Location: `https://jarmil.eu/?token=${encodeURIComponent(token)}&userId=${encodeURIComponent(email)}`,
      });
      res.end();
    } catch (err) {
      logger.error({ err }, 'Google OAuth callback error');
      res.writeHead(302, { Location: 'https://jarmil.eu/?auth=error' });
      res.end();
    }
  })();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function startVoiceServer(): void {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    logger.info('GOOGLE_CLIENT_ID/SECRET not set — voice server disabled');
    return;
  }
  if (!NANOCLAW_API_TOKEN) {
    logger.warn('API_TOKEN not set — voice server disabled');
    return;
  }

  const server = http.createServer((req, res) => {
    setCorsHeaders(res);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const path = req.url?.split('?')[0];

    if (req.method === 'GET' && path === '/auth/google') {
      handleAuthGoogle(res);
      return;
    }
    if (req.method === 'GET' && path === '/auth/callback') {
      handleAuthCallback(req, res);
      return;
    }

    res.writeHead(404);
    res.end();
  });

  const wss = new WebSocketServer({ server, path: '/ws' });
  wss.on('connection', handleVoiceSession);

  server.listen(VOICE_PORT, '127.0.0.1', () => {
    logger.info(
      { port: VOICE_PORT, allowedEmails: [...VOICE_ALLOWED_EMAILS] },
      'Voice server started (Google OAuth)',
    );
  });
}
