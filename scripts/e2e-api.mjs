#!/usr/bin/env node
/**
 * E2E test for the NanoClaw HTTP API (src/api-server.ts).
 *
 * Sends real queries to a running NanoClaw instance and asserts on the
 * agent's answers. Requires the service to be running with API_TOKEN set.
 *
 * NOTE: each query is a real agent run — it spawns a container, consumes
 * tokens, and (when API_SLACK_CHANNEL_ID is set) posts the question and
 * result to the API Slack channel.
 *
 * Usage:
 *   npm run e2e                             # all tests: check, prime, search
 *   node scripts/e2e-api.mjs --only=check   # health check only
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const QUERY_TIMEOUT_MS = 5 * 60 * 1000;

function loadEnv() {
  const env = {};
  const raw = fs.readFileSync(path.join(ROOT, '.env'), 'utf8');
  for (const line of raw.split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) env[m[1]] = m[2].replace(/^"|"$/g, '');
  }
  return env;
}

const env = loadEnv();
const PORT = env.API_PORT || '3002';
const TOKEN = env.API_TOKEN;
const BASE = `http://127.0.0.1:${PORT}`;

if (!TOKEN) {
  console.error('FAIL: API_TOKEN is not set in .env — API server is not running.');
  process.exit(1);
}

const AUTH = { Authorization: `Bearer ${TOKEN}` };

/** POST /api/query and collect SSE events until `done` or timeout. */
async function query(text) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), QUERY_TIMEOUT_MS);
  const started = Date.now();
  try {
    const res = await fetch(`${BASE}/api/query`, {
      method: 'POST',
      headers: { ...AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });
    if (res.status !== 200) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    const chunks = [];
    const decoder = new TextDecoder();
    let buf = '';
    for await (const part of res.body) {
      buf += decoder.decode(part, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const data = frame.replace(/^data: /, '');
        let event;
        try {
          event = JSON.parse(data);
        } catch {
          continue;
        }
        const elapsed = `${Math.round((Date.now() - started) / 1000)}s`;
        if (event.type === 'progress') {
          console.log(`  [${elapsed}] progress: ${event.text.slice(0, 100)}`);
        } else if (event.type === 'chunk') {
          console.log(`  [${elapsed}] chunk: ${event.text.slice(0, 200)}`);
          chunks.push(event.text);
        } else if (event.type === 'error') {
          throw new Error(`SSE error event: ${event.text}`);
        } else if (event.type === 'done') {
          return chunks.join('\n');
        }
      }
    }
    throw new Error('SSE stream ended without a done event');
  } finally {
    clearTimeout(timer);
  }
}

function assertContains(answer, needles, label) {
  const missing = needles.filter((n) => !answer.includes(n));
  if (missing.length > 0) {
    throw new Error(`${label}: answer is missing ${JSON.stringify(missing)}`);
  }
}

const tests = {
  async check() {
    const res = await fetch(`${BASE}/api/check`, { headers: AUTH });
    const body = await res.json();
    if (res.status !== 200 || body.status !== 'ok') {
      throw new Error(`health check failed: HTTP ${res.status} ${JSON.stringify(body)}`);
    }
    const unauth = await fetch(`${BASE}/api/check`);
    if (unauth.status !== 401) {
      throw new Error(`expected 401 without token, got ${unauth.status}`);
    }
  },

  async prime() {
    const answer = await query(
      'E2E test (automatický, neodpovídej nic navíc): Napiš a spusť krátký ' +
        'skript, který rozhodne, zda je číslo prvočíslo. Ověř s ním čísla ' +
        '17, 20 a 97. Odpověz PŘESNĚ jedním řádkem ve formátu ' +
        'E2E_PRIME: 17=ANO,20=NE,97=ANO — s hodnotami podle výstupu skriptu.',
    );
    assertContains(answer, ['E2E_PRIME', '17=ANO', '20=NE', '97=ANO'], 'prime');
  },

  async search() {
    // Forces real internet access from the agent container: the answer has to
    // come from a live HTTP fetch, not from model memory.
    const answer = await query(
      'E2E test (automatický, neodpovídej nic navíc): Stáhni z internetu ' +
        'stránku https://example.com a odpověz PŘESNĚ jedním řádkem ve ' +
        'formátu E2E_SEARCH: <obsah HTML tagu title>.',
    );
    assertContains(answer, ['E2E_SEARCH', 'Example Domain'], 'search');
  },
};

const args = process.argv.slice(2);
const only = args.find((a) => a.startsWith('--only='))?.split('=')[1];
const names = only ? [only] : ['check', 'prime', 'search'];

let failed = 0;
for (const name of names) {
  if (!tests[name]) {
    console.error(`Unknown test: ${name} (available: ${Object.keys(tests).join(', ')})`);
    process.exit(1);
  }
  const started = Date.now();
  process.stdout.write(`RUN  ${name}\n`);
  try {
    await tests[name]();
    console.log(`PASS ${name} (${Math.round((Date.now() - started) / 1000)}s)`);
  } catch (err) {
    failed++;
    console.error(`FAIL ${name}: ${err.message}`);
  }
}

process.exit(failed > 0 ? 1 : 0);
