#!/usr/bin/env node
// Runs a script and posts its output to Slack — same behavior as NanoClaw's
// script-mode scheduled tasks (src/task-scheduler.ts), but standalone for launchd.
//
// Usage:
//   node run-and-post.mjs <channel-id> <workdir> <command> [args...]
//   node run-and-post.mjs --check          # verify Slack token (auth.test)
//
// workdir is relative to the repo root. DRY_RUN=1 prints instead of posting.

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT_TIMEOUT_MS = 60_000;
const MAX_MESSAGE_LENGTH = 4000;
const RETRY_DELAYS_MS = [15_000, 60_000, 180_000];

function log(...args) {
  const ts = new Date().toLocaleString('cs-CZ', { timeZone: 'Europe/Prague' });
  console.log(`[${ts}]`, ...args);
}

// Same keystore as NanoClaw: ~/.config/nanoclaw/{master.key,secrets.enc}
function getKeystoreSecret(key) {
  try {
    const dir = path.join(os.homedir(), '.config/nanoclaw');
    const masterKey = fs.readFileSync(path.join(dir, 'master.key'));
    if (masterKey.length !== 32) return null;
    const { iv, tag, data } = JSON.parse(fs.readFileSync(path.join(dir, 'secrets.enc'), 'utf-8'));
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const dec = Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf-8');
    return JSON.parse(dec)[key] ?? null;
  } catch {
    return null;
  }
}

// Fallback for setups without the keystore: SLACK_BOT_TOKEN=xoxb-... in ~/.config/slack-bot.env
function getEnvFileSecret(key) {
  try {
    const content = fs.readFileSync(path.join(os.homedir(), '.config/slack-bot.env'), 'utf-8');
    const match = content.match(new RegExp(`^\\s*${key}\\s*=\\s*["']?([^"'\\s]+)`, 'm'));
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

function getSlackToken() {
  return process.env.SLACK_BOT_TOKEN || getKeystoreSecret('SLACK_BOT_TOKEN') || getEnvFileSecret('SLACK_BOT_TOKEN');
}

async function slackApi(token, method, body) {
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });
  if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
  const json = await res.json();
  if (!json.ok) {
    const err = new Error(`Slack ${method}: ${json.error}`);
    err.permanent = true;
    throw err;
  }
  return json;
}

// Retries network failures (e.g. Wi-Fi not up yet right after wake), not API errors.
async function withRetry(fn) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (err.permanent || attempt >= RETRY_DELAYS_MS.length) throw err;
      log(`Slack nedostupný (${err.message}), zkusím znovu za ${RETRY_DELAYS_MS[attempt] / 1000}s`);
      await new Promise((r) => setTimeout(r, RETRY_DELAYS_MS[attempt]));
    }
  }
}

async function postToSlack(token, channel, text) {
  if (process.env.DRY_RUN) {
    log(`DRY_RUN → ${channel}:\n${text}`);
    return;
  }
  for (let i = 0; i < text.length; i += MAX_MESSAGE_LENGTH) {
    const chunk = text.slice(i, i + MAX_MESSAGE_LENGTH);
    await withRetry(() => slackApi(token, 'chat.postMessage', { channel, text: chunk }));
  }
  log(`Odesláno do ${channel} (${text.length} znaků)`);
}

function runScript(cwd, command, args) {
  const env = { ...process.env, PATH: `${path.dirname(process.execPath)}:${process.env.PATH ?? ''}` };
  return new Promise((resolve) => {
    execFile(command, args, { cwd, env, timeout: SCRIPT_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({ error, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const token = getSlackToken();
  if (!token && !process.env.DRY_RUN) {
    log('Chybí SLACK_BOT_TOKEN (keystore ~/.config/nanoclaw ani ~/.config/slack-bot.env)');
    process.exit(2);
  }

  if (argv[0] === '--check') {
    const res = await withRetry(() => slackApi(token, 'auth.test', {}));
    log(`Slack token OK: bot "${res.user}" v workspace "${res.team}"`);
    return;
  }

  const [channel, workdir, command, ...args] = argv;
  if (!channel || !workdir || !command) {
    console.error('Usage: run-and-post.mjs <channel-id> <workdir> <command> [args...]');
    process.exit(2);
  }

  const cwd = path.resolve(REPO_DIR, workdir);
  log(`Spouštím ${[command, ...args].join(' ')} v ${cwd}`);
  const { error, stdout, stderr } = await runScript(cwd, command, args);

  let text;
  if (error) {
    const reason = error.killed ? `timeout po ${SCRIPT_TIMEOUT_MS / 1000}s` : error.message;
    log(`Skript selhal: ${reason}`);
    text = `Chyba skriptu: ${reason}${stderr && !error.message.includes(stderr) ? `\n${stderr}` : ''}`;
  } else {
    text = stdout || stderr;
  }

  if (!text) {
    log('Skript nic nevypsal, nic se neposílá');
    return;
  }
  await postToSlack(token, channel, text);
  if (error) process.exit(1);
}

main().catch((err) => {
  log(`Chyba: ${err.message}`);
  process.exit(1);
});
