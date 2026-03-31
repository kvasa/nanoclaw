#!/usr/bin/env node
/**
 * Migrate sensitive credentials from .env to the encrypted secrets store.
 *
 * Secrets are stored in AES-256-GCM encrypted form:
 *   ~/.config/nanoclaw/master.key  — 32-byte random key (chmod 600)
 *   ~/.config/nanoclaw/secrets.enc — encrypted JSON map  (chmod 600)
 *
 * Usage:
 *   node scripts/setup-keystore.mjs          # migrate .env → encrypted store
 *   node scripts/setup-keystore.mjs --list   # show what's in the store
 *   node scripts/setup-keystore.mjs --clear  # remove all secrets from store
 *   node scripts/setup-keystore.mjs --set KEY=value  # set a single secret
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENV_FILE = path.join(__dirname, '..', '.env');
const CONFIG_DIR = path.join(os.homedir(), '.config', 'nanoclaw');
const MASTER_KEY_FILE = path.join(CONFIG_DIR, 'master.key');
const SECRETS_FILE = path.join(CONFIG_DIR, 'secrets.enc');
const ALGORITHM = 'aes-256-gcm';

const SENSITIVE_KEYS = [
  'ANTHROPIC_API_KEY',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'ANTHROPIC_AUTH_TOKEN',
  'RHL_PASS',
  'APPLE_APP_PASSWORD',
  'GARMIN_PASSWORD',
  'BACKUP_PASSWORD',
  'SLACK_BOT_TOKEN',
  'SLACK_APP_TOKEN',
  'OPENAI_API_KEY',
  'API_TOKEN',
  'SPOTIFY_REFRESH_TOKEN',
];

// ── Crypto ────────────────────────────────────────────────────────────────────

function loadMasterKey() {
  if (!fs.existsSync(MASTER_KEY_FILE)) return null;
  const key = fs.readFileSync(MASTER_KEY_FILE);
  return key.length === 32 ? key : null;
}

function getOrCreateMasterKey() {
  const existing = loadMasterKey();
  if (existing) return existing;
  const key = crypto.randomBytes(32);
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(MASTER_KEY_FILE, key, { mode: 0o600 });
  console.log(`  ✓ Generated new master key at ${MASTER_KEY_FILE}`);
  return key;
}

function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const data = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  return JSON.stringify({
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    data: data.toString('hex'),
  });
}

function decrypt(ciphertext, key) {
  const { iv, tag, data } = JSON.parse(ciphertext);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(data, 'hex')),
    decipher.final(),
  ]).toString('utf-8');
}

function loadSecrets(key) {
  if (!fs.existsSync(SECRETS_FILE)) return {};
  try {
    return JSON.parse(decrypt(fs.readFileSync(SECRETS_FILE, 'utf-8'), key));
  } catch {
    return {};
  }
}

function saveSecrets(secrets, key) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(SECRETS_FILE, encrypt(JSON.stringify(secrets), key), { mode: 0o600 });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseEnv(content) {
  const result = {};
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (value) result[key] = value;
  }
  return result;
}

function redactEnv(content, migratedKeys) {
  return content
    .split('\n')
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return line;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) return line;
      const key = trimmed.slice(0, eqIdx).trim();
      if (!migratedKeys.has(key)) return line;
      return `# ${key} — stored in encrypted keystore (~/.config/nanoclaw/secrets.enc)`;
    })
    .join('\n');
}

function ask(rl, question) {
  return new Promise((resolve) => rl.question(question, resolve));
}

// ── Commands ──────────────────────────────────────────────────────────────────

function cmdList() {
  const key = loadMasterKey();
  if (!key) {
    console.log('\nNo encrypted store found. Run without flags to migrate from .env.\n');
    return;
  }
  const secrets = loadSecrets(key);
  console.log('\nSecrets in encrypted store:\n');
  let found = 0;
  for (const k of SENSITIVE_KEYS) {
    if (k in secrets) {
      console.log(`  ✓ ${k}  (${secrets[k].length} chars)`);
      found++;
    } else {
      console.log(`  · ${k}  (not stored)`);
    }
  }
  const extra = Object.keys(secrets).filter((k) => !SENSITIVE_KEYS.includes(k));
  for (const k of extra) {
    console.log(`  + ${k}  (${secrets[k].length} chars)`);
    found++;
  }
  console.log(`\n${found} key(s) stored. Files:\n  ${MASTER_KEY_FILE}\n  ${SECRETS_FILE}\n`);
}

function cmdClear() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question('\nRemove all secrets from encrypted store? [y/N] ', (answer) => {
    rl.close();
    if (answer.trim().toLowerCase() !== 'y') { console.log('Aborted.\n'); return; }
    try { fs.unlinkSync(SECRETS_FILE); } catch { /* already gone */ }
    try { fs.unlinkSync(MASTER_KEY_FILE); } catch { /* already gone */ }
    console.log('Done. Secrets removed. Remember to restore values to .env if needed.\n');
  });
}

function cmdSet(arg) {
  const eqIdx = arg.indexOf('=');
  if (eqIdx === -1) {
    console.error('Usage: --set KEY=value\n');
    process.exit(1);
  }
  const key = arg.slice(0, eqIdx).trim();
  const value = arg.slice(eqIdx + 1);
  const masterKey = getOrCreateMasterKey();
  const secrets = loadSecrets(masterKey);
  secrets[key] = value;
  saveSecrets(secrets, masterKey);
  console.log(`\n  ✓ ${key} stored in encrypted keystore.\n`);
}

async function cmdMigrate() {
  if (!fs.existsSync(ENV_FILE)) {
    console.error(`\n❌  .env not found at ${ENV_FILE}\n`);
    process.exit(1);
  }

  const envContent = fs.readFileSync(ENV_FILE, 'utf-8');
  const envVars = parseEnv(envContent);
  const toMigrate = SENSITIVE_KEYS.filter((k) => envVars[k]);

  const masterKey = loadMasterKey();
  const existing = masterKey ? loadSecrets(masterKey) : {};
  const alreadyStored = toMigrate.filter((k) => k in existing);

  if (toMigrate.length === 0) {
    console.log('\n✓  No sensitive keys found in .env — nothing to migrate.\n');
    if (Object.keys(existing).length > 0) cmdList();
    return;
  }

  console.log('\nNanoClaw keystore migration\n');
  console.log('Sensitive keys to move from .env → encrypted store:');
  for (const k of toMigrate) {
    console.log(`  ${alreadyStored.includes(k) ? '⚠ overwrite' : '+'} ${k}`);
  }
  console.log(`\nStore: ${SECRETS_FILE}`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await ask(rl, '\nProceed? [y/N] ');
  rl.close();

  if (answer.trim().toLowerCase() !== 'y') {
    console.log('Aborted.\n');
    return;
  }

  const newMasterKey = getOrCreateMasterKey();
  const secrets = loadSecrets(newMasterKey);
  const migrated = new Set();

  for (const k of toMigrate) {
    try {
      secrets[k] = envVars[k];
      migrated.add(k);
    } catch (err) {
      console.error(`  ✗ ${k} — ${err.message}`);
    }
  }

  saveSecrets(secrets, newMasterKey);

  // Verify read-back
  const verify = loadSecrets(newMasterKey);
  const failed = [...migrated].filter((k) => verify[k] !== envVars[k]);
  if (failed.length > 0) {
    console.error(`\n❌  Verification failed for: ${failed.join(', ')}`);
    console.error('    .env left unchanged.\n');
    process.exit(1);
  }

  for (const k of migrated) console.log(`  ✓ ${k}`);

  // Redact .env
  const newEnv = redactEnv(envContent, migrated);
  fs.writeFileSync(ENV_FILE, newEnv, { mode: 0o600 });

  console.log(`\n✓  ${migrated.size} key(s) migrated and verified. Removed from .env.\n`);
}

// ── Entry point ───────────────────────────────────────────────────────────────

const arg = process.argv[2];

if (arg === '--list') {
  cmdList();
} else if (arg === '--clear') {
  cmdClear();
} else if (arg?.startsWith('--set')) {
  const val = arg.startsWith('--set=') ? arg.slice(6) : process.argv[3];
  cmdSet(val ?? '');
} else {
  cmdMigrate().catch((err) => {
    console.error('\n❌  Unexpected error:', err.message, '\n');
    process.exit(1);
  });
}
