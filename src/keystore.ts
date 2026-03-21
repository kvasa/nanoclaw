/**
 * Encrypted secrets store for NanoClaw.
 *
 * Secrets are stored in AES-256-GCM encrypted form:
 *   ~/.config/nanoclaw/master.key  — 32-byte random key (chmod 600)
 *   ~/.config/nanoclaw/secrets.enc — encrypted JSON map of key→value (chmod 600)
 *
 * The master key is generated once and protected by file-system permissions.
 * This is security-equivalent to gnome-keyring without PAM integration, and
 * works on headless servers without any daemon.
 *
 * Run `node scripts/setup-keystore.mjs` to migrate existing .env secrets.
 */
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CONFIG_DIR = path.join(os.homedir(), '.config', 'nanoclaw');
const MASTER_KEY_FILE = path.join(CONFIG_DIR, 'master.key');
const SECRETS_FILE = path.join(CONFIG_DIR, 'secrets.enc');
const ALGORITHM = 'aes-256-gcm';

/**
 * Keys that are considered sensitive and should live in the encrypted store.
 * readEnvFile() checks here first, then falls back to .env.
 */
export const KEYSTORE_KEYS = new Set([
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
]);

/** Returns true if the encrypted store is initialised (master key exists). */
export function isKeystoreAvailable(): boolean {
  return fs.existsSync(MASTER_KEY_FILE);
}

function loadMasterKey(): Buffer | null {
  try {
    const key = fs.readFileSync(MASTER_KEY_FILE);
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

function generateMasterKey(): Buffer {
  const key = crypto.randomBytes(32);
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(MASTER_KEY_FILE, key, { mode: 0o600 });
  return key;
}

interface Envelope {
  iv: string;
  tag: string;
  data: string;
}

function encrypt(plaintext: string, key: Buffer): string {
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final(),
  ]);
  const envelope: Envelope = {
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    data: encrypted.toString('hex'),
  };
  return JSON.stringify(envelope);
}

function decrypt(ciphertext: string, key: Buffer): string {
  const { iv, tag, data } = JSON.parse(ciphertext) as Envelope;
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'hex'),
  );
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(data, 'hex')),
    decipher.final(),
  ]).toString('utf-8');
}

function loadSecrets(key: Buffer): Record<string, string> {
  try {
    const content = fs.readFileSync(SECRETS_FILE, 'utf-8');
    return JSON.parse(decrypt(content, key)) as Record<string, string>;
  } catch {
    return {};
  }
}

function saveSecrets(secrets: Record<string, string>, key: Buffer): void {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(SECRETS_FILE, encrypt(JSON.stringify(secrets), key), {
    mode: 0o600,
  });
}

/** Read a single secret from the encrypted store. Returns null if not found. */
export function getSecret(secretKey: string): string | null {
  const masterKey = loadMasterKey();
  if (!masterKey) return null;
  const secrets = loadSecrets(masterKey);
  return secrets[secretKey] ?? null;
}

/** Write a secret to the encrypted store (creates master key on first use). */
export function setSecret(secretKey: string, value: string): boolean {
  try {
    const masterKey = loadMasterKey() ?? generateMasterKey();
    const secrets = loadSecrets(masterKey);
    secrets[secretKey] = value;
    saveSecrets(secrets, masterKey);
    return true;
  } catch {
    return false;
  }
}

/** Remove a secret from the encrypted store. */
export function deleteSecret(secretKey: string): boolean {
  const masterKey = loadMasterKey();
  if (!masterKey) return false;
  const secrets = loadSecrets(masterKey);
  if (!(secretKey in secrets)) return false;
  delete secrets[secretKey];
  saveSecrets(secrets, masterKey);
  return true;
}
