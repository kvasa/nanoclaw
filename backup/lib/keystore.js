/**
 * Read-only reader for NanoClaw's encrypted secrets store, for the plain-JS
 * backup/restore scripts.
 *
 * The store is written by src/keystore.ts (and scripts/setup-keystore.mjs,
 * same format):
 *   <dir>/master.key  — 32-byte random key
 *   <dir>/secrets.enc — encrypted JSON map of key -> value, envelope
 *                       {"iv": <24 hex>, "tag": <32 hex>, "data": <hex>},
 *                       AES-256-GCM with a 12-byte IV.
 * <dir> defaults to ~/.config/nanoclaw, overridable via NANOCLAW_KEYSTORE_DIR
 * (test hook — mirrors src/keystore.ts's configDir()).
 *
 * This file only reads. The envelope shape is pinned by a cross-implementation
 * contract test against src/keystore.ts's _encrypt/_decrypt (see
 * src/env-parser-contract.test.ts).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ALGORITHM = 'aes-256-gcm';

function configDir() {
  return (
    process.env.NANOCLAW_KEYSTORE_DIR ??
    path.join(os.homedir(), '.config', 'nanoclaw')
  );
}

function masterKeyFile() {
  return path.join(configDir(), 'master.key');
}

function secretsFile() {
  return path.join(configDir(), 'secrets.enc');
}

function decrypt(ciphertext, key) {
  const { iv, tag, data } = JSON.parse(ciphertext);
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

/**
 * Read a single secret from the encrypted keystore. Fail-soft: this helper
 * must never throw — the callers (backup.js, restore.js) have their own
 * .env/env-var fallbacks and error messages.
 *
 * Returns null when the store doesn't exist, is unreadable, or the key is
 * not present.
 */
export function getKeystoreSecret(name) {
  let masterKey;
  try {
    masterKey = fs.readFileSync(masterKeyFile());
  } catch {
    return null;
  }
  if (masterKey.length !== 32) return null;

  let content;
  try {
    content = fs.readFileSync(secretsFile(), 'utf-8');
  } catch {
    return null;
  }

  try {
    const secrets = JSON.parse(decrypt(content, masterKey));
    return secrets[name] ?? null;
  } catch {
    console.error(
      '[backup] WARN: keystore exists but cannot be read — falling back to .env',
    );
    return null;
  }
}
