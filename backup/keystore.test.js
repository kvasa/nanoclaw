/**
 * Tests for backup/lib/keystore.js — the plain-JS reader for NanoClaw's
 * encrypted secrets store (src/keystore.ts writes the same format).
 *
 * Every test points NANOCLAW_KEYSTORE_DIR at a throwaway temp directory —
 * never touches the real ~/.config/nanoclaw store.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getKeystoreSecret } from './lib/keystore.js';

const ALGORITHM = 'aes-256-gcm';

/** Build a {iv, tag, data} envelope matching src/keystore.ts's encrypt(). */
function encryptEnvelope(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final(),
  ]);
  return JSON.stringify({
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    data: encrypted.toString('hex'),
  });
}

function writeStore(dir, secrets, key = crypto.randomBytes(32)) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'master.key'), key, { mode: 0o600 });
  fs.writeFileSync(
    path.join(dir, 'secrets.enc'),
    encryptEnvelope(JSON.stringify(secrets), key),
    { mode: 0o600 },
  );
  return key;
}

describe('getKeystoreSecret', () => {
  let tmpDir;
  let originalEnv;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncbk-keystore-test-'));
    originalEnv = process.env.NANOCLAW_KEYSTORE_DIR;
    process.env.NANOCLAW_KEYSTORE_DIR = tmpDir;
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.NANOCLAW_KEYSTORE_DIR;
    } else {
      process.env.NANOCLAW_KEYSTORE_DIR = originalEnv;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('round-trips a value written in the store format; unknown key returns null', () => {
    writeStore(tmpDir, { BACKUP_PASSWORD: 'super-secret-value' });

    expect(getKeystoreSecret('BACKUP_PASSWORD')).toBe('super-secret-value');
    expect(getKeystoreSecret('NOT_A_KEY')).toBeNull();
  });

  it('returns null without throwing when the store does not exist', () => {
    const warnSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => getKeystoreSecret('BACKUP_PASSWORD')).not.toThrow();
    expect(getKeystoreSecret('BACKUP_PASSWORD')).toBeNull();
    expect(warnSpy).not.toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it('returns null without throwing when secrets.enc is corrupt', () => {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'master.key'), crypto.randomBytes(32), {
      mode: 0o600,
    });
    fs.writeFileSync(path.join(tmpDir, 'secrets.enc'), 'garbage', {
      mode: 0o600,
    });
    const warnSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => getKeystoreSecret('BACKUP_PASSWORD')).not.toThrow();
    expect(getKeystoreSecret('BACKUP_PASSWORD')).toBeNull();
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });
});
