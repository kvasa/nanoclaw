import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

describe('keystore', () => {
  let tmpDir: string;
  let originalEnv: string | undefined;
  let keystore: typeof import('./keystore.js');

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keystore-test-'));
    originalEnv = process.env.NANOCLAW_KEYSTORE_DIR;
    process.env.NANOCLAW_KEYSTORE_DIR = tmpDir;
    keystore = await import('./keystore.js');
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.NANOCLAW_KEYSTORE_DIR;
    } else {
      process.env.NANOCLAW_KEYSTORE_DIR = originalEnv;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('round-trips a secret through set/get and reports the store as available', () => {
    expect(keystore.setSecret('K', 'v')).toBe(true);
    expect(keystore.getSecret('K')).toBe('v');
    expect(keystore.isKeystoreAvailable()).toBe(true);
  });

  it('treats a missing store as empty, not an error, and creates both files on write', () => {
    expect(keystore.getSecret('K')).toBeNull();

    const masterKeyFile = path.join(tmpDir, 'master.key');
    const secretsFile = path.join(tmpDir, 'secrets.enc');
    expect(fs.existsSync(masterKeyFile)).toBe(false);
    expect(fs.existsSync(secretsFile)).toBe(false);

    expect(keystore.setSecret('K', 'v')).toBe(true);
    expect(fs.existsSync(masterKeyFile)).toBe(true);
    expect(fs.existsSync(secretsFile)).toBe(true);
  });

  it('refuses to overwrite a corrupted store instead of wiping it', () => {
    expect(keystore.setSecret('A', '1')).toBe(true);
    expect(keystore.setSecret('B', '2')).toBe(true);

    const secretsFile = path.join(tmpDir, 'secrets.enc');
    fs.writeFileSync(secretsFile, 'garbage');

    expect(keystore.setSecret('C', '3')).toBe(false);
    expect(fs.readFileSync(secretsFile, 'utf-8')).toBe('garbage');
    expect(keystore.getSecret('A')).toBeNull();
  });

  it('refuses to write or delete when the master key does not match the store', () => {
    expect(keystore.setSecret('A', '1')).toBe(true);

    const masterKeyFile = path.join(tmpDir, 'master.key');
    const secretsFile = path.join(tmpDir, 'secrets.enc');
    const before = fs.readFileSync(secretsFile, 'utf-8');

    fs.writeFileSync(masterKeyFile, crypto.randomBytes(32), { mode: 0o600 });

    expect(keystore.setSecret('C', '3')).toBe(false);
    expect(keystore.deleteSecret('A')).toBe(false);
    expect(fs.readFileSync(secretsFile, 'utf-8')).toBe(before);
  });

  it('deletes a secret while leaving the others intact', () => {
    expect(keystore.setSecret('A', '1')).toBe(true);
    expect(keystore.setSecret('B', '2')).toBe(true);

    expect(keystore.deleteSecret('A')).toBe(true);
    expect(keystore.getSecret('A')).toBeNull();
    expect(keystore.getSecret('B')).toBe('2');
  });
});
