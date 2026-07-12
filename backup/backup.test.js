/**
 * Tests for the backup/restore crypto and channel resolution.
 *
 * The two load-bearing guarantees:
 *  - an old-format (v1 / PBKDF2) archive still restores after the scrypt
 *    KDF change (backwards compatibility of disaster recovery), and
 *  - Slack channel resolution never falls back to the main channel.
 *
 * No real password, key, or credential appears here — everything is
 * generated per-run. Tests only touch temp directories.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import {
  encryptFile,
  validateBackupPassword,
  resolveSlackChannelId,
  copyRecursive,
  pruneOldBackups,
  FORMAT_VERSION,
  MIN_PASSWORD_LENGTH,
} from './backup.js';
import { decryptFile, assertSafeArchive } from './restore.js';

const MAGIC = Buffer.from('NCBK');
const PBKDF2_ITERATIONS = 100_000;

let tmpDir;
const password = crypto.randomBytes(24).toString('base64');

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncbk-test-'));
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function tmp(name) {
  return path.join(tmpDir, name);
}

/** Build a v1 (PBKDF2) archive the way backup.js@format-1 used to. */
function encryptFileV1(inputPath, outputPath, pw) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(pw, salt, PBKDF2_ITERATIONS, 32, 'sha512');
  const plaintext = fs.readFileSync(inputPath);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const header = Buffer.alloc(53);
  MAGIC.copy(header, 0);
  header.writeUInt8(1, 4);
  salt.copy(header, 5);
  iv.copy(header, 21);
  authTag.copy(header, 37);
  fs.writeFileSync(outputPath, Buffer.concat([header, encrypted]));
}

describe('backup encryption round-trip', () => {
  it('writes format version 2 and round-trips byte-identically', () => {
    const plain = tmp('plain-v2.bin');
    const enc = tmp('archive-v2.enc');
    const out = tmp('restored-v2.bin');
    const content = crypto.randomBytes(4096);
    fs.writeFileSync(plain, content);

    encryptFile(plain, enc, password);

    const header = fs.readFileSync(enc).subarray(0, 5);
    expect(header.subarray(0, 4).equals(MAGIC)).toBe(true);
    expect(header.readUInt8(4)).toBe(FORMAT_VERSION);
    expect(FORMAT_VERSION).toBe(2);

    decryptFile(enc, out, password);
    expect(fs.readFileSync(out).equals(content)).toBe(true);
  });

  it('still restores an old v1 (PBKDF2) archive', () => {
    const plain = tmp('plain-v1.bin');
    const enc = tmp('archive-v1.enc');
    const out = tmp('restored-v1.bin');
    const content = crypto.randomBytes(4096);
    fs.writeFileSync(plain, content);

    encryptFileV1(plain, enc, password);
    decryptFile(enc, out, password);

    expect(fs.readFileSync(out).equals(content)).toBe(true);
  });

  it('fails cleanly on a wrong password instead of returning garbage', () => {
    const plain = tmp('plain-wrongpw.bin');
    const enc = tmp('archive-wrongpw.enc');
    const out = tmp('restored-wrongpw.bin');
    fs.writeFileSync(plain, crypto.randomBytes(1024));

    encryptFile(plain, enc, password);

    expect(() =>
      decryptFile(enc, out, `${password}-but-wrong`),
    ).toThrow(/wrong password or corrupted/i);
    expect(fs.existsSync(out)).toBe(false);
  });

  it('rejects an unsupported format version with a clear error', () => {
    const plain = tmp('plain-v9.bin');
    const enc = tmp('archive-v9.enc');
    fs.writeFileSync(plain, crypto.randomBytes(64));
    encryptFile(plain, enc, password);

    const data = fs.readFileSync(enc);
    data.writeUInt8(9, 4);
    fs.writeFileSync(enc, data);

    expect(() => decryptFile(enc, tmp('out-v9.bin'), password)).toThrow(
      /Unsupported backup format version: 9/,
    );
  });
});

describe('backup password validation', () => {
  it('rejects a missing password', () => {
    expect(validateBackupPassword(undefined)).toMatch(/not set/);
  });

  it('rejects a short password without echoing it', () => {
    const shortPw = 'a'.repeat(MIN_PASSWORD_LENGTH - 1);
    const reason = validateBackupPassword(shortPw);
    expect(reason).toMatch(/too short/);
    expect(reason).not.toContain(shortPw);
  });

  it('accepts a password of the minimum length', () => {
    expect(validateBackupPassword('x'.repeat(MIN_PASSWORD_LENGTH))).toBeNull();
  });
});

describe('resolveSlackChannelId', () => {
  function makeDb(rows) {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');
    const dbPath = tmp(`groups-${crypto.randomBytes(4).toString('hex')}.db`);
    const db = new Database(dbPath);
    db.exec(
      'CREATE TABLE registered_groups (jid TEXT, folder TEXT, is_main INTEGER)',
    );
    const insert = db.prepare(
      'INSERT INTO registered_groups (jid, folder, is_main) VALUES (?, ?, ?)',
    );
    for (const r of rows) insert.run(r.jid, r.folder, r.is_main);
    db.close();
    return dbPath;
  }

  it('never falls back to the main channel when no backups group exists', () => {
    const dbPath = makeDb([
      { jid: 'slack:CMAIN', folder: 'main', is_main: 1 },
    ]);
    expect(resolveSlackChannelId(undefined, dbPath)).toBeNull();
  });

  it('resolves the dedicated backups group', () => {
    const dbPath = makeDb([
      { jid: 'slack:CMAIN', folder: 'main', is_main: 1 },
      { jid: 'slack:CBACKUPS', folder: 'backups', is_main: 0 },
    ]);
    expect(resolveSlackChannelId(undefined, dbPath)).toBe('CBACKUPS');
  });

  it('prefers the env channel and strips the slack: prefix', () => {
    expect(resolveSlackChannelId('slack:CENV', '/nonexistent.db')).toBe(
      'CENV',
    );
  });
});

describe('copyRecursive symlink handling', () => {
  it('copies regular files but never follows symlinks to files or dirs', () => {
    const outside = tmp('copyrec-outside');
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'host-only');

    const srcRoot = tmp('copyrec-src');
    fs.mkdirSync(path.join(srcRoot, 'sub'), { recursive: true });
    fs.writeFileSync(path.join(srcRoot, 'a.txt'), 'A');
    fs.writeFileSync(path.join(srcRoot, 'sub', 'b.txt'), 'B');
    fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(srcRoot, 'evil.txt'));
    fs.symlinkSync(outside, path.join(srcRoot, 'evildir'));

    const destRoot = tmp('copyrec-dest');
    const stats = copyRecursive(srcRoot, destRoot);

    expect(fs.readFileSync(path.join(destRoot, 'a.txt'), 'utf-8')).toBe('A');
    expect(fs.readFileSync(path.join(destRoot, 'sub', 'b.txt'), 'utf-8')).toBe('B');
    // Neither as file, dir, nor link — lstat must find nothing at all.
    expect(() => fs.lstatSync(path.join(destRoot, 'evil.txt'))).toThrow();
    expect(() => fs.lstatSync(path.join(destRoot, 'evildir'))).toThrow();
    expect(stats.files).toBe(2);
  });

  it('skips a dangling symlink without throwing', () => {
    const srcRoot = tmp('copyrec-dangling-src');
    fs.mkdirSync(srcRoot, { recursive: true });
    fs.symlinkSync(
      path.join(srcRoot, 'does-not-exist'),
      path.join(srcRoot, 'dangling'),
    );

    const destRoot = tmp('copyrec-dangling-dest');
    let stats;
    expect(() => {
      stats = copyRecursive(srcRoot, destRoot);
    }).not.toThrow();
    expect(stats.files).toBe(0);
    expect(() => fs.lstatSync(path.join(destRoot, 'dangling'))).toThrow();
  });
});

describe('pruneOldBackups', () => {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const HOUR_MS = 60 * 60 * 1000;

  function setMtime(filePath, ageMs) {
    const t = new Date(Date.now() - ageMs);
    fs.utimesSync(filePath, t, t);
  }

  it('deletes .enc backups older than 7 days and stale .tmp partials older than 1 day, keeps everything else', () => {
    const dir = tmp(`prune-${crypto.randomBytes(4).toString('hex')}`);
    fs.mkdirSync(dir, { recursive: true });

    const oldEnc = path.join(dir, 'nanoclaw-backup-old.tar.gz.enc');
    const newEnc = path.join(dir, 'nanoclaw-backup-new.tar.gz.enc');
    const oldTmp = path.join(dir, '.nanoclaw-backup-x.tar.gz.enc.tmp');
    const freshTmp = path.join(dir, '.nanoclaw-backup-y.tar.gz.enc.tmp');
    const readme = path.join(dir, 'README.txt');

    for (const f of [oldEnc, newEnc, oldTmp, freshTmp, readme]) {
      fs.writeFileSync(f, 'x');
    }

    setMtime(oldEnc, 8 * DAY_MS);
    setMtime(newEnc, 1 * DAY_MS);
    setMtime(oldTmp, 2 * DAY_MS);
    setMtime(freshTmp, 1 * HOUR_MS);
    setMtime(readme, 8 * DAY_MS);

    pruneOldBackups(dir);

    expect(fs.existsSync(oldEnc)).toBe(false);
    expect(fs.existsSync(newEnc)).toBe(true);
    expect(fs.existsSync(oldTmp)).toBe(false);
    expect(fs.existsSync(freshTmp)).toBe(true);
    expect(fs.existsSync(readme)).toBe(true);
  });
});

describe('assertSafeArchive', () => {
  it('accepts a normal relative archive', () => {
    const dir = tmp('safe-tar');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'file.txt'), 'ok');
    const tarPath = tmp('safe.tgz');
    execFileSync('tar', ['-czf', tarPath, '-C', dir, '.']);

    expect(() => assertSafeArchive(tarPath)).not.toThrow();
  });

  it('rejects an archive with an absolute member path', () => {
    const dir = tmp('abs-tar');
    fs.mkdirSync(dir, { recursive: true });
    const absFile = path.join(dir, 'abs.txt');
    fs.writeFileSync(absFile, 'evil');
    const tarPath = tmp('abs.tgz');
    // -P preserves the absolute member name inside the archive
    execFileSync('tar', ['-czPf', tarPath, absFile]);

    expect(() => assertSafeArchive(tarPath)).toThrow(/unsafe path/);
  });

  it('rejects an archive with a .. traversal member', () => {
    const outer = tmp('trav-tar');
    const inner = path.join(outer, 'inner');
    fs.mkdirSync(inner, { recursive: true });
    fs.writeFileSync(path.join(outer, 'escape.txt'), 'evil');
    const tarPath = tmp('trav.tgz');
    // From inner/, ../escape.txt is stored with a leading .. (kept by -P)
    execFileSync('tar', ['-czPf', tarPath, '-C', inner, '../escape.txt']);

    expect(() => assertSafeArchive(tarPath)).toThrow(/unsafe path/);
  });

  it('rejects an archive containing a symlink member', () => {
    const dir = tmp('symlink-tar');
    fs.mkdirSync(dir, { recursive: true });
    fs.symlinkSync('/tmp', path.join(dir, 'link'));
    const tarPath = tmp('symlink.tgz');
    execFileSync('tar', ['-czf', tarPath, 'link'], { cwd: dir });

    expect(() => assertSafeArchive(tarPath)).toThrow(/link member/);
  });

  it('rejects an archive containing a hardlink member', () => {
    const dir = tmp('hardlink-tar');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'orig.txt'), 'content');
    fs.linkSync(path.join(dir, 'orig.txt'), path.join(dir, 'hard.txt'));
    const tarPath = tmp('hardlink.tgz');
    // GNU tar stores the second occurrence as a hardlink member
    execFileSync('tar', ['-czf', tarPath, 'orig.txt', 'hard.txt'], { cwd: dir });

    expect(() => assertSafeArchive(tarPath)).toThrow(/link member/);
  });
});
