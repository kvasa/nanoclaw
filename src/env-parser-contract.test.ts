/**
 * Contract test pinning src/env.ts's parser semantics to the shared plain-JS
 * parser at backup/lib/env.js. src/env.ts cannot import backup/lib/* (tsconfig
 * rootDir: "./src" excludes anything outside src/), and backup/lib/env.js is
 * plain ESM JS that vitest can import directly — so this test is the tripwire:
 * if either implementation's quoting/comment/whitespace semantics drift, this
 * fails instead of the two scripts silently reading different credentials.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest';

import { _resetEnvWarnings, readEnvFile } from './env.js';
import { _encrypt, _decrypt } from './keystore.js';
import { parseEnv as sharedParseEnv } from '../backup/lib/env.js';
import { getKeystoreSecret } from '../backup/lib/keystore.js';

vi.mock('./keystore.js', async () => {
  const actual =
    await vi.importActual<typeof import('./keystore.js')>('./keystore.js');
  return {
    ...actual,
    isKeystoreAvailable: () => false,
    getSecret: () => null,
    // Keep KEYSTORE_KEYS distinct from the fixture keys below so the
    // keystore path never engages for this test.
    KEYSTORE_KEYS: new Set(['SOME_OTHER_KEYSTORE_KEY']),
  };
});

const FIXTURE = [
  '# a comment line',
  '',
  'KEY=val',
  'KEY_DQUOTE="quoted"',
  "KEY_SQUOTE='single'",
  'KEY_EMPTY=',
  'lower=case',
  'KEY_SPACED = spaced',
  'KEY_EQ=a=b=c',
].join('\n');

const FIXTURE_KEYS = [
  'KEY',
  'KEY_DQUOTE',
  'KEY_SQUOTE',
  'KEY_EMPTY',
  'lower',
  'KEY_SPACED',
  'KEY_EQ',
];

describe('env parser contract: src/env.ts readEnvFile vs backup/lib/env.js parseEnv', () => {
  let tmpRoot: string;
  let cwdSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    _resetEnvWarnings();
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nanoclaw-env-contract-'));
    fs.writeFileSync(path.join(tmpRoot, '.env'), FIXTURE);
    cwdSpy = vi.spyOn(process, 'cwd').mockReturnValue(tmpRoot);
  });

  afterEach(() => {
    cwdSpy.mockRestore();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('produces the same map for every rule exercised by the fixture', () => {
    const fromTs = readEnvFile(FIXTURE_KEYS);
    const fromShared = sharedParseEnv(FIXTURE);

    // fromShared returns all keys found; filter to the fixture set for a
    // like-for-like comparison against readEnvFile's requested-keys map.
    const fromSharedFiltered: Record<string, string> = {};
    for (const k of FIXTURE_KEYS) {
      if (k in fromShared) fromSharedFiltered[k] = fromShared[k];
    }

    expect(fromTs).toEqual(fromSharedFiltered);

    // Sanity: pin the actual expected values so a change in either
    // implementation's semantics is caught even if both drift together.
    expect(fromTs).toEqual({
      KEY: 'val',
      KEY_DQUOTE: 'quoted',
      KEY_SQUOTE: 'single',
      lower: 'case',
      KEY_SPACED: 'spaced',
      KEY_EQ: 'a=b=c',
    });
    // KEY_EMPTY is skipped by both implementations (empty values are
    // dropped), so it must not appear in either map.
    expect(fromTs).not.toHaveProperty('KEY_EMPTY');
  });
});

describe('keystore envelope shape contract', () => {
  it('produces a JSON envelope with iv/tag/data hex fields and round-trips', () => {
    const key = Buffer.alloc(32, 7); // deterministic 32-byte key
    const plaintext = 'contract-test-plaintext';

    const envelope = _encrypt(plaintext, key);
    const parsed = JSON.parse(envelope);

    expect(Object.keys(parsed).sort()).toEqual(['data', 'iv', 'tag']);
    expect(parsed.iv).toMatch(/^[0-9a-f]{24}$/); // 12-byte IV -> 24 hex chars
    expect(parsed.tag).toMatch(/^[0-9a-f]{32}$/); // 16-byte auth tag -> 32 hex chars
    expect(parsed.data).toMatch(/^[0-9a-f]*$/);

    expect(_decrypt(envelope, key)).toBe(plaintext);
  });

  // setup-keystore.mjs implements the same {iv, tag, data} hex-field
  // envelope shape (scripts/setup-keystore.mjs:61-70) but is not imported
  // here — the script runs commands on import (migration/CLI side effects),
  // so importing it in a test would have real side effects. Its envelope
  // shape is pinned only by this shape assertion on the TS side plus the
  // "must match" cross-comments between the two files; see plan 030
  // Maintenance notes.
});

describe('keystore cross-implementation contract: src/keystore.ts writer vs backup/lib/keystore.js reader', () => {
  let tmpDir: string;
  let originalEnv: string | undefined;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(
      path.join(os.tmpdir(), 'nanoclaw-keystore-contract-'),
    );
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

  it('backup/lib/keystore.js reads a value written by src/keystore.ts setSecret', async () => {
    const keystore = await import('./keystore.js');

    expect(keystore.setSecret('BACKUP_PASSWORD', 'contract-test-value')).toBe(
      true,
    );

    expect(getKeystoreSecret('BACKUP_PASSWORD')).toBe('contract-test-value');
    expect(getKeystoreSecret('NOT_A_REAL_KEY')).toBeNull();
  });
});
