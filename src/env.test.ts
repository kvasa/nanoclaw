import fs from 'fs';
import os from 'os';
import path from 'path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { _resetEnvWarnings, readEnvFile } from './env.js';

vi.mock('./keystore.js', () => ({
  isKeystoreAvailable: () => false,
  getSecret: () => null,
  KEYSTORE_KEYS: new Set([
    'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN',
    'RHL_PASS',
  ]),
}));

describe('readEnvFile keystore warning', () => {
  let tmpRoot: string;
  let originalCwd: string;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    _resetEnvWarnings();
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nanoclaw-env-'));
    fs.writeFileSync(
      path.join(tmpRoot, '.env'),
      'ANTHROPIC_API_KEY=sk-fake\nRHL_PASS=abc\nNON_SECRET=public\n',
    );
    originalCwd = process.cwd();
    process.chdir(tmpRoot);
    stderrSpy = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    stderrSpy.mockRestore();
  });

  it('warns only ONCE per key even when readEnvFile is called many times', () => {
    // Simulate the IPC watcher / container-runner hot path — readEnvFile is
    // called on every container spawn and MCP call. Without dedup, every call
    // floods the error log with the same WARN lines (the actual production bug).
    for (let i = 0; i < 50; i++) {
      readEnvFile(['ANTHROPIC_API_KEY', 'RHL_PASS', 'NON_SECRET']);
    }

    const warningCalls = stderrSpy.mock.calls
      .map((c: unknown[]) => String(c[0]))
      .filter((s: string) =>
        s.includes('loaded from .env — consider migrating'),
      );

    expect(warningCalls).toHaveLength(2); // one per keystore key, not 100
    expect(
      warningCalls.some((s: string) => s.includes('ANTHROPIC_API_KEY')),
    ).toBe(true);
    expect(warningCalls.some((s: string) => s.includes('RHL_PASS'))).toBe(true);
  });

  it('does not warn for non-secret keys', () => {
    readEnvFile(['NON_SECRET']);
    const warningCalls = stderrSpy.mock.calls
      .map((c: unknown[]) => String(c[0]))
      .filter((s: string) => s.includes('loaded from .env'));
    expect(warningCalls).toHaveLength(0);
  });
});
