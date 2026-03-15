import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AdditionalMount, MountAllowlist } from './types.js';

let tmpDir: string;
let allowlistPath: string;

// We need fresh module imports for each test because mount-security.ts
// caches the allowlist at module level. We mock config.js to point
// MOUNT_ALLOWLIST_PATH to our temp file per test.

function writeAllowlist(data: unknown): void {
  fs.writeFileSync(allowlistPath, JSON.stringify(data));
}

function makeValidAllowlist(overrides: Partial<MountAllowlist> = {}): MountAllowlist {
  return {
    allowedRoots: overrides.allowedRoots ?? [
      { path: tmpDir, allowReadWrite: true, description: 'Test root' },
    ],
    blockedPatterns: overrides.blockedPatterns ?? [],
    nonMainReadOnly: overrides.nonMainReadOnly ?? false,
  };
}

/** Create a real directory under tmpDir and return its path */
function makeHostDir(name: string): string {
  const dir = path.join(tmpDir, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mount-security-test-'));
  allowlistPath = path.join(tmpDir, 'mount-allowlist.json');
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

/**
 * Helper to import mount-security with a fresh module cache.
 * Each call gets its own module-level cachedAllowlist/allowlistLoadError.
 */
async function importMountSecurity() {
  vi.doMock('./config.js', () => ({
    MOUNT_ALLOWLIST_PATH: allowlistPath,
  }));
  vi.doMock('./env.js', () => ({
    readEnvFile: () => ({}),
  }));
  const mod = await import('./mount-security.js');
  return mod;
}

// ---------------------------------------------------------------------------
// loadMountAllowlist
// ---------------------------------------------------------------------------

describe('loadMountAllowlist', () => {
  it('returns null when file does not exist', async () => {
    const { loadMountAllowlist } = await importMountSecurity();
    expect(loadMountAllowlist()).toBeNull();
  });

  it('returns null on invalid JSON', async () => {
    fs.writeFileSync(allowlistPath, '{ not valid json !!!');
    const { loadMountAllowlist } = await importMountSecurity();
    expect(loadMountAllowlist()).toBeNull();
  });

  it('returns null when allowedRoots is not an array', async () => {
    writeAllowlist({
      allowedRoots: 'not-an-array',
      blockedPatterns: [],
      nonMainReadOnly: true,
    });
    const { loadMountAllowlist } = await importMountSecurity();
    expect(loadMountAllowlist()).toBeNull();
  });

  it('returns null when blockedPatterns is not an array', async () => {
    writeAllowlist({
      allowedRoots: [],
      blockedPatterns: 'not-an-array',
      nonMainReadOnly: true,
    });
    const { loadMountAllowlist } = await importMountSecurity();
    expect(loadMountAllowlist()).toBeNull();
  });

  it('returns null when nonMainReadOnly is not a boolean', async () => {
    writeAllowlist({
      allowedRoots: [],
      blockedPatterns: [],
      nonMainReadOnly: 'yes',
    });
    const { loadMountAllowlist } = await importMountSecurity();
    expect(loadMountAllowlist()).toBeNull();
  });

  it('caches result - second call with same error does not re-attempt', async () => {
    // File doesn't exist — first call sets allowlistLoadError
    const { loadMountAllowlist } = await importMountSecurity();
    expect(loadMountAllowlist()).toBeNull();

    // Now create the file — but cached error should prevent re-read
    writeAllowlist(makeValidAllowlist());
    expect(loadMountAllowlist()).toBeNull();
  });

  it('caches successful result on second call', async () => {
    writeAllowlist(makeValidAllowlist());
    const { loadMountAllowlist } = await importMountSecurity();

    const first = loadMountAllowlist();
    expect(first).not.toBeNull();

    const second = loadMountAllowlist();
    expect(second).toBe(first); // Same reference — cached
  });

  it('merges DEFAULT_BLOCKED_PATTERNS with allowlist blockedPatterns', async () => {
    writeAllowlist(makeValidAllowlist({ blockedPatterns: ['my-custom-pattern'] }));
    const { loadMountAllowlist } = await importMountSecurity();

    const result = loadMountAllowlist();
    expect(result).not.toBeNull();
    // Should contain both default patterns and custom pattern
    expect(result!.blockedPatterns).toContain('.ssh');
    expect(result!.blockedPatterns).toContain('.env');
    expect(result!.blockedPatterns).toContain('credentials');
    expect(result!.blockedPatterns).toContain('my-custom-pattern');
  });

  it('deduplicates blocked patterns when allowlist contains defaults', async () => {
    writeAllowlist(makeValidAllowlist({ blockedPatterns: ['.ssh', 'custom'] }));
    const { loadMountAllowlist } = await importMountSecurity();

    const result = loadMountAllowlist();
    expect(result).not.toBeNull();
    // .ssh should appear exactly once (deduped via Set)
    const sshCount = result!.blockedPatterns.filter((p: string) => p === '.ssh').length;
    expect(sshCount).toBe(1);
    expect(result!.blockedPatterns).toContain('custom');
  });

  it('successfully loads a valid allowlist', async () => {
    const allowlist = makeValidAllowlist();
    writeAllowlist(allowlist);
    const { loadMountAllowlist } = await importMountSecurity();

    const result = loadMountAllowlist();
    expect(result).not.toBeNull();
    expect(result!.allowedRoots).toHaveLength(1);
    expect(result!.allowedRoots[0].path).toBe(tmpDir);
    expect(result!.nonMainReadOnly).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateMount
// ---------------------------------------------------------------------------

describe('validateMount', () => {
  it('returns not-allowed when no allowlist configured', async () => {
    // allowlistPath doesn't exist
    const { validateMount } = await importMountSecurity();
    const result = validateMount({ hostPath: '/some/path', containerPath: 'data' }, true);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('No mount allowlist configured');
  });

  it('returns not-allowed for container path with ".."', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('safe');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: '../escape' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('..');
  });

  it('returns not-allowed for absolute container path', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('safe');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: '/absolute/path' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Invalid container path');
  });

  it('falls back to basename when container path is empty string', async () => {
    // When containerPath is '' (falsy), the code uses path.basename(hostPath)
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('safe');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: '' },
      true,
    );
    // Empty string is falsy, so it falls back to basename 'safe'
    expect(result.allowed).toBe(true);
    expect(result.resolvedContainerPath).toBe('safe');
  });

  it('returns not-allowed for whitespace-only container path', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('safe');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: '   ' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Invalid container path');
  });

  it('returns not-allowed when host path does not exist', async () => {
    writeAllowlist(makeValidAllowlist());
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: path.join(tmpDir, 'nonexistent'), containerPath: 'data' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('does not exist');
  });

  it('returns not-allowed when path matches blocked pattern .ssh', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('.ssh');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'ssh-keys' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('blocked pattern');
    expect(result.reason).toContain('.ssh');
  });

  it('returns not-allowed when path matches blocked pattern .env', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('.env');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'envfiles' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('blocked pattern');
  });

  it('returns not-allowed when path matches blocked pattern credentials', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('credentials');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'creds' },
      true,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('blocked pattern');
  });

  it('returns not-allowed when path is not under any allowed root', async () => {
    // Allowed root is tmpDir, but host path is outside it
    writeAllowlist(makeValidAllowlist());
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-test-'));
    const { validateMount } = await importMountSecurity();

    try {
      const result = validateMount(
        { hostPath: outsideDir, containerPath: 'data' },
        true,
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('not under any allowed root');
    } finally {
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it('returns allowed for valid path under allowed root with readonly=true', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('my-project');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'my-project', readonly: true },
      true,
    );
    expect(result.allowed).toBe(true);
    expect(result.effectiveReadonly).toBe(true);
    expect(result.realHostPath).toBe(fs.realpathSync(hostDir));
    expect(result.resolvedContainerPath).toBe('my-project');
  });

  it('non-main group: read-write forced to read-only when nonMainReadOnly=true', async () => {
    writeAllowlist(makeValidAllowlist({ nonMainReadOnly: true }));
    const hostDir = makeHostDir('project');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'project', readonly: false },
      false, // isMain = false
    );
    expect(result.allowed).toBe(true);
    expect(result.effectiveReadonly).toBe(true);
  });

  it('main group: mount can be read-write if root allows it', async () => {
    writeAllowlist(
      makeValidAllowlist({
        allowedRoots: [
          { path: tmpDir, allowReadWrite: true, description: 'Test' },
        ],
      }),
    );
    const hostDir = makeHostDir('project');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'project', readonly: false },
      true, // isMain = true
    );
    expect(result.allowed).toBe(true);
    expect(result.effectiveReadonly).toBe(false);
  });

  it('read-write forced to read-only when root does not allow read-write', async () => {
    writeAllowlist(
      makeValidAllowlist({
        allowedRoots: [
          { path: tmpDir, allowReadWrite: false, description: 'Read-only root' },
        ],
      }),
    );
    const hostDir = makeHostDir('project');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'project', readonly: false },
      true,
    );
    expect(result.allowed).toBe(true);
    expect(result.effectiveReadonly).toBe(true);
  });

  it('derives containerPath from hostPath basename when not specified', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('my-data');
    const { validateMount } = await importMountSecurity();

    const result = validateMount({ hostPath: hostDir }, true);
    expect(result.allowed).toBe(true);
    expect(result.resolvedContainerPath).toBe('my-data');
  });

  it('accepts valid relative container paths like "mydata"', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('safe');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'mydata' },
      true,
    );
    expect(result.allowed).toBe(true);
  });

  it('accepts valid relative container paths like "project/data"', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('safe');
    const { validateMount } = await importMountSecurity();

    const result = validateMount(
      { hostPath: hostDir, containerPath: 'project/data' },
      true,
    );
    expect(result.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// validateAdditionalMounts
// ---------------------------------------------------------------------------

describe('validateAdditionalMounts', () => {
  it('returns empty array when all mounts are rejected', async () => {
    // No allowlist file — everything rejected
    const { validateAdditionalMounts } = await importMountSecurity();

    const result = validateAdditionalMounts(
      [
        { hostPath: '/does/not/exist', containerPath: 'a' },
        { hostPath: '/also/missing', containerPath: 'b' },
      ],
      'test-group',
      true,
    );
    expect(result).toEqual([]);
  });

  it('returns only valid mounts from mixed valid/invalid array', async () => {
    writeAllowlist(makeValidAllowlist());
    const validDir = makeHostDir('valid-project');
    const { validateAdditionalMounts } = await importMountSecurity();

    const result = validateAdditionalMounts(
      [
        { hostPath: validDir, containerPath: 'valid' },
        { hostPath: '/nonexistent/path', containerPath: 'invalid' },
      ],
      'test-group',
      true,
    );
    expect(result).toHaveLength(1);
    expect(result[0].containerPath).toBe('/workspace/extra/valid');
  });

  it('correctly maps containerPath to /workspace/extra/{containerPath}', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('data');
    const { validateAdditionalMounts } = await importMountSecurity();

    const result = validateAdditionalMounts(
      [{ hostPath: hostDir, containerPath: 'my-data' }],
      'test-group',
      true,
    );
    expect(result).toHaveLength(1);
    expect(result[0].containerPath).toBe('/workspace/extra/my-data');
    expect(result[0].hostPath).toBe(fs.realpathSync(hostDir));
  });

  it('sets readonly correctly on validated mounts', async () => {
    writeAllowlist(makeValidAllowlist());
    const hostDir = makeHostDir('project');
    const { validateAdditionalMounts } = await importMountSecurity();

    const result = validateAdditionalMounts(
      [{ hostPath: hostDir, containerPath: 'project', readonly: false }],
      'test-group',
      true,
    );
    expect(result).toHaveLength(1);
    expect(result[0].readonly).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// generateAllowlistTemplate
// ---------------------------------------------------------------------------

describe('generateAllowlistTemplate', () => {
  it('returns valid JSON string', async () => {
    const { generateAllowlistTemplate } = await importMountSecurity();
    const template = generateAllowlistTemplate();
    const parsed = JSON.parse(template);
    expect(parsed).toHaveProperty('allowedRoots');
    expect(parsed).toHaveProperty('blockedPatterns');
    expect(parsed).toHaveProperty('nonMainReadOnly');
    expect(Array.isArray(parsed.allowedRoots)).toBe(true);
    expect(Array.isArray(parsed.blockedPatterns)).toBe(true);
    expect(typeof parsed.nonMainReadOnly).toBe('boolean');
  });
});
