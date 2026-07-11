import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';

// Sentinel markers must match container-runner.ts
const OUTPUT_START_MARKER = '---NANOCLAW_OUTPUT_START---';
const OUTPUT_END_MARKER = '---NANOCLAW_OUTPUT_END---';

// Mock config
vi.mock('./config.js', () => ({
  CONTAINER_IMAGE: 'nanoclaw-agent:latest',
  CONTAINER_MAX_OUTPUT_SIZE: 10485760,
  CONTAINER_TIMEOUT: 1800000, // 30min
  CONTAINER_MEMORY: '2g',
  CONTAINER_CPUS: '2',
  CONTAINER_PIDS_LIMIT: '512',
  CREDENTIAL_PROXY_PORT: 3001,
  DATA_DIR: '/tmp/nanoclaw-test-data',
  GROUPS_DIR: '/tmp/nanoclaw-test-groups',
  IDLE_TIMEOUT: 1800000, // 30min
  TIMEZONE: 'America/Los_Angeles',
}));

// Mock logger
vi.mock('./logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock fs
vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs');
  return {
    ...actual,
    default: {
      ...actual,
      existsSync: vi.fn(() => false),
      mkdirSync: vi.fn(),
      writeFileSync: vi.fn(),
      readFileSync: vi.fn(() => ''),
      readdirSync: vi.fn(() => []),
      statSync: vi.fn(() => ({ isDirectory: () => false })),
      copyFileSync: vi.fn(),
      cpSync: vi.fn(),
    },
  };
});

// Mock os (only homedir, which locates the legacy shared Garmin token dir)
vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os');
  return {
    ...actual,
    default: {
      ...actual,
      homedir: vi.fn(() => '/tmp/nanoclaw-test-home'),
    },
  };
});

// Mock mount-security
vi.mock('./mount-security.js', () => ({
  validateAdditionalMounts: vi.fn(() => []),
}));

// Create a controllable fake ChildProcess
function createFakeProcess() {
  const proc = new EventEmitter() as EventEmitter & {
    stdin: PassThrough;
    stdout: PassThrough;
    stderr: PassThrough;
    kill: ReturnType<typeof vi.fn>;
    pid: number;
  };
  proc.stdin = new PassThrough();
  proc.stdout = new PassThrough();
  proc.stderr = new PassThrough();
  proc.kill = vi.fn();
  proc.pid = 12345;
  return proc;
}

let fakeProc: ReturnType<typeof createFakeProcess>;

// Mock child_process.spawn. Also stub execFileSync/execSync: container-runtime.js
// (imported transitively via container-runner.ts) calls execFileSync for
// ensureContainerNetwork()/containerNetworkGateway() as part of hostGatewayArgs().
// Without this stub those would hit the *real* Docker daemon on the host
// running the tests (creating/inspecting an actual "nanoclaw" network) —
// this keeps the test suite hermetic and independent of a local Docker install.
vi.mock('child_process', async () => {
  const actual =
    await vi.importActual<typeof import('child_process')>('child_process');
  return {
    ...actual,
    spawn: vi.fn(() => fakeProc),
    exec: vi.fn(
      (_cmd: string, _opts: unknown, cb?: (err: Error | null) => void) => {
        if (cb) cb(null);
        return new EventEmitter();
      },
    ),
    execFileSync: vi.fn((_bin: string, args: string[] = []) => {
      // Simulate: network already exists, gateway resolves to a fixed IP.
      if (args.includes('--format')) return '172.30.0.1\n';
      return '';
    }),
    execSync: vi.fn(() => ''),
  };
});

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

import { runContainerAgent, ContainerOutput } from './container-runner.js';
import { CONTAINER_NETWORK } from './container-runtime.js';
import type { RegisteredGroup } from './types.js';

const testGroup: RegisteredGroup = {
  name: 'Test Group',
  folder: 'test-group',
  trigger: '@Andy',
  added_at: new Date().toISOString(),
};

const testInput = {
  prompt: 'Hello',
  groupFolder: 'test-group',
  chatJid: 'test@g.us',
  isMain: false,
};

function emitOutputMarker(
  proc: ReturnType<typeof createFakeProcess>,
  output: ContainerOutput,
) {
  const json = JSON.stringify(output);
  proc.stdout.push(`${OUTPUT_START_MARKER}\n${json}\n${OUTPUT_END_MARKER}\n`);
}

describe('container-runner timeout behavior', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    fakeProc = createFakeProcess();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('timeout after output resolves as success', async () => {
    const onOutput = vi.fn(async () => {});
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      onOutput,
    );

    // Emit output with a result
    emitOutputMarker(fakeProc, {
      status: 'success',
      result: 'Here is my response',
      newSessionId: 'session-123',
    });

    // Let output processing settle
    await vi.advanceTimersByTimeAsync(10);

    // Fire the hard timeout (IDLE_TIMEOUT + 30s = 1830000ms)
    await vi.advanceTimersByTimeAsync(1830000);

    // Emit close event (as if container was stopped by the timeout)
    fakeProc.emit('close', 137);

    // Let the promise resolve
    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('success');
    expect(result.newSessionId).toBe('session-123');
    expect(onOutput).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'Here is my response' }),
    );
  });

  it('timeout with no output resolves as error', async () => {
    const onOutput = vi.fn(async () => {});
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      onOutput,
    );

    // No output emitted — fire the hard timeout
    await vi.advanceTimersByTimeAsync(1830000);

    // Emit close event
    fakeProc.emit('close', 137);

    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('error');
    expect(result.error).toContain('timed out');
    expect(onOutput).not.toHaveBeenCalled();
  });

  it('normal exit after output resolves as success', async () => {
    const onOutput = vi.fn(async () => {});
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      onOutput,
    );

    // Emit output
    emitOutputMarker(fakeProc, {
      status: 'success',
      result: 'Done',
      newSessionId: 'session-456',
    });

    await vi.advanceTimersByTimeAsync(10);

    // Normal exit (no timeout)
    fakeProc.emit('close', 0);

    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('success');
    expect(result.newSessionId).toBe('session-456');
  });
});

describe('output callback failure never leaves the run pending', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    fakeProc = createFakeProcess();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // The load-bearing test: before the fix, a rejecting callback poisoned
  // outputChain, the completion path's .then never ran, and this promise
  // never settled (the test failed by timeout).
  it('a rejecting onOutput still settles the run, as an error', async () => {
    const onOutput = vi.fn(async () => {
      throw new Error('setSession exploded');
    });
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      onOutput,
    );

    emitOutputMarker(fakeProc, { status: 'success', result: 'hi' });
    await vi.advanceTimersByTimeAsync(10);
    fakeProc.emit('close', 0);
    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('error');
    expect(result.error).toContain('Output callback failed');
  });

  it('a synchronously-throwing onOutput still settles the run', async () => {
    const onOutput = vi.fn(() => {
      throw new Error('sync boom');
    }) as unknown as (output: ContainerOutput) => Promise<void>;
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      onOutput,
    );

    emitOutputMarker(fakeProc, { status: 'success', result: 'hi' });
    await vi.advanceTimersByTimeAsync(10);
    fakeProc.emit('close', 0);
    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('error');
  });

  it('a callback failing on the first output still delivers the second', async () => {
    const seen: (string | null | undefined)[] = [];
    const onOutput = vi.fn(async (output: ContainerOutput) => {
      seen.push(output.result);
      if (seen.length === 1) throw new Error('first one fails');
    });
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      onOutput,
    );

    emitOutputMarker(fakeProc, { status: 'success', result: 'first' });
    await vi.advanceTimersByTimeAsync(10);
    emitOutputMarker(fakeProc, { status: 'success', result: 'second' });
    await vi.advanceTimersByTimeAsync(10);
    fakeProc.emit('close', 0);
    await vi.advanceTimersByTimeAsync(10);

    await resultPromise;
    expect(onOutput).toHaveBeenCalledTimes(2);
    expect(seen).toEqual(['first', 'second']);
  });

  // The happy path (callback resolves -> status success + newSessionId) is
  // covered by 'normal exit after output resolves as success' above.
});

describe('a stdin write failure does not crash the host', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    fakeProc = createFakeProcess();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // Before the fix, an 'error' event on stdin with no listener would throw,
  // become an uncaughtException, and (per src/logger.ts) exit the process.
  // Vitest fails a test on an unhandled exception, so simply not throwing
  // here — while still resolving via the normal close path — is the
  // assertion that the fix is in place.
  it('an EPIPE-style stdin error is caught and the run still resolves via close', async () => {
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      vi.fn(async () => {}),
    );

    // Simulate the container dying before it drains stdin: the pipe breaks
    // and the Writable emits 'error' (e.g. EPIPE) asynchronously.
    fakeProc.stdin.emit('error', new Error('EPIPE: broken pipe'));
    await vi.advanceTimersByTimeAsync(10);

    // The container's own close handler is what actually resolves the run.
    fakeProc.emit('close', 1);
    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('error');
  });

  it('a synchronous throw from stdin.write is caught and the run still resolves', async () => {
    const writeSpy = vi
      .spyOn(fakeProc.stdin, 'write')
      .mockImplementation(() => {
        throw new Error('write after end');
      });

    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      vi.fn(async () => {}),
    );

    fakeProc.emit('close', 1);
    await vi.advanceTimersByTimeAsync(10);

    const result = await resultPromise;
    expect(result.status).toBe('error');
    writeSpy.mockRestore();
  });
});

describe('container args credential hygiene', () => {
  const CRED_KEYS = ['APPLE_ID', 'APPLE_APP_PASSWORD', 'CALDAV_BASE_URL'];
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    vi.useFakeTimers();
    fakeProc = createFakeProcess();
    for (const key of CRED_KEYS) {
      savedEnv[key] = process.env[key];
    }
    process.env.APPLE_ID = 'fake-apple-id@example.com';
    process.env.APPLE_APP_PASSWORD = 'fake-app-password';
    process.env.CALDAV_BASE_URL = 'https://caldav.example.invalid/';
  });

  afterEach(() => {
    for (const key of CRED_KEYS) {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    }
    vi.useRealTimers();
  });

  it('never passes Apple credentials as -e flags (they go through the proxy)', async () => {
    const resultPromise = runContainerAgent(
      testGroup,
      { ...testInput, enabledMcpServers: ['calendar'] },
      () => {},
      vi.fn(async () => {}),
    );

    emitOutputMarker(fakeProc, { status: 'success', result: 'ok' });
    await vi.advanceTimersByTimeAsync(10);
    fakeProc.emit('close', 0);
    await vi.advanceTimersByTimeAsync(10);
    await resultPromise;

    // spawn's mock accumulates calls across tests in this file — take the
    // last docker run, which is the one this test triggered.
    const dockerRun = vi
      .mocked(spawn)
      .mock.calls.filter(
        (call) => call[0] === 'docker' && (call[1] as string[])[0] === 'run',
      )
      .at(-1);
    expect(dockerRun).toBeDefined();
    const args = dockerRun![1] as string[];
    // Guard against a vacuous pass: env flags are being produced at all.
    expect(args).toContain('-e');
    expect(args.filter((a) => /APPLE_|CALDAV_/.test(a))).toEqual([]);
  });
});

describe('dedicated container network', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    fakeProc = createFakeProcess();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('places the container on the dedicated nanoclaw network', async () => {
    const resultPromise = runContainerAgent(
      testGroup,
      testInput,
      () => {},
      vi.fn(async () => {}),
    );

    emitOutputMarker(fakeProc, { status: 'success', result: 'ok' });
    await vi.advanceTimersByTimeAsync(10);
    fakeProc.emit('close', 0);
    await vi.advanceTimersByTimeAsync(10);
    await resultPromise;

    const dockerRun = vi
      .mocked(spawn)
      .mock.calls.filter(
        (call) => call[0] === 'docker' && (call[1] as string[])[0] === 'run',
      )
      .at(-1);
    expect(dockerRun).toBeDefined();
    const args = dockerRun![1] as string[];
    const networkIdx = args.indexOf('--network');
    expect(networkIdx).toBeGreaterThan(-1);
    expect(args[networkIdx + 1]).toBe(CONTAINER_NETWORK);
    expect(CONTAINER_NETWORK).toBe('nanoclaw');
  });
});

describe('Garmin per-group token directory', () => {
  const legacyDir = path.join('/tmp/nanoclaw-test-home', '.garmin-mcp');
  const groupTokenDir = path.join(
    '/tmp/nanoclaw-test-data',
    'sessions',
    'test-group',
    'garmin-mcp',
  );

  beforeEach(() => {
    vi.useFakeTimers();
    fakeProc = createFakeProcess();
    // Reset to the file's default (nothing exists) before each test so
    // earlier tests in this suite don't leak state into later ones.
    vi.mocked(fs.existsSync).mockImplementation(() => false);
    vi.mocked(fs.mkdirSync).mockReset();
    vi.mocked(fs.cpSync).mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function runAndGetDockerArgs(
    enabledMcpServers?: string[],
  ): Promise<string[]> {
    const resultPromise = runContainerAgent(
      testGroup,
      { ...testInput, enabledMcpServers },
      () => {},
      vi.fn(async () => {}),
    );

    emitOutputMarker(fakeProc, { status: 'success', result: 'ok' });
    await vi.advanceTimersByTimeAsync(10);
    fakeProc.emit('close', 0);
    await vi.advanceTimersByTimeAsync(10);
    await resultPromise;

    const dockerRun = vi
      .mocked(spawn)
      .mock.calls.filter(
        (call) => call[0] === 'docker' && (call[1] as string[])[0] === 'run',
      )
      .at(-1);
    expect(dockerRun).toBeDefined();
    return dockerRun![1] as string[];
  }

  it('garmin enabled and already seeded: mounts the per-group dir, not the shared homedir one', async () => {
    // Simulate a group that was already seeded on a previous run: the
    // per-group dir exists, so no copy from the legacy dir is needed.
    vi.mocked(fs.existsSync).mockImplementation((p) => p === groupTokenDir);

    const args = await runAndGetDockerArgs(['garmin']);

    expect(args).toContain('-v');
    expect(args).toContain(`${groupTokenDir}:/home/node/.garmin-mcp:rw`);
    expect(args.some((a) => a.includes(legacyDir))).toBe(false);
    expect(fs.cpSync).not.toHaveBeenCalled();
  });

  it('garmin enabled, no per-group dir yet, legacy dir present: seeds per-group dir from legacy and mounts it', async () => {
    // Start with only the legacy shared dir existing. Once the code copies
    // it (fs.cpSync), flip the per-group dir to "exists" — mirroring what a
    // real filesystem would do — so the mount-check that follows the copy
    // sees it.
    let groupDirSeeded = false;
    vi.mocked(fs.existsSync).mockImplementation((p) => {
      if (p === groupTokenDir) return groupDirSeeded;
      if (p === legacyDir) return true;
      return false;
    });
    vi.mocked(fs.cpSync).mockImplementation(() => {
      groupDirSeeded = true;
    });

    const args = await runAndGetDockerArgs(['garmin']);

    expect(fs.mkdirSync).toHaveBeenCalledWith(path.dirname(groupTokenDir), {
      recursive: true,
    });
    expect(fs.cpSync).toHaveBeenCalledWith(legacyDir, groupTokenDir, {
      recursive: true,
    });
    expect(args).toContain(`${groupTokenDir}:/home/node/.garmin-mcp:rw`);
    expect(args.some((a) => a.includes(legacyDir))).toBe(false);
  });

  it('garmin not enabled: no garmin-mcp mount at all', async () => {
    const args = await runAndGetDockerArgs(undefined);

    expect(args.some((a) => a.includes('garmin-mcp'))).toBe(false);
    expect(fs.cpSync).not.toHaveBeenCalled();
  });
});
