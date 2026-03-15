import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock logger
vi.mock('./logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock child_process — store the mock fns so tests can configure them
const mockExecSync = vi.fn();
const mockExecFileSync = vi.fn();
vi.mock('child_process', () => ({
  execSync: (...args: unknown[]) => mockExecSync(...args),
  execFileSync: (...args: unknown[]) => mockExecFileSync(...args),
}));

import {
  CONTAINER_RUNTIME_BIN,
  readonlyMountArgs,
  stopContainerArgs,
  ensureContainerRuntimeRunning,
  cleanupOrphans,
} from './container-runtime.js';
import { logger } from './logger.js';

beforeEach(() => {
  vi.clearAllMocks();
  mockExecFileSync.mockReturnValue('');
});

// --- Pure functions ---

describe('readonlyMountArgs', () => {
  it('returns -v flag with :ro suffix', () => {
    const args = readonlyMountArgs('/host/path', '/container/path');
    expect(args).toEqual(['-v', '/host/path:/container/path:ro']);
  });
});

describe('stopContainerArgs', () => {
  it('returns [binary, stop, name] array without shell interpolation', () => {
    expect(stopContainerArgs('nanoclaw-test-123')).toEqual([
      CONTAINER_RUNTIME_BIN,
      'stop',
      'nanoclaw-test-123',
    ]);
  });

  it('treats shell metacharacters as literal container name parts', () => {
    const name = 'nanoclaw-test; rm -rf /';
    const [bin, cmd, arg] = stopContainerArgs(name);
    expect(bin).toBe(CONTAINER_RUNTIME_BIN);
    expect(cmd).toBe('stop');
    expect(arg).toBe(name); // passed as-is, not interpreted by shell
  });
});

// --- ensureContainerRuntimeRunning ---

describe('ensureContainerRuntimeRunning', () => {
  it('does nothing when runtime is already running', () => {
    mockExecSync.mockReturnValueOnce('');

    ensureContainerRuntimeRunning();

    expect(mockExecSync).toHaveBeenCalledTimes(1);
    expect(mockExecSync).toHaveBeenCalledWith(`${CONTAINER_RUNTIME_BIN} info`, {
      stdio: 'pipe',
      timeout: 10000,
    });
    expect(logger.debug).toHaveBeenCalledWith(
      'Container runtime already running',
    );
  });

  it('throws when docker info fails', () => {
    mockExecSync.mockImplementationOnce(() => {
      throw new Error('Cannot connect to the Docker daemon');
    });

    expect(() => ensureContainerRuntimeRunning()).toThrow(
      'Container runtime is required but failed to start',
    );
    expect(logger.error).toHaveBeenCalled();
  });
});

// --- cleanupOrphans ---

describe('cleanupOrphans', () => {
  it('stops orphaned nanoclaw containers using execFileSync (not shell)', () => {
    mockExecSync.mockReturnValueOnce(
      'nanoclaw-group1-111\nnanoclaw-group2-222\n',
    );

    cleanupOrphans();

    // ps via execSync, 2 stop calls via execFileSync
    expect(mockExecSync).toHaveBeenCalledTimes(1);
    expect(mockExecFileSync).toHaveBeenCalledTimes(2);
    expect(mockExecFileSync).toHaveBeenNthCalledWith(
      1,
      CONTAINER_RUNTIME_BIN,
      ['stop', 'nanoclaw-group1-111'],
      { stdio: 'pipe' },
    );
    expect(mockExecFileSync).toHaveBeenNthCalledWith(
      2,
      CONTAINER_RUNTIME_BIN,
      ['stop', 'nanoclaw-group2-222'],
      { stdio: 'pipe' },
    );
    expect(logger.info).toHaveBeenCalledWith(
      { count: 2, names: ['nanoclaw-group1-111', 'nanoclaw-group2-222'] },
      'Stopped orphaned containers',
    );
  });

  it('does nothing when no orphans exist', () => {
    mockExecSync.mockReturnValueOnce('');

    cleanupOrphans();

    expect(mockExecSync).toHaveBeenCalledTimes(1);
    expect(logger.info).not.toHaveBeenCalled();
  });

  it('warns and continues when ps fails', () => {
    mockExecSync.mockImplementationOnce(() => {
      throw new Error('docker not available');
    });

    cleanupOrphans(); // should not throw

    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ err: expect.any(Error) }),
      'Failed to clean up orphaned containers',
    );
  });

  it('continues stopping remaining containers when one stop fails', () => {
    mockExecSync.mockReturnValueOnce('nanoclaw-a-1\nnanoclaw-b-2\n');
    // First stop fails
    mockExecFileSync.mockImplementationOnce(() => {
      throw new Error('already stopped');
    });
    // Second stop succeeds (default mock returns '')

    cleanupOrphans(); // should not throw

    expect(mockExecFileSync).toHaveBeenCalledTimes(2);
    expect(logger.info).toHaveBeenCalledWith(
      { count: 2, names: ['nanoclaw-a-1', 'nanoclaw-b-2'] },
      'Stopped orphaned containers',
    );
  });
});
