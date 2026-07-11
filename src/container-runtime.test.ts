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
  CONTAINER_NETWORK,
  CONTAINER_RUNTIME_BIN,
  readonlyMountArgs,
  resourceLimitArgs,
  stopContainerArgs,
  ensureContainerRuntimeRunning,
  ensureContainerNetwork,
  containerNetworkGateway,
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

describe('resourceLimitArgs', () => {
  it('emits --memory, --cpus and (on docker) --pids-limit', () => {
    const args = resourceLimitArgs({
      memory: '2g',
      cpus: '2',
      pidsLimit: '512',
    });
    expect(args).toContain('--memory');
    expect(args).toContain('2g');
    expect(args).toContain('--cpus');
    expect(args).toContain('2');
    // Default runtime is docker, which supports --pids-limit.
    expect(CONTAINER_RUNTIME_BIN).toBe('docker');
    expect(args).toContain('--pids-limit');
    expect(args).toContain('512');
  });

  it('omits a limit when its value is empty', () => {
    const args = resourceLimitArgs({ memory: '', cpus: '2', pidsLimit: '' });
    expect(args).not.toContain('--memory');
    expect(args).not.toContain('--pids-limit');
    expect(args).toEqual(['--cpus', '2']);
  });

  it('returns no flags when all limits are empty', () => {
    expect(resourceLimitArgs({})).toEqual([]);
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

// --- ensureContainerNetwork ---

describe('ensureContainerNetwork', () => {
  it('skips creation when the network already exists', () => {
    mockExecFileSync.mockReturnValueOnce(''); // inspect succeeds

    ensureContainerNetwork();

    expect(mockExecFileSync).toHaveBeenCalledTimes(1);
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'docker',
      ['network', 'inspect', CONTAINER_NETWORK],
      { stdio: 'pipe' },
    );
  });

  it('creates the network when inspect fails', () => {
    mockExecFileSync.mockImplementationOnce(() => {
      throw new Error('network not found');
    });
    mockExecFileSync.mockReturnValueOnce(''); // create succeeds

    ensureContainerNetwork();

    expect(mockExecFileSync).toHaveBeenCalledTimes(2);
    expect(mockExecFileSync).toHaveBeenNthCalledWith(
      1,
      'docker',
      ['network', 'inspect', CONTAINER_NETWORK],
      { stdio: 'pipe' },
    );
    expect(mockExecFileSync).toHaveBeenNthCalledWith(
      2,
      'docker',
      ['network', 'create', CONTAINER_NETWORK],
      { stdio: 'pipe' },
    );
    expect(logger.info).toHaveBeenCalledWith(
      { network: CONTAINER_NETWORK },
      'Created dedicated container network',
    );
  });

  it('warns and does not throw when both inspect and create fail', () => {
    mockExecFileSync.mockImplementationOnce(() => {
      throw new Error('network not found');
    });
    mockExecFileSync.mockImplementationOnce(() => {
      throw new Error('permission denied');
    });

    expect(() => ensureContainerNetwork()).not.toThrow();

    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ err: expect.any(Error) }),
      'Failed to create dedicated container network',
    );
  });
});

// --- containerNetworkGateway ---

describe('containerNetworkGateway', () => {
  it('parses the gateway IP from docker network inspect output', () => {
    mockExecFileSync.mockReturnValueOnce('172.20.0.1\n');

    const gateway = containerNetworkGateway();

    expect(gateway).toBe('172.20.0.1');
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'docker',
      [
        'network',
        'inspect',
        CONTAINER_NETWORK,
        '--format',
        '{{(index .IPAM.Config 0).Gateway}}',
      ],
      { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' },
    );
  });

  it('returns undefined and warns when inspect fails', () => {
    mockExecFileSync.mockImplementationOnce(() => {
      throw new Error('docker not available');
    });

    const gateway = containerNetworkGateway();

    expect(gateway).toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ err: expect.any(Error) }),
      'Failed to determine dedicated container network gateway',
    );
  });

  it('returns undefined when the format output is empty', () => {
    mockExecFileSync.mockReturnValueOnce('');

    const gateway = containerNetworkGateway();

    expect(gateway).toBeUndefined();
  });
});
