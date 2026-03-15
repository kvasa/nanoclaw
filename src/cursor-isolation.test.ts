/**
 * Regression tests for cursor isolation in saveState().
 *
 * The bug: saveState() serialized ALL groups' lastAgentTimestamp values into
 * a single JSON blob. If group A saved, then group B saved, then group A
 * rolled back and saved again, group B's cursor would be overwritten.
 *
 * The fix: saveState(chatJid) does a synchronous read-modify-write of only
 * the specified group's entry in the DB JSON blob. These tests exercise the
 * actual _saveState() / _setLastAgentTimestamp() exports from index.ts.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock heavy dependencies that index.ts imports so the module can load
// without starting the actual message loop or connecting to services.
vi.mock('./config.js', () => ({
  ASSISTANT_NAME: 'TestBot',
  DATA_DIR: '/tmp/nanoclaw-test-data',
  DEFAULT_MESSAGE_LIMIT: 100,
  STORE_DIR: '/tmp/nanoclaw-test-store',
  GROUPS_DIR: '/tmp/nanoclaw-test-groups',
  TRIGGER_PATTERN: /TestBot/i,
  CONTAINER_TIMEOUT_MS: 60000,
  REACTION_TRANSITION_DELAY_MS: 2000,
  MAX_CONTAINER_OUTPUT_SIZE: 100000,
  CREDENTIAL_PROXY_PORT: 0,
}));

vi.mock('./logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('./group-folder.js', () => ({
  isValidGroupFolder: () => true,
  resolveGroupFolderPath: () => '/tmp/nanoclaw-test-groups/test',
}));

// Prevent side-effects from channel imports
vi.mock('./channels/index.js', () => ({}));
vi.mock('./ipc.js', () => ({ startIpcWatcher: vi.fn() }));
vi.mock('./task-scheduler.js', () => ({ startSchedulerLoop: vi.fn() }));
vi.mock('./credential-proxy.js', () => ({
  startCredentialProxy: vi.fn(),
  detectAuthMode: () => 'api-key',
}));
vi.mock('./container-runner.js', () => ({
  runContainerAgent: vi.fn(),
}));
vi.mock('./router.js', () => ({
  findChannel: vi.fn(),
  formatMessages: vi.fn(),
  formatOutbound: vi.fn(),
  escapeXml: vi.fn(),
}));
vi.mock('./reaction-tracker.js', () => ({
  ReactionTracker: vi.fn(),
}));
vi.mock('./group-queue.js', () => ({
  GroupQueue: class {
    enqueue = vi.fn();
  },
}));
vi.mock('./sender-allowlist.js', () => ({
  isSenderAllowed: vi.fn().mockReturnValue(true),
  isTriggerAllowed: vi.fn().mockReturnValue(true),
  loadSenderAllowlist: vi.fn(),
}));

import { _initTestDatabase, getRouterState, setRouterState } from './db.js';
import {
  _saveState,
  _setLastAgentTimestamp,
  _getLastAgentTimestamp,
} from './index.js';

beforeEach(() => {
  _initTestDatabase();
});

describe('cursor isolation (per-group saveState)', () => {
  it('saving group A cursor does not affect group B cursor', () => {
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
      }),
    );

    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:05.000Z',
      'groupB@g.us': '2024-01-01T00:00:02.000Z',
    });

    _saveState('groupA@g.us');

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:05.000Z');
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:02.000Z');
  });

  it('rolling back group A cursor does not overwrite group B advanced cursor', () => {
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
      }),
    );

    // Step 1: Group A advances and saves
    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:02.000Z',
    });
    _saveState('groupA@g.us');

    // Step 2: Group B advances and saves
    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:20.000Z',
    });
    _saveState('groupB@g.us');

    // Step 3: Group A rolls back and saves
    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:01.000Z',
      'groupB@g.us': '2024-01-01T00:00:20.000Z',
    });
    _saveState('groupA@g.us');

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:01.000Z');
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:20.000Z');
  });

  it('simulates cross-group clobber that the fix prevents', () => {
    // This test proves the fix works: even when in-memory has a stale view
    // of group B, saving only group A doesn't touch group B in the DB.
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
      }),
    );

    // Group B advances and saves
    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:01.000Z',
      'groupB@g.us': '2024-01-01T00:00:20.000Z',
    });
    _saveState('groupB@g.us');

    // Group A has a stale in-memory view of B (hasn't seen B's advance)
    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:02.000Z', // stale!
    });
    _saveState('groupA@g.us');

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:10.000Z');
    // B must NOT be clobbered back to stale value
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:20.000Z');
  });

  it('per-group save works when DB has no prior last_agent_timestamp', () => {
    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:01.000Z',
    });

    _saveState('groupA@g.us');

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:01.000Z');
  });

  it('per-group save works when DB has corrupted JSON', () => {
    setRouterState('last_agent_timestamp', 'NOT_JSON{{{');

    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:01.000Z',
    });

    _saveState('groupA@g.us');

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:01.000Z');
  });

  it('per-group save preserves cursors for groups not in memory', () => {
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
        'groupC@g.us': '2024-01-01T00:00:03.000Z',
      }),
    );

    _setLastAgentTimestamp({
      'groupA@g.us': '2024-01-01T00:00:05.000Z',
    });

    _saveState('groupA@g.us');

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:05.000Z');
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:02.000Z');
    expect(stored['groupC@g.us']).toBe('2024-01-01T00:00:03.000Z');
  });
});
