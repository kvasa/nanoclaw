/**
 * Regression tests for cursor isolation in saveState().
 *
 * The bug: saveState() serialized ALL groups' lastAgentTimestamp values into
 * a single JSON blob. If group A saved, then group B saved, then group A
 * rolled back and saved again, group B's cursor would be overwritten.
 *
 * The fix: saveState(chatJid) does a synchronous read-modify-write of only
 * the specified group's entry in the DB JSON blob. We replicate that logic
 * here to verify isolation without importing the full index.ts module.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock config and logger to avoid circular dependency issues
vi.mock('./config.js', () => ({
  ASSISTANT_NAME: 'TestBot',
  DATA_DIR: '/tmp/nanoclaw-test-data',
  DEFAULT_MESSAGE_LIMIT: 100,
  STORE_DIR: '/tmp/nanoclaw-test-store',
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
}));

import { _initTestDatabase, getRouterState, setRouterState } from './db.js';

/**
 * Replicates the per-group cursor save logic from saveState(chatJid) in index.ts.
 * This is the fixed version: read DB, patch one key, write back.
 */
function saveGroupCursor(
  chatJid: string,
  lastAgentTimestamp: Record<string, string>,
): void {
  const raw = getRouterState('last_agent_timestamp');
  let stored: Record<string, string> = {};
  try {
    stored = raw ? JSON.parse(raw) : {};
  } catch {
    stored = {};
  }
  stored[chatJid] = lastAgentTimestamp[chatJid] ?? '';
  setRouterState('last_agent_timestamp', JSON.stringify(stored));
}

/**
 * Replicates the OLD buggy saveState() that writes the entire map at once.
 * Used to demonstrate the bug in the "before fix" test case.
 */
function saveAllCursors(lastAgentTimestamp: Record<string, string>): void {
  setRouterState(
    'last_agent_timestamp',
    JSON.stringify(lastAgentTimestamp),
  );
}

beforeEach(() => {
  _initTestDatabase();
});

describe('cursor isolation (per-group saveState)', () => {
  it('saving group A cursor does not affect group B cursor', () => {
    // Both groups have cursors in DB
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
      }),
    );

    // Group A advances its in-memory cursor
    const inMemory: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:05.000Z',
      'groupB@g.us': '2024-01-01T00:00:02.000Z',
    };

    // Save only group A using the fixed per-group logic
    saveGroupCursor('groupA@g.us', inMemory);

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:05.000Z');
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:02.000Z');
  });

  it('rolling back group A cursor does not overwrite group B advanced cursor', () => {
    // Initial: both groups at some cursor
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
      }),
    );

    // Step 1: Group A advances cursor and saves
    const memoryAfterA: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:02.000Z',
    };
    saveGroupCursor('groupA@g.us', memoryAfterA);

    // Step 2: Group B advances cursor and saves
    const memoryAfterB: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:20.000Z',
    };
    saveGroupCursor('groupB@g.us', memoryAfterB);

    // Step 3: Group A errors and rolls back its cursor
    const memoryAfterRollback: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:01.000Z', // rolled back
      'groupB@g.us': '2024-01-01T00:00:20.000Z',
    };
    saveGroupCursor('groupA@g.us', memoryAfterRollback);

    // Verify: A rolled back, B still at its advanced position
    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:01.000Z');
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:20.000Z');
  });

  it('demonstrates the old bug: full-map save causes cross-group cursor clobber', () => {
    // This test demonstrates the bug that existed before the fix.
    // The old saveState() wrote the entire in-memory map, so a stale
    // in-memory snapshot of group B's cursor could overwrite DB.

    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
      }),
    );

    // Group A's in-memory view (before B advances)
    const memoryA: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:02.000Z', // stale!
    };

    // Group B advances in its own async context
    const memoryB: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:10.000Z',
      'groupB@g.us': '2024-01-01T00:00:20.000Z',
    };
    saveAllCursors(memoryB); // B saves its advance

    // Now A saves with its stale view — this clobbers B!
    saveAllCursors(memoryA);

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    // With the old code, B's cursor was clobbered back to the stale value
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:02.000Z'); // BUG: B lost its advance
  });

  it('per-group save works when DB has no prior last_agent_timestamp', () => {
    const memory: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:01.000Z',
    };

    saveGroupCursor('groupA@g.us', memory);

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:01.000Z');
  });

  it('per-group save works when DB has corrupted JSON', () => {
    setRouterState('last_agent_timestamp', 'NOT_JSON{{{');

    const memory: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:01.000Z',
    };

    saveGroupCursor('groupA@g.us', memory);

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:01.000Z');
  });

  it('per-group save preserves cursors for groups not in memory', () => {
    // DB has groups A, B, C
    setRouterState(
      'last_agent_timestamp',
      JSON.stringify({
        'groupA@g.us': '2024-01-01T00:00:01.000Z',
        'groupB@g.us': '2024-01-01T00:00:02.000Z',
        'groupC@g.us': '2024-01-01T00:00:03.000Z',
      }),
    );

    // In-memory only knows about A (e.g., partial load)
    const memory: Record<string, string> = {
      'groupA@g.us': '2024-01-01T00:00:05.000Z',
    };

    saveGroupCursor('groupA@g.us', memory);

    const stored = JSON.parse(getRouterState('last_agent_timestamp')!);
    expect(stored['groupA@g.us']).toBe('2024-01-01T00:00:05.000Z');
    expect(stored['groupB@g.us']).toBe('2024-01-01T00:00:02.000Z');
    expect(stored['groupC@g.us']).toBe('2024-01-01T00:00:03.000Z');
  });
});
