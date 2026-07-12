/**
 * Characterization tests for processGroupMessages() — the orchestrator's
 * message-processing core (src/index.ts).
 *
 * These tests pin CURRENT behavior (including any warts) so future refactors
 * have a safety net. They deliberately change no production behavior. An
 * edited characterization test in a future diff is a flag for "behavior
 * change, look closely".
 *
 * Harness copied from src/cursor-isolation.test.ts: heavy dependencies are
 * mocked, but the database is the REAL in-memory SQLite via
 * _initTestDatabase() — message fetching, session deletion, and cursor
 * persistence are exercised against real queries, not mock-theater.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';

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
  IDLE_TIMEOUT: 60000,
  TIMEZONE: 'UTC',
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
  writeTasksSnapshot: vi.fn(),
  writeGroupsSnapshot: vi.fn(),
  writeEmailsSnapshot: vi.fn(),
}));
vi.mock('./router.js', () => ({
  findChannel: vi.fn(),
  formatMessages: vi.fn(),
  formatOutbound: vi.fn(),
  escapeXml: vi.fn(),
}));
vi.mock('./reaction-tracker.js', () => ({
  ReactionTracker: class {
    start = vi.fn().mockResolvedValue(undefined);
    finalize = vi.fn().mockResolvedValue(undefined);
  },
}));
vi.mock('./group-queue.js', () => ({
  GroupQueue: class {
    enqueue = vi.fn();
    closeStdin = vi.fn();
    updateThreadTs = vi.fn();
    sendMessage = vi.fn().mockReturnValue(false);
    enqueueMessageCheck = vi.fn();
    registerProcess = vi.fn();
  },
}));
vi.mock('./sender-allowlist.js', () => ({
  isSenderAllowed: vi.fn().mockReturnValue(true),
  isTriggerAllowed: vi.fn().mockReturnValue(true),
  loadSenderAllowlist: vi.fn(),
  shouldDropMessage: vi.fn().mockReturnValue(false),
}));

import type { ContainerOutput } from './container-runner.js';
import { runContainerAgent } from './container-runner.js';
import {
  _initTestDatabase,
  getSession,
  setSession,
  storeChatMetadata,
  storeMessage,
} from './db.js';
import { findChannel, formatMessages } from './router.js';
import type { RegisteredGroup } from './types.js';
import {
  _getLastAgentTimestamp,
  _processGroupMessages,
  _setLastAgentTimestamp,
  _setRegisteredGroups,
} from './index.js';

const JID = 'group1@g.us';
const FOLDER = 'test-folder';

const T1 = '2024-01-01T00:00:01.000Z';
const T2 = '2024-01-01T00:00:02.000Z';

function makeGroup(overrides: Partial<RegisteredGroup> = {}): RegisteredGroup {
  return {
    name: 'Test Group',
    folder: FOLDER,
    trigger: '@TestBot',
    added_at: '2024-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function seedMessage(
  id: string,
  content: string,
  timestamp: string,
  opts: { is_from_me?: boolean; is_bot_message?: boolean } = {},
): void {
  storeMessage({
    id,
    chat_jid: JID,
    sender: 'user1@s.whatsapp.net',
    sender_name: 'User One',
    content,
    timestamp,
    is_from_me: opts.is_from_me ?? false,
    is_bot_message: opts.is_bot_message ?? false,
  });
}

type ChannelSpies = {
  name: string;
  sendMessage: Mock;
  setTyping: Mock;
  addReaction: Mock;
};

let channel: ChannelSpies;

/** Mock the container agent: streams `outputs` via onOutput, resolves `final`. */
function mockAgentRun(
  outputs: ContainerOutput[],
  final: ContainerOutput,
): void {
  vi.mocked(runContainerAgent).mockImplementation(
    async (_group, _input, _registerProcess, onOutput) => {
      for (const output of outputs) {
        await onOutput?.(output);
      }
      return final;
    },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  _initTestDatabase();
  // messages.chat_jid has a foreign key on chats.jid — seed the chat row.
  storeChatMetadata(
    JID,
    '2024-01-01T00:00:00.000Z',
    'Test Group',
    'test',
    true,
  );
  _setRegisteredGroups({});
  _setLastAgentTimestamp({});

  channel = {
    name: 'test-channel',
    sendMessage: vi.fn().mockResolvedValue(undefined),
    setTyping: vi.fn().mockResolvedValue(undefined),
    addReaction: vi.fn().mockResolvedValue(undefined),
  };
  vi.mocked(findChannel).mockReturnValue(channel as never);
  vi.mocked(formatMessages).mockReturnValue('formatted-prompt');

  // Default agent run: succeeds without streaming any output.
  mockAgentRun([], { status: 'success', result: null });
});

describe('processGroupMessages characterization', () => {
  it('unknown group JID returns true without running the agent', async () => {
    const result = await _processGroupMessages('unknown@g.us');

    expect(result).toBe(true);
    expect(runContainerAgent).not.toHaveBeenCalled();
    expect(channel.sendMessage).not.toHaveBeenCalled();
  });

  it('no channel owning the JID returns true without running the agent', async () => {
    _setRegisteredGroups({ [JID]: makeGroup() });
    seedMessage('m1', 'TestBot hello', T1);
    vi.mocked(findChannel).mockReturnValue(null as never);

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(runContainerAgent).not.toHaveBeenCalled();
  });

  it('no new messages (cursor at latest) returns true without running', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ isMain: true }) });
    seedMessage('m1', 'TestBot hello', T1);
    _setLastAgentTimestamp({ [JID]: T1 });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(runContainerAgent).not.toHaveBeenCalled();
    expect(channel.sendMessage).not.toHaveBeenCalled();
    expect(_getLastAgentTimestamp()[JID]).toBe(T1);
  });

  it('/clear deletes the session, advances the cursor, confirms, and skips the agent', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ isMain: true }) });
    setSession(FOLDER, 'sess-1');
    seedMessage('m1', 'some earlier message', T1);
    seedMessage('m2', '/clear', T2);
    _setLastAgentTimestamp({ [JID]: '' });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(getSession(FOLDER)).toBeUndefined();
    // Cursor advances to the LAST message's timestamp in the batch.
    expect(_getLastAgentTimestamp()[JID]).toBe(T2);
    expect(channel.sendMessage).toHaveBeenCalledWith(JID, 'Context cleared.');
    expect(runContainerAgent).not.toHaveBeenCalled();
  });

  it('non-main group requiring a trigger: no trigger in batch → true, no run, cursor NOT advanced', async () => {
    _setRegisteredGroups({ [JID]: makeGroup() });
    seedMessage('m1', 'just chatting, no mention', T1);
    _setLastAgentTimestamp({ [JID]: '' });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(runContainerAgent).not.toHaveBeenCalled();
    expect(formatMessages).not.toHaveBeenCalled();
    // Returns before the cursor-advance branch.
    expect(_getLastAgentTimestamp()[JID]).toBe('');
  });

  it('non-main group with trigger present runs the agent and advances the cursor', async () => {
    _setRegisteredGroups({ [JID]: makeGroup() });
    seedMessage('m1', 'unrelated chatter', T1);
    seedMessage('m2', 'TestBot please help', T2);
    _setLastAgentTimestamp({ [JID]: '' });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(runContainerAgent).toHaveBeenCalledTimes(1);
    expect(formatMessages).toHaveBeenCalledTimes(1);
    // formatMessages receives the full missed batch and the timezone.
    const [batch, tz] = vi.mocked(formatMessages).mock.calls[0];
    expect(batch.map((m) => m.id)).toEqual(['m1', 'm2']);
    expect(tz).toBe('UTC');
    expect(_getLastAgentTimestamp()[JID]).toBe(T2);
  });

  it('main group runs without any trigger in the batch', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ isMain: true }) });
    seedMessage('m1', 'no mention of the bot here', T1);
    _setLastAgentTimestamp({ [JID]: '' });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(runContainerAgent).toHaveBeenCalledTimes(1);
    expect(_getLastAgentTimestamp()[JID]).toBe(T1);
  });

  it('success path: sends the streamed result, toggles typing, keeps cursor advanced', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ requiresTrigger: false }) });
    seedMessage('m1', 'hi there', T1);
    _setLastAgentTimestamp({ [JID]: '' });
    mockAgentRun([{ status: 'success', result: 'hello', newSessionId: 's1' }], {
      status: 'success',
      result: 'hello',
    });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(channel.sendMessage).toHaveBeenCalledWith(JID, 'hello');
    expect(channel.setTyping.mock.calls).toEqual([
      [JID, true],
      [JID, false],
    ]);
    expect(_getLastAgentTimestamp()[JID]).toBe(T1);
    // The streamed newSessionId is persisted.
    expect(getSession(FOLDER)).toBe('s1');
  });

  it('error before any output: returns false and rolls the cursor back', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ requiresTrigger: false }) });
    seedMessage('m0', 'older message', T1);
    seedMessage('m1', 'new message', T2);
    _setLastAgentTimestamp({ [JID]: T1 });
    mockAgentRun([], { status: 'error', result: null, error: 'boom' });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(false);
    expect(channel.sendMessage).not.toHaveBeenCalled();
    // Rolled back to the pre-call cursor so retries re-process the batch.
    expect(_getLastAgentTimestamp()[JID]).toBe(T1);
  });

  it('error AFTER output was sent: returns true and does NOT roll back (duplicate suppression)', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ requiresTrigger: false }) });
    seedMessage('m0', 'older message', T1);
    seedMessage('m1', 'new message', T2);
    _setLastAgentTimestamp({ [JID]: T1 });
    mockAgentRun([{ status: 'success', result: 'partial' }], {
      status: 'error',
      result: null,
      error: 'boom',
    });

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(channel.sendMessage).toHaveBeenCalledWith(JID, 'partial');
    // Cursor stays advanced — re-processing would send duplicates.
    expect(_getLastAgentTimestamp()[JID]).toBe(T2);
  });

  it('strips <internal> blocks from streamed output before sending', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ requiresTrigger: false }) });
    seedMessage('m1', 'hi', T1);
    _setLastAgentTimestamp({ [JID]: '' });
    mockAgentRun(
      [
        {
          status: 'success',
          result: '<internal>reasoning</internal>visible',
        },
      ],
      { status: 'success', result: null },
    );

    const result = await _processGroupMessages(JID);

    expect(result).toBe(true);
    expect(channel.sendMessage).toHaveBeenCalledWith(JID, 'visible');
  });

  it('output that is ONLY an <internal> block sends nothing and does not count as output sent', async () => {
    _setRegisteredGroups({ [JID]: makeGroup({ requiresTrigger: false }) });
    seedMessage('m0', 'older message', T1);
    seedMessage('m1', 'new message', T2);
    _setLastAgentTimestamp({ [JID]: T1 });
    // Internal-only stream, then an error: since nothing visible reached the
    // user, outputSentToUser stays false and the cursor MUST roll back.
    mockAgentRun(
      [{ status: 'success', result: '<internal>reasoning</internal>  ' }],
      { status: 'error', result: null, error: 'boom' },
    );

    const result = await _processGroupMessages(JID);

    expect(result).toBe(false);
    expect(channel.sendMessage).not.toHaveBeenCalled();
    expect(_getLastAgentTimestamp()[JID]).toBe(T1);
  });
});
