import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  _initTestDatabase,
  createTask,
  deleteTask,
  getAllChats,
  getAllRegisteredGroups,
  getMessagesSince,
  getNewMessages,
  getTaskById,
  logTaskRun,
  ownsIssuedMessageTs,
  pruneOldMessages,
  pruneOldTaskRunLogs,
  recordIssuedMessageTs,
  resolveDrainWindow,
  setRegisteredGroup,
  storeChatMetadata,
  storeMessage,
  updateTask,
} from './db.js';

beforeEach(() => {
  _initTestDatabase();
});

// Helper to store a message using the normalized NewMessage interface
function store(overrides: {
  id: string;
  chat_jid: string;
  sender: string;
  sender_name: string;
  content: string;
  timestamp: string;
  is_from_me?: boolean;
}) {
  storeMessage({
    id: overrides.id,
    chat_jid: overrides.chat_jid,
    sender: overrides.sender,
    sender_name: overrides.sender_name,
    content: overrides.content,
    timestamp: overrides.timestamp,
    is_from_me: overrides.is_from_me ?? false,
  });
}

// --- storeMessage (NewMessage format) ---

describe('storeMessage', () => {
  it('stores a message and retrieves it', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');

    store({
      id: 'msg-1',
      chat_jid: 'group@g.us',
      sender: '123@s.whatsapp.net',
      sender_name: 'Alice',
      content: 'hello world',
      timestamp: '2024-01-01T00:00:01.000Z',
    });

    const messages = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:00.000Z',
      'Andy',
    );
    expect(messages).toHaveLength(1);
    expect(messages[0].id).toBe('msg-1');
    expect(messages[0].sender).toBe('123@s.whatsapp.net');
    expect(messages[0].sender_name).toBe('Alice');
    expect(messages[0].content).toBe('hello world');
  });

  it('filters out empty content', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');

    store({
      id: 'msg-2',
      chat_jid: 'group@g.us',
      sender: '111@s.whatsapp.net',
      sender_name: 'Dave',
      content: '',
      timestamp: '2024-01-01T00:00:04.000Z',
    });

    const messages = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:00.000Z',
      'Andy',
    );
    expect(messages).toHaveLength(0);
  });

  it('stores is_from_me flag', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');

    store({
      id: 'msg-3',
      chat_jid: 'group@g.us',
      sender: 'me@s.whatsapp.net',
      sender_name: 'Me',
      content: 'my message',
      timestamp: '2024-01-01T00:00:05.000Z',
      is_from_me: true,
    });

    // Message is stored (we can retrieve it — is_from_me doesn't affect retrieval)
    const messages = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:00.000Z',
      'Andy',
    );
    expect(messages).toHaveLength(1);
  });

  it('upserts on duplicate id+chat_jid', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');

    store({
      id: 'msg-dup',
      chat_jid: 'group@g.us',
      sender: '123@s.whatsapp.net',
      sender_name: 'Alice',
      content: 'original',
      timestamp: '2024-01-01T00:00:01.000Z',
    });

    store({
      id: 'msg-dup',
      chat_jid: 'group@g.us',
      sender: '123@s.whatsapp.net',
      sender_name: 'Alice',
      content: 'updated',
      timestamp: '2024-01-01T00:00:01.000Z',
    });

    const messages = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:00.000Z',
      'Andy',
    );
    expect(messages).toHaveLength(1);
    expect(messages[0].content).toBe('updated');
  });
});

// --- getMessagesSince ---

describe('getMessagesSince', () => {
  beforeEach(() => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');

    store({
      id: 'm1',
      chat_jid: 'group@g.us',
      sender: 'Alice@s.whatsapp.net',
      sender_name: 'Alice',
      content: 'first',
      timestamp: '2024-01-01T00:00:01.000Z',
    });
    store({
      id: 'm2',
      chat_jid: 'group@g.us',
      sender: 'Bob@s.whatsapp.net',
      sender_name: 'Bob',
      content: 'second',
      timestamp: '2024-01-01T00:00:02.000Z',
    });
    storeMessage({
      id: 'm3',
      chat_jid: 'group@g.us',
      sender: 'Bot@s.whatsapp.net',
      sender_name: 'Bot',
      content: 'bot reply',
      timestamp: '2024-01-01T00:00:03.000Z',
      is_bot_message: true,
    });
    store({
      id: 'm4',
      chat_jid: 'group@g.us',
      sender: 'Carol@s.whatsapp.net',
      sender_name: 'Carol',
      content: 'third',
      timestamp: '2024-01-01T00:00:04.000Z',
    });
  });

  it('returns messages after the given timestamp', () => {
    const msgs = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:02.000Z',
      'Andy',
    );
    // Should exclude m1, m2 (before/at timestamp), m3 (bot message)
    expect(msgs).toHaveLength(1);
    expect(msgs[0].content).toBe('third');
  });

  it('excludes bot messages via is_bot_message flag', () => {
    const msgs = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:00.000Z',
      'Andy',
    );
    const botMsgs = msgs.filter((m) => m.content === 'bot reply');
    expect(botMsgs).toHaveLength(0);
  });

  it('returns all non-bot messages when sinceTimestamp is empty', () => {
    const msgs = getMessagesSince('group@g.us', '', 'Andy');
    // 3 user messages (bot message excluded)
    expect(msgs).toHaveLength(3);
  });

  it('filters pre-migration bot messages via content prefix backstop', () => {
    // Simulate a message written before migration: has prefix but is_bot_message = 0
    store({
      id: 'm5',
      chat_jid: 'group@g.us',
      sender: 'Bot@s.whatsapp.net',
      sender_name: 'Bot',
      content: 'Andy: old bot reply',
      timestamp: '2024-01-01T00:00:05.000Z',
    });
    const msgs = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:04.000Z',
      'Andy',
    );
    expect(msgs).toHaveLength(0);
  });
});

// --- getNewMessages ---

describe('getNewMessages', () => {
  beforeEach(() => {
    storeChatMetadata('group1@g.us', '2024-01-01T00:00:00.000Z');
    storeChatMetadata('group2@g.us', '2024-01-01T00:00:00.000Z');

    store({
      id: 'a1',
      chat_jid: 'group1@g.us',
      sender: 'user@s.whatsapp.net',
      sender_name: 'User',
      content: 'g1 msg1',
      timestamp: '2024-01-01T00:00:01.000Z',
    });
    store({
      id: 'a2',
      chat_jid: 'group2@g.us',
      sender: 'user@s.whatsapp.net',
      sender_name: 'User',
      content: 'g2 msg1',
      timestamp: '2024-01-01T00:00:02.000Z',
    });
    storeMessage({
      id: 'a3',
      chat_jid: 'group1@g.us',
      sender: 'user@s.whatsapp.net',
      sender_name: 'User',
      content: 'bot reply',
      timestamp: '2024-01-01T00:00:03.000Z',
      is_bot_message: true,
    });
    store({
      id: 'a4',
      chat_jid: 'group1@g.us',
      sender: 'user@s.whatsapp.net',
      sender_name: 'User',
      content: 'g1 msg2',
      timestamp: '2024-01-01T00:00:04.000Z',
    });
  });

  it('returns new messages across multiple groups', () => {
    const { messages, newTimestamp } = getNewMessages(
      ['group1@g.us', 'group2@g.us'],
      '2024-01-01T00:00:00.000Z',
      'Andy',
    );
    // Excludes bot message, returns 3 user messages
    expect(messages).toHaveLength(3);
    expect(newTimestamp).toBe('2024-01-01T00:00:04.000Z');
  });

  it('filters by timestamp', () => {
    const { messages } = getNewMessages(
      ['group1@g.us', 'group2@g.us'],
      '2024-01-01T00:00:02.000Z',
      'Andy',
    );
    // Only g1 msg2 (after ts, not bot)
    expect(messages).toHaveLength(1);
    expect(messages[0].content).toBe('g1 msg2');
  });

  it('returns empty for no registered groups', () => {
    const { messages, newTimestamp } = getNewMessages([], '', 'Andy');
    expect(messages).toHaveLength(0);
    expect(newTimestamp).toBe('');
  });

  describe('burst draining (cursor set, backlog exceeds limit)', () => {
    function seedBurst(jid: string, count: number, day: string): void {
      storeChatMetadata(jid, `${day}T00:00:00.000Z`);
      for (let i = 1; i <= count; i++) {
        store({
          id: `b-${String(i).padStart(2, '0')}`,
          chat_jid: jid,
          sender: 'user@s.whatsapp.net',
          sender_name: 'User',
          content: `burst ${i}`,
          timestamp: `${day}T00:00:${String(i).padStart(2, '0')}.000Z`,
        });
      }
    }

    it('drains a burst larger than the limit across polls without losing messages', () => {
      seedBurst('burst@g.us', 15, '2024-02-01');

      const first = getNewMessages(
        ['burst@g.us'],
        '2024-02-01T00:00:00.000Z',
        'Andy',
        10,
      );
      // Oldest 10 first; cursor stops at the last contiguously returned row
      expect(first.messages.map((m) => m.id)).toEqual(
        Array.from(
          { length: 10 },
          (_, i) => `b-${String(i + 1).padStart(2, '0')}`,
        ),
      );
      expect(first.newTimestamp).toBe('2024-02-01T00:00:10.000Z');

      const second = getNewMessages(
        ['burst@g.us'],
        first.newTimestamp,
        'Andy',
        10,
      );
      expect(second.messages.map((m) => m.id)).toEqual(
        Array.from(
          { length: 5 },
          (_, i) => `b-${String(i + 11).padStart(2, '0')}`,
        ),
      );
      expect(second.newTimestamp).toBe('2024-02-01T00:00:15.000Z');

      // Union of both polls covers all 15 ids exactly once
      const allIds = [...first.messages, ...second.messages].map((m) => m.id);
      expect(allIds).toHaveLength(15);
      expect(new Set(allIds).size).toBe(15);
    });

    it('bootstrap (empty cursor) still returns only the newest rows', () => {
      seedBurst('burst@g.us', 15, '2024-02-01');

      const { messages, newTimestamp } = getNewMessages(
        ['burst@g.us'],
        '',
        'Andy',
        10,
      );
      expect(messages).toHaveLength(10);
      // Newest row present, oldest deliberately skipped (no history replay)
      expect(messages.map((m) => m.id)).toContain('b-15');
      expect(messages.map((m) => m.id)).not.toContain('b-01');
      // Chronological order and global-max cursor
      expect(messages[0].id).toBe('b-06');
      expect(newTimestamp).toBe('2024-02-01T00:00:15.000Z');
    });

    it('does not lose or double-process rows sharing the timestamp at the window edge', () => {
      storeChatMetadata('edge@g.us', '2024-03-01T00:00:00.000Z');
      const seed = (id: string, timestamp: string) =>
        store({
          id,
          chat_jid: 'edge@g.us',
          sender: 'user@s.whatsapp.net',
          sender_name: 'User',
          content: `edge ${id}`,
          timestamp,
        });
      seed('e-1', '2024-03-01T00:00:01.000Z');
      seed('e-2', '2024-03-01T00:00:02.000Z');
      // Three rows sharing one timestamp; a limit of 4 cuts inside the group
      seed('e-3a', '2024-03-01T00:00:03.000Z');
      seed('e-3b', '2024-03-01T00:00:03.000Z');
      seed('e-3c', '2024-03-01T00:00:03.000Z');

      const first = getNewMessages(
        ['edge@g.us'],
        '2024-03-01T00:00:00.000Z',
        'Andy',
        4,
      );
      // Boundary group trimmed; cursor held just below the boundary
      expect(first.messages.map((m) => m.id)).toEqual(['e-1', 'e-2']);
      expect(first.newTimestamp).toBe('2024-03-01T00:00:02.000Z');

      const second = getNewMessages(
        ['edge@g.us'],
        first.newTimestamp,
        'Andy',
        4,
      );
      // The complete equal-timestamp group arrives in one piece next poll
      expect(second.messages.map((m) => m.id)).toEqual([
        'e-3a',
        'e-3b',
        'e-3c',
      ]);
      expect(second.newTimestamp).toBe('2024-03-01T00:00:03.000Z');

      const allIds = [...first.messages, ...second.messages].map((m) => m.id);
      expect(allIds).toHaveLength(5);
      expect(new Set(allIds).size).toBe(5);
    });

    it('drain branch still filters bot messages and empty content', () => {
      storeChatMetadata('filter@g.us', '2024-04-01T00:00:00.000Z');
      store({
        id: 'f-1',
        chat_jid: 'filter@g.us',
        sender: 'user@s.whatsapp.net',
        sender_name: 'User',
        content: 'real message 1',
        timestamp: '2024-04-01T00:00:01.000Z',
      });
      storeMessage({
        id: 'f-2',
        chat_jid: 'filter@g.us',
        sender: 'bot@s.whatsapp.net',
        sender_name: 'Andy',
        content: 'bot reply',
        timestamp: '2024-04-01T00:00:02.000Z',
        is_from_me: true,
        is_bot_message: true,
      });
      // Legacy bot message written before the is_bot_message migration:
      // flag unset, caught by the content-prefix backstop
      store({
        id: 'f-3',
        chat_jid: 'filter@g.us',
        sender: 'bot@s.whatsapp.net',
        sender_name: 'Andy',
        content: 'Andy: legacy bot reply',
        timestamp: '2024-04-01T00:00:03.000Z',
      });
      store({
        id: 'f-4',
        chat_jid: 'filter@g.us',
        sender: 'user@s.whatsapp.net',
        sender_name: 'User',
        content: '',
        timestamp: '2024-04-01T00:00:04.000Z',
      });
      store({
        id: 'f-5',
        chat_jid: 'filter@g.us',
        sender: 'user@s.whatsapp.net',
        sender_name: 'User',
        content: 'real message 2',
        timestamp: '2024-04-01T00:00:05.000Z',
      });

      const { messages, newTimestamp } = getNewMessages(
        ['filter@g.us'],
        '2024-04-01T00:00:00.000Z',
        'Andy',
        10,
      );
      expect(messages.map((m) => m.id)).toEqual(['f-1', 'f-5']);
      expect(newTimestamp).toBe('2024-04-01T00:00:05.000Z');
    });
  });
});

// --- resolveDrainWindow (equal-timestamp boundary helper) ---

describe('resolveDrainWindow', () => {
  function row(id: string, timestamp: string) {
    return {
      id,
      chat_jid: 'group@g.us',
      sender: 'user@s.whatsapp.net',
      sender_name: 'User',
      content: `msg ${id}`,
      timestamp,
    };
  }

  it('returns rows unchanged with max timestamp when the window is not full', () => {
    const rows = [
      row('a', '2024-01-01T00:00:01.000Z'),
      row('b', '2024-01-01T00:00:02.000Z'),
    ];
    const result = resolveDrainWindow(rows, 5, '2024-01-01T00:00:00.000Z');
    expect(result.messages).toEqual(rows);
    expect(result.newTimestamp).toBe('2024-01-01T00:00:02.000Z');
  });

  it('returns the fallback cursor for an empty window', () => {
    const result = resolveDrainWindow([], 5, '2024-01-01T00:00:00.000Z');
    expect(result.messages).toEqual([]);
    expect(result.newTimestamp).toBe('2024-01-01T00:00:00.000Z');
  });

  it('keeps a full window intact when the boundary timestamp is unique', () => {
    const rows = [
      row('a', '2024-01-01T00:00:01.000Z'),
      row('b', '2024-01-01T00:00:02.000Z'),
      row('c', '2024-01-01T00:00:03.000Z'),
    ];
    const result = resolveDrainWindow(rows, 3, '2024-01-01T00:00:00.000Z');
    expect(result.messages).toEqual(rows);
    expect(result.newTimestamp).toBe('2024-01-01T00:00:03.000Z');
  });

  it('trims boundary-timestamp rows and holds the cursor below the boundary', () => {
    const rows = [
      row('a', '2024-01-01T00:00:01.000Z'),
      row('b', '2024-01-01T00:00:02.000Z'),
      row('c1', '2024-01-01T00:00:03.000Z'),
      row('c2', '2024-01-01T00:00:03.000Z'),
    ];
    const result = resolveDrainWindow(rows, 4, '2024-01-01T00:00:00.000Z');
    expect(result.messages.map((m) => m.id)).toEqual(['a', 'b']);
    expect(result.newTimestamp).toBe('2024-01-01T00:00:02.000Z');
  });

  it('keeps a degenerate window where every row shares one timestamp', () => {
    const rows = [
      row('a', '2024-01-01T00:00:01.000Z'),
      row('b', '2024-01-01T00:00:01.000Z'),
      row('c', '2024-01-01T00:00:01.000Z'),
    ];
    const result = resolveDrainWindow(rows, 3, '2024-01-01T00:00:00.000Z');
    expect(result.messages).toEqual(rows);
    expect(result.newTimestamp).toBe('2024-01-01T00:00:01.000Z');
  });
});

// --- storeChatMetadata ---

describe('storeChatMetadata', () => {
  it('stores chat with JID as default name', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');
    const chats = getAllChats();
    expect(chats).toHaveLength(1);
    expect(chats[0].jid).toBe('group@g.us');
    expect(chats[0].name).toBe('group@g.us');
  });

  it('stores chat with explicit name', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z', 'My Group');
    const chats = getAllChats();
    expect(chats[0].name).toBe('My Group');
  });

  it('updates name on subsequent call with name', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');
    storeChatMetadata('group@g.us', '2024-01-01T00:00:01.000Z', 'Updated Name');
    const chats = getAllChats();
    expect(chats).toHaveLength(1);
    expect(chats[0].name).toBe('Updated Name');
  });

  it('preserves newer timestamp on conflict', () => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:05.000Z');
    storeChatMetadata('group@g.us', '2024-01-01T00:00:01.000Z');
    const chats = getAllChats();
    expect(chats[0].last_message_time).toBe('2024-01-01T00:00:05.000Z');
  });
});

// --- Task CRUD ---

describe('task CRUD', () => {
  it('creates and retrieves a task', () => {
    createTask({
      id: 'task-1',
      group_folder: 'main',
      chat_jid: 'group@g.us',
      prompt: 'do something',
      schedule_type: 'once',
      schedule_value: '2024-06-01T00:00:00.000Z',
      context_mode: 'isolated',
      next_run: '2024-06-01T00:00:00.000Z',
      status: 'active',
      created_at: '2024-01-01T00:00:00.000Z',
    });

    const task = getTaskById('task-1');
    expect(task).toBeDefined();
    expect(task!.prompt).toBe('do something');
    expect(task!.status).toBe('active');
  });

  it('updates task status', () => {
    createTask({
      id: 'task-2',
      group_folder: 'main',
      chat_jid: 'group@g.us',
      prompt: 'test',
      schedule_type: 'once',
      schedule_value: '2024-06-01T00:00:00.000Z',
      context_mode: 'isolated',
      next_run: null,
      status: 'active',
      created_at: '2024-01-01T00:00:00.000Z',
    });

    updateTask('task-2', { status: 'paused' });
    expect(getTaskById('task-2')!.status).toBe('paused');
  });

  it('deletes a task and its run logs', () => {
    createTask({
      id: 'task-3',
      group_folder: 'main',
      chat_jid: 'group@g.us',
      prompt: 'delete me',
      schedule_type: 'once',
      schedule_value: '2024-06-01T00:00:00.000Z',
      context_mode: 'isolated',
      next_run: null,
      status: 'active',
      created_at: '2024-01-01T00:00:00.000Z',
    });

    deleteTask('task-3');
    expect(getTaskById('task-3')).toBeUndefined();
  });
});

// --- LIMIT behavior ---

describe('message query LIMIT', () => {
  beforeEach(() => {
    storeChatMetadata('group@g.us', '2024-01-01T00:00:00.000Z');

    for (let i = 1; i <= 10; i++) {
      store({
        id: `lim-${i}`,
        chat_jid: 'group@g.us',
        sender: 'user@s.whatsapp.net',
        sender_name: 'User',
        content: `message ${i}`,
        timestamp: `2024-01-01T00:00:${String(i).padStart(2, '0')}.000Z`,
      });
    }
  });

  it('getNewMessages caps to limit and drains oldest-first with a cursor', () => {
    const { messages, newTimestamp } = getNewMessages(
      ['group@g.us'],
      '2024-01-01T00:00:00.000Z',
      'Andy',
      3,
    );
    expect(messages).toHaveLength(3);
    // With a non-empty cursor the OLDEST rows come first so the cursor never
    // advances past unreturned messages.
    expect(messages[0].content).toBe('message 1');
    expect(messages[2].content).toBe('message 3');
    // Chronological order preserved
    expect(messages[1].timestamp > messages[0].timestamp).toBe(true);
    // newTimestamp reflects the last contiguously drained row
    expect(newTimestamp).toBe('2024-01-01T00:00:03.000Z');
  });

  it('getMessagesSince caps to limit and returns most recent in chronological order', () => {
    const messages = getMessagesSince(
      'group@g.us',
      '2024-01-01T00:00:00.000Z',
      'Andy',
      3,
    );
    expect(messages).toHaveLength(3);
    expect(messages[0].content).toBe('message 8');
    expect(messages[2].content).toBe('message 10');
    expect(messages[1].timestamp > messages[0].timestamp).toBe(true);
  });

  it('returns all messages when count is under the limit', () => {
    const { messages } = getNewMessages(
      ['group@g.us'],
      '2024-01-01T00:00:00.000Z',
      'Andy',
      50,
    );
    expect(messages).toHaveLength(10);
  });
});

// --- RegisteredGroup isMain round-trip ---

describe('registered group isMain', () => {
  it('persists isMain=true through set/get round-trip', () => {
    setRegisteredGroup('main@s.whatsapp.net', {
      name: 'Main Chat',
      folder: 'whatsapp_main',
      trigger: '@Andy',
      added_at: '2024-01-01T00:00:00.000Z',
      isMain: true,
    });

    const groups = getAllRegisteredGroups();
    const group = groups['main@s.whatsapp.net'];
    expect(group).toBeDefined();
    expect(group.isMain).toBe(true);
    expect(group.folder).toBe('whatsapp_main');
  });

  it('omits isMain for non-main groups', () => {
    setRegisteredGroup('group@g.us', {
      name: 'Family Chat',
      folder: 'whatsapp_family-chat',
      trigger: '@Andy',
      added_at: '2024-01-01T00:00:00.000Z',
    });

    const groups = getAllRegisteredGroups();
    const group = groups['group@g.us'];
    expect(group).toBeDefined();
    expect(group.isMain).toBeUndefined();
  });
});

// --- retention pruning ---

describe('retention pruning', () => {
  const NOW = new Date('2026-01-01T00:00:00.000Z');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function daysAgoIso(days: number): string {
    return new Date(NOW.getTime() - days * 86_400_000).toISOString();
  }

  function storeAged(id: string, daysAgo: number): void {
    store({
      id,
      chat_jid: 'group@g.us',
      sender: '123@s.whatsapp.net',
      sender_name: 'Alice',
      content: `message ${id}`,
      timestamp: daysAgoIso(daysAgo),
    });
  }

  it('pruneOldMessages deletes rows older than the window and keeps recent ones', () => {
    storeChatMetadata('group@g.us', daysAgoIso(100));
    storeAged('old', 100);
    storeAged('recent', 10);

    const deleted = pruneOldMessages(90);

    expect(deleted).toBe(1);
    const remaining = getMessagesSince('group@g.us', daysAgoIso(365), 'Andy:');
    expect(remaining.map((m) => m.id)).toEqual(['recent']);
  });

  it('pruneOldMessages deletes nothing when everything is recent', () => {
    storeChatMetadata('group@g.us', daysAgoIso(10));
    storeAged('a', 10);
    storeAged('b', 1);

    expect(pruneOldMessages(90)).toBe(0);
    expect(
      getMessagesSince('group@g.us', daysAgoIso(365), 'Andy:').length,
    ).toBe(2);
  });

  it('keeps a message exactly at the cutoff (comparison is strictly older)', () => {
    storeChatMetadata('group@g.us', daysAgoIso(90));
    // With frozen time, this timestamp equals the computed cutoff exactly.
    storeAged('boundary', 90);

    expect(pruneOldMessages(90)).toBe(0);
    expect(
      getMessagesSince('group@g.us', daysAgoIso(365), 'Andy:').length,
    ).toBe(1);
  });

  it('pruning messages leaves chats and scheduled_tasks untouched', () => {
    storeChatMetadata('group@g.us', daysAgoIso(200));
    storeAged('doomed', 200);
    createTask({
      id: 'task-keep',
      group_folder: 'main',
      chat_jid: 'group@g.us',
      prompt: 'survive the prune',
      schedule_type: 'once',
      schedule_value: daysAgoIso(200),
      context_mode: 'isolated',
      next_run: daysAgoIso(200),
      status: 'active',
      created_at: daysAgoIso(200),
    });

    expect(pruneOldMessages(90)).toBe(1);

    expect(getAllChats().some((c) => c.jid === 'group@g.us')).toBe(true);
    expect(getTaskById('task-keep')).toBeDefined();
  });

  it('pruneOldTaskRunLogs deletes old run logs and keeps recent ones', () => {
    createTask({
      id: 'task-logs',
      group_folder: 'main',
      chat_jid: 'group@g.us',
      prompt: 'log some runs',
      schedule_type: 'cron',
      schedule_value: '0 0 * * *',
      context_mode: 'isolated',
      next_run: daysAgoIso(0),
      status: 'active',
      created_at: daysAgoIso(120),
    });
    logTaskRun({
      task_id: 'task-logs',
      run_at: daysAgoIso(100),
      duration_ms: 1000,
      status: 'success',
      result: 'old run',
      error: null,
    });
    logTaskRun({
      task_id: 'task-logs',
      run_at: daysAgoIso(1),
      duration_ms: 1000,
      status: 'success',
      result: 'recent run',
      error: null,
    });

    expect(pruneOldTaskRunLogs(30)).toBe(1);
    // Exactly one row survived: a prune-everything pass finds one row.
    expect(pruneOldTaskRunLogs(0)).toBe(1);
  });
});

describe('issued_message_ts (edit/delete ownership persistence)', () => {
  it('persists ownership through the real table (not an in-process cache)', () => {
    // Unlike the old in-memory Map, this round-trips through SQLite, which
    // in production is the same on-disk file across a host restart — so an
    // ownership row recorded before a restart is still there after.
    recordIssuedMessageTs('chat@g.us', '1700000000.000001', 'group-a');

    expect(
      ownsIssuedMessageTs('chat@g.us', '1700000000.000001', 'group-a'),
    ).toBe(true);
  });

  it('fails closed for an unknown ts', () => {
    expect(
      ownsIssuedMessageTs('chat@g.us', '1700000000.999999', 'group-a'),
    ).toBe(false);
  });

  it('fails closed when the ts belongs to a different group', () => {
    recordIssuedMessageTs('chat@g.us', '1700000000.000002', 'group-a');

    expect(
      ownsIssuedMessageTs('chat@g.us', '1700000000.000002', 'group-b'),
    ).toBe(false);
  });

  it('bounds the table to the newest 1000 rows, evicting the oldest', () => {
    const total = 1005;
    for (let i = 0; i < total; i++) {
      recordIssuedMessageTs(
        'chat@g.us',
        `170000${String(i).padStart(4, '0')}.000000`,
        'group-a',
      );
    }

    let owned = 0;
    for (let i = 0; i < total; i++) {
      if (
        ownsIssuedMessageTs(
          'chat@g.us',
          `170000${String(i).padStart(4, '0')}.000000`,
          'group-a',
        )
      ) {
        owned++;
      }
    }
    // Exactly 1000 of the 1005 inserted rows survived the bound.
    expect(owned).toBe(1000);

    // The oldest 5 of the 1005 inserted rows are gone...
    for (let i = 0; i < 5; i++) {
      expect(
        ownsIssuedMessageTs(
          'chat@g.us',
          `170000${String(i).padStart(4, '0')}.000000`,
          'group-a',
        ),
      ).toBe(false);
    }
    // ...while the most recent one survived.
    expect(
      ownsIssuedMessageTs('chat@g.us', '1700001004.000000', 'group-a'),
    ).toBe(true);
  });
});
