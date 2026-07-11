/**
 * Tests for edit_message / delete_message ownership: a group may only edit
 * or delete a Slack ts the host actually issued to it. Drives the real
 * watcher loop over a temp DATA_DIR with fake timers, same harness as
 * ipc-email.test.ts (the watcher can only be started once per module
 * instance, so tests run sequentially against one watcher).
 */
import fs from 'fs';
import path from 'path';

import { describe, it, expect, beforeAll, vi } from 'vitest';

vi.mock('./config.js', async () => {
  const actual =
    await vi.importActual<typeof import('./config.js')>('./config.js');
  const os = await import('os');
  const nodePath = await import('path');
  const nodeFs = await import('fs');
  return {
    ...actual,
    DATA_DIR: nodeFs.mkdtempSync(
      nodePath.join(os.tmpdir(), 'nanoclaw-ipc-ownership-'),
    ),
    IPC_POLL_INTERVAL: 20,
  };
});

vi.mock('./logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('./tts.js', () => ({
  synthesizeSpeech: vi.fn(async () => null),
}));

import { DATA_DIR } from './config.js';
import { _initTestDatabase } from './db.js';
import {
  startIpcWatcher,
  IpcDeps,
  _recordIssuedTs,
  _ownsMessageTs,
} from './ipc.js';
import { logger } from './logger.js';
import { RegisteredGroup } from './types.js';

const MAIN_JID = 'main@s';
const A_JID = 'a@s';
const B_JID = 'b@s';
// Groups A and B are both authorized for the SAME channel scenario via their
// own JIDs; the cross-group case posts as A and edits as B in A's channel.
const MAIN_GROUP: RegisteredGroup = {
  name: 'Main',
  folder: 'main',
  trigger: 'always',
  added_at: '2024-01-01T00:00:00.000Z',
  isMain: true,
};
const GROUP_A: RegisteredGroup = {
  name: 'A',
  folder: 'group-a',
  trigger: '@Andy',
  added_at: '2024-01-01T00:00:00.000Z',
};
const GROUP_B: RegisteredGroup = {
  name: 'B',
  folder: 'group-b',
  trigger: '@Andy',
  added_at: '2024-01-01T00:00:00.000Z',
};

let tsCounter = 0;
const sendMessage = vi.fn(async () => {});
const sendMessageWithTs = vi.fn(async () => {
  tsCounter += 1;
  return `170000000${tsCounter}.000100`;
});
const editMessage = vi.fn(async () => {});
const deleteMessage = vi.fn(async () => {});

const deps: IpcDeps = {
  sendMessage,
  sendMessageWithTs,
  editMessage,
  deleteMessage,
  sendFile: async () => {},
  sendVoice: async () => {},
  registeredGroups: () => ({
    [MAIN_JID]: MAIN_GROUP,
    [A_JID]: GROUP_A,
    [B_JID]: GROUP_B,
  }),
  registerGroup: () => {},
  syncGroups: async () => {},
  getAvailableGroups: () => [],
  writeGroupsSnapshot: () => {},
};

let fileCounter = 0;
function writeIpcFile(groupFolder: string, data: unknown): void {
  const dir = path.join(DATA_DIR, 'ipc', groupFolder, 'messages');
  fs.mkdirSync(dir, { recursive: true });
  fileCounter += 1;
  const tmp = path.join(dir, `${fileCounter}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, path.join(dir, `${fileCounter}.json`));
}

async function runPolls(): Promise<void> {
  await vi.advanceTimersByTimeAsync(100);
}

/** Post a message with returnTs as `group` into `chatJid`; returns its ts. */
async function postWithTs(group: string, chatJid: string): Promise<string> {
  const before = sendMessageWithTs.mock.results.length;
  writeIpcFile(group, {
    type: 'message',
    chatJid,
    text: 'status line',
    returnTs: 'true',
    requestId: `req-${fileCounter + 1}`,
  });
  await runPolls();
  const result = sendMessageWithTs.mock.results[before];
  return (await result.value) as string;
}

beforeAll(() => {
  _initTestDatabase();
  vi.useFakeTimers();
  startIpcWatcher(deps);
  return () => {
    vi.useRealTimers();
  };
});

describe('edit/delete message ownership', () => {
  it('a group may edit a message it posted', async () => {
    const ts = await postWithTs('group-a', A_JID);

    writeIpcFile('group-a', {
      type: 'edit_message',
      chatJid: A_JID,
      messageTs: ts,
      text: 'updated status',
    });
    await runPolls();

    expect(editMessage).toHaveBeenCalledWith(A_JID, ts, 'updated status');
  });

  it('a group may NOT edit a ts it never posted', async () => {
    writeIpcFile('group-a', {
      type: 'edit_message',
      chatJid: A_JID,
      messageTs: '1690000000.999999',
      text: 'rewritten answer',
    });
    await runPolls();

    expect(editMessage).not.toHaveBeenCalledWith(
      A_JID,
      '1690000000.999999',
      'rewritten answer',
    );
    expect(logger.warn).toHaveBeenCalledWith(
      { chatJid: A_JID, sourceGroup: 'group-a' },
      'Unauthorized edit_message: group did not post this message',
    );
  });

  it('a group may NOT edit a ts issued to a different group', async () => {
    // Main posts into A's channel (main may target any chatJid) — the ts
    // belongs to main. A is channel-authorized for its own chat but must
    // still be refused, because it never posted that message.
    const ts = await postWithTs('main', A_JID);

    writeIpcFile('group-a', {
      type: 'edit_message',
      chatJid: A_JID,
      messageTs: ts,
      text: 'cross-context rewrite',
    });
    await runPolls();

    expect(editMessage).not.toHaveBeenCalledWith(
      A_JID,
      ts,
      'cross-context rewrite',
    );
  });

  it('a group may delete a message it posted', async () => {
    const ts = await postWithTs('group-b', B_JID);

    writeIpcFile('group-b', {
      type: 'delete_message',
      chatJid: B_JID,
      messageTs: ts,
    });
    await runPolls();

    expect(deleteMessage).toHaveBeenCalledWith(B_JID, ts);
  });

  it('a group may NOT delete a ts it never posted', async () => {
    writeIpcFile('group-b', {
      type: 'delete_message',
      chatJid: B_JID,
      messageTs: '1690000001.888888',
    });
    await runPolls();

    expect(deleteMessage).not.toHaveBeenCalledWith(B_JID, '1690000001.888888');
    expect(logger.warn).toHaveBeenCalledWith(
      { chatJid: B_JID, sourceGroup: 'group-b' },
      'Unauthorized delete_message: group did not post this message',
    );
  });

  it('a group may NOT delete a ts issued to a different group', async () => {
    const ts = await postWithTs('main', B_JID);

    writeIpcFile('group-b', {
      type: 'delete_message',
      chatJid: B_JID,
      messageTs: ts,
    });
    await runPolls();

    expect(deleteMessage).not.toHaveBeenCalledWith(B_JID, ts);
  });

  it('the main group may edit a ts it did not post (explicit admin bypass)', async () => {
    const ts = await postWithTs('group-a', A_JID);

    writeIpcFile('main', {
      type: 'edit_message',
      chatJid: A_JID,
      messageTs: ts,
      text: 'admin correction',
    });
    await runPolls();

    expect(editMessage).toHaveBeenCalledWith(A_JID, ts, 'admin correction');
  });

  it('an announcement ts is owned by the announcing group', async () => {
    const announceDeps = deps as IpcDeps & {
      postAnnouncement?: (
        jid: string,
        text: string,
      ) => Promise<string | undefined>;
    };
    announceDeps.postAnnouncement = vi.fn(async () => '1790000000.000001');

    writeIpcFile('group-a', {
      type: 'announce_start',
      chatJid: A_JID,
      text: 'Zpracovávám…',
      requestId: 'ann-1',
    });
    await runPolls();

    writeIpcFile('group-a', {
      type: 'edit_message',
      chatJid: A_JID,
      messageTs: '1790000000.000001',
      text: 'Hotovo',
    });
    await runPolls();

    expect(editMessage).toHaveBeenCalledWith(
      A_JID,
      '1790000000.000001',
      'Hotovo',
    );
  });
});

describe('issued-ts tracking bound', () => {
  it('evicts the oldest entry beyond the cap instead of growing forever', () => {
    _recordIssuedTs('group-a', 'bound@s', '1000000000.000000');
    expect(_ownsMessageTs('group-a', 'bound@s', '1000000000.000000')).toBe(
      true,
    );

    for (let i = 1; i <= 1000; i++) {
      _recordIssuedTs(
        'group-a',
        'bound@s',
        `100000${String(i).padStart(4, '0')}.000000`,
      );
    }

    // The first entry fell off the back of the bounded map...
    expect(_ownsMessageTs('group-a', 'bound@s', '1000000000.000000')).toBe(
      false,
    );
    // ...while the most recent one is still owned.
    expect(_ownsMessageTs('group-a', 'bound@s', '1000001000.000000')).toBe(
      true,
    );
  });
});
