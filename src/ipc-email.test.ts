/**
 * Tests for the send_email / compose_email IPC branches.
 *
 * The load-bearing property: an email approval waits on a human (up to 10
 * minutes), and the IPC watcher must NOT stall on it — later IPC files from
 * any group must keep flowing while the approval is pending.
 *
 * These tests drive the real watcher loop (startIpcWatcher) over a temp
 * DATA_DIR with fake timers. The watcher can only be started once per module
 * instance, so the tests run sequentially against one watcher.
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
      nodePath.join(os.tmpdir(), 'nanoclaw-ipc-email-'),
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
import { startIpcWatcher, IpcDeps } from './ipc.js';
import { logger } from './logger.js';
import { RegisteredGroup } from './types.js';

const MAIN_JID = 'main@s';
const MAIN_GROUP: RegisteredGroup = {
  name: 'Main',
  folder: 'main',
  trigger: 'always',
  added_at: '2024-01-01T00:00:00.000Z',
  isMain: true,
};
const OTHER_GROUP: RegisteredGroup = {
  name: 'Other',
  folder: 'other-group',
  trigger: '@Andy',
  added_at: '2024-01-01T00:00:00.000Z',
};

interface Deferred {
  resolve: (sent: boolean) => void;
  reject: (err: Error) => void;
}

const emailDeferreds: Deferred[] = [];
const composeDeferreds: Deferred[] = [];

const sendMessage = vi.fn(async () => {});
const sendEmailReply = vi.fn(
  () =>
    new Promise<boolean>((resolve, reject) => {
      emailDeferreds.push({ resolve, reject });
    }),
);
const composeEmail = vi.fn(
  () =>
    new Promise<boolean>((resolve, reject) => {
      composeDeferreds.push({ resolve, reject });
    }),
);

const deps: IpcDeps = {
  sendMessage,
  sendEmailReply,
  composeEmail,
  sendFile: async () => {},
  sendVoice: async () => {},
  registeredGroups: () => ({
    [MAIN_JID]: MAIN_GROUP,
    'other@s': OTHER_GROUP,
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

function messagesDir(groupFolder: string): string {
  return path.join(DATA_DIR, 'ipc', groupFolder, 'messages');
}

/** Run enough poll cycles for pending IPC files to be picked up. */
async function runPolls(): Promise<void> {
  await vi.advanceTimersByTimeAsync(100);
}

beforeAll(() => {
  _initTestDatabase();
  vi.useFakeTimers();
  startIpcWatcher(deps);
  return () => {
    vi.useRealTimers();
  };
});

describe('email approval must not block the IPC watcher', () => {
  it('processes a later message while an email approval is pending', async () => {
    writeIpcFile('main', {
      type: 'send_email',
      threadJid: 'gmail:abc123',
      text: 'reply body',
    });
    await runPolls();
    expect(sendEmailReply).toHaveBeenCalledWith('gmail:abc123', 'reply body');
    // The file's job is done once the approval is started: it must be
    // unlinked, not left claimed as .processing.
    expect(fs.readdirSync(messagesDir('main'))).toEqual([]);

    // Approval still pending (deferred unresolved) — a subsequent message
    // must still go out.
    writeIpcFile('main', {
      type: 'message',
      chatJid: MAIN_JID,
      text: 'later message',
    });
    await runPolls();
    expect(sendMessage).toHaveBeenCalledWith(
      MAIN_JID,
      'later message',
      undefined,
    );
  });

  it('sends ✅ feedback when the pending approval is granted', async () => {
    emailDeferreds[0].resolve(true);
    await runPolls();
    expect(sendMessage).toHaveBeenCalledWith(
      MAIN_JID,
      `✅ Email reply odeslán`,
    );
  });

  it('sends ❌ feedback when the approval is denied', async () => {
    writeIpcFile('main', {
      type: 'send_email',
      threadJid: 'gmail:def456',
      text: 'denied body',
    });
    await runPolls();
    emailDeferreds[1].resolve(false);
    await runPolls();
    expect(sendMessage).toHaveBeenCalledWith(
      MAIN_JID,
      `❌ Email reply zamítnut (nebyl odeslán)`,
    );
  });

  it('logs and survives a rejected approval gate without quarantining', async () => {
    writeIpcFile('main', {
      type: 'send_email',
      threadJid: 'gmail:fee789',
      text: 'will fail',
    });
    await runPolls();
    emailDeferreds[2].reject(new Error('gate exploded'));
    await runPolls();
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ threadJid: 'gmail:fee789' }),
      'IPC send_email failed',
    );
    // The rejection happens after the file was unlinked; it must not try to
    // move anything to the error quarantine.
    expect(fs.existsSync(path.join(DATA_DIR, 'ipc', 'errors'))).toBe(false);
  });

  it('still blocks send_email from a non-main group before any work starts', async () => {
    const callsBefore = sendEmailReply.mock.calls.length;
    writeIpcFile('other-group', {
      type: 'send_email',
      threadJid: 'gmail:aaa111',
      text: 'sneaky',
    });
    await runPolls();
    expect(sendEmailReply.mock.calls.length).toBe(callsBefore);
    expect(logger.warn).toHaveBeenCalledWith(
      { sourceGroup: 'other-group' },
      'Unauthorized send_email attempt blocked',
    );
  });

  it('compose_email is detached the same way and sends its feedback', async () => {
    writeIpcFile('main', {
      type: 'compose_email',
      to: 'someone@example.com',
      subject: 'hi',
      body: 'text',
    });
    await runPolls();
    expect(composeEmail).toHaveBeenCalledWith(
      'someone@example.com',
      'hi',
      'text',
    );

    // Pending compose does not block later messages either.
    writeIpcFile('main', {
      type: 'message',
      chatJid: MAIN_JID,
      text: 'after compose',
    });
    await runPolls();
    expect(sendMessage).toHaveBeenCalledWith(
      MAIN_JID,
      'after compose',
      undefined,
    );

    composeDeferreds[0].resolve(true);
    await runPolls();
    expect(sendMessage).toHaveBeenCalledWith(
      MAIN_JID,
      `✅ Email odeslán na someone@example.com`,
    );
  });
});
