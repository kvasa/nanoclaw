import { describe, it, expect, vi, beforeEach } from 'vitest';

// Baseline: GMAIL_ALLOW_ALL_SENDERS defaults to true here so the many
// pre-existing tests below (about retry/failure/processed-marking behavior,
// unrelated to the allowlist) keep working unmodified. The
// "sender allowlist gating" describe block below exercises the fail-closed
// default explicitly by overriding this via vi.doMock + a fresh dynamic
// import of the module under test.
vi.mock('../config.js', () => ({
  GMAIL_ALLOWED_SENDERS: new Set<string>(),
  GMAIL_ALLOWED_DOMAINS: new Set<string>(),
  GMAIL_ALLOW_ALL_SENDERS: true,
  GMAIL_RATE_LIMIT_GLOBAL: 1000,
  GMAIL_RATE_LIMIT_OUTGOING: 1000,
  GMAIL_RATE_LIMIT_PER_SENDER: 1000,
  GMAIL_RATE_LIMIT_READ_EMAILS: 1000,
  GMAIL_RATE_LIMIT_WINDOW_MS: 3600000,
}));

vi.mock('../logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../db.js', () => ({
  addGmailProcessedId: vi.fn(),
  getRecentGmailProcessedIds: vi.fn(() => []),
  pruneOldGmailProcessedIds: vi.fn(),
}));

import { GmailChannel, GmailChannelOpts } from './gmail.js';
import { addGmailProcessedId } from '../db.js';
import { GMAIL_ALLOWED_SENDERS, GMAIL_ALLOWED_DOMAINS } from '../config.js';
import { RegisteredGroup } from '../types.js';

function makeOpts(overrides?: Partial<GmailChannelOpts>): GmailChannelOpts {
  return {
    onMessage: vi.fn(),
    onChatMetadata: vi.fn(),
    registeredGroups: () => ({}),
    ...overrides,
  };
}

/** Build a fake gmail_v1.Gmail client with mockable users.messages methods. */
function makeFakeGmail() {
  return {
    users: {
      messages: {
        list: vi.fn(),
        get: vi.fn(),
        modify: vi.fn().mockResolvedValue({}),
      },
    },
  };
}

/** Build a minimal but well-formed Gmail "get" response for a text email. */
function makeFakeMessage(opts?: {
  from?: string;
  subject?: string;
  body?: string;
  threadId?: string;
}) {
  const from = opts?.from ?? 'Alice <alice@example.com>';
  const subject = opts?.subject ?? 'Test Subject';
  const body = opts?.body ?? 'Hello world';
  const threadId = opts?.threadId ?? 'thread-1';
  return {
    data: {
      threadId,
      internalDate: `${Date.now()}`,
      payload: {
        headers: [
          { name: 'From', value: from },
          { name: 'Subject', value: subject },
          { name: 'Message-ID', value: '<msgid@example.com>' },
        ],
        mimeType: 'text/plain',
        body: { data: Buffer.from(body).toString('base64') },
      },
    },
  };
}

/** Attach a fake gmail client and inject a registered main group so
 * processMessage() delivers instead of bailing out early. */
function primeChannel(
  channel: GmailChannel,
  fakeGmail: ReturnType<typeof makeFakeGmail>,
) {
  (channel as unknown as { gmail: unknown }).gmail = fakeGmail;
}

function mainGroupOpts(onMessage = vi.fn()): GmailChannelOpts {
  const groups: Record<string, RegisteredGroup> = {
    'main-jid': {
      name: 'main',
      folder: 'main',
      trigger: '',
      added_at: new Date().toISOString(),
      isMain: true,
    },
  };
  return makeOpts({ onMessage, registeredGroups: () => groups });
}

function callPoll(channel: GmailChannel): Promise<void> {
  return (
    channel as unknown as { pollForMessages: () => Promise<void> }
  ).pollForMessages();
}

describe('GmailChannel', () => {
  let channel: GmailChannel;

  beforeEach(() => {
    channel = new GmailChannel(makeOpts());
  });

  describe('ownsJid', () => {
    it('returns true for gmail: prefixed JIDs', () => {
      expect(channel.ownsJid('gmail:abc123')).toBe(true);
      expect(channel.ownsJid('gmail:thread-id-456')).toBe(true);
    });

    it('returns false for non-gmail JIDs', () => {
      expect(channel.ownsJid('12345@g.us')).toBe(false);
      expect(channel.ownsJid('tg:123')).toBe(false);
      expect(channel.ownsJid('dc:456')).toBe(false);
      expect(channel.ownsJid('user@s.whatsapp.net')).toBe(false);
    });
  });

  describe('name', () => {
    it('is gmail', () => {
      expect(channel.name).toBe('gmail');
    });
  });

  describe('isConnected', () => {
    it('returns false before connect', () => {
      expect(channel.isConnected()).toBe(false);
    });
  });

  describe('disconnect', () => {
    it('sets connected to false', async () => {
      await channel.disconnect();
      expect(channel.isConnected()).toBe(false);
    });
  });

  describe('constructor options', () => {
    it('accepts custom poll interval', () => {
      const ch = new GmailChannel(makeOpts(), 30000);
      expect(ch.name).toBe('gmail');
    });

    it('defaults to unread query when no filter configured', () => {
      const ch = new GmailChannel(makeOpts());
      const query = (
        ch as unknown as { buildQuery: () => string }
      ).buildQuery();
      expect(query).toBe('is:unread category:primary');
    });

    it('defaults with no options provided', () => {
      const ch = new GmailChannel(makeOpts());
      expect(ch.name).toBe('gmail');
    });
  });

  describe('pollForMessages processed-marking', () => {
    beforeEach(() => {
      vi.mocked(addGmailProcessedId).mockClear();
    });

    it('does not durably mark a message that fails transiently, and retries it on the next poll', async () => {
      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new GmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: { messages: [{ id: 'msg1' }] },
      });
      fakeGmail.users.messages.get
        .mockRejectedValueOnce(new Error('transient 500'))
        .mockResolvedValueOnce(makeFakeMessage());

      // First poll: fetch fails, message must NOT be durably recorded.
      await callPoll(ch);
      expect(addGmailProcessedId).not.toHaveBeenCalled();
      expect(onMessage).not.toHaveBeenCalled();

      // Second poll: same stub is still returned by list() (still unread),
      // and this time it succeeds — delivered and recorded.
      await callPoll(ch);
      expect(onMessage).toHaveBeenCalledTimes(1);
      expect(addGmailProcessedId).toHaveBeenCalledWith('msg1');
      expect(addGmailProcessedId).toHaveBeenCalledTimes(1);
    });

    it('records the message durably exactly once, after delivery, on the normal success path', async () => {
      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new GmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: { messages: [{ id: 'msg1' }] },
      });
      fakeGmail.users.messages.get.mockResolvedValue(makeFakeMessage());

      await callPoll(ch);

      expect(onMessage).toHaveBeenCalledTimes(1);
      expect(addGmailProcessedId).toHaveBeenCalledTimes(1);
      expect(addGmailProcessedId).toHaveBeenCalledWith('msg1');
      // onMessage must have been invoked before the durable mark, per the
      // "mark only after successful delivery" contract.
      const onMessageOrder = onMessage.mock.invocationCallOrder[0];
      const addGmailOrder =
        vi.mocked(addGmailProcessedId).mock.invocationCallOrder[0];
      expect(onMessageOrder).toBeLessThan(addGmailOrder);
    });

    it('gives up durably after MAX_PROCESS_ATTEMPTS repeated failures', async () => {
      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new GmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: { messages: [{ id: 'msg1' }] },
      });
      fakeGmail.users.messages.get.mockRejectedValue(
        new Error('permanently broken'),
      );

      // Polls 1..3 (MAX_PROCESS_ATTEMPTS): each fails, last one gives up.
      await callPoll(ch);
      await callPoll(ch);
      await callPoll(ch);

      expect(onMessage).not.toHaveBeenCalled();
      expect(addGmailProcessedId).toHaveBeenCalledTimes(1);
      expect(addGmailProcessedId).toHaveBeenCalledWith('msg1');
      expect(fakeGmail.users.messages.get).toHaveBeenCalledTimes(3);

      // A 4th poll must skip it entirely: it's now in processedIds and
      // was never removed, so get() must not be called again for it.
      await callPoll(ch);
      expect(fakeGmail.users.messages.get).toHaveBeenCalledTimes(3);
    });

    it('does not let one bad message block the rest of the batch', async () => {
      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new GmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: {
          messages: [{ id: 'bad-msg' }, { id: 'good-msg' }],
        },
      });
      fakeGmail.users.messages.get.mockImplementation(
        async (req: { id?: string }) => {
          if (req.id === 'bad-msg') throw new Error('boom');
          return makeFakeMessage({ threadId: 'thread-good' });
        },
      );

      await callPoll(ch);

      expect(onMessage).toHaveBeenCalledTimes(1);
      expect(addGmailProcessedId).toHaveBeenCalledTimes(1);
      expect(addGmailProcessedId).toHaveBeenCalledWith('good-msg');
      // bad-msg must not have been recorded (it's retried, not given up on
      // after a single failure).
      expect(addGmailProcessedId).not.toHaveBeenCalledWith('bad-msg');
    });
  });

  describe('sender allowlist gating', () => {
    beforeEach(() => {
      vi.mocked(addGmailProcessedId).mockClear();
      GMAIL_ALLOWED_SENDERS.clear();
      GMAIL_ALLOWED_DOMAINS.clear();
    });

    it('rejects every sender when no allowlist is configured and GMAIL_ALLOW_ALL_SENDERS is unset', async () => {
      // Override the module-level baseline (GMAIL_ALLOW_ALL_SENDERS: true,
      // kept for the unrelated tests above) to exercise the real fail-closed
      // default via a fresh import of the module under test.
      vi.resetModules();
      vi.doMock('../config.js', () => ({
        GMAIL_ALLOWED_SENDERS: new Set<string>(),
        GMAIL_ALLOWED_DOMAINS: new Set<string>(),
        GMAIL_ALLOW_ALL_SENDERS: false,
        GMAIL_RATE_LIMIT_GLOBAL: 1000,
        GMAIL_RATE_LIMIT_OUTGOING: 1000,
        GMAIL_RATE_LIMIT_PER_SENDER: 1000,
        GMAIL_RATE_LIMIT_READ_EMAILS: 1000,
        GMAIL_RATE_LIMIT_WINDOW_MS: 3600000,
      }));

      const { GmailChannel: FreshGmailChannel } = await import('./gmail.js');
      const { addGmailProcessedId: freshAddGmailProcessedId } =
        await import('../db.js');

      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new FreshGmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: { messages: [{ id: 'msg1' }] },
      });
      fakeGmail.users.messages.get.mockResolvedValue(
        makeFakeMessage({ from: 'Mallory <mallory@evil.example>' }),
      );

      await (
        ch as unknown as { pollForMessages: () => Promise<void> }
      ).pollForMessages();

      expect(onMessage).not.toHaveBeenCalled();
      // Rejected messages are still marked read so they don't keep re-appearing.
      expect(fakeGmail.users.messages.modify).toHaveBeenCalledWith({
        userId: 'me',
        id: 'msg1',
        requestBody: { removeLabelIds: ['UNREAD'] },
      });
      // ...but they ARE durably recorded as processed by the poll loop
      // (fail-closed rejection is not a transient failure — no throw).
      expect(freshAddGmailProcessedId).toHaveBeenCalledWith('msg1');
    });

    it('delivers from any sender when GMAIL_ALLOW_ALL_SENDERS is explicitly set (legacy opt-out)', async () => {
      // Uses the module-level baseline mock, which already sets
      // GMAIL_ALLOW_ALL_SENDERS: true.
      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new GmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: { messages: [{ id: 'msg1' }] },
      });
      fakeGmail.users.messages.get.mockResolvedValue(
        makeFakeMessage({ from: 'Mallory <mallory@evil.example>' }),
      );

      await callPoll(ch);

      expect(onMessage).toHaveBeenCalledTimes(1);
    });

    it('with an allowlist configured, delivers an allowed sender and rejects a disallowed one', async () => {
      GMAIL_ALLOWED_SENDERS.add('alice@example.com');

      const onMessage = vi.fn();
      const opts = mainGroupOpts(onMessage);
      const ch = new GmailChannel(opts);
      const fakeGmail = makeFakeGmail();
      primeChannel(ch, fakeGmail);

      fakeGmail.users.messages.list.mockResolvedValue({
        data: { messages: [{ id: 'allowed-msg' }, { id: 'blocked-msg' }] },
      });
      fakeGmail.users.messages.get.mockImplementation(
        async (req: { id?: string }) => {
          if (req.id === 'allowed-msg') {
            return makeFakeMessage({
              from: 'Alice <alice@example.com>',
              threadId: 'thread-allowed',
            });
          }
          return makeFakeMessage({
            from: 'Mallory <mallory@evil.example>',
            threadId: 'thread-blocked',
          });
        },
      );

      await callPoll(ch);

      expect(onMessage).toHaveBeenCalledTimes(1);
      expect(onMessage).toHaveBeenCalledWith(
        'main-jid',
        expect.objectContaining({ sender: 'alice@example.com' }),
      );
    });
  });
});
