import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ReactionTracker } from './reaction-tracker.js';
import { Channel } from './types.js';

// Mock logger to suppress output
vi.mock('./logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// Mock config to provide REACTION_TRANSITION_DELAY_MS
vi.mock('./config.js', () => ({
  REACTION_TRANSITION_DELAY_MS: 2000,
}));

function makeChannel(overrides: Partial<Channel> = {}): Channel {
  return {
    name: 'test',
    connect: vi.fn().mockResolvedValue(undefined),
    sendMessage: vi.fn().mockResolvedValue(undefined),
    isConnected: vi.fn().mockReturnValue(true),
    ownsJid: vi.fn().mockReturnValue(false),
    disconnect: vi.fn().mockResolvedValue(undefined),
    addReaction: vi.fn().mockResolvedValue(undefined),
    removeReaction: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe('ReactionTracker', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // --- start() ---

  it('start() calls addReaction with eyes', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();

    expect(channel.addReaction).toHaveBeenCalledWith('jid1', 'msg1', 'eyes');
  });

  it('start() does nothing when msgId is undefined', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', undefined);

    await tracker.start();

    expect(channel.addReaction).not.toHaveBeenCalled();
  });

  it('start() transitions from eyes to gear after TRANSITION_DELAY', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();
    expect(channel.addReaction).toHaveBeenCalledTimes(1);
    expect(channel.addReaction).toHaveBeenCalledWith('jid1', 'msg1', 'eyes');

    // Advance past the transition delay
    await vi.advanceTimersByTimeAsync(2100);

    expect(channel.removeReaction).toHaveBeenCalledWith('jid1', 'msg1', 'eyes');
    expect(channel.addReaction).toHaveBeenCalledWith('jid1', 'msg1', 'gear');
  });

  // --- finalize() ---

  it('finalize() before transition: cancels transition, removes eyes, adds final emoji', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();

    // Finalize before the 2s transition fires
    await tracker.finalize('checkmark');

    expect(channel.removeReaction).toHaveBeenCalledWith('jid1', 'msg1', 'eyes');
    expect(channel.addReaction).toHaveBeenCalledWith('jid1', 'msg1', 'checkmark');

    // Advance timers — transition should NOT fire (it was cleared)
    const addReactionCalls = vi.mocked(channel.addReaction!).mock.calls.length;
    await vi.advanceTimersByTimeAsync(3000);
    expect(vi.mocked(channel.addReaction!).mock.calls.length).toBe(addReactionCalls);
  });

  it('finalize() after transition to gear: removes gear, adds final emoji', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();
    // Let transition to gear happen
    await vi.advanceTimersByTimeAsync(2100);

    vi.mocked(channel.removeReaction!).mockClear();
    vi.mocked(channel.addReaction!).mockClear();

    await tracker.finalize('checkmark');

    expect(channel.removeReaction).toHaveBeenCalledWith('jid1', 'msg1', 'gear');
    expect(channel.addReaction).toHaveBeenCalledWith('jid1', 'msg1', 'checkmark');
  });

  it('finalize() is idempotent - second call does nothing', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();
    await tracker.finalize('checkmark');

    // Clear mocks and call again
    vi.mocked(channel.addReaction!).mockClear();
    vi.mocked(channel.removeReaction!).mockClear();

    await tracker.finalize('warning');

    expect(channel.addReaction).not.toHaveBeenCalled();
    expect(channel.removeReaction).not.toHaveBeenCalled();
  });

  it('finalize() does nothing when msgId is undefined', async () => {
    const channel = makeChannel();
    const tracker = new ReactionTracker(channel, 'jid1', undefined);

    await tracker.finalize('checkmark');

    expect(channel.addReaction).not.toHaveBeenCalled();
    expect(channel.removeReaction).not.toHaveBeenCalled();
  });

  // --- Error handling ---

  it('addReaction failure in start() does not throw', async () => {
    const channel = makeChannel({
      addReaction: vi.fn().mockRejectedValue(new Error('network error')),
    });
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    // Should not throw
    await expect(tracker.start()).resolves.toBeUndefined();
  });

  it('addReaction failure in start() prevents transition timer from being set', async () => {
    const channel = makeChannel({
      addReaction: vi.fn().mockRejectedValue(new Error('network error')),
    });
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();
    // After start fails, advancing time should not trigger any further calls
    vi.mocked(channel.addReaction!).mockClear();
    await vi.advanceTimersByTimeAsync(3000);
    // addReaction should not have been called again (no transition scheduled)
    expect(channel.addReaction).not.toHaveBeenCalled();
  });

  it('removeReaction failure during finalize does not prevent final emoji from being added', async () => {
    const channel = makeChannel({
      removeReaction: vi.fn().mockRejectedValue(new Error('remove failed')),
    });
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();
    await tracker.finalize('checkmark');

    // Despite removeReaction failing, addReaction for final emoji should still be called
    expect(channel.addReaction).toHaveBeenCalledWith('jid1', 'msg1', 'checkmark');
  });

  it('addReaction failure during finalize does not throw', async () => {
    const addReaction = vi.fn()
      .mockResolvedValueOnce(undefined) // start() - eyes
      .mockRejectedValueOnce(new Error('add failed')); // finalize() - final emoji

    const channel = makeChannel({ addReaction });
    const tracker = new ReactionTracker(channel, 'jid1', 'msg1');

    await tracker.start();
    await expect(tracker.finalize('checkmark')).resolves.toBeUndefined();
  });
});
