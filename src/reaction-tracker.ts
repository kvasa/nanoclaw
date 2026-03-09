import { REACTION_TRANSITION_DELAY_MS } from './config.js';
import { logger } from './logger.js';
import { Channel } from './types.js';

/**
 * Manages the reaction emoji lifecycle for a message being processed.
 * Progression: eyes → gear → final (checkmark or warning).
 *
 * Encapsulates the mutable state and timer logic that was previously
 * spread across multiple closure variables in processGroupMessages.
 */
export class ReactionTracker {
  private currentEmoji: string | null = null;
  private transitionTimer: ReturnType<typeof setTimeout> | null = null;
  private finalized = false;

  constructor(
    private channel: Channel,
    private jid: string,
    private msgId: string | undefined,
  ) {}

  /** Add 'eyes' reaction and schedule transition to 'gear'. */
  async start(): Promise<void> {
    if (!this.msgId) return;

    try {
      await this.channel.addReaction?.(this.jid, this.msgId, 'eyes');
      this.currentEmoji = 'eyes';
    } catch (err) {
      logger.debug({ err, jid: this.jid }, 'Failed to add eyes reaction');
      return;
    }

    this.transitionTimer = setTimeout(async () => {
      if (this.currentEmoji !== 'eyes') return; // already finalized
      try {
        await this.channel.removeReaction?.(this.jid, this.msgId!, 'eyes');
      } catch (err) {
        logger.debug({ err, jid: this.jid }, 'Failed to remove eyes reaction');
      }
      if (this.currentEmoji !== 'eyes') return; // finalized while removing
      this.currentEmoji = 'gear';
      try {
        await this.channel.addReaction?.(this.jid, this.msgId!, 'gear');
      } catch (err) {
        logger.debug({ err, jid: this.jid }, 'Failed to add gear reaction');
      }
    }, REACTION_TRANSITION_DELAY_MS);
  }

  /** Remove current emoji and set the final one. Idempotent. */
  async finalize(emoji: string): Promise<void> {
    if (!this.msgId || this.finalized) return;
    this.finalized = true;

    if (this.transitionTimer) clearTimeout(this.transitionTimer);
    const removing = this.currentEmoji;
    this.currentEmoji = null; // signal to timer callback to bail out

    if (removing) {
      try {
        await this.channel.removeReaction?.(this.jid, this.msgId, removing);
      } catch (err) {
        logger.debug(
          { err, jid: this.jid },
          'Failed to remove reaction during finalize',
        );
      }
    }
    try {
      await this.channel.addReaction?.(this.jid, this.msgId, emoji);
    } catch (err) {
      logger.debug(
        { err, jid: this.jid, emoji },
        'Failed to add final reaction',
      );
    }
  }
}
