import type { ContainerOutput } from './container-runner.js';

const STALE_MARKER = /No conversation found with session ID/;

/**
 * A streamed result carries the stale-session marker. The SDK was asked to
 * resume a session whose conversation file no longer exists on disk. Checks
 * both `result` and `error` because the SDK reports it either way.
 */
export function isStaleSessionOutput(output: ContainerOutput): boolean {
  return (
    STALE_MARKER.test(output.result ?? '') ||
    STALE_MARKER.test(output.error ?? '')
  );
}

/**
 * The final (non-streamed) output carries the stale-session marker. Only
 * `error` is populated on this path.
 */
export function isStaleSessionError(output: ContainerOutput): boolean {
  return !!output.error && STALE_MARKER.test(output.error);
}

/** Streamed result that is really an API 400 the SDK surfaced as text. */
export function isCorruptedSessionOutput(output: ContainerOutput): boolean {
  return (
    !!output.result &&
    /API Error: 400\b/.test(output.result) &&
    /Could not process/.test(output.result)
  );
}

/** Final output whose error is an API 400 for unprocessable session data. */
export function isCorruptedSessionError(output: ContainerOutput): boolean {
  return (
    !!output.error &&
    /\b400\b/.test(output.error) &&
    /Could not process/.test(output.error)
  );
}

export interface SessionStore {
  /** Persist a session id we successfully used. */
  save(sessionId: string): void;
  /** Forget a session id that turned out to be unusable. */
  clear(): void;
}

export interface RecoveryRunOptions {
  /** The session id to resume on the first attempt, if any. */
  initialSessionId: string | undefined;
  /** Spawns the container. Called once, or twice if the first resume was stale. */
  run: (sessionId: string | undefined) => Promise<ContainerOutput>;
  session: SessionStore;
}

/**
 * Run the agent, recovering once from an unusable (stale or corrupted) session.
 *
 * A stored session id is resumed on the first attempt. If that attempt fails
 * *because* the session is unusable, the id is cleared and the run is retried
 * once from a fresh session, so the user's message is not silently dropped.
 * An id from an unusable session is never persisted.
 */
export async function runWithSessionRecovery(
  opts: RecoveryRunOptions,
): Promise<'success' | 'error'> {
  let attemptSessionId = opts.initialSessionId;
  for (let attempt = 0; attempt < 2; attempt++) {
    const output = await opts.run(attemptSessionId);

    const stale = isStaleSessionError(output);
    const corrupted = isCorruptedSessionError(output);

    // Never persist the id of a session we couldn't actually use.
    if (output.newSessionId && !stale && !corrupted) {
      opts.session.save(output.newSessionId);
    }

    if (output.status === 'error') {
      if (stale || corrupted) {
        opts.session.clear();
        // Retry once from a clean session before giving up.
        if (attempt === 0 && attemptSessionId) {
          attemptSessionId = undefined;
          continue;
        }
      }
      return 'error';
    }

    return 'success';
  }
  return 'error';
}
