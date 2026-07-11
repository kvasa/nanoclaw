import { describe, it, expect, vi } from 'vitest';

import type { ContainerOutput } from './container-runner.js';
import {
  isStaleSessionOutput,
  isStaleSessionError,
  isCorruptedSessionOutput,
  isCorruptedSessionError,
  runWithSessionRecovery,
  SessionStore,
} from './session-recovery.js';

const STALE_MSG = 'No conversation found with session ID abc-123';

function output(partial: Partial<ContainerOutput>): ContainerOutput {
  return { status: 'success', result: null, ...partial };
}

describe('session detection predicates', () => {
  it('isStaleSessionOutput matches the marker in result', () => {
    expect(isStaleSessionOutput(output({ result: STALE_MSG }))).toBe(true);
  });

  it('isStaleSessionOutput matches the marker in error', () => {
    expect(
      isStaleSessionOutput(output({ status: 'error', error: STALE_MSG })),
    ).toBe(true);
  });

  it('isStaleSessionError matches error only — not result (deliberate asymmetry)', () => {
    expect(
      isStaleSessionError(output({ status: 'error', error: STALE_MSG })),
    ).toBe(true);
    expect(isStaleSessionError(output({ result: STALE_MSG }))).toBe(false);
  });

  it('isCorruptedSessionOutput requires both API Error: 400 and Could not process', () => {
    expect(
      isCorruptedSessionOutput(
        output({ result: 'API Error: 400 Could not process image data' }),
      ),
    ).toBe(true);
    expect(
      isCorruptedSessionOutput(output({ result: 'API Error: 400 bad input' })),
    ).toBe(false);
    expect(
      isCorruptedSessionOutput(output({ result: 'Could not process image' })),
    ).toBe(false);
  });

  it('isCorruptedSessionError matches 400 plus Could not process in error', () => {
    expect(
      isCorruptedSessionError(
        output({ status: 'error', error: 'status 400: Could not process' }),
      ),
    ).toBe(true);
    expect(
      isCorruptedSessionError(output({ status: 'error', error: 'status 400' })),
    ).toBe(false);
  });

  it('all predicates are false for an ordinary successful output', () => {
    const ok = output({ result: 'All done!', newSessionId: 'new-1' });
    expect(isStaleSessionOutput(ok)).toBe(false);
    expect(isStaleSessionError(ok)).toBe(false);
    expect(isCorruptedSessionOutput(ok)).toBe(false);
    expect(isCorruptedSessionError(ok)).toBe(false);
  });
});

describe('runWithSessionRecovery', () => {
  function makeSession() {
    return {
      save: vi.fn<SessionStore['save']>(),
      clear: vi.fn<SessionStore['clear']>(),
    };
  }

  function scriptedRun(outputs: ContainerOutput[]) {
    let call = 0;
    return vi.fn(async (_sessionId: string | undefined) => {
      const next = outputs[call];
      call++;
      if (!next) throw new Error('run called more times than scripted');
      return next;
    });
  }

  it('happy path: fresh success saves the new id and returns success', async () => {
    const session = makeSession();
    const run = scriptedRun([output({ result: 'ok', newSessionId: 'sess-1' })]);

    const result = await runWithSessionRecovery({
      initialSessionId: 'stored-id',
      run,
      session,
    });

    expect(result).toBe('success');
    expect(run).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledWith('stored-id');
    expect(session.save).toHaveBeenCalledExactlyOnceWith('sess-1');
    expect(session.clear).not.toHaveBeenCalled();
  });

  it('stale session: clears, retries once without an id, succeeds', async () => {
    const session = makeSession();
    const run = scriptedRun([
      output({ status: 'error', error: STALE_MSG }),
      output({ result: 'ok', newSessionId: 'fresh-id' }),
    ]);

    const result = await runWithSessionRecovery({
      initialSessionId: 'stale-id',
      run,
      session,
    });

    expect(result).toBe('success');
    expect(run).toHaveBeenCalledTimes(2);
    expect(run).toHaveBeenNthCalledWith(2, undefined);
    expect(session.clear).toHaveBeenCalledTimes(1);
    expect(session.save).toHaveBeenCalledExactlyOnceWith('fresh-id');
  });

  it('stale session: retry also fails — gives up with error', async () => {
    const session = makeSession();
    const run = scriptedRun([
      output({ status: 'error', error: STALE_MSG }),
      output({ status: 'error', error: 'Container exited with code 1' }),
    ]);

    const result = await runWithSessionRecovery({
      initialSessionId: 'stale-id',
      run,
      session,
    });

    expect(result).toBe('error');
    expect(run).toHaveBeenCalledTimes(2);
    expect(session.save).not.toHaveBeenCalled();
  });

  it('stale error with no initial session id: no pointless retry', async () => {
    const session = makeSession();
    const run = scriptedRun([output({ status: 'error', error: STALE_MSG })]);

    const result = await runWithSessionRecovery({
      initialSessionId: undefined,
      run,
      session,
    });

    expect(result).toBe('error');
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('corrupted session: clears, retries once, succeeds', async () => {
    const session = makeSession();
    const run = scriptedRun([
      output({
        status: 'error',
        error: 'API Error: 400 Could not process image',
      }),
      output({ result: 'ok', newSessionId: 'fresh-id' }),
    ]);

    const result = await runWithSessionRecovery({
      initialSessionId: 'corrupt-id',
      run,
      session,
    });

    expect(result).toBe('success');
    expect(run).toHaveBeenCalledTimes(2);
    expect(run).toHaveBeenNthCalledWith(2, undefined);
    expect(session.clear).toHaveBeenCalledTimes(1);
    expect(session.save).toHaveBeenCalledExactlyOnceWith('fresh-id');
  });

  it('never persists the id of an unusable session', async () => {
    const session = makeSession();
    const run = scriptedRun([
      output({ status: 'error', error: STALE_MSG, newSessionId: 'bad-id' }),
      output({ status: 'error', error: STALE_MSG, newSessionId: 'bad-id-2' }),
    ]);

    await runWithSessionRecovery({
      initialSessionId: 'stale-id',
      run,
      session,
    });

    expect(session.save).not.toHaveBeenCalled();
  });

  it('ordinary error: no retry, no session mutation', async () => {
    const session = makeSession();
    const run = scriptedRun([
      output({ status: 'error', error: 'Container exited with code 1' }),
    ]);

    const result = await runWithSessionRecovery({
      initialSessionId: 'stored-id',
      run,
      session,
    });

    expect(result).toBe('error');
    expect(run).toHaveBeenCalledTimes(1);
    expect(session.save).not.toHaveBeenCalled();
    expect(session.clear).not.toHaveBeenCalled();
  });
});
