import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { _initTestDatabase, createTask, getTaskById } from './db.js';
import {
  _resetSchedulerLoopForTests,
  buildTaskOpenerText,
  computeNextRun,
  runTask,
  startSchedulerLoop,
} from './task-scheduler.js';
import type { ScheduledTask } from './types.js';

// Mock container-runner so runTask is testable without spawning containers.
vi.mock('./container-runner.js', () => ({
  runContainerAgent: vi.fn(),
  writeTasksSnapshot: vi.fn(),
}));
import { runContainerAgent } from './container-runner.js';
const runContainerAgentMock = vi.mocked(runContainerAgent);

describe('task scheduler', () => {
  beforeEach(() => {
    _initTestDatabase();
    _resetSchedulerLoopForTests();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('pauses due tasks with invalid group folders to prevent retry churn', async () => {
    createTask({
      id: 'task-invalid-folder',
      group_folder: '../../outside',
      chat_jid: 'bad@g.us',
      prompt: 'run',
      schedule_type: 'once',
      schedule_value: '2026-02-22T00:00:00.000Z',
      context_mode: 'isolated',
      next_run: new Date(Date.now() - 60_000).toISOString(),
      status: 'active',
      created_at: '2026-02-22T00:00:00.000Z',
    });

    const enqueueTask = vi.fn(
      (_groupJid: string, _taskId: string, fn: () => Promise<void>) => {
        void fn();
      },
    );

    startSchedulerLoop({
      registeredGroups: () => ({}),
      getSessions: () => ({}),
      queue: { enqueueTask } as any,
      onProcess: () => {},
      sendMessage: async () => {},
    });

    await vi.advanceTimersByTimeAsync(10);

    const task = getTaskById('task-invalid-folder');
    expect(task?.status).toBe('paused');
  });

  it('computeNextRun anchors interval tasks to scheduled time to prevent drift', () => {
    const scheduledTime = new Date(Date.now() - 2000).toISOString(); // 2s ago
    const task = {
      id: 'drift-test',
      group_folder: 'test',
      chat_jid: 'test@g.us',
      prompt: 'test',
      schedule_type: 'interval' as const,
      schedule_value: '60000', // 1 minute
      context_mode: 'isolated' as const,
      next_run: scheduledTime,
      last_run: null,
      last_result: null,
      status: 'active' as const,
      created_at: '2026-01-01T00:00:00.000Z',
    };

    const nextRun = computeNextRun(task);
    expect(nextRun).not.toBeNull();

    // Should be anchored to scheduledTime + 60s, NOT Date.now() + 60s
    const expected = new Date(scheduledTime).getTime() + 60000;
    expect(new Date(nextRun!).getTime()).toBe(expected);
  });

  it('computeNextRun returns null for once-tasks', () => {
    const task = {
      id: 'once-test',
      group_folder: 'test',
      chat_jid: 'test@g.us',
      prompt: 'test',
      schedule_type: 'once' as const,
      schedule_value: '2026-01-01T00:00:00.000Z',
      context_mode: 'isolated' as const,
      next_run: new Date(Date.now() - 1000).toISOString(),
      last_run: null,
      last_result: null,
      status: 'active' as const,
      created_at: '2026-01-01T00:00:00.000Z',
    };

    expect(computeNextRun(task)).toBeNull();
  });

  describe('opener + thread routing', () => {
    const baseGroup = {
      name: 'Tips',
      folder: 'tips',
      trigger: '@Jarmil',
      added_at: '2026-01-01T00:00:00Z',
    };

    function makeTask(overrides: Partial<ScheduledTask> = {}): ScheduledTask {
      return {
        id: 'task-opener-1',
        group_folder: 'tips',
        chat_jid: 'slack:C123',
        prompt: 'Připrav denní souhrn novinek\nA další kroky.',
        schedule_type: 'cron',
        schedule_value: '0 9 * * *',
        context_mode: 'isolated',
        next_run: '2026-05-22T09:00:00.000Z',
        last_run: null,
        last_result: null,
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
        ...overrides,
      };
    }

    function makeDeps(opts: {
      postTaskOpener?: (j: string, t: string) => Promise<string | undefined>;
      onContainer?: (input: unknown) => void;
    }) {
      const sendMessage = vi.fn(async () => {});
      const updateThreadTs = vi.fn();
      const closeStdin = vi.fn();
      const notifyIdle = vi.fn();
      const onProcess = vi.fn();

      runContainerAgentMock.mockImplementation(
        async (_group, input, _onProc, onOutput) => {
          opts.onContainer?.(input);
          if (onOutput) {
            await onOutput({
              status: 'success',
              result: 'final answer for user',
            });
          }
          return {
            status: 'success' as const,
            result: 'final answer for user',
          };
        },
      );

      return {
        sendMessage,
        updateThreadTs,
        closeStdin,
        notifyIdle,
        onProcess,
        deps: {
          registeredGroups: () => ({ 'slack:C123': baseGroup }),
          getSessions: () => ({}),
          queue: {
            updateThreadTs,
            closeStdin,
            notifyIdle,
          } as any,
          onProcess,
          sendMessage,
          postTaskOpener: opts.postTaskOpener,
        },
      };
    }

    it('posts an opener, routes thread_ts to the opener ts, and sends the final result to the main channel', async () => {
      vi.useRealTimers(); // runTask uses real microtasks
      const task = makeTask();
      createTask({
        id: task.id,
        group_folder: task.group_folder,
        chat_jid: task.chat_jid,
        prompt: task.prompt,
        schedule_type: task.schedule_type,
        schedule_value: task.schedule_value,
        context_mode: task.context_mode,
        next_run: task.next_run,
        status: task.status,
        created_at: task.created_at,
      });

      const containerInputs: unknown[] = [];
      const postOpener = vi.fn(
        async (_jid: string, _text: string): Promise<string | undefined> =>
          'TS_1234567890',
      );
      const t = makeDeps({
        postTaskOpener: postOpener,
        onContainer: (input) => containerInputs.push(input),
      });

      await runTask(task, t.deps);

      // 1. Opener was posted to the task's target channel with the expected text shape.
      expect(postOpener).toHaveBeenCalledTimes(1);
      expect(postOpener.mock.calls[0][0]).toBe('slack:C123');
      expect(postOpener.mock.calls[0][1]).toMatch(/Spouštím naplánovaný úkol/);

      // 2. Thread routing was set to the opener's ts.
      expect(t.updateThreadTs).toHaveBeenCalledWith('tips', 'TS_1234567890');

      // 3. Container was started with triggerMessageTs = opener ts.
      const input = containerInputs[0] as { triggerMessageTs?: string };
      expect(input.triggerMessageTs).toBe('TS_1234567890');

      // 4. Final result message was forwarded to the chat (host posts it to main channel; deps.sendMessage receives no thread ts).
      expect(t.sendMessage).toHaveBeenCalledWith(
        'slack:C123',
        'final answer for user',
      );
      // deps.sendMessage's signature is (jid, text) only — no threadTs leakage.
      expect(t.sendMessage.mock.calls[0]).toHaveLength(2);
    });

    it('clears thread_ts when no opener channel is available (prevents progress leaking into stale threads)', async () => {
      vi.useRealTimers();
      const task = makeTask({ id: 'task-no-channel' });
      createTask({
        id: task.id,
        group_folder: task.group_folder,
        chat_jid: task.chat_jid,
        prompt: task.prompt,
        schedule_type: task.schedule_type,
        schedule_value: task.schedule_value,
        context_mode: task.context_mode,
        next_run: task.next_run,
        status: task.status,
        created_at: task.created_at,
      });

      // No postTaskOpener configured at all — e.g. very old caller, or
      // channel returns undefined.
      const t = makeDeps({ postTaskOpener: undefined });

      await runTask(task, t.deps);

      // Stale thread_ts must be cleared so progress doesn't land in the
      // previous interactive thread (the exact bug the user has reported
      // repeatedly).
      expect(t.updateThreadTs).toHaveBeenCalledWith('tips', undefined);
    });

    it('continues without thread routing when postTaskOpener throws', async () => {
      vi.useRealTimers();
      const task = makeTask({ id: 'task-opener-throws' });
      createTask({
        id: task.id,
        group_folder: task.group_folder,
        chat_jid: task.chat_jid,
        prompt: task.prompt,
        schedule_type: task.schedule_type,
        schedule_value: task.schedule_value,
        context_mode: task.context_mode,
        next_run: task.next_run,
        status: task.status,
        created_at: task.created_at,
      });

      const t = makeDeps({
        postTaskOpener: vi.fn(async () => {
          throw new Error('slack api down');
        }),
      });

      await runTask(task, t.deps);

      // Cleared (undefined) — never propagates a stale thread.
      expect(t.updateThreadTs).toHaveBeenCalledWith('tips', undefined);
      // Container still ran.
      expect(runContainerAgentMock).toHaveBeenCalled();
    });
  });

  describe('buildTaskOpenerText', () => {
    it('uses the first non-empty line of the prompt as the headline', () => {
      const text = buildTaskOpenerText({
        id: 't',
        group_folder: 'g',
        chat_jid: 'slack:C1',
        prompt: '\n\nSestav report\nA další\n',
        schedule_type: 'cron',
        schedule_value: '0 9 * * *',
        context_mode: 'isolated',
        next_run: null,
        last_run: null,
        last_result: null,
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
      });
      expect(text).toContain('_Sestav report_');
      expect(text).toContain('cron `0 9 * * *`');
      expect(text).not.toContain('A další');
    });

    it('truncates very long headlines', () => {
      const text = buildTaskOpenerText({
        id: 't',
        group_folder: 'g',
        chat_jid: 'slack:C1',
        prompt: 'x'.repeat(500),
        schedule_type: 'interval',
        schedule_value: '60000',
        context_mode: 'isolated',
        next_run: null,
        last_run: null,
        last_result: null,
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
      });
      expect(text).toContain('…');
      expect(text.length).toBeLessThan(300);
    });
  });

  it('computeNextRun skips missed intervals without infinite loop', () => {
    // Task was due 10 intervals ago (missed)
    const ms = 60000;
    const missedBy = ms * 10;
    const scheduledTime = new Date(Date.now() - missedBy).toISOString();

    const task = {
      id: 'skip-test',
      group_folder: 'test',
      chat_jid: 'test@g.us',
      prompt: 'test',
      schedule_type: 'interval' as const,
      schedule_value: String(ms),
      context_mode: 'isolated' as const,
      next_run: scheduledTime,
      last_run: null,
      last_result: null,
      status: 'active' as const,
      created_at: '2026-01-01T00:00:00.000Z',
    };

    const nextRun = computeNextRun(task);
    expect(nextRun).not.toBeNull();
    // Must be in the future
    expect(new Date(nextRun!).getTime()).toBeGreaterThan(Date.now());
    // Must be aligned to the original schedule grid
    const offset =
      (new Date(nextRun!).getTime() - new Date(scheduledTime).getTime()) % ms;
    expect(offset).toBe(0);
  });
});
