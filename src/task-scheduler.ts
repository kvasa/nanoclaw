import { ChildProcess } from 'child_process';
import { CronExpressionParser } from 'cron-parser';
import fs from 'fs';

import {
  ASSISTANT_NAME,
  MESSAGE_RETENTION_DAYS,
  SCHEDULER_POLL_INTERVAL,
  TASK_CLOSE_DELAY_MS,
  TASK_LOG_RETENTION_DAYS,
  TIMEZONE,
} from './config.js';
import {
  ContainerOutput,
  runContainerAgent,
  writeTasksSnapshot,
} from './container-runner.js';
import {
  getAllTasks,
  getDueTasks,
  getTaskById,
  logTaskRun,
  pruneOldMessages,
  pruneOldTaskRunLogs,
  updateTask,
  updateTaskAfterRun,
} from './db.js';
import { GroupQueue } from './group-queue.js';
import { resolveGroupFolderPath } from './group-folder.js';
import { logger } from './logger.js';
import { RegisteredGroup, ScheduledTask } from './types.js';

/**
 * Compute the next run time for a recurring task, anchored to the
 * task's scheduled time rather than Date.now() to prevent cumulative
 * drift on interval-based tasks.
 *
 * Co-authored-by: @community-pr-601
 */
export function computeNextRun(task: ScheduledTask): string | null {
  if (task.schedule_type === 'once') return null;

  const now = Date.now();

  if (task.schedule_type === 'cron') {
    try {
      const interval = CronExpressionParser.parse(task.schedule_value, {
        tz: TIMEZONE,
      });
      return interval.next().toISOString();
    } catch (err) {
      logger.error(
        { taskId: task.id, value: task.schedule_value, err },
        'Invalid cron expression',
      );
      return null;
    }
  }

  if (task.schedule_type === 'interval') {
    const ms = parseInt(task.schedule_value, 10);
    if (!ms || ms <= 0) {
      // Guard against malformed interval that would cause an infinite loop
      logger.warn(
        { taskId: task.id, value: task.schedule_value },
        'Invalid interval value',
      );
      return new Date(now + 60_000).toISOString();
    }
    // Anchor to the scheduled time, not now, to prevent drift.
    // Skip past any missed intervals so we always land in the future.
    const base = new Date(task.next_run ?? 0).getTime();
    if (task.next_run == null || Number.isNaN(base)) {
      logger.warn(
        { taskId: task.id, nextRun: task.next_run },
        'Invalid next_run anchor for interval task',
      );
      return new Date(now + 60_000).toISOString();
    }
    let next = base + ms;
    if (next <= now) {
      next = base + ms * (Math.floor((now - base) / ms) + 1);
    }
    return new Date(next).toISOString();
  }

  return null;
}

export interface SchedulerDependencies {
  registeredGroups: () => Record<string, RegisteredGroup>;
  getSessions: () => Record<string, string>;
  queue: GroupQueue;
  onProcess: (
    groupJid: string,
    proc: ChildProcess,
    containerName: string,
    groupFolder: string,
  ) => void;
  sendMessage: (jid: string, text: string) => Promise<void>;
  /**
   * Post an opener message to the target channel and return its message ts
   * (used as the thread root for progress updates). For channels that don't
   * support threading (WhatsApp/Telegram/etc.), this should still post the
   * message but may return undefined.
   *
   * When undefined is returned the scheduler still clears any stale thread_ts
   * so progress updates don't land in an unrelated thread.
   */
  postTaskOpener?: (jid: string, text: string) => Promise<string | undefined>;
}

function summarizeTaskPrompt(prompt: string): string {
  // Strip leading whitespace and take the first non-empty line as the headline.
  const lines = prompt
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  const head = lines[0] || prompt.trim();
  const max = 140;
  return head.length > max ? head.slice(0, max) + '…' : head;
}

export function buildTaskOpenerText(task: ScheduledTask): string {
  const headline = summarizeTaskPrompt(task.prompt);
  const schedule =
    task.schedule_type === 'cron'
      ? `cron \`${task.schedule_value}\``
      : task.schedule_type === 'interval'
        ? `každých ${task.schedule_value}ms`
        : 'jednorázový';
  return `🤖 Spouštím naplánovaný úkol _${headline}_ (${schedule})\n_Průběžné kroky pošlu do vlákna této zprávy. Výsledek přijde sem do kanálu._`;
}

export async function runTask(
  task: ScheduledTask,
  deps: SchedulerDependencies,
): Promise<void> {
  const startTime = Date.now();
  let groupDir: string;
  try {
    groupDir = resolveGroupFolderPath(task.group_folder);
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    // Stop retry churn for malformed legacy rows.
    updateTask(task.id, { status: 'paused' });
    logger.error(
      { taskId: task.id, groupFolder: task.group_folder, error },
      'Task has invalid group folder',
    );
    logTaskRun({
      task_id: task.id,
      run_at: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      status: 'error',
      result: null,
      error,
    });
    return;
  }
  fs.mkdirSync(groupDir, { recursive: true });

  logger.info(
    { taskId: task.id, group: task.group_folder },
    'Running scheduled task',
  );

  const groups = deps.registeredGroups();
  const group = Object.values(groups).find(
    (g) => g.folder === task.group_folder,
  );

  if (!group) {
    logger.error(
      { taskId: task.id, groupFolder: task.group_folder },
      'Group not found for task',
    );
    logTaskRun({
      task_id: task.id,
      run_at: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
      status: 'error',
      result: null,
      error: `Group not found: ${task.group_folder}`,
    });
    return;
  }

  // Update tasks snapshot for container to read (filtered by group)
  const isMain = group.isMain === true;
  const tasks = getAllTasks();
  writeTasksSnapshot(
    task.group_folder,
    isMain,
    tasks.map((t) => ({
      id: t.id,
      groupFolder: t.group_folder,
      prompt: t.prompt,
      schedule_type: t.schedule_type,
      schedule_value: t.schedule_value,
      status: t.status,
      next_run: t.next_run,
    })),
  );

  let result: string | null = null;
  let error: string | null = null;

  // For group context mode, use the group's current session
  const sessions = deps.getSessions();
  const sessionId =
    task.context_mode === 'group' ? sessions[task.group_folder] : undefined;

  // Post a fresh opener to the target channel BEFORE the container starts.
  // Progress updates from the container route into this message's thread.
  // The final result (sent via deps.sendMessage below) lands in the main
  // channel, not the thread. This pattern was previously DIY-implemented in
  // task prompts via shell hacks on /workspace/ipc/thread_ts.
  let openerTs: string | undefined;
  if (deps.postTaskOpener && !task.suppress_opener) {
    try {
      openerTs = await deps.postTaskOpener(
        task.chat_jid,
        buildTaskOpenerText(task),
      );
    } catch (err) {
      logger.warn(
        { taskId: task.id, err },
        'Failed to post task opener, continuing without thread',
      );
    }
  }
  // Always overwrite/clear thread_ts so progress doesn't leak into a stale
  // interactive thread from a previous session.
  deps.queue.updateThreadTs(task.group_folder, openerTs);

  // After the task produces a result, close the container promptly.
  // Tasks are single-turn — no need to wait IDLE_TIMEOUT (30 min) for the
  // query loop to time out. A short delay handles any final MCP calls.
  // Use configured delay from config.ts
  let closeTimer: ReturnType<typeof setTimeout> | null = null;

  const scheduleClose = () => {
    if (closeTimer) return; // already scheduled
    closeTimer = setTimeout(() => {
      logger.debug({ taskId: task.id }, 'Closing task container after result');
      deps.queue.closeStdin(task.chat_jid);
    }, TASK_CLOSE_DELAY_MS);
  };

  try {
    const output = await runContainerAgent(
      group,
      {
        prompt: task.prompt,
        sessionId,
        groupFolder: task.group_folder,
        chatJid: task.chat_jid,
        isMain,
        isScheduledTask: true,
        assistantName: ASSISTANT_NAME,
        enabledMcpServers: group.containerConfig?.enabledMcpServers,
        triggerMessageTs: openerTs,
      },
      (proc, containerName) =>
        deps.onProcess(task.chat_jid, proc, containerName, task.group_folder),
      async (streamedOutput: ContainerOutput) => {
        if (streamedOutput.result) {
          result = streamedOutput.result;
          // Forward result to user (sendMessage handles formatting)
          await deps.sendMessage(task.chat_jid, streamedOutput.result);
          scheduleClose();
        }
        if (streamedOutput.status === 'success') {
          deps.queue.notifyIdle(task.chat_jid);
          scheduleClose(); // Close promptly even when result is null (e.g. IPC-only tasks)
        }
        if (streamedOutput.status === 'error') {
          error = streamedOutput.error || 'Unknown error';
        }
      },
    );

    if (closeTimer) clearTimeout(closeTimer);

    if (output.status === 'error') {
      error = output.error || 'Unknown error';
    } else if (output.result) {
      // Result was already forwarded to the user via the streaming callback above
      result = output.result;
    }

    logger.info(
      { taskId: task.id, durationMs: Date.now() - startTime },
      'Task completed',
    );
  } catch (err) {
    if (closeTimer) clearTimeout(closeTimer);
    error = err instanceof Error ? err.message : String(err);
    logger.error({ taskId: task.id, error }, 'Task failed');
  }

  const durationMs = Date.now() - startTime;

  logTaskRun({
    task_id: task.id,
    run_at: new Date().toISOString(),
    duration_ms: durationMs,
    status: error ? 'error' : 'success',
    result,
    error,
  });

  const nextRun = computeNextRun(task);
  if (nextRun === null && task.schedule_type !== 'once') {
    const resultSummary = `Error: invalid ${task.schedule_type} schedule "${task.schedule_value}" — task paused`;
    updateTaskAfterRun(task.id, null, resultSummary); // records last_run/result, sets 'completed'
    updateTask(task.id, { status: 'paused' }); // final status wins: paused
    return;
  }
  const resultSummary = error
    ? `Error: ${error}`
    : result
      ? result.slice(0, 200)
      : 'Completed';
  updateTaskAfterRun(task.id, nextRun, resultSummary);
}

let schedulerRunning = false;

export function startSchedulerLoop(deps: SchedulerDependencies): void {
  if (schedulerRunning) {
    logger.debug('Scheduler loop already running, skipping duplicate start');
    return;
  }
  schedulerRunning = true;
  logger.info('Scheduler loop started');

  // Daily retention prune, hosted here because this loop already ticks
  // continuously. lastPruneAt starts at 0, so the first prune runs on the
  // first tick after startup and deletes the accumulated backlog.
  let lastPruneAt = 0;
  const PRUNE_INTERVAL_MS = 24 * 60 * 60 * 1000;

  const loop = async () => {
    // Own try/catch: set lastPruneAt before pruning so a throwing prune
    // waits a day instead of retrying every tick, and a prune failure never
    // stops due tasks from running.
    if (Date.now() - lastPruneAt > PRUNE_INTERVAL_MS) {
      lastPruneAt = Date.now();
      try {
        const messages = pruneOldMessages(MESSAGE_RETENTION_DAYS);
        const taskLogs = pruneOldTaskRunLogs(TASK_LOG_RETENTION_DAYS);
        if (messages > 0 || taskLogs > 0) {
          logger.info({ messages, taskLogs }, 'Pruned old rows');
        }
      } catch (err) {
        logger.error({ err }, 'Retention prune failed');
      }
    }

    try {
      const dueTasks = getDueTasks();
      if (dueTasks.length > 0) {
        logger.info({ count: dueTasks.length }, 'Found due tasks');
      }

      for (const task of dueTasks) {
        // Re-check task status in case it was paused/cancelled
        const currentTask = getTaskById(task.id);
        if (!currentTask || currentTask.status !== 'active') {
          continue;
        }

        deps.queue.enqueueTask(currentTask.chat_jid, currentTask.id, () =>
          runTask(currentTask, deps),
        );
      }
    } catch (err) {
      logger.error({ err }, 'Error in scheduler loop');
    }

    setTimeout(loop, SCHEDULER_POLL_INTERVAL);
  };

  loop();
}

/** @internal - for tests only. */
export function _resetSchedulerLoopForTests(): void {
  schedulerRunning = false;
}
