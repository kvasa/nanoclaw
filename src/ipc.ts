import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

import { CronExpressionParser } from 'cron-parser';

import { DATA_DIR, IPC_POLL_INTERVAL, TIMEZONE } from './config.js';
import { AvailableGroup } from './container-runner.js';
import { createTask, deleteTask, getTaskById, updateTask } from './db.js';
import { isValidGroupFolder } from './group-folder.js';
import { logger } from './logger.js';
import {
  IpcCancelTaskSchema,
  IpcFileMessageSchema,
  IpcPauseTaskSchema,
  IpcReadEmailsSchema,
  IpcRefreshGroupsSchema,
  IpcRegisterGroupSchema,
  IpcResumeTaskSchema,
  IpcScheduleTaskSchema,
  IpcUpdateTaskSchema,
} from './schemas.js';
import { synthesizeSpeech, TtsVoice } from './tts.js';
import { RegisteredGroup, SendFileOptions } from './types.js';

export interface IpcDeps {
  sendMessage: (jid: string, text: string, threadTs?: string) => Promise<void>;
  sendEmailReply?: (threadJid: string, text: string) => Promise<boolean>;
  composeEmail?: (
    to: string,
    subject: string,
    body: string,
  ) => Promise<boolean>;
  readEmails?: (
    query: string,
    maxResults: number,
  ) => Promise<
    Array<{
      threadJid: string;
      subject: string;
      from: string;
      snippet: string;
      date: string;
      body: string;
    }>
  >;
  sendFile: (
    jid: string,
    filePath: string,
    groupFolder: string,
    options?: SendFileOptions,
  ) => Promise<void>;
  sendVoice: (
    jid: string,
    audioBuffer: Buffer,
    caption?: string,
  ) => Promise<void>;
  registeredGroups: () => Record<string, RegisteredGroup>;
  registerGroup: (jid: string, group: RegisteredGroup) => void;
  syncGroups: (force: boolean) => Promise<void>;
  getAvailableGroups: () => AvailableGroup[];
  writeGroupsSnapshot: (
    groupFolder: string,
    isMain: boolean,
    availableGroups: AvailableGroup[],
    registeredJids: Set<string>,
  ) => void;
  onTasksChanged: () => void;
}

let ipcWatcherRunning = false;

export function startIpcWatcher(deps: IpcDeps): void {
  if (ipcWatcherRunning) {
    logger.debug('IPC watcher already running, skipping duplicate start');
    return;
  }
  ipcWatcherRunning = true;

  const ipcBaseDir = path.join(DATA_DIR, 'ipc');
  fs.mkdirSync(ipcBaseDir, { recursive: true });

  const processIpcFiles = async () => {
    // Scan all group IPC directories (identity determined by directory)
    let groupFolders: string[];
    try {
      groupFolders = fs.readdirSync(ipcBaseDir).filter((f) => {
        const stat = fs.statSync(path.join(ipcBaseDir, f));
        return stat.isDirectory() && f !== 'errors';
      });
    } catch (err) {
      logger.error({ err }, 'Error reading IPC base directory');
      setTimeout(processIpcFiles, IPC_POLL_INTERVAL);
      return;
    }

    const registeredGroups = deps.registeredGroups();

    // Build folder→isMain lookup from registered groups
    const folderIsMain = new Map<string, boolean>();
    for (const group of Object.values(registeredGroups)) {
      if (group.isMain) folderIsMain.set(group.folder, true);
    }

    for (const sourceGroup of groupFolders) {
      const isMain = folderIsMain.get(sourceGroup) === true;
      const messagesDir = path.join(ipcBaseDir, sourceGroup, 'messages');
      const tasksDir = path.join(ipcBaseDir, sourceGroup, 'tasks');

      // Process messages from this group's IPC directory
      try {
        if (fs.existsSync(messagesDir)) {
          const messageFiles = fs
            .readdirSync(messagesDir)
            .filter((f) => f.endsWith('.json'));
          for (const file of messageFiles) {
            const filePath = path.join(messagesDir, file);
            try {
              const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
              const parsed = IpcFileMessageSchema.safeParse(raw);
              if (!parsed.success) {
                logger.warn(
                  { file, sourceGroup, errors: parsed.error.issues },
                  'Invalid IPC message schema',
                );
              } else {
                const data = parsed.data;

                const mainJid = Object.entries(registeredGroups).find(
                  ([, g]) => g.isMain,
                )?.[0];

                // send_email / compose_email use special fields — handle separately
                if (data.type === 'send_email') {
                  // Only main group can send email replies
                  if (!isMain) {
                    logger.warn(
                      { sourceGroup },
                      'Unauthorized send_email attempt blocked',
                    );
                  } else if (deps.sendEmailReply) {
                    const sent = await deps.sendEmailReply(
                      data.threadJid,
                      data.text,
                    );
                    logger.info(
                      { threadJid: data.threadJid, sent, sourceGroup },
                      'IPC send_email resolved',
                    );
                    if (mainJid) {
                      const feedback = sent
                        ? `✅ Email reply odeslán`
                        : `❌ Email reply zamítnut (nebyl odeslán)`;
                      await deps.sendMessage(mainJid, feedback);
                    }
                  } else {
                    logger.warn(
                      { threadJid: data.threadJid, sourceGroup },
                      'send_email requested but Gmail channel is not connected — dropping',
                    );
                  }
                } else if (data.type === 'compose_email') {
                  if (!isMain) {
                    logger.warn(
                      { sourceGroup },
                      'Unauthorized compose_email attempt blocked',
                    );
                  } else if (!deps.composeEmail) {
                    logger.warn(
                      'compose_email requested but Gmail channel not available',
                    );
                  } else {
                    const sent = await deps.composeEmail(
                      data.to,
                      data.subject,
                      data.body,
                    );
                    logger.info(
                      { to: data.to, sent, sourceGroup },
                      'IPC compose_email resolved',
                    );
                    if (mainJid) {
                      const feedback = sent
                        ? `✅ Email odeslán na ${data.to}`
                        : `❌ Email zamítnut (nebyl odeslán)`;
                      await deps.sendMessage(mainJid, feedback);
                    }
                  }
                } else if (data.type === 'read_emails') {
                  const parsed = IpcReadEmailsSchema.safeParse(raw);
                  if (!parsed.success) {
                    logger.warn(
                      { file, sourceGroup, errors: parsed.error.issues },
                      'Invalid read_emails schema',
                    );
                  } else if (!isMain) {
                    logger.warn(
                      { sourceGroup },
                      'Unauthorized read_emails attempt blocked',
                    );
                  } else if (!deps.readEmails) {
                    logger.warn(
                      'read_emails requested but Gmail channel not available',
                    );
                  } else {
                    const { query, maxResults, requestId } = parsed.data;
                    // Validate requestId format before using in path construction
                    if (!/^[a-zA-Z0-9_-]+$/.test(requestId)) {
                      logger.warn(
                        { requestId, sourceGroup },
                        'read_emails: invalid requestId format blocked',
                      );
                      try {
                        fs.unlinkSync(filePath);
                      } catch {
                        /* ignore */
                      }
                      continue;
                    }
                    const emails = await deps.readEmails(
                      query ?? 'is:unread',
                      maxResults ?? 10,
                    );
                    const responseDir = path.join(
                      ipcBaseDir,
                      sourceGroup,
                      'input',
                    );
                    fs.mkdirSync(responseDir, { recursive: true });
                    const responseFile = path.join(
                      responseDir,
                      `read_emails_${requestId}.json`,
                    );
                    fs.writeFileSync(
                      responseFile,
                      JSON.stringify({ requestId, emails }),
                    );
                    logger.info(
                      { count: emails.length, sourceGroup },
                      'IPC read_emails resolved',
                    );
                  }
                } else {
                  const targetGroup = registeredGroups[data.chatJid];
                  const authorized =
                    isMain ||
                    (targetGroup && targetGroup.folder === sourceGroup);

                  if (!authorized) {
                    logger.warn(
                      { chatJid: data.chatJid, sourceGroup, type: data.type },
                      'Unauthorized IPC message attempt blocked',
                    );
                  } else if (data.type === 'message') {
                    await deps.sendMessage(
                      data.chatJid,
                      data.text,
                      data.threadTs,
                    );
                    logger.info(
                      { chatJid: data.chatJid, sourceGroup },
                      'IPC message sent',
                    );
                  } else if (data.type === 'send_file') {
                    await deps.sendFile(
                      data.chatJid,
                      data.filePath,
                      sourceGroup,
                      data.options,
                    );
                    logger.info(
                      {
                        chatJid: data.chatJid,
                        filePath: data.filePath,
                        sourceGroup,
                      },
                      'IPC file sent',
                    );
                  } else if (data.type === 'send_voice') {
                    const audioBuffer = await synthesizeSpeech(
                      data.text,
                      data.voice as TtsVoice | undefined,
                    );
                    if (audioBuffer) {
                      await deps.sendVoice(
                        data.chatJid,
                        audioBuffer,
                        data.caption,
                      );
                      logger.info(
                        {
                          chatJid: data.chatJid,
                          textLength: data.text.length,
                          audioSize: audioBuffer.length,
                          sourceGroup,
                        },
                        'IPC voice message sent',
                      );
                    } else {
                      logger.warn(
                        { chatJid: data.chatJid, sourceGroup },
                        'TTS synthesis failed for voice message',
                      );
                    }
                  }
                }
              }
              fs.unlinkSync(filePath);
            } catch (err) {
              logger.error(
                { file, sourceGroup, err },
                'Error processing IPC message',
              );
              const errorDir = path.join(ipcBaseDir, 'errors');
              fs.mkdirSync(errorDir, { recursive: true });
              fs.renameSync(
                filePath,
                path.join(errorDir, `${sourceGroup}-${file}`),
              );
            }
          }
        }
      } catch (err) {
        logger.error(
          { err, sourceGroup },
          'Error reading IPC messages directory',
        );
      }

      // Process tasks from this group's IPC directory
      try {
        if (fs.existsSync(tasksDir)) {
          const taskFiles = fs
            .readdirSync(tasksDir)
            .filter((f) => f.endsWith('.json'));
          for (const file of taskFiles) {
            const filePath = path.join(tasksDir, file);
            try {
              const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
              // Pass source group identity to processTaskIpc for authorization
              await processTaskIpc(data, sourceGroup, isMain, deps);
              fs.unlinkSync(filePath);
            } catch (err) {
              logger.error(
                { file, sourceGroup, err },
                'Error processing IPC task',
              );
              const errorDir = path.join(ipcBaseDir, 'errors');
              fs.mkdirSync(errorDir, { recursive: true });
              fs.renameSync(
                filePath,
                path.join(errorDir, `${sourceGroup}-${file}`),
              );
            }
          }
        }
      } catch (err) {
        logger.error({ err, sourceGroup }, 'Error reading IPC tasks directory');
      }
    }

    setTimeout(processIpcFiles, IPC_POLL_INTERVAL);
  };

  processIpcFiles();
  logger.info('IPC watcher started (per-group namespaces)');
}

export async function processTaskIpc(
  data: {
    type: string;
    taskId?: string;
    prompt?: string;
    schedule_type?: string;
    schedule_value?: string;
    context_mode?: string;
    groupFolder?: string;
    chatJid?: string;
    targetJid?: string;
    // For register_group
    jid?: string;
    name?: string;
    folder?: string;
    trigger?: string;
    requiresTrigger?: boolean;
    containerConfig?: RegisteredGroup['containerConfig'];
  },
  sourceGroup: string, // Verified identity from IPC directory
  isMain: boolean, // Verified from directory path
  deps: IpcDeps,
): Promise<void> {
  const registeredGroups = deps.registeredGroups();

  switch (data.type) {
    case 'schedule_task':
      if (
        data.prompt &&
        data.schedule_type &&
        data.schedule_value &&
        data.targetJid
      ) {
        // Resolve the target group from JID
        const targetJid = data.targetJid as string;
        const targetGroupEntry = registeredGroups[targetJid];

        if (!targetGroupEntry) {
          logger.warn(
            { targetJid },
            'Cannot schedule task: target group not registered',
          );
          break;
        }

        const targetFolder = targetGroupEntry.folder;

        // Authorization: non-main groups can only schedule for themselves
        if (!isMain && targetFolder !== sourceGroup) {
          logger.warn(
            { sourceGroup, targetFolder },
            'Unauthorized schedule_task attempt blocked',
          );
          break;
        }

        const scheduleType = data.schedule_type as 'cron' | 'interval' | 'once';

        let nextRun: string | null = null;
        if (scheduleType === 'cron') {
          try {
            const interval = CronExpressionParser.parse(data.schedule_value, {
              tz: TIMEZONE,
            });
            nextRun = interval.next().toISOString();
          } catch {
            logger.warn(
              { scheduleValue: data.schedule_value },
              'Invalid cron expression',
            );
            break;
          }
        } else if (scheduleType === 'interval') {
          const ms = parseInt(data.schedule_value, 10);
          if (isNaN(ms) || ms <= 0) {
            logger.warn(
              { scheduleValue: data.schedule_value },
              'Invalid interval',
            );
            break;
          }
          nextRun = new Date(Date.now() + ms).toISOString();
        } else if (scheduleType === 'once') {
          const date = new Date(data.schedule_value);
          if (isNaN(date.getTime())) {
            logger.warn(
              { scheduleValue: data.schedule_value },
              'Invalid timestamp',
            );
            break;
          }
          nextRun = date.toISOString();
        }

        const taskId =
          data.taskId ||
          `task-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
        const contextMode =
          data.context_mode === 'group' || data.context_mode === 'isolated'
            ? data.context_mode
            : 'isolated';
        createTask({
          id: taskId,
          group_folder: targetFolder,
          chat_jid: targetJid,
          prompt: data.prompt,
          schedule_type: scheduleType,
          schedule_value: data.schedule_value,
          context_mode: contextMode,
          next_run: nextRun,
          status: 'active',
          created_at: new Date().toISOString(),
        });
        logger.info(
          { taskId, sourceGroup, targetFolder, contextMode },
          'Task created via IPC',
        );
        deps.onTasksChanged();
      }
      break;

    case 'pause_task':
      if (data.taskId) {
        const task = getTaskById(data.taskId);
        if (task && (isMain || task.group_folder === sourceGroup)) {
          updateTask(data.taskId, { status: 'paused' });
          logger.info(
            { taskId: data.taskId, sourceGroup },
            'Task paused via IPC',
          );
          deps.onTasksChanged();
        } else {
          logger.warn(
            { taskId: data.taskId, sourceGroup },
            'Unauthorized task pause attempt',
          );
        }
      }
      break;

    case 'resume_task':
      if (data.taskId) {
        const task = getTaskById(data.taskId);
        if (task && (isMain || task.group_folder === sourceGroup)) {
          updateTask(data.taskId, { status: 'active' });
          logger.info(
            { taskId: data.taskId, sourceGroup },
            'Task resumed via IPC',
          );
          deps.onTasksChanged();
        } else {
          logger.warn(
            { taskId: data.taskId, sourceGroup },
            'Unauthorized task resume attempt',
          );
        }
      }
      break;

    case 'cancel_task':
      if (data.taskId) {
        const task = getTaskById(data.taskId);
        if (task && (isMain || task.group_folder === sourceGroup)) {
          deleteTask(data.taskId);
          logger.info(
            { taskId: data.taskId, sourceGroup },
            'Task cancelled via IPC',
          );
          deps.onTasksChanged();
        } else {
          logger.warn(
            { taskId: data.taskId, sourceGroup },
            'Unauthorized task cancel attempt',
          );
        }
      }
      break;

    case 'update_task':
      if (data.taskId) {
        const task = getTaskById(data.taskId);
        if (!task) {
          logger.warn(
            { taskId: data.taskId, sourceGroup },
            'Task not found for update',
          );
          break;
        }
        if (!isMain && task.group_folder !== sourceGroup) {
          logger.warn(
            { taskId: data.taskId, sourceGroup },
            'Unauthorized task update attempt',
          );
          break;
        }

        const updates: Parameters<typeof updateTask>[1] = {};
        if (data.prompt !== undefined) updates.prompt = data.prompt;
        if (data.schedule_type !== undefined)
          updates.schedule_type = data.schedule_type as
            | 'cron'
            | 'interval'
            | 'once';
        if (data.schedule_value !== undefined)
          updates.schedule_value = data.schedule_value;

        // Recompute next_run if schedule changed
        if (data.schedule_type || data.schedule_value) {
          const updatedTask = {
            ...task,
            ...updates,
          };
          if (updatedTask.schedule_type === 'cron') {
            try {
              const interval = CronExpressionParser.parse(
                updatedTask.schedule_value,
                { tz: TIMEZONE },
              );
              updates.next_run = interval.next().toISOString();
            } catch {
              logger.warn(
                { taskId: data.taskId, value: updatedTask.schedule_value },
                'Invalid cron in task update',
              );
              break;
            }
          } else if (updatedTask.schedule_type === 'interval') {
            const ms = parseInt(updatedTask.schedule_value, 10);
            if (!isNaN(ms) && ms > 0) {
              updates.next_run = new Date(Date.now() + ms).toISOString();
            }
          }
        }

        updateTask(data.taskId, updates);
        logger.info(
          { taskId: data.taskId, sourceGroup, updates },
          'Task updated via IPC',
        );
        deps.onTasksChanged();
      }
      break;

    case 'refresh_groups':
      // Only main group can request a refresh
      if (isMain) {
        logger.info(
          { sourceGroup },
          'Group metadata refresh requested via IPC',
        );
        await deps.syncGroups(true);
        // Write updated snapshot immediately
        const availableGroups = deps.getAvailableGroups();
        deps.writeGroupsSnapshot(
          sourceGroup,
          true,
          availableGroups,
          new Set(Object.keys(registeredGroups)),
        );
      } else {
        logger.warn(
          { sourceGroup },
          'Unauthorized refresh_groups attempt blocked',
        );
      }
      break;

    case 'register_group':
      // Only main group can register new groups
      if (!isMain) {
        logger.warn(
          { sourceGroup },
          'Unauthorized register_group attempt blocked',
        );
        break;
      }
      {
        const validated = IpcRegisterGroupSchema.safeParse(data);
        if (!validated.success) {
          logger.warn(
            { sourceGroup, errors: validated.error.issues },
            'Invalid register_group request - schema validation failed',
          );
          break;
        }
        const vd = validated.data;
        if (!isValidGroupFolder(vd.folder)) {
          logger.warn(
            { sourceGroup, folder: vd.folder },
            'Invalid register_group request - unsafe folder name',
          );
          break;
        }
        // Defense in depth: agent cannot set isMain via IPC
        deps.registerGroup(vd.jid, {
          name: vd.name,
          folder: vd.folder,
          trigger: vd.trigger,
          added_at: new Date().toISOString(),
          containerConfig: vd.containerConfig,
          requiresTrigger: vd.requiresTrigger,
        });
      }
      break;

    default:
      logger.warn({ type: data.type }, 'Unknown IPC task type');
  }
}
