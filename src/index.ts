import fs from 'fs';
import path from 'path';

import {
  API_GROUP_ID,
  API_HOST,
  API_PORT,
  API_SLACK_CHANNEL_ID,
  API_TOKEN,
  ASSISTANT_NAME,
  CREDENTIAL_PROXY_PORT,
  DATA_DIR,
  IDLE_TIMEOUT,
  POLL_INTERVAL,
  TIMEZONE,
  TRIGGER_PATTERN,
} from './config.js';
import { startApiServer, SlackNotifier } from './api-server.js';
import { startVoiceServer } from './voice-server.js';
import { startCredentialProxy } from './credential-proxy.js';
import './channels/index.js';
import {
  getChannelFactory,
  getRegisteredChannelNames,
} from './channels/registry.js';
import { GmailChannel } from './channels/gmail.js';
import { SlackChannel } from './channels/slack.js';
import {
  ContainerOutput,
  runContainerAgent,
  writeEmailsSnapshot,
  writeGroupsSnapshot,
  writeTasksSnapshot,
} from './container-runner.js';
import {
  cleanupOrphans,
  ensureContainerRuntimeRunning,
  PROXY_BIND_HOST,
} from './container-runtime.js';
import {
  deleteSession,
  getAllChats,
  getAllRegisteredGroups,
  getAllSessions,
  getAllTasks,
  getMessagesSince,
  getNewMessages,
  getRouterState,
  initDatabase,
  setRegisteredGroup,
  setRouterState,
  setSession,
  storeChatMetadata,
  storeMessage,
} from './db.js';
import { GroupQueue } from './group-queue.js';
import { resolveGroupFolderPath } from './group-folder.js';
import { startIpcWatcher } from './ipc.js';
import { findChannel, formatMessages, formatOutbound } from './router.js';
import {
  restoreRemoteControl,
  startRemoteControl,
  stopRemoteControl,
} from './remote-control.js';
import {
  isSenderAllowed,
  isTriggerAllowed,
  loadSenderAllowlist,
  shouldDropMessage,
} from './sender-allowlist.js';
import { startSchedulerLoop } from './task-scheduler.js';
import {
  Channel,
  NewMessage,
  RegisteredGroup,
  SendFileOptions,
} from './types.js';
import { logger } from './logger.js';
import { ReactionTracker } from './reaction-tracker.js';

// Re-export for backwards compatibility during refactor
export { escapeXml, formatMessages } from './router.js';

let lastTimestamp = '';
let sessions: Record<string, string> = {};
let registeredGroups: Record<string, RegisteredGroup> = {};
let lastAgentTimestamp: Record<string, string> = {};
let messageLoopRunning = false;
let gmailChannel: GmailChannel | undefined;

const channels: Channel[] = [];
const queue = new GroupQueue();
const pipedReactions = new Map<string, ReactionTracker>();

// In-memory store for the latest user message threadTs per chatJid.
// threadTs is ephemeral (not persisted in DB) and used for Slack thread replies.
const latestThreadTs: Record<string, string> = {};

function loadState(): void {
  lastTimestamp = getRouterState('last_timestamp') || '';
  const agentTs = getRouterState('last_agent_timestamp');
  try {
    lastAgentTimestamp = agentTs ? JSON.parse(agentTs) : {};
  } catch {
    logger.warn('Corrupted last_agent_timestamp in DB, resetting');
    lastAgentTimestamp = {};
  }
  sessions = getAllSessions();
  registeredGroups = getAllRegisteredGroups();
  logger.info(
    { groupCount: Object.keys(registeredGroups).length },
    'State loaded',
  );
}

/**
 * Save router state to DB.
 *
 * When `chatJid` is provided, only that group's cursor is persisted via a
 * synchronous read-modify-write of the `last_agent_timestamp` JSON blob.
 * Because there is no `await` inside this path, the Node.js event loop
 * guarantees no interleaving — so group A saving its cursor can never
 * clobber group B's cursor.
 *
 * When called without arguments (initial boot / global timestamp update),
 * the full in-memory map is flushed.
 */
function saveState(chatJid?: string): void {
  setRouterState('last_timestamp', lastTimestamp);

  if (chatJid) {
    // Atomic per-group cursor update: read current DB value, patch one key, write back.
    const raw = getRouterState('last_agent_timestamp');
    let stored: Record<string, string> = {};
    try {
      stored = raw ? JSON.parse(raw) : {};
    } catch {
      stored = {};
    }
    stored[chatJid] = lastAgentTimestamp[chatJid] ?? '';
    setRouterState('last_agent_timestamp', JSON.stringify(stored));
  } else {
    setRouterState('last_agent_timestamp', JSON.stringify(lastAgentTimestamp));
  }
}

function registerGroup(jid: string, group: RegisteredGroup): void {
  let groupDir: string;
  try {
    groupDir = resolveGroupFolderPath(group.folder);
  } catch (err) {
    logger.warn(
      { jid, folder: group.folder, err },
      'Rejecting group registration with invalid folder',
    );
    return;
  }

  registeredGroups[jid] = group;
  setRegisteredGroup(jid, group);

  // Create group folder
  fs.mkdirSync(path.join(groupDir, 'logs'), { recursive: true });

  logger.info(
    { jid, name: group.name, folder: group.folder },
    'Group registered',
  );
}

/**
 * Get available groups list for the agent.
 * Returns groups ordered by most recent activity.
 */
export function getAvailableGroups(): import('./container-runner.js').AvailableGroup[] {
  const chats = getAllChats();
  const registeredJids = new Set(Object.keys(registeredGroups));

  return chats
    .filter((c) => c.jid !== '__group_sync__' && c.is_group)
    .map((c) => ({
      jid: c.jid,
      name: c.name,
      lastActivity: c.last_message_time,
      isRegistered: registeredJids.has(c.jid),
    }));
}

/** @internal - exported for testing */
export function _setRegisteredGroups(
  groups: Record<string, RegisteredGroup>,
): void {
  registeredGroups = groups;
}

/** @internal - exported for testing cursor isolation */
export function _saveState(chatJid?: string): void {
  saveState(chatJid);
}

/** @internal - exported for testing cursor isolation */
export function _setLastAgentTimestamp(
  timestamps: Record<string, string>,
): void {
  lastAgentTimestamp = timestamps;
}

/** @internal - exported for testing cursor isolation */
export function _getLastAgentTimestamp(): Record<string, string> {
  return lastAgentTimestamp;
}

/** Find the last non-bot message ID (for reaction targeting). */
function findLastUserMessageId(messages: NewMessage[]): string | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (!messages[i].is_bot_message && !messages[i].is_from_me)
      return messages[i].id;
  }
  return undefined;
}

/**
 * Process all pending messages for a group.
 * Called by the GroupQueue when it's this group's turn.
 */
async function processGroupMessages(chatJid: string): Promise<boolean> {
  const group = registeredGroups[chatJid];
  if (!group) return true;

  const channel = findChannel(channels, chatJid);
  if (!channel) {
    logger.warn({ chatJid }, 'No channel owns JID, skipping messages');
    return true;
  }

  const isMainGroup = group.isMain === true;

  const sinceTimestamp = lastAgentTimestamp[chatJid] || '';
  const missedMessages = getMessagesSince(
    chatJid,
    sinceTimestamp,
    ASSISTANT_NAME,
  );

  if (missedMessages.length === 0) return true;

  // Handle /clear command — reset session and message cursor
  const hasClear = missedMessages.some((m) => /\/clear\b/i.test(m.content));
  if (hasClear) {
    delete sessions[group.folder];
    deleteSession(group.folder);
    lastAgentTimestamp[chatJid] =
      missedMessages[missedMessages.length - 1].timestamp;
    saveState(chatJid);
    await channel.sendMessage(chatJid, 'Context cleared.');
    logger.info({ group: group.name }, '/clear command processed');
    return true;
  }

  // For non-main groups, check if trigger is required and present
  if (!isMainGroup && group.requiresTrigger !== false) {
    const allowlistCfg = loadSenderAllowlist();
    const hasTrigger = missedMessages.some(
      (m) =>
        TRIGGER_PATTERN.test(m.content.trim()) &&
        (m.is_from_me || isTriggerAllowed(chatJid, m.sender, allowlistCfg)),
    );
    if (!hasTrigger) return true;
  }

  const prompt = formatMessages(missedMessages, TIMEZONE);

  // Advance cursor so the piping path in startMessageLoop won't re-fetch
  // these messages. Save the old cursor so we can roll back on error.
  const previousCursor = lastAgentTimestamp[chatJid] || '';
  lastAgentTimestamp[chatJid] =
    missedMessages[missedMessages.length - 1].timestamp;
  saveState(chatJid);

  logger.info(
    { group: group.name, messageCount: missedMessages.length },
    'Processing messages',
  );

  // Track idle timer for closing stdin when agent is idle
  let idleTimer: ReturnType<typeof setTimeout> | null = null;

  const resetIdleTimer = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      logger.debug(
        { group: group.name },
        'Idle timeout, closing container stdin',
      );
      queue.closeStdin(chatJid);
    }, IDLE_TIMEOUT);
  };

  // Use the in-memory threadTs for Slack thread replies (DB doesn't store threadTs).
  // Progress updates (via IPC) are sent as thread replies; final response goes to main channel.
  const triggerTs = latestThreadTs[chatJid];
  // Clear after use so stale values don't leak to future invocations
  delete latestThreadTs[chatJid];
  // Write threadTs to file so the container can read it dynamically
  // (env var is only set once at container start, but messages can be piped later)
  if (triggerTs) {
    queue.updateThreadTs(chatJid, triggerTs);
  }

  await channel.setTyping?.(chatJid, true);
  const reactedMsgId = findLastUserMessageId(missedMessages);
  const reaction = new ReactionTracker(channel, chatJid, reactedMsgId);
  await reaction.start();
  let hadError = false;
  let outputSentToUser = false;

  const output = await runAgent(
    group,
    prompt,
    chatJid,
    triggerTs,
    async (result) => {
      // Streaming output callback — called for each agent result
      if (result.result) {
        const raw =
          typeof result.result === 'string'
            ? result.result
            : JSON.stringify(result.result);
        // Strip <internal>...</internal> blocks — agent uses these for internal reasoning
        const text = raw.replace(/<internal>[\s\S]*?<\/internal>/g, '').trim();
        logger.info(
          { group: group.name },
          `Agent output: ${raw.slice(0, 200)}`,
        );
        if (text) {
          await channel.sendMessage(chatJid, text);
          outputSentToUser = true;
        }
        await reaction.finalize('white_check_mark');
        await pipedReactions.get(chatJid)?.finalize('white_check_mark');
        pipedReactions.delete(chatJid);
        // Only reset idle timer on actual results, not session-update markers (result: null)
        resetIdleTimer();
      }

      if (result.status === 'success') {
        queue.notifyIdle(chatJid);
      }

      if (result.status === 'error') {
        hadError = true;
        await reaction.finalize('warning');
        await pipedReactions.get(chatJid)?.finalize('warning');
        pipedReactions.delete(chatJid);
      }
    },
  );

  await channel.setTyping?.(chatJid, false);
  if (idleTimer) clearTimeout(idleTimer);

  // Fallback: if no streaming callback fired (e.g. container crashed), finalize reaction
  const finalEmoji =
    output === 'error' || hadError ? 'warning' : 'white_check_mark';
  await reaction.finalize(finalEmoji);
  await pipedReactions.get(chatJid)?.finalize(finalEmoji);
  pipedReactions.delete(chatJid);

  if (output === 'error' || hadError) {
    // If we already sent output to the user, don't roll back the cursor —
    // the user got their response and re-processing would send duplicates.
    if (outputSentToUser) {
      logger.warn(
        { group: group.name },
        'Agent error after output was sent, skipping cursor rollback to prevent duplicates',
      );
      return true;
    }
    // Roll back cursor so retries can re-process these messages
    lastAgentTimestamp[chatJid] = previousCursor;
    saveState(chatJid);
    logger.warn(
      { group: group.name },
      'Agent error, rolled back message cursor for retry',
    );
    return false;
  }

  return true;
}

async function runAgent(
  group: RegisteredGroup,
  prompt: string,
  chatJid: string,
  triggerMessageTs?: string,
  onOutput?: (output: ContainerOutput) => Promise<void>,
): Promise<'success' | 'error'> {
  const isMain = group.isMain === true;
  const sessionId = sessions[group.folder];

  // Update tasks snapshot for container to read (filtered by group)
  const tasks = getAllTasks();
  writeTasksSnapshot(
    group.folder,
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

  // Update available groups snapshot (main group only can see all groups)
  const availableGroups = getAvailableGroups();
  writeGroupsSnapshot(
    group.folder,
    isMain,
    availableGroups,
    new Set(Object.keys(registeredGroups)),
  );

  // Write email snapshot for main group so agent can read recent emails
  if (isMain && gmailChannel) {
    writeEmailsSnapshot(group.folder, gmailChannel.getRecentEmails());
  }

  // Wrap onOutput to track session ID from streamed results
  // Also intercept corrupted-session errors (e.g. expired image data)
  const wrappedOnOutput = onOutput
    ? async (output: ContainerOutput) => {
        // Detect API errors that slipped through as "success" results
        // (SDK returns them as result text rather than throwing)
        const isCorruptedSession =
          output.result &&
          /API Error: 400\b/.test(output.result) &&
          /Could not process/.test(output.result);
        if (isCorruptedSession) {
          logger.warn(
            { group: group.name, error: output.result },
            'Intercepted corrupted session error, clearing session',
          );
          delete sessions[group.folder];
          deleteSession(group.folder);
          // Convert to error so it doesn't get forwarded to user
          output.status = 'error';
          output.error = output.result ?? undefined;
          output.result = null;
          return; // Don't forward to user
        }
        if (output.newSessionId) {
          sessions[group.folder] = output.newSessionId;
          setSession(group.folder, output.newSessionId);
        }
        await onOutput(output);
      }
    : undefined;

  try {
    const output = await runContainerAgent(
      group,
      {
        prompt,
        sessionId,
        groupFolder: group.folder,
        chatJid,
        isMain,
        assistantName: ASSISTANT_NAME,
        enabledMcpServers: group.containerConfig?.enabledMcpServers,
        triggerMessageTs,
      },
      (proc, containerName) =>
        queue.registerProcess(chatJid, proc, containerName, group.folder),
      wrappedOnOutput,
    );

    if (output.newSessionId) {
      sessions[group.folder] = output.newSessionId;
      setSession(group.folder, output.newSessionId);
    }

    if (output.status === 'error') {
      logger.error(
        { group: group.name, error: output.error },
        'Container agent error',
      );
      // If the error indicates corrupted session data (e.g. expired image),
      // clear the session so the next invocation starts fresh.
      if (
        output.error &&
        /\b400\b/.test(output.error) &&
        /Could not process/.test(output.error)
      ) {
        delete sessions[group.folder];
        deleteSession(group.folder);
        logger.warn(
          { group: group.name },
          'Cleared corrupted session after image processing error',
        );
      }
      return 'error';
    }

    return 'success';
  } catch (err) {
    logger.error({ group: group.name, err }, 'Agent error');
    return 'error';
  }
}

async function startMessageLoop(): Promise<void> {
  if (messageLoopRunning) {
    logger.debug('Message loop already running, skipping duplicate start');
    return;
  }
  messageLoopRunning = true;

  logger.info(`NanoClaw running (trigger: @${ASSISTANT_NAME})`);

  while (true) {
    try {
      const jids = Object.keys(registeredGroups);
      const { messages, newTimestamp } = getNewMessages(
        jids,
        lastTimestamp,
        ASSISTANT_NAME,
      );

      if (messages.length > 0) {
        logger.info({ count: messages.length }, 'New messages');

        // Advance the "seen" cursor for all messages immediately
        lastTimestamp = newTimestamp;
        saveState();

        // Deduplicate by group
        const messagesByGroup = new Map<string, NewMessage[]>();
        for (const msg of messages) {
          const existing = messagesByGroup.get(msg.chat_jid);
          if (existing) {
            existing.push(msg);
          } else {
            messagesByGroup.set(msg.chat_jid, [msg]);
          }
        }

        for (const [chatJid, groupMessages] of messagesByGroup) {
          const group = registeredGroups[chatJid];
          if (!group) continue;

          const channel = findChannel(channels, chatJid);
          if (!channel) {
            logger.warn({ chatJid }, 'No channel owns JID, skipping messages');
            continue;
          }

          const isMainGroup = group.isMain === true;
          const needsTrigger = !isMainGroup && group.requiresTrigger !== false;

          // For non-main groups, only act on trigger messages.
          // Non-trigger messages accumulate in DB and get pulled as
          // context when a trigger eventually arrives.
          if (needsTrigger) {
            const allowlistCfg = loadSenderAllowlist();
            const hasTrigger = groupMessages.some(
              (m) =>
                TRIGGER_PATTERN.test(m.content.trim()) &&
                (m.is_from_me ||
                  isTriggerAllowed(chatJid, m.sender, allowlistCfg)),
            );
            if (!hasTrigger) continue;
          }

          // Pull all messages since lastAgentTimestamp so non-trigger
          // context that accumulated between triggers is included.
          const allPending = getMessagesSince(
            chatJid,
            lastAgentTimestamp[chatJid] || '',
            ASSISTANT_NAME,
          );
          const messagesToSend =
            allPending.length > 0 ? allPending : groupMessages;
          const formatted = formatMessages(messagesToSend, TIMEZONE);

          // Handle /clear command — reset session, kill active container
          const hasClearCmd = messagesToSend.some((m) =>
            /\/clear\b/i.test(m.content),
          );
          if (hasClearCmd) {
            queue.closeStdin(chatJid);
            delete sessions[group.folder];
            deleteSession(group.folder);
            lastAgentTimestamp[chatJid] =
              messagesToSend[messagesToSend.length - 1].timestamp;
            saveState(chatJid);
            await channel.sendMessage(chatJid, 'Context cleared.');
            logger.info(
              { group: group.name },
              '/clear command processed (active container)',
            );
            continue;
          }

          if (queue.sendMessage(chatJid, formatted)) {
            // Update threadTs file so the container uses the new message's thread
            const pipedThreadTs = latestThreadTs[chatJid];
            if (pipedThreadTs) {
              queue.updateThreadTs(chatJid, pipedThreadTs);
              delete latestThreadTs[chatJid];
            }
            logger.debug(
              { chatJid, count: messagesToSend.length },
              'Piped messages to active container',
            );
            lastAgentTimestamp[chatJid] =
              messagesToSend[messagesToSend.length - 1].timestamp;
            saveState(chatJid);
            // Show typing indicator while the container processes the piped message
            channel.setTyping?.(chatJid, true);
            const pipedMsgId = findLastUserMessageId(messagesToSend);
            if (pipedMsgId) {
              const pipedReaction = new ReactionTracker(
                channel,
                chatJid,
                pipedMsgId,
              );
              pipedReactions.set(chatJid, pipedReaction);
              pipedReaction.start().catch(() => {});
            }
          } else {
            // No active container — enqueue for a new one
            queue.enqueueMessageCheck(chatJid);
          }
        }
      }
    } catch (err) {
      logger.error({ err }, 'Error in message loop');
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
  }
}

/**
 * Startup recovery: check for unprocessed messages in registered groups.
 * Handles crash between advancing lastTimestamp and processing messages.
 */
function recoverPendingMessages(): void {
  for (const [chatJid, group] of Object.entries(registeredGroups)) {
    const sinceTimestamp = lastAgentTimestamp[chatJid] || '';
    const pending = getMessagesSince(chatJid, sinceTimestamp, ASSISTANT_NAME);
    if (pending.length > 0) {
      logger.info(
        { group: group.name, pendingCount: pending.length },
        'Recovery: found unprocessed messages',
      );
      queue.enqueueMessageCheck(chatJid);
    }
  }
}

function ensureContainerSystemRunning(): void {
  ensureContainerRuntimeRunning();
  cleanupOrphans();
}

async function main(): Promise<void> {
  ensureContainerSystemRunning();
  initDatabase();
  logger.info('Database initialized');
  loadState();
  restoreRemoteControl();

  // Start credential proxy (containers route API calls through this)
  const proxyServer = await startCredentialProxy(
    CREDENTIAL_PROXY_PORT,
    PROXY_BIND_HOST,
  );

  // API server is started after channels connect (needs Slack channel for notifications)
  let apiServer: import('http').Server | undefined;

  // Graceful shutdown handlers
  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    proxyServer.close();
    apiServer?.close();
    await queue.shutdown(10000);
    for (const ch of channels) await ch.disconnect();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Handle /remote-control and /remote-control-end commands
  async function handleRemoteControl(
    command: string,
    chatJid: string,
    msg: NewMessage,
  ): Promise<void> {
    const group = registeredGroups[chatJid];
    if (!group?.isMain) {
      logger.warn(
        { chatJid, sender: msg.sender },
        'Remote control rejected: not main group',
      );
      return;
    }

    const channel = findChannel(channels, chatJid);
    if (!channel) return;

    if (command === '/remote-control') {
      const result = await startRemoteControl(
        msg.sender,
        chatJid,
        process.cwd(),
      );
      if (result.ok) {
        await channel.sendMessage(chatJid, result.url);
      } else {
        await channel.sendMessage(
          chatJid,
          `Remote Control failed: ${result.error}`,
        );
      }
    } else {
      const result = stopRemoteControl();
      if (result.ok) {
        await channel.sendMessage(chatJid, 'Remote Control session ended.');
      } else {
        await channel.sendMessage(chatJid, result.error);
      }
    }
  }

  // Channel callbacks (shared by all channels)
  const channelOpts = {
    onMessage: (chatJid: string, msg: NewMessage) => {
      // Remote control commands — intercept before storage
      const trimmed = msg.content.trim();
      if (trimmed === '/remote-control' || trimmed === '/remote-control-end') {
        handleRemoteControl(trimmed, chatJid, msg).catch((err) =>
          logger.error({ err, chatJid }, 'Remote control command error'),
        );
        return;
      }

      // Sender allowlist drop mode: discard messages from denied senders before storing
      if (!msg.is_from_me && !msg.is_bot_message && registeredGroups[chatJid]) {
        const cfg = loadSenderAllowlist();
        if (
          shouldDropMessage(chatJid, cfg) &&
          !isSenderAllowed(chatJid, msg.sender, cfg)
        ) {
          if (cfg.logDenied) {
            logger.debug(
              { chatJid, sender: msg.sender },
              'sender-allowlist: dropping message (drop mode)',
            );
          }
          return;
        }
      }
      // Preserve threadTs in memory for Slack thread replies (not stored in DB)
      if (msg.threadTs && !msg.is_bot_message) {
        latestThreadTs[chatJid] = msg.threadTs;
      }
      storeMessage(msg);
    },
    onChatMetadata: (
      chatJid: string,
      timestamp: string,
      name?: string,
      channel?: string,
      isGroup?: boolean,
    ) => storeChatMetadata(chatJid, timestamp, name, channel, isGroup),
    registeredGroups: () => registeredGroups,
  };

  // Create and connect all registered channels.
  // Each channel self-registers via the barrel import above.
  // Factories return null when credentials are missing, so unconfigured channels are skipped.
  const failedChannels: { name: string; error: string }[] = [];
  for (const channelName of getRegisteredChannelNames()) {
    const factory = getChannelFactory(channelName)!;
    const channel = factory(channelOpts);
    if (!channel) {
      logger.warn(
        { channel: channelName },
        'Channel installed but credentials missing — skipping. Check .env or re-run the channel skill.',
      );
      continue;
    }
    try {
      await channel.connect();
      channels.push(channel);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(
        { channel: channelName, err },
        'Channel failed to connect — skipping',
      );
      failedChannels.push({ name: channelName, error: msg });
    }
  }
  if (channels.length === 0) {
    logger.fatal('No channels connected');
    process.exit(1);
  }

  // Notify main channel about any channels that failed to connect
  if (failedChannels.length > 0) {
    const mainEntry = Object.entries(registeredGroups).find(
      ([, g]) => g.isMain,
    );
    if (mainEntry) {
      const [mainJid] = mainEntry;
      const mainChannel = findChannel(channels, mainJid);
      if (mainChannel) {
        const lines = failedChannels.map((f) => `• *${f.name}*: ${f.error}`);
        await mainChannel.sendMessage(
          mainJid,
          `⚠️ Failed to connect channel(s):\n${lines.join('\n')}\n\nRe-authenticate with the relevant /add-<channel> skill.`,
        );
      }
    }
  }

  // Wire Gmail approval gate: all outgoing Gmail replies require Slack confirmation
  const slackCh = channels.find((c) => c.name === 'slack') as
    | SlackChannel
    | undefined;
  const gmailCh = channels.find((c) => c.name === 'gmail') as
    | GmailChannel
    | undefined;
  gmailChannel = gmailCh;
  if (slackCh && gmailCh) {
    gmailCh.approvalGate = async (opts) => {
      const mainEntry = Object.entries(registeredGroups).find(
        ([, g]) => g.isMain,
      );
      if (!mainEntry) {
        logger.warn('Gmail approval gate: no main group found — blocking send');
        return false;
      }
      const mainJid = mainEntry[0];
      if (!mainJid.startsWith('slack:')) {
        logger.warn(
          { mainJid },
          'Gmail approval gate: main group is not Slack — blocking send',
        );
        return false;
      }
      const channelId = mainJid.replace(/^slack:/, '');
      return slackCh.requestEmailApproval({ channelId, ...opts });
    };
    logger.info('Gmail approval gate wired to Slack main channel');
  }

  // Start API server for direct client access (optional — requires API_TOKEN)
  if (API_TOKEN) {
    // Build Slack notifier for mirroring API queries to a Slack channel
    let slackNotifier: SlackNotifier | undefined;
    if (API_SLACK_CHANNEL_ID) {
      const slackJid = `slack:${API_SLACK_CHANNEL_ID}`;
      let lastProgressAt = 0;
      slackNotifier = {
        async postQuestion(text: string) {
          const ch = findChannel(channels, slackJid);
          if (!ch?.isConnected()) return undefined;
          return (ch as SlackChannel).sendMessageWithTs(
            slackJid,
            `*API Query:*\n${text}`,
          );
        },
        async postProgress(threadTs: string, text: string) {
          const now = Date.now();
          if (now - lastProgressAt < 3000) return; // throttle: max 1 per 3s
          lastProgressAt = now;
          const ch = findChannel(channels, slackJid);
          if (!ch?.isConnected()) return;
          await ch.sendMessage(slackJid, text, threadTs);
        },
        async postResult(text: string) {
          const ch = findChannel(channels, slackJid);
          if (!ch?.isConnected()) return;
          await ch.sendMessage(slackJid, text);
        },
      };
    }

    apiServer = await startApiServer({
      port: API_PORT,
      host: API_HOST,
      token: API_TOKEN,
      defaultGroupId: API_GROUP_ID,
      getRegisteredGroups: () => registeredGroups,
      getSession: (folder) => sessions[folder],
      setSession: (folder, id) => {
        sessions[folder] = id;
        setSession(folder, id);
      },
      slackNotifier,
    });
  }

  startVoiceServer();

  // Start subsystems (independently of connection handler)
  startSchedulerLoop({
    registeredGroups: () => registeredGroups,
    getSessions: () => sessions,
    queue,
    onProcess: (groupJid, proc, containerName, groupFolder) =>
      queue.registerProcess(groupJid, proc, containerName, groupFolder),
    sendMessage: async (jid, rawText) => {
      const channel = findChannel(channels, jid);
      if (!channel) {
        logger.warn({ jid }, 'No channel owns JID, cannot send message');
        return;
      }
      const text = formatOutbound(rawText);
      if (text) await channel.sendMessage(jid, text);
    },
  });
  startIpcWatcher({
    sendMessage: (jid, text, threadTs) => {
      const channel = findChannel(channels, jid);
      if (!channel) throw new Error(`No channel for JID: ${jid}`);
      return channel.sendMessage(jid, text, threadTs);
    },
    sendEmailReply: gmailCh
      ? (threadJid, text): Promise<boolean> =>
          gmailCh.replyEmail(threadJid, text)
      : undefined,
    composeEmail: gmailCh
      ? (to, subject, body): Promise<boolean> =>
          gmailCh.composeEmail(to, subject, body)
      : undefined,
    readEmails: gmailCh
      ? (query, maxResults) => gmailCh.readEmails(query, maxResults)
      : undefined,
    sendVoice: async (jid: string, audioBuffer: Buffer, caption?: string) => {
      const channel = findChannel(channels, jid);
      if (!channel) throw new Error(`No channel for JID: ${jid}`);
      if (!channel.sendVoice) {
        throw new Error(
          `Channel ${channel.name} does not support voice sending`,
        );
      }
      return channel.sendVoice(jid, audioBuffer, caption);
    },
    sendFile: async (
      jid: string,
      containerPath: string,
      groupFolder: string,
      options?: SendFileOptions,
    ) => {
      const channel = findChannel(channels, jid);
      if (!channel) throw new Error(`No channel for JID: ${jid}`);
      if (!channel.sendFile) {
        throw new Error(
          `Channel ${channel.name} does not support file sending`,
        );
      }

      // Map container path (/workspace/group/...) to host path
      const groupDir = resolveGroupFolderPath(groupFolder);
      const prefix = '/workspace/group/';
      if (!containerPath.startsWith(prefix)) {
        throw new Error(`Invalid container path: ${containerPath}`);
      }
      const relativePath = containerPath.slice(prefix.length);
      const hostPath = path.resolve(groupDir, relativePath);

      // Security: ensure resolved path stays within group directory
      if (!hostPath.startsWith(groupDir + path.sep) && hostPath !== groupDir) {
        throw new Error('Path traversal blocked');
      }

      if (!fs.existsSync(hostPath)) {
        throw new Error(`File not found: ${containerPath}`);
      }

      // Resolve symlinks and verify the real path is still within groupDir.
      // This prevents a container from creating a symlink that points outside
      // its group directory (e.g. to /etc/passwd).
      let realPath: string;
      try {
        realPath = fs.realpathSync(hostPath);
      } catch {
        throw new Error(`File not accessible: ${containerPath}`);
      }
      if (!realPath.startsWith(groupDir + path.sep) && realPath !== groupDir) {
        throw new Error('Symlink traversal blocked');
      }

      return channel.sendFile(jid, hostPath, options);
    },
    registeredGroups: () => registeredGroups,
    registerGroup,
    syncGroups: async (force: boolean) => {
      await Promise.all(
        channels
          .filter((ch) => ch.syncGroups)
          .map((ch) => ch.syncGroups!(force)),
      );
    },
    getAvailableGroups,
    writeGroupsSnapshot: (gf, im, ag, rj) =>
      writeGroupsSnapshot(gf, im, ag, rj),
    onTasksChanged: () => {
      const tasks = getAllTasks();
      const taskRows = tasks.map((t) => ({
        id: t.id,
        groupFolder: t.group_folder,
        prompt: t.prompt,
        schedule_type: t.schedule_type,
        schedule_value: t.schedule_value,
        status: t.status,
        next_run: t.next_run,
      }));
      for (const group of Object.values(registeredGroups)) {
        writeTasksSnapshot(group.folder, group.isMain === true, taskRows);
      }
    },
  });
  queue.setProcessMessagesFn(processGroupMessages);
  recoverPendingMessages();
  startMessageLoop().catch((err) => {
    logger.fatal({ err }, 'Message loop crashed unexpectedly');
    process.exit(1);
  });
}

// Guard: only run when executed directly, not when imported by tests
const isDirectRun =
  process.argv[1] &&
  new URL(import.meta.url).pathname ===
    new URL(`file://${process.argv[1]}`).pathname;

if (isDirectRun) {
  main().catch((err) => {
    logger.error({ err }, 'Failed to start NanoClaw');
    process.exit(1);
  });
}
