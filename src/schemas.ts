/**
 * Zod schemas for IPC message validation and container I/O.
 * Replaces manual field checks with type-safe parsing.
 */
import { z } from 'zod';

// --- IPC Message Schemas (processIpcFiles) ---

export const IpcMessageSchema = z.object({
  type: z.literal('message'),
  chatJid: z.string(),
  text: z.string(),
});

export const IpcSendFileSchema = z.object({
  type: z.literal('send_file'),
  chatJid: z.string(),
  filePath: z.string(),
  options: z
    .object({
      filename: z.string().optional(),
      initialComment: z.string().optional(),
      title: z.string().optional(),
    })
    .optional(),
});

export const IpcSendVoiceSchema = z.object({
  type: z.literal('send_voice'),
  chatJid: z.string(),
  text: z.string(),
  voice: z.string().optional(),
  caption: z.string().optional(),
});

export const IpcSendEmailSchema = z.object({
  type: z.literal('send_email'),
  threadJid: z
    .string()
    .regex(/^gmail:[a-f0-9]+$/i, 'Invalid Gmail thread JID format'),
  text: z.string(),
});

export const IpcComposeEmailSchema = z.object({
  type: z.literal('compose_email'),
  to: z.string().email(),
  subject: z.string(),
  body: z.string(),
});

export const IpcReadEmailsSchema = z.object({
  type: z.literal('read_emails'),
  query: z.string().optional(),
  maxResults: z.number().int().min(1).max(50).optional(),
  requestId: z.string().max(128).regex(/^[a-zA-Z0-9_-]+$/),
});

export const IpcFileMessageSchema = z.discriminatedUnion('type', [
  IpcMessageSchema,
  IpcSendFileSchema,
  IpcSendVoiceSchema,
  IpcSendEmailSchema,
  IpcComposeEmailSchema,
  IpcReadEmailsSchema,
]);

// --- IPC Task Schemas (processTaskIpc) ---

export const IpcScheduleTaskSchema = z.object({
  type: z.literal('schedule_task'),
  prompt: z.string(),
  schedule_type: z.enum(['cron', 'interval', 'once']),
  schedule_value: z.string(),
  targetJid: z.string(),
  taskId: z.string().optional(),
  context_mode: z.enum(['group', 'isolated']).optional(),
  groupFolder: z.string().optional(),
  chatJid: z.string().optional(),
});

export const IpcTaskIdSchema = z.object({
  taskId: z.string(),
});

export const IpcPauseTaskSchema = IpcTaskIdSchema.extend({
  type: z.literal('pause_task'),
});

export const IpcResumeTaskSchema = IpcTaskIdSchema.extend({
  type: z.literal('resume_task'),
});

export const IpcCancelTaskSchema = IpcTaskIdSchema.extend({
  type: z.literal('cancel_task'),
});

export const IpcUpdateTaskSchema = z.object({
  type: z.literal('update_task'),
  taskId: z.string(),
  prompt: z.string().optional(),
  schedule_type: z.enum(['cron', 'interval', 'once']).optional(),
  schedule_value: z.string().optional(),
});

export const IpcRefreshGroupsSchema = z.object({
  type: z.literal('refresh_groups'),
});

export const IpcRegisterGroupSchema = z.object({
  type: z.literal('register_group'),
  jid: z.string(),
  name: z.string(),
  folder: z.string(),
  trigger: z.string(),
  requiresTrigger: z.boolean().optional(),
  containerConfig: z
    .object({
      additionalMounts: z
        .array(
          z.object({
            hostPath: z.string(),
            containerPath: z.string().optional(),
            readonly: z.boolean().optional(),
          }),
        )
        .optional(),
      timeout: z.number().optional(),
      enabledMcpServers: z.array(z.string()).optional(),
    })
    .optional(),
});

// --- Container Output Schema ---

export const ContainerOutputSchema = z.object({
  status: z.enum(['success', 'error']),
  result: z.string().nullable(),
  newSessionId: z.string().optional(),
  error: z.string().optional(),
});
