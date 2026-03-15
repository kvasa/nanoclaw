import path from 'path';

import { readEnvFile } from './env.js';

// Read config values from .env (falls back to process.env).
// Secrets (API keys, tokens) are NOT read here — they are loaded only
// by the credential proxy (credential-proxy.ts), never exposed to containers.
const envConfig = readEnvFile([
  'ASSISTANT_NAME',
  'ASSISTANT_HAS_OWN_NUMBER',
  'LOG_LEVEL',
  'GMAIL_ALLOWED_SENDERS',
  'GMAIL_ALLOWED_DOMAINS',
  'GMAIL_RATE_LIMIT_PER_SENDER',
  'GMAIL_RATE_LIMIT_GLOBAL',
  'GMAIL_RATE_LIMIT_WINDOW_MS',
  'GMAIL_RATE_LIMIT_OUTGOING',
]);

export const ASSISTANT_NAME =
  process.env.ASSISTANT_NAME || envConfig.ASSISTANT_NAME || 'Andy';
export const ASSISTANT_HAS_OWN_NUMBER =
  (process.env.ASSISTANT_HAS_OWN_NUMBER ||
    envConfig.ASSISTANT_HAS_OWN_NUMBER) === 'true';
export const POLL_INTERVAL = 2000;
export const SCHEDULER_POLL_INTERVAL = 60000;

// Absolute paths needed for container mounts
const PROJECT_ROOT = process.cwd();
const HOME_DIR = process.env.HOME || '/Users/user';

// Mount security: allowlist stored OUTSIDE project root, never mounted into containers
export const MOUNT_ALLOWLIST_PATH = path.join(
  HOME_DIR,
  '.config',
  'nanoclaw',
  'mount-allowlist.json',
);
export const SENDER_ALLOWLIST_PATH = path.join(
  HOME_DIR,
  '.config',
  'nanoclaw',
  'sender-allowlist.json',
);
export const STORE_DIR = path.resolve(PROJECT_ROOT, 'store');
export const GROUPS_DIR = path.resolve(PROJECT_ROOT, 'groups');
export const DATA_DIR = path.resolve(PROJECT_ROOT, 'data');

export const CONTAINER_IMAGE =
  process.env.CONTAINER_IMAGE || 'nanoclaw-agent:latest';
export const CONTAINER_TIMEOUT = parseInt(
  process.env.CONTAINER_TIMEOUT || '1800000',
  10,
);
export const CONTAINER_MAX_OUTPUT_SIZE = parseInt(
  process.env.CONTAINER_MAX_OUTPUT_SIZE || '10485760',
  10,
); // 10MB default
export const CREDENTIAL_PROXY_PORT = parseInt(
  process.env.CREDENTIAL_PROXY_PORT || '3001',
  10,
);
export const IPC_POLL_INTERVAL = 1000;
export const IDLE_TIMEOUT = parseInt(process.env.IDLE_TIMEOUT || '1800000', 10); // 30min default — how long to keep container alive after last result
export const MAX_CONCURRENT_CONTAINERS = Math.max(
  1,
  parseInt(process.env.MAX_CONCURRENT_CONTAINERS || '5', 10) || 5,
);

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export const TRIGGER_PATTERN = new RegExp(
  `^@${escapeRegex(ASSISTANT_NAME)}\\b`,
  'i',
);

// Timezone for scheduled tasks (cron expressions, etc.)
// Uses system timezone by default
export const TIMEZONE =
  process.env.TZ || Intl.DateTimeFormat().resolvedOptions().timeZone;

export const LOG_LEVEL = process.env.LOG_LEVEL || envConfig.LOG_LEVEL || 'info';

// Gmail sender allowlist (optional). If set, only emails from these addresses/domains are processed.
// GMAIL_ALLOWED_SENDERS: comma-separated email addresses, e.g. "alice@example.com,bob@work.com"
// GMAIL_ALLOWED_DOMAINS: comma-separated domains, e.g. "example.com,work.com"
const _gmailSenders =
  process.env.GMAIL_ALLOWED_SENDERS || envConfig.GMAIL_ALLOWED_SENDERS || '';
const _gmailDomains =
  process.env.GMAIL_ALLOWED_DOMAINS || envConfig.GMAIL_ALLOWED_DOMAINS || '';
export const GMAIL_ALLOWED_SENDERS: Set<string> = new Set(
  _gmailSenders
    ? _gmailSenders
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    : [],
);
export const GMAIL_ALLOWED_DOMAINS: Set<string> = new Set(
  _gmailDomains
    ? _gmailDomains
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    : [],
);

// Rate limiting: max emails processed per sender per window, and global max per window.
// GMAIL_RATE_LIMIT_PER_SENDER: max emails from one sender per window (default 5)
// GMAIL_RATE_LIMIT_GLOBAL: max emails total per window (default 20)
// GMAIL_RATE_LIMIT_OUTGOING: max outgoing emails (sent+rejected) per window (default 10)
// GMAIL_RATE_LIMIT_WINDOW_MS: window in ms (default 3600000 = 1 hour)
export const GMAIL_RATE_LIMIT_PER_SENDER = parseInt(
  process.env.GMAIL_RATE_LIMIT_PER_SENDER ||
    envConfig.GMAIL_RATE_LIMIT_PER_SENDER ||
    '5',
  10,
);
export const GMAIL_RATE_LIMIT_GLOBAL = parseInt(
  process.env.GMAIL_RATE_LIMIT_GLOBAL ||
    envConfig.GMAIL_RATE_LIMIT_GLOBAL ||
    '20',
  10,
);
export const GMAIL_RATE_LIMIT_OUTGOING = parseInt(
  process.env.GMAIL_RATE_LIMIT_OUTGOING ||
    envConfig.GMAIL_RATE_LIMIT_OUTGOING ||
    '10',
  10,
);
export const GMAIL_RATE_LIMIT_WINDOW_MS = parseInt(
  process.env.GMAIL_RATE_LIMIT_WINDOW_MS ||
    envConfig.GMAIL_RATE_LIMIT_WINDOW_MS ||
    '3600000',
  10,
);

// Reaction emoji progression timing (eyes → gear delay)
export const REACTION_TRANSITION_DELAY_MS = 2000;

// Default message fetch limit for getNewMessages / getMessagesSince
export const DEFAULT_MESSAGE_LIMIT = 200;

// How long to wait after task result before closing container stdin
export const TASK_CLOSE_DELAY_MS = 10000;

// Retry backoff for failed container runs
export const MAX_RETRIES = 5;
export const BASE_RETRY_MS = 5000;
