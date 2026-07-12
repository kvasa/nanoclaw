#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import os from 'node:os';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

// Constants
const PROJECT_ROOT = path.resolve(import.meta.dirname, '..');
const BACKUPS_DIR = path.join(PROJECT_ROOT, 'backups');
const MAGIC = Buffer.from('NCBK');
// Version 2 = scrypt KDF. Version 1 (PBKDF2) is still restorable via
// restore.js, which dispatches on this header byte.
const FORMAT_VERSION = 2;
// scrypt parameters for new backups. The archive leaves the host (Slack), so
// the KDF must make offline guessing expensive. 128*N*r bytes of memory are
// needed; maxmem must sit above that or scryptSync throws.
const SCRYPT_PARAMS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
// The password is the only thing between an offline attacker and every
// credential in the archive — refuse to encrypt with a weak one.
const MIN_PASSWORD_LENGTH = 16;
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const RETENTION_DAYS = 7; // Delete encrypted backups older than this

const SKIP_DIRS = new Set([
  'logs', 'node_modules', '.git', 'dist', 'ipc',
  '.next',          // Next.js build cache
  'venv', '.venv',  // Python virtual environments
  '__pycache__',    // Python bytecode cache
  '.cache',         // Generic build caches
  'slack-uploads',  // Inbound/outbound chat attachments (bulky media)
]);
const SKIP_FILE_PATTERNS = [
  /^core\.\d+$/,
  /\.db-wal$/,
  /\.db-shm$/,
  /\.tgz$/,          // Tar archives
  /\.tar\.gz$/,      // Tar archives
  /\.so(\.\d+)*$/,   // Shared libraries (.so, .so.1.14.1)
  // Bulky binary media — not part of restorable system state.
  // Keep the backup focused on scripts, code, memory, config and the DB.
  /\.(jpe?g|png|gif|webp|bmp|tiff?|heic|heif|ico|svg)$/i, // Images
  /\.(m4a|mp3|wav|ogg|opus|aac|flac|mp4|mov|webm|mkv|avi)$/i, // Audio/video
  /\.pdf$/i,         // PDF documents
];

// ── .env parser (port of src/env.ts) ────────────────────────────────

function readEnvFile(keys) {
  const envPath = path.join(PROJECT_ROOT, '.env');
  let content;
  try {
    content = fs.readFileSync(envPath, 'utf-8');
  } catch {
    return {};
  }
  const wanted = new Set(keys);
  const result = {};
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    if (!wanted.has(key)) continue;
    let value = trimmed.slice(eqIdx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (value) result[key] = value;
  }
  return result;
}

// ── File collection ─────────────────────────────────────────────────

function shouldSkipDir(name) {
  return SKIP_DIRS.has(name);
}

function shouldSkipFile(name, size) {
  if (size > MAX_FILE_SIZE) return true;
  return SKIP_FILE_PATTERNS.some((p) => p.test(name));
}

function copyRecursive(src, dest, stats = { files: 0, bytes: 0 }) {
  // lstat, never stat: these trees are agent-writable, and a planted symlink
  // must not pull arbitrary host files into the archive. existsSync follows
  // links (a dangling symlink reports false), so a try/catch around lstatSync
  // handles missing paths, dangling symlinks and races in one place.
  let stat;
  try {
    stat = fs.lstatSync(src);
  } catch (err) {
    if (err.code === 'ENOENT') return stats;
    throw err;
  }
  if (stat.isSymbolicLink()) {
    console.log(`  [skip] symlink not followed: ${src}`);
    return stats;
  }
  if (stat.isDirectory()) {
    const entries = fs.readdirSync(src);
    for (const entry of entries) {
      if (shouldSkipDir(entry)) continue;
      copyRecursive(path.join(src, entry), path.join(dest, entry), stats);
    }
  } else if (stat.isFile()) {
    if (shouldSkipFile(path.basename(src), stat.size)) return stats;
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
    stats.files++;
    stats.bytes += stat.size;
  }
  return stats;
}

function copyFile(src, dest, stats) {
  // Same symlink policy as copyRecursive: lstat and skip links.
  let stat;
  try {
    stat = fs.lstatSync(src);
  } catch (err) {
    if (err.code === 'ENOENT') return;
    throw err;
  }
  if (stat.isSymbolicLink()) {
    console.log(`  [skip] symlink not followed: ${src}`);
    return;
  }
  if (stat.size > MAX_FILE_SIZE) return;
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  stats.files++;
  stats.bytes += stat.size;
}

// ── Active sessions lookup ───────────────────────────────────────────

function getActiveSessions() {
  const dbPath = path.join(PROJECT_ROOT, 'store', 'messages.db');
  if (!fs.existsSync(dbPath)) return {};

  try {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    const rows = db.prepare('SELECT group_folder, session_id FROM sessions').all();
    db.close();
    const result = {};
    for (const row of rows) {
      result[row.group_folder] = row.session_id;
    }
    return result;
  } catch {
    return {};
  }
}

// ── SQLite backup ───────────────────────────────────────────────────

function backupDatabase(tempDir, stats) {
  const dbPath = path.join(PROJECT_ROOT, 'store', 'messages.db');
  if (!fs.existsSync(dbPath)) {
    console.log('  [skip] store/messages.db not found');
    return;
  }

  const destPath = path.join(tempDir, 'store', 'messages.db');
  fs.mkdirSync(path.dirname(destPath), { recursive: true });

  // Try better-sqlite3 VACUUM INTO (clean snapshot, no WAL dependency)
  try {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    db.exec(`VACUUM INTO '${destPath.replace(/'/g, "''")}'`);
    db.close();
    const size = fs.statSync(destPath).size;
    stats.files++;
    stats.bytes += size;
    console.log(`  [ok] store/messages.db (VACUUM INTO, ${formatBytes(size)})`);
    return;
  } catch (err) {
    console.log(`  [warn] better-sqlite3 VACUUM INTO failed: ${err.message}`);
  }

  // Fallback: sqlite3 CLI
  try {
    execSync(`sqlite3 "${dbPath}" "VACUUM INTO '${destPath}'"`, {
      stdio: 'pipe',
    });
    const size = fs.statSync(destPath).size;
    stats.files++;
    stats.bytes += size;
    console.log(`  [ok] store/messages.db (sqlite3 CLI, ${formatBytes(size)})`);
    return;
  } catch {
    console.log('  [warn] sqlite3 CLI not available');
  }

  // Last resort: direct copy
  fs.copyFileSync(dbPath, destPath);
  const size = fs.statSync(destPath).size;
  stats.files++;
  stats.bytes += size;
  console.log(
    `  [ok] store/messages.db (direct copy, ${formatBytes(size)}) — WAL data may be incomplete`
  );
}

// ── Encryption ──────────────────────────────────────────────────────

// Validate the backup password before any archive is produced. Returns a
// human-readable reason when the password is unusable, null when it is fine.
// Never include the password (or its length) in the reason.
function validateBackupPassword(password) {
  if (!password) {
    return 'BACKUP_PASSWORD not set in .env or environment.';
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `BACKUP_PASSWORD is too short (minimum ${MIN_PASSWORD_LENGTH} characters). The encrypted archive is uploaded off-host; a weak password exposes every credential in it to offline cracking.`;
  }
  return null;
}

function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, 32, SCRYPT_PARAMS);
}

function encryptFile(inputPath, outputPath, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const key = deriveKey(password, salt);

  const plaintext = fs.readFileSync(inputPath);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Header: MAGIC(4) + VERSION(1) + SALT(16) + IV(16) + AUTH_TAG(16) = 53 bytes
  const header = Buffer.alloc(53);
  MAGIC.copy(header, 0);
  header.writeUInt8(FORMAT_VERSION, 4);
  salt.copy(header, 5);
  iv.copy(header, 21);
  authTag.copy(header, 37);

  fs.writeFileSync(outputPath, Buffer.concat([header, encrypted]));
}

// ── Helpers ─────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

// Delete encrypted backups older than RETENTION_DAYS, and sweep orphaned
// `.tmp` partials left behind by a crashed run (see encTempPath below).
// Best-effort: a failure to remove one stale file must never fail the
// backup run. This is the single retention owner for backups/ — cleanup.js
// no longer touches it.
const TMP_PARTIAL_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 1 day
const TMP_PARTIAL_RE = /^\..*\.tmp$/;

function pruneOldBackups(dir = BACKUPS_DIR) {
  if (!fs.existsSync(dir)) return;
  const encCutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const tmpCutoff = Date.now() - TMP_PARTIAL_MAX_AGE_MS;
  let removed = 0;
  let freed = 0;
  let removedPartials = 0;
  for (const name of fs.readdirSync(dir)) {
    const isEnc = name.endsWith('.enc');
    const isTmpPartial = TMP_PARTIAL_RE.test(name);
    if (!isEnc && !isTmpPartial) continue;
    const filePath = path.join(dir, name);
    try {
      const st = fs.statSync(filePath);
      if (isEnc) {
        if (st.mtimeMs >= encCutoff) continue;
        fs.unlinkSync(filePath);
        removed++;
        freed += st.size;
      } else {
        // A partial younger than the cutoff may belong to a concurrently
        // running backup — leave it alone.
        if (st.mtimeMs >= tmpCutoff) continue;
        fs.unlinkSync(filePath);
        removedPartials++;
        freed += st.size;
        console.log(`  pruned stale partial: ${name}`);
      }
    } catch (err) {
      console.log(`  [warn] could not prune ${name}: ${err.message}`);
    }
  }
  if (removed > 0 || removedPartials > 0) {
    console.log(
      `  Pruned ${removed} backup(s) older than ${RETENTION_DAYS} days and ${removedPartials} stale partial(s) (freed ${formatBytes(freed)})`
    );
  } else {
    console.log(`  No backups older than ${RETENTION_DAYS} days or stale partials to prune`);
  }
}

// ── Slack upload ────────────────────────────────────────────────────

// Resolve the target Slack channel id (without the "slack:" prefix).
// Priority: BACKUP_SLACK_CHANNEL env, then the dedicated "backups" group.
// Deliberately NO fallback to the main group: this archive carries every
// credential the system has, and a misconfiguration must skip the upload,
// not post the secrets into whatever channel happens to be primary.
const BACKUP_CHANNEL_FOLDER = 'backups';

function resolveSlackChannelId(
  envChannel,
  dbPath = path.join(PROJECT_ROOT, 'store', 'messages.db'),
) {
  if (envChannel) return envChannel.replace(/^slack:/, '');
  if (!fs.existsSync(dbPath)) return null;
  try {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');
    const db = new Database(dbPath, { readonly: true });
    const row = db
      .prepare('SELECT jid FROM registered_groups WHERE folder = ? LIMIT 1')
      .get(BACKUP_CHANNEL_FOLDER);
    db.close();
    if (!row || !row.jid) return null;
    return String(row.jid).replace(/^slack:/, '');
  } catch {
    return null;
  }
}

// Upload the encrypted backup straight to Slack. Best-effort: a failed
// upload (no token, channel, network) must not fail the backup itself —
// the local archive and prune have already succeeded by this point.
async function sendBackupToSlack(encFilePath) {
  const env = readEnvFile(['SLACK_BOT_TOKEN', 'BACKUP_SLACK_CHANNEL']);
  const botToken = env.SLACK_BOT_TOKEN || process.env.SLACK_BOT_TOKEN;
  if (!botToken) {
    console.log('  [skip] SLACK_BOT_TOKEN not set — backup not sent to Slack');
    return;
  }
  const channelId = resolveSlackChannelId(
    env.BACKUP_SLACK_CHANNEL || process.env.BACKUP_SLACK_CHANNEL
  );
  if (!channelId) {
    console.log(
      '  [skip] no dedicated backup channel (set BACKUP_SLACK_CHANNEL or create a "backups" group) — backup not sent'
    );
    return;
  }
  try {
    const require = createRequire(import.meta.url);
    const { WebClient } = require('@slack/web-api');
    const client = new WebClient(botToken);
    const fileData = fs.readFileSync(encFilePath);
    await client.filesUploadV2({
      channel_id: channelId,
      file: fileData,
      filename: path.basename(encFilePath),
      initial_comment: 'Automatická záloha NanoClaw (šifrovaná).',
    });
    console.log(`  [ok] sent to Slack channel ${channelId} (${formatBytes(fileData.length)})`);
  } catch (err) {
    console.log(`  [warn] Slack upload failed: ${err.message}`);
  }
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
  console.log('NanoClaw Backup\n');

  // 1. Read and validate password — refuse to produce a weakly-protected
  // archive rather than upload one to a third party.
  const env = readEnvFile(['BACKUP_PASSWORD']);
  const password = env.BACKUP_PASSWORD || process.env.BACKUP_PASSWORD;
  const passwordProblem = validateBackupPassword(password);
  if (passwordProblem) {
    console.error(`Error: ${passwordProblem}`);
    console.error('Set a strong BACKUP_PASSWORD in .env and try again.');
    process.exit(1);
  }

  const tempDir = path.join(os.tmpdir(), `ncbk-${Date.now()}`);
  const tarPath = `${tempDir}.tar.gz`;

  try {
    fs.mkdirSync(tempDir, { recursive: true });
    const stats = { files: 0, bytes: 0 };

    // 2. SQLite backup
    console.log('Backing up database...');
    backupDatabase(tempDir, stats);

    // 3. Collect files
    console.log('Collecting files...');

    // store/auth/
    const authStats = copyRecursive(
      path.join(PROJECT_ROOT, 'store', 'auth'),
      path.join(tempDir, 'store', 'auth'),
      stats
    );
    console.log(`  [ok] store/auth/ (${authStats.files} files total so far)`);

    // store metadata
    for (const f of ['auth-status.txt', 'qr-data.txt']) {
      copyFile(
        path.join(PROJECT_ROOT, 'store', f),
        path.join(tempDir, 'store', f),
        stats
      );
    }

    // .env
    copyFile(path.join(PROJECT_ROOT, '.env'), path.join(tempDir, '.env'), stats);

    // .nanoclaw/state.yaml + base/
    copyFile(
      path.join(PROJECT_ROOT, '.nanoclaw', 'state.yaml'),
      path.join(tempDir, '.nanoclaw', 'state.yaml'),
      stats
    );
    copyRecursive(
      path.join(PROJECT_ROOT, '.nanoclaw', 'base'),
      path.join(tempDir, '.nanoclaw', 'base'),
      stats
    );

    // groups/
    const groupsDir = path.join(PROJECT_ROOT, 'groups');
    if (fs.existsSync(groupsDir)) {
      for (const group of fs.readdirSync(groupsDir)) {
        const groupPath = path.join(groupsDir, group);
        if (!fs.statSync(groupPath).isDirectory()) continue;
        copyRecursive(groupPath, path.join(tempDir, 'groups', group), stats);
      }
      console.log(`  [ok] groups/ (${stats.files} files total so far)`);
    }

    // data/sessions/ (selective: memory, settings, active session transcript only)
    const sessionsDir = path.join(PROJECT_ROOT, 'data', 'sessions');
    const activeSessions = getActiveSessions();
    if (fs.existsSync(sessionsDir)) {
      for (const group of fs.readdirSync(sessionsDir)) {
        const groupPath = path.join(sessionsDir, group);
        if (!fs.statSync(groupPath).isDirectory()) continue;
        const destGroup = path.join(tempDir, 'data', 'sessions', group);

        // settings.json
        copyFile(
          path.join(groupPath, '.claude', 'settings.json'),
          path.join(destGroup, '.claude', 'settings.json'),
          stats
        );

        // memory/
        copyRecursive(
          path.join(groupPath, '.claude', 'projects', '-workspace-group', 'memory'),
          path.join(destGroup, '.claude', 'projects', '-workspace-group', 'memory'),
          stats
        );

        // sessions-index.json
        copyFile(
          path.join(groupPath, '.claude', 'projects', '-workspace-group', 'sessions-index.json'),
          path.join(destGroup, '.claude', 'projects', '-workspace-group', 'sessions-index.json'),
          stats
        );

        // Active session JSONL transcript only
        const activeId = activeSessions[group];
        if (activeId) {
          copyFile(
            path.join(groupPath, '.claude', 'projects', '-workspace-group', `${activeId}.jsonl`),
            path.join(destGroup, '.claude', 'projects', '-workspace-group', `${activeId}.jsonl`),
            stats
          );
        }

        // agent-runner-src/ (per-group customized agent runner)
        copyRecursive(
          path.join(groupPath, 'agent-runner-src'),
          path.join(destGroup, 'agent-runner-src'),
          stats
        );
      }
      console.log(`  [ok] data/sessions/ (selective, ${stats.files} files total so far)`);
    }

    // data/env/env
    copyFile(
      path.join(PROJECT_ROOT, 'data', 'env', 'env'),
      path.join(tempDir, 'data', 'env', 'env'),
      stats
    );

    console.log(`\nCollected ${stats.files} files (${formatBytes(stats.bytes)} uncompressed)`);

    // 4. Create tar.gz
    console.log('Creating archive...');
    execSync(`tar -czf "${tarPath}" -C "${tempDir}" .`, { stdio: 'pipe' });
    const tarSize = fs.statSync(tarPath).size;
    console.log(`  Archive: ${formatBytes(tarSize)}`);

    // 5. Encrypt
    console.log('Encrypting...');
    fs.mkdirSync(BACKUPS_DIR, { recursive: true });
    const encName = `nanoclaw-backup-${timestamp()}.tar.gz.enc`;
    const encTempPath = path.join(BACKUPS_DIR, `.${encName}.tmp`);
    const encFinalPath = path.join(BACKUPS_DIR, encName);

    encryptFile(tarPath, encTempPath, password);
    fs.renameSync(encTempPath, encFinalPath);

    const encSize = fs.statSync(encFinalPath).size;

    console.log(`\nBackup complete!`);
    console.log(`  File: ${encFinalPath}`);
    console.log(`  Size: ${formatBytes(encSize)}`);
    console.log(`  Files: ${stats.files}`);

    // Retention: remove backups older than RETENTION_DAYS. Only after a
    // successful new backup so we never prune our way to zero on failure.
    console.log('\nPruning old backups...');
    pruneOldBackups();

    // Send the encrypted archive to Slack (best-effort; never fails the run).
    // Pass --no-slack to create+prune locally without sending (useful for tests).
    if (process.argv.includes('--no-slack')) {
      console.log('\n[--no-slack] Skipping Slack upload');
    } else {
      console.log('\nSending to Slack...');
      await sendBackupToSlack(encFinalPath);
    }
  } finally {
    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });
    if (fs.existsSync(tarPath)) fs.unlinkSync(tarPath);
  }
}

// Exported for tests only; run main() only when executed directly so the
// test import does not trigger a real backup.
export {
  encryptFile,
  deriveKey,
  validateBackupPassword,
  resolveSlackChannelId,
  copyRecursive,
  pruneOldBackups,
  FORMAT_VERSION,
  MIN_PASSWORD_LENGTH,
  SCRYPT_PARAMS,
};

const isDirectRun =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isDirectRun) {
  main().catch((err) => {
    console.error('Backup failed:', err);
    process.exit(1);
  });
}
