#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import os from 'node:os';
import { createRequire } from 'node:module';

// Constants
const PROJECT_ROOT = path.resolve(import.meta.dirname, '..');
const BACKUPS_DIR = path.join(PROJECT_ROOT, 'backups');
const MAGIC = Buffer.from('NCBK');
const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 100_000;
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

const SKIP_DIRS = new Set(['logs', 'node_modules', '.git', 'dist', 'ipc']);
const SKIP_FILE_PATTERNS = [/^core\.\d+$/, /\.db-wal$/, /\.db-shm$/];

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
  if (!fs.existsSync(src)) return stats;

  const stat = fs.statSync(src);
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
  if (!fs.existsSync(src)) return;
  const stat = fs.statSync(src);
  if (stat.size > MAX_FILE_SIZE) return;
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  stats.files++;
  stats.bytes += stat.size;
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

function encryptFile(inputPath, outputPath, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha512');

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

// ── Main ────────────────────────────────────────────────────────────

function main() {
  console.log('NanoClaw Backup\n');

  // 1. Read password
  const env = readEnvFile(['BACKUP_PASSWORD']);
  const password = env.BACKUP_PASSWORD || process.env.BACKUP_PASSWORD;
  if (!password) {
    console.error('Error: BACKUP_PASSWORD not set in .env or environment.');
    console.error('Add BACKUP_PASSWORD=your-password to .env and try again.');
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

    // data/sessions/
    copyRecursive(
      path.join(PROJECT_ROOT, 'data', 'sessions'),
      path.join(tempDir, 'data', 'sessions'),
      stats
    );
    console.log(`  [ok] data/sessions/`);

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
  } finally {
    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });
    if (fs.existsSync(tarPath)) fs.unlinkSync(tarPath);
  }
}

main();
