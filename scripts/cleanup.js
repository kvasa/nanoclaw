#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';

// Constants
const PROJECT_ROOT = path.resolve(import.meta.dirname, '..');
const DRY_RUN = process.argv.includes('--dry-run');
const MAX_AGE_DAYS = 14;
const MAX_AGE_MS = MAX_AGE_DAYS * 24 * 60 * 60 * 1000;

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist']);

// Stats tracker
const stats = { deleted: 0, bytesFreed: 0, errors: 0 };

// ── Helpers ─────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function safeDelete(filePath) {
  try {
    const size = fs.statSync(filePath).size;
    if (DRY_RUN) {
      console.log(`  [dry-run] would delete ${path.relative(PROJECT_ROOT, filePath)} (${formatBytes(size)})`);
    } else {
      fs.unlinkSync(filePath);
      console.log(`  [deleted] ${path.relative(PROJECT_ROOT, filePath)} (${formatBytes(size)})`);
    }
    stats.deleted++;
    stats.bytesFreed += size;
  } catch (err) {
    console.log(`  [error] ${path.relative(PROJECT_ROOT, filePath)}: ${err.message}`);
    stats.errors++;
  }
}

function walkDir(dir, callback) {
  if (!fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walkDir(fullPath, callback);
    } else if (entry.isFile()) {
      callback(fullPath, entry.name);
    }
  }
}

// ── 1. Container logs (groups/*/logs/) ──────────────────────────────

function cleanContainerLogs() {
  const groupsDir = path.join(PROJECT_ROOT, 'groups');
  if (!fs.existsSync(groupsDir)) { console.log('  [skip] groups/ not found'); return; }

  const cutoff = Date.now() - MAX_AGE_MS;
  const dateRe = /^container-(\d{4}-\d{2}-\d{2})T/;
  let count = 0;

  for (const group of fs.readdirSync(groupsDir, { withFileTypes: true })) {
    if (!group.isDirectory()) continue;
    const logsDir = path.join(groupsDir, group.name, 'logs');
    if (!fs.existsSync(logsDir)) continue;

    for (const file of fs.readdirSync(logsDir, { withFileTypes: true })) {
      if (!file.isFile() || !file.name.endsWith('.log')) continue;
      const filePath = path.join(logsDir, file.name);

      // Parse date from filename, fallback to mtime
      const match = dateRe.exec(file.name);
      let fileTime;
      if (match) {
        fileTime = new Date(match[1]).getTime();
      } else {
        fileTime = fs.statSync(filePath).mtimeMs;
      }

      if (fileTime < cutoff) {
        safeDelete(filePath);
        count++;
      }
    }
  }

  if (count === 0) console.log(`  [skip] no logs older than ${MAX_AGE_DAYS} days`);
}

// ── 2. Old backups (backups/) ───────────────────────────────────────

function cleanOldBackups() {
  const backupsDir = path.join(PROJECT_ROOT, 'backups');
  if (!fs.existsSync(backupsDir)) { console.log('  [skip] backups/ not found'); return; }

  const cutoff = Date.now() - MAX_AGE_MS;
  const backupRe = /^nanoclaw-backup-(\d{4}-\d{2}-\d{2})T/;

  const backups = fs.readdirSync(backupsDir)
    .filter(f => backupRe.test(f))
    .map(f => {
      const match = backupRe.exec(f);
      return { name: f, date: new Date(match[1]).getTime() };
    })
    .sort((a, b) => b.date - a.date); // newest first

  if (backups.length === 0) { console.log('  [skip] no backups found'); return; }

  // Always keep at least 1 backup
  console.log(`  [keep] ${backups[0].name} (newest, always kept)`);
  let count = 0;

  for (let i = 1; i < backups.length; i++) {
    if (backups[i].date < cutoff) {
      safeDelete(path.join(backupsDir, backups[i].name));
      count++;
    }
  }

  if (count === 0) console.log(`  [skip] no backups older than ${MAX_AGE_DAYS} days`);
}

// ── 3. Docker cache ─────────────────────────────────────────────────

function cleanDockerCache() {
  const commands = [
    { label: 'buildx prune', cmd: 'docker buildx prune --all --force' },
    { label: 'image prune', cmd: 'docker image prune --force' },
    { label: 'container prune', cmd: 'docker container prune --force' },
  ];

  for (const { label, cmd } of commands) {
    if (DRY_RUN) {
      console.log(`  [dry-run] would run: ${cmd}`);
      continue;
    }
    try {
      const output = execSync(cmd, { stdio: 'pipe', timeout: 120_000 }).toString();
      const reclaimedMatch = output.match(/Total reclaimed space:\s*(.+)/i);
      const reclaimed = reclaimedMatch ? reclaimedMatch[1].trim() : '0 B';
      console.log(`  [ok] ${label}: ${reclaimed} reclaimed`);
    } catch (err) {
      console.log(`  [warn] ${label}: ${err.message}`);
    }
  }
}

// ── 4. Core dump files ──────────────────────────────────────────────

function cleanCoreDumps() {
  const coreRe = /^core\.\d+$/;
  let count = 0;

  const scanDirs = [
    path.join(PROJECT_ROOT, 'groups'),
    path.join(PROJECT_ROOT, 'data', 'sessions'),
  ];

  for (const dir of scanDirs) {
    walkDir(dir, (filePath, fileName) => {
      if (coreRe.test(fileName)) {
        safeDelete(filePath);
        count++;
      }
    });
  }

  if (count === 0) console.log('  [skip] no core dumps found');
}

// ── 5. Session debug files (data/sessions/) ─────────────────────────

function cleanSessionDebugFiles() {
  const sessionsDir = path.join(PROJECT_ROOT, 'data', 'sessions');
  if (!fs.existsSync(sessionsDir)) { console.log('  [skip] data/sessions/ not found'); return; }

  const cutoff = Date.now() - MAX_AGE_MS;
  let count = 0;

  for (const session of fs.readdirSync(sessionsDir, { withFileTypes: true })) {
    if (!session.isDirectory()) continue;

    const subDirs = [
      path.join(sessionsDir, session.name, '.claude', 'debug'),
      path.join(sessionsDir, session.name, '.claude', 'shell-snapshots'),
    ];

    for (const subDir of subDirs) {
      if (!fs.existsSync(subDir)) continue;
      for (const file of fs.readdirSync(subDir, { withFileTypes: true })) {
        if (!file.isFile()) continue;
        const filePath = path.join(subDir, file.name);
        try {
          if (fs.statSync(filePath).mtimeMs < cutoff) {
            safeDelete(filePath);
            count++;
          }
        } catch { /* skip unreadable files */ }
      }
    }
  }

  if (count === 0) console.log(`  [skip] no debug files older than ${MAX_AGE_DAYS} days`);
}

// ── 6. IPC error logs (data/ipc/errors/) ────────────────────────────

function cleanIpcErrors() {
  const errorsDir = path.join(PROJECT_ROOT, 'data', 'ipc', 'errors');
  if (!fs.existsSync(errorsDir)) { console.log('  [skip] data/ipc/errors/ not found'); return; }

  const cutoff = Date.now() - MAX_AGE_MS;
  let count = 0;

  for (const file of fs.readdirSync(errorsDir, { withFileTypes: true })) {
    if (!file.isFile() || !file.name.endsWith('.json')) continue;
    const filePath = path.join(errorsDir, file.name);
    try {
      if (fs.statSync(filePath).mtimeMs < cutoff) {
        safeDelete(filePath);
        count++;
      }
    } catch { /* skip unreadable files */ }
  }

  if (count === 0) console.log(`  [skip] no error logs older than ${MAX_AGE_DAYS} days`);
}

// ── 7. SQLite VACUUM (store/messages.db) ────────────────────────────

function vacuumDatabase() {
  const dbPath = path.join(PROJECT_ROOT, 'store', 'messages.db');
  if (!fs.existsSync(dbPath)) { console.log('  [skip] store/messages.db not found'); return; }

  if (DRY_RUN) {
    const size = fs.statSync(dbPath).size;
    console.log(`  [dry-run] would VACUUM store/messages.db (${formatBytes(size)})`);
    return;
  }

  const sizeBefore = fs.statSync(dbPath).size;

  // Try better-sqlite3
  try {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');
    const db = new Database(dbPath);
    db.exec('VACUUM');
    db.close();
    const sizeAfter = fs.statSync(dbPath).size;
    const freed = sizeBefore - sizeAfter;
    if (freed > 0) {
      console.log(`  [ok] VACUUM freed ${formatBytes(freed)} (${formatBytes(sizeBefore)} -> ${formatBytes(sizeAfter)})`);
      stats.bytesFreed += freed;
    } else {
      console.log(`  [ok] VACUUM complete, no space to reclaim (${formatBytes(sizeAfter)})`);
    }
    return;
  } catch (err) {
    if (err.message?.includes('locked')) {
      console.log(`  [warn] database locked (NanoClaw is running), skipping VACUUM`);
      return;
    }
    // Fall through to sqlite3 CLI
  }

  // Fallback: sqlite3 CLI
  try {
    execSync(`sqlite3 "${dbPath}" "VACUUM"`, { stdio: 'pipe', timeout: 30_000 });
    const sizeAfter = fs.statSync(dbPath).size;
    const freed = sizeBefore - sizeAfter;
    if (freed > 0) {
      console.log(`  [ok] VACUUM freed ${formatBytes(freed)} (sqlite3 CLI)`);
      stats.bytesFreed += freed;
    } else {
      console.log(`  [ok] VACUUM complete, no space to reclaim (sqlite3 CLI)`);
    }
  } catch (err) {
    if (err.message?.includes('locked')) {
      console.log(`  [warn] database locked (NanoClaw is running), skipping VACUUM`);
    } else {
      console.log(`  [skip] no SQLite interface available`);
    }
  }
}

// ── Main ────────────────────────────────────────────────────────────

function main() {
  console.log(`NanoClaw Cleanup${DRY_RUN ? ' (DRY RUN)' : ''}\n`);

  console.log('1. Container logs (groups/*/logs/)...');
  cleanContainerLogs();

  console.log('\n2. Old backups (backups/)...');
  cleanOldBackups();

  console.log('\n3. Docker cache...');
  cleanDockerCache();

  console.log('\n4. Core dump files...');
  cleanCoreDumps();

  console.log('\n5. Session debug files (data/sessions/)...');
  cleanSessionDebugFiles();

  console.log('\n6. IPC error logs (data/ipc/errors/)...');
  cleanIpcErrors();

  console.log('\n7. SQLite VACUUM (store/messages.db)...');
  vacuumDatabase();

  console.log('\n' + '='.repeat(50));
  console.log('Cleanup complete!');
  console.log(`  Files deleted: ${stats.deleted}`);
  console.log(`  Space freed: ${formatBytes(stats.bytesFreed)}`);
  if (stats.errors > 0) console.log(`  Errors: ${stats.errors}`);
  if (DRY_RUN) console.log('\n  (Dry run — no files were actually deleted)');
}

main();
