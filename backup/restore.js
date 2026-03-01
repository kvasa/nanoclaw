#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import os from 'node:os';
import readline from 'node:readline';

// Constants (must match backup.js)
const PROJECT_ROOT = path.resolve(import.meta.dirname, '..');
const BACKUPS_DIR = path.join(PROJECT_ROOT, 'backups');
const MAGIC = Buffer.from('NCBK');
const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 100_000;
const HEADER_SIZE = 53; // MAGIC(4) + VERSION(1) + SALT(16) + IV(16) + AUTH_TAG(16)

const CRITICAL_FILES = [
  'store/messages.db',
  '.env',
  'store/auth',
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

// ── Password acquisition ────────────────────────────────────────────

async function getPassword() {
  // 1. Try .env
  const env = readEnvFile(['BACKUP_PASSWORD']);
  if (env.BACKUP_PASSWORD) return env.BACKUP_PASSWORD;

  // 2. Try environment variable
  if (process.env.BACKUP_PASSWORD) return process.env.BACKUP_PASSWORD;

  // 3. Interactive prompt
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question('Enter backup password: ', (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// ── Decryption ──────────────────────────────────────────────────────

function decryptFile(inputPath, outputPath, password) {
  const data = fs.readFileSync(inputPath);

  if (data.length < HEADER_SIZE) {
    throw new Error('File too small to be a valid backup.');
  }

  // Verify magic bytes
  if (!data.subarray(0, 4).equals(MAGIC)) {
    throw new Error('Not a valid NanoClaw backup file (bad magic bytes).');
  }

  const version = data.readUInt8(4);
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported backup format version: ${version} (expected ${FORMAT_VERSION}).`);
  }

  const salt = data.subarray(5, 21);
  const iv = data.subarray(21, 37);
  const authTag = data.subarray(37, 53);
  const encrypted = data.subarray(53);

  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha512');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  try {
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    fs.writeFileSync(outputPath, decrypted);
  } catch {
    throw new Error('Decryption failed — wrong password or corrupted backup.');
  }
}

// ── Backup selection ────────────────────────────────────────────────

function listBackups() {
  if (!fs.existsSync(BACKUPS_DIR)) return [];
  return fs
    .readdirSync(BACKUPS_DIR)
    .filter((f) => f.endsWith('.tar.gz.enc'))
    .sort()
    .reverse();
}

function resolveBackupPath(arg) {
  if (arg) {
    const resolved = path.resolve(arg);
    if (!fs.existsSync(resolved)) {
      console.error(`Error: Backup file not found: ${resolved}`);
      process.exit(1);
    }
    return resolved;
  }

  const backups = listBackups();
  if (backups.length === 0) {
    console.error('No backups found in backups/ directory.');
    console.error('Usage: node backup/restore.js <path-to-backup> [--force]');
    process.exit(1);
  }

  console.log('Available backups:');
  for (const [i, name] of backups.entries()) {
    const size = fs.statSync(path.join(BACKUPS_DIR, name)).size;
    console.log(`  ${i + 1}. ${name} (${formatBytes(size)})`);
  }
  console.log(`\nUsing latest: ${backups[0]}\n`);
  return path.join(BACKUPS_DIR, backups[0]);
}

// ── Safety checks ───────────────────────────────────────────────────

function checkExistingFiles(force) {
  const existing = CRITICAL_FILES.filter((f) =>
    fs.existsSync(path.join(PROJECT_ROOT, f))
  );

  if (existing.length > 0 && !force) {
    console.error('Warning: The following files/directories already exist:');
    for (const f of existing) {
      console.error(`  - ${f}`);
    }
    console.error('\nRestore will overwrite these files.');
    console.error('Use --force to proceed, or move them manually first.');
    process.exit(1);
  }

  return existing;
}

// ── Post-restore verification ───────────────────────────────────────

function verifyRestore() {
  const results = [];
  for (const f of CRITICAL_FILES) {
    const fullPath = path.join(PROJECT_ROOT, f);
    const exists = fs.existsSync(fullPath);
    results.push({ file: f, exists });
  }
  return results;
}

// ── Helpers ─────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
  console.log('NanoClaw Restore\n');

  // Parse arguments
  const args = process.argv.slice(2);
  const force = args.includes('--force');
  const backupArg = args.find((a) => !a.startsWith('--'));

  // 1. Check if NanoClaw is running
  try {
    execSync('systemctl --user is-active nanoclaw', { stdio: 'pipe' });
    console.error('Error: NanoClaw is currently running. Stop it before restoring:');
    console.error('  systemctl --user stop nanoclaw');
    process.exit(1);
  } catch {
    // not running — good
  }

  // 2. Resolve backup file
  const backupPath = resolveBackupPath(backupArg);
  console.log(`Backup: ${backupPath}`);

  // 2. Get password
  const password = await getPassword();
  if (!password) {
    console.error('Error: No password provided.');
    process.exit(1);
  }

  // 3. Safety check
  const existing = checkExistingFiles(force);
  if (existing.length > 0) {
    console.log(`Overwriting ${existing.length} existing file(s) (--force)\n`);
  }

  const tarPath = path.join(os.tmpdir(), `ncbk-restore-${Date.now()}.tar.gz`);

  try {
    // 4. Decrypt
    console.log('Decrypting...');
    decryptFile(backupPath, tarPath, password);
    const tarSize = fs.statSync(tarPath).size;
    console.log(`  Decrypted archive: ${formatBytes(tarSize)}`);

    // 5. Remove stale SQLite WAL/SHM files (they belong to the old DB, not the restored one)
    for (const ext of ['-wal', '-shm']) {
      const walPath = path.join(PROJECT_ROOT, 'store', `messages.db${ext}`);
      if (fs.existsSync(walPath)) {
        fs.unlinkSync(walPath);
        console.log(`  Removed stale ${path.basename(walPath)}`);
      }
    }

    // 6. Extract
    console.log('Extracting...');
    execSync(`tar -xzf "${tarPath}" -C "${PROJECT_ROOT}"`, { stdio: 'pipe' });
    console.log('  Files extracted to project root.');

    // 6. Verify
    console.log('\nVerification:');
    const results = verifyRestore();
    let allOk = true;
    for (const { file, exists } of results) {
      const status = exists ? 'ok' : 'MISSING';
      if (!exists) allOk = false;
      console.log(`  [${status}] ${file}`);
    }

    console.log(`\nRestore ${allOk ? 'complete' : 'completed with warnings'}!`);
    console.log('\nNext steps:');
    console.log('  1. npm install');
    console.log('  2. npm run build');
    console.log('  3. npm start  (or: systemctl --user start nanoclaw)');
  } finally {
    if (fs.existsSync(tarPath)) fs.unlinkSync(tarPath);
  }
}

main().catch((err) => {
  console.error(`\nError: ${err.message}`);
  process.exit(1);
});
