import fs from 'fs';
import path from 'path';
import { getSecret, isKeystoreAvailable, KEYSTORE_KEYS } from './keystore.js';

/**
 * Parse the .env file and return values for the requested keys.
 * Does NOT load anything into process.env — callers decide what to
 * do with the values. This keeps secrets out of the process environment
 * so they don't leak to child processes.
 *
 * For keys listed in KEYSTORE_KEYS, the OS keyring is checked first.
 * The .env value is used as a fallback (backwards compatibility).
 */
export function readEnvFile(keys: string[]): Record<string, string> {
  const result: Record<string, string> = {};

  // Read sensitive keys from the OS keyring first
  if (isKeystoreAvailable()) {
    for (const key of keys) {
      if (!KEYSTORE_KEYS.has(key)) continue;
      const secret = getSecret(key);
      if (secret) {
        result[key] = secret;
      }
    }
  }

  // Read remaining keys (and fallback for keystore misses) from .env
  const stillNeeded = keys.filter((k) => !(k in result));
  if (stillNeeded.length === 0) return result;

  const envFile = path.join(process.cwd(), '.env');
  let content: string;
  try {
    content = fs.readFileSync(envFile, 'utf-8');
  } catch {
    return result;
  }

  const wanted = new Set(stillNeeded);

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
    if (value) {
      result[key] = value;
      if (KEYSTORE_KEYS.has(key)) {
        process.stderr.write(
          `[nanoclaw] WARN: ${key} loaded from .env — consider migrating: node scripts/setup-keystore.mjs\n`,
        );
      }
    }
  }

  return result;
}
