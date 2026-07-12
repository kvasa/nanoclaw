/**
 * Shared .env parser for the plain-JS scripts (backup/restore/setup-keystore/
 * e2e-api). Semantics mirror src/env.ts's readEnvFile exactly (minus the
 * keystore-first lookup, which only src/env.ts needs): skip blank/`#` lines,
 * split on the first `=`, trim key and value, strip one layer of matching
 * single/double quotes, skip empty values.
 *
 * src/env.ts cannot import this file (tsconfig rootDir: "./src" excludes
 * anything outside src/) — a contract test in
 * src/env-parser-contract.test.ts pins the two implementations to the same
 * behavior instead.
 */
import fs from 'node:fs';

/**
 * Parse .env file content into a key/value map. Returns ALL keys found
 * (callers filter to what they need via readEnvValues).
 */
export function parseEnv(content) {
  const result = {};
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
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

/**
 * Read and parse an .env file from disk. A missing file returns {}.
 * If `keys` is given, the result is filtered to that set.
 */
export function readEnvValues(envPath, keys) {
  let content;
  try {
    content = fs.readFileSync(envPath, 'utf-8');
  } catch {
    return {};
  }
  const parsed = parseEnv(content);
  if (!keys) return parsed;
  const wanted = new Set(keys);
  const result = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (wanted.has(key)) result[key] = value;
  }
  return result;
}
