/**
 * Shared encrypted-backup format constants and header helpers, used by both
 * backup.js (write) and restore.js (read). A drift between the two here made
 * backups unrestorable in the past — this module is the single source of
 * truth for the header layout and KDF parameters.
 */

export const MAGIC = Buffer.from('NCBK');

// KDF history, dispatched on the header version byte:
//   1 = PBKDF2-SHA512, 100k iterations (backups written before 2026-07-11)
//   2 = scrypt N=2^17, r=8, p=1
// The v1 path must NOT be deleted while any v1 archive might still exist —
// removing it silently makes every old backup unrestorable, and you find
// out at the worst possible moment.
export const FORMAT_VERSION = 2;

// v1 archives only.
export const PBKDF2_ITERATIONS = 100_000;

// scrypt parameters for new backups. The archive leaves the host (Slack), so
// the KDF must make offline guessing expensive. 128*N*r bytes of memory are
// needed; maxmem must sit above that or scryptSync throws.
export const SCRYPT_PARAMS = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

// The password is the only thing between an offline attacker and every
// credential in the archive — refuse to encrypt with a weak one.
export const MIN_PASSWORD_LENGTH = 16;

// MAGIC(4) + VERSION(1) + SALT(16) + IV(16) + AUTH_TAG(16) = 53 bytes
export const HEADER_SIZE = 53;

/**
 * Build the 53-byte archive header: MAGIC(4) + VERSION(1) + SALT(16) +
 * IV(16) + AUTH_TAG(16).
 */
export function buildHeader(version, salt, iv, authTag) {
  const header = Buffer.alloc(HEADER_SIZE);
  MAGIC.copy(header, 0);
  header.writeUInt8(version, 4);
  salt.copy(header, 5);
  iv.copy(header, 21);
  authTag.copy(header, 37);
  return header;
}

/**
 * Parse and validate the 53-byte archive header from the start of `buf`.
 * Throws if `buf` is too small or the magic bytes don't match.
 */
export function parseHeader(buf) {
  if (buf.length < HEADER_SIZE) {
    throw new Error('File too small to be a valid backup.');
  }
  if (!buf.subarray(0, 4).equals(MAGIC)) {
    throw new Error('Not a valid NanoClaw backup file (bad magic bytes).');
  }
  const version = buf.readUInt8(4);
  const salt = buf.subarray(5, 21);
  const iv = buf.subarray(21, 37);
  const authTag = buf.subarray(37, 53);
  return { version, salt, iv, authTag, payloadOffset: HEADER_SIZE };
}
