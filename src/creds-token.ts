/**
 * Single-use credential token generated at startup.
 * Passed to containers so they can authenticate requests to the /mcp-creds endpoint.
 * Prevents rogue processes outside docker0 from enumerating MCP credentials.
 */
import crypto from 'crypto';

export const NANOCLAW_CREDS_TOKEN: string = crypto
  .randomBytes(32)
  .toString('hex');
