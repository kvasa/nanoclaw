/**
 * Per-container credential tokens.
 * Each container spawn gets its own token bound to the group and the MCP
 * servers that group enabled. The token travels to the container as
 * NANOCLAW_CREDS_TOKEN and is presented back to the /mcp-creds endpoint,
 * which uses the grant to return only the credentials that container is
 * entitled to. Also prevents rogue processes outside docker0 from
 * enumerating MCP credentials.
 */
import crypto from 'crypto';

/** What a single issued token is allowed to fetch. */
export interface CredsGrant {
  groupFolder: string;
  enabledMcpServers: string[];
}

const grants = new Map<string, CredsGrant>();

/**
 * Issue a credential token bound to one group and the MCP servers it enabled.
 * Called once per container spawn. Tokens stay valid until the container
 * exits (not single-use — a container that retries its startup fetch must
 * not silently end up credential-less).
 */
export function issueCredsToken(grant: CredsGrant): string {
  const token = crypto.randomBytes(32).toString('hex');
  grants.set(token, grant);
  return token;
}

/** Resolve a presented token. Returns undefined for unknown tokens. */
export function resolveCredsToken(token: string): CredsGrant | undefined {
  return grants.get(token);
}

/** Drop a token once its container is gone. */
export function revokeCredsToken(token: string): void {
  grants.delete(token);
}

/** @internal - exported for testing */
export function _resetCredsTokens(): void {
  grants.clear();
}
