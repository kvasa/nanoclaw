# NanoClaw Agent Container
# Runs Claude Agent SDK in isolated Linux VM with browser automation

FROM node:22-slim

# Install system dependencies for Chromium
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-liberation \
    fonts-noto-cjk \
    fonts-noto-color-emoji \
    libgbm1 \
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libasound2 \
    libpangocairo-1.0-0 \
    libcups2 \
    libdrm2 \
    libxshmfence1 \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set Chromium path for agent-browser
ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# Install agent-browser (pre-Rust, stable) and claude-code globally
RUN npm install -g agent-browser@0.19.0 @anthropic-ai/claude-code

# Create app directory
WORKDIR /app

# Copy package files first for better caching
COPY agent-runner/package*.json ./

# Install dependencies
# SDK 0.2.114+ ships the CLI as optional platform deps; on Linux both
# musl and glibc variants install, and the SDK resolver picks musl first.
# Our base image is Debian (glibc), so drop the musl binary to force the
# SDK to fall through to the glibc variant.
RUN npm install && \
    rm -rf node_modules/@anthropic-ai/claude-agent-sdk-linux-x64-musl

# Copy source code
COPY agent-runner/ ./

# Build TypeScript and save source hash for cache invalidation
RUN npm run build && \
    find src -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1 > .source-hash

# Create workspace directories
RUN mkdir -p /workspace/group /workspace/global /workspace/extra /workspace/ipc/messages /workspace/ipc/tasks /workspace/ipc/input

# Create entrypoint script with compilation cache.
# If the mounted source matches the pre-built version, skip tsc entirely.
# Container input (prompt, group info) is passed via stdin JSON.
# Credentials are injected by the host's credential proxy — never passed here.
# Follow-up messages arrive via IPC files in /workspace/ipc/input/
COPY <<'ENTRY' /app/entrypoint.sh
#!/bin/bash
set -e
cd /app

# Fetch MCP credentials from the host credential proxy before reading stdin.
# Credentials are NOT passed as docker -e flags (they would be visible in docker inspect).
# Values are base64-encoded in transit to safely handle any special characters.
if [ -n "$ANTHROPIC_BASE_URL" ]; then
  node -e "
const http = require('http');
const u = new URL('/mcp-creds', process.env.ANTHROPIC_BASE_URL);
const opts = {host: u.hostname, port: Number(u.port), path: u.pathname, headers: process.env.NANOCLAW_CREDS_TOKEN ? {Authorization: 'Bearer ' + process.env.NANOCLAW_CREDS_TOKEN} : {}};
http.get(opts, (res) => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => {
    try {
      const creds = JSON.parse(d);
      for (const [k, v] of Object.entries(creds)) {
        if (v) process.stdout.write(k + '\t' + Buffer.from(String(v)).toString('base64') + '\n');
      }
    } catch (e) { process.stderr.write('[mcp-creds] parse error: ' + e.message + '\n'); }
  });
}).on('error', e => process.stderr.write('[mcp-creds] fetch error: ' + e.message + '\n'));
" > /tmp/.mcp-creds || true
  if [ -s /tmp/.mcp-creds ]; then
    while IFS=$'\t' read -r cred_key cred_b64; do
      [[ "$cred_key" =~ ^[A-Z_][A-Z0-9_]*$ ]] && export "${cred_key}=$(printf '%s' "${cred_b64}" | base64 -d)"
    done < /tmp/.mcp-creds
  fi
  rm -f /tmp/.mcp-creds
fi

CURRENT_HASH=$(find src -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)
BUILD_HASH=$(cat .source-hash 2>/dev/null || echo "")
if [ "$CURRENT_HASH" = "$BUILD_HASH" ] && [ -d dist ]; then
  # Source unchanged — use pre-built dist from image
  DIST_DIR=/app/dist
else
  # Source was modified by group — recompile
  npx tsc --outDir /tmp/dist 2>&1 >&2
  ln -s /app/node_modules /tmp/dist/node_modules
  chmod -R a-w /tmp/dist
  DIST_DIR=/tmp/dist
fi
cat > /tmp/input.json
node "$DIST_DIR/index.js" < /tmp/input.json
ENTRY
RUN chmod +x /app/entrypoint.sh

# Set ownership to node user (non-root) for writable directories
RUN chown -R node:node /workspace && chmod 777 /home/node

# Switch to non-root user (required for --dangerously-skip-permissions)
USER node

# Set working directory to group workspace
WORKDIR /workspace/group

# Entry point reads JSON from stdin, outputs JSON to stdout
ENTRYPOINT ["/app/entrypoint.sh"]
