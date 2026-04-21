# NanoClaw Agent Container
# Runs Claude Agent SDK in isolated Linux VM with browser automation

FROM node:22-slim

# Install system dependencies for Chromium.
# --no-install-recommends drops ~220 MB of unused recommends pulled in by
# chromium and git (printer config GUI, Samba, Avahi/mDNS, cpp-12,
# GIR bindings, X server tooling). We explicitly re-add the four that we
# actually want: ca-certificates (TLS trust), openssh-client (git over ssh),
# less (git pager), patch (3-way merges).
# Python3 toolkit: python3 + pip + venv plus the most common stdlib-adjacent
# libraries (requests, bs4, lxml, yaml, dateutil). Installed via apt so they
# reuse shared libs and skip wheel download overhead; agents can still pip
# install extras inside a venv under /workspace.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    curl \
    fonts-liberation \
    fonts-noto-cjk \
    fonts-noto-color-emoji \
    git \
    less \
    libasound2 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnss3 \
    libpangocairo-1.0-0 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxshmfence1 \
    openssh-client \
    patch \
    python3 \
    python3-bs4 \
    python3-dateutil \
    python3-lxml \
    python3-pip \
    python3-requests \
    python3-venv \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

# Set Chromium path for agent-browser
ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# Install agent-browser (native Rust) globally.
# We don't install @anthropic-ai/claude-code: the SDK (0.2.114+) ships the
# CLI as a platform-specific optional dep (claude-agent-sdk-linux-x64) and
# agent-runner/src/index.ts resolves that path explicitly via
# pathToClaudeCodeExecutable — the global install would be a 226 MB duplicate.
# After install, strip the multi-arch agent-browser binaries we never run
# in this Debian x64 container (keeps only linux-x64, ~58 MB saved).
# NOTE: When bumping agent-browser, also regenerate
# container/skills/agent-browser/SKILL.md from `agent-browser skills get core`
# and bump the `source-version` field in its frontmatter (see the HTML comment
# at the top of that file for the exact commands).
RUN npm install -g agent-browser@0.26.0 && \
    find /usr/local/lib/node_modules/agent-browser/bin \
        -type f -name 'agent-browser-*' \
        ! -name 'agent-browser-linux-x64' -delete && \
    npm cache clean --force

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
