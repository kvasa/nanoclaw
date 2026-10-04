#!/bin/bash
# Copies the secrets the scripts need from the NanoClaw server to this Mac over SSH.
#
#   ./mac/pull-secrets.sh <ssh-host> [cesta k repu na serveru, default: code/nanoclaw]
set -euo pipefail

HOST="${1:?Použití: $0 <ssh-host> [cesta k repu na serveru]}"
REMOTE_REPO="${2:-code/nanoclaw}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "→ Keystore (Slack token, iCloud kalendář…)"
mkdir -p "$HOME/.config/nanoclaw"
chmod 700 "$HOME/.config/nanoclaw"
scp -p "$HOST:.config/nanoclaw/master.key" "$HOST:.config/nanoclaw/secrets.enc" "$HOME/.config/nanoclaw/"
chmod 600 "$HOME/.config/nanoclaw/master.key" "$HOME/.config/nanoclaw/secrets.enc"

echo "→ Garmin tokeny"
mkdir -p "$HOME/.garmin-mcp"
chmod 700 "$HOME/.garmin-mcp"
scp -p "$HOST:.garmin-mcp/*.json" "$HOME/.garmin-mcp/"
chmod 600 "$HOME/.garmin-mcp/"*.json

echo "→ Google service account (investice)"
scp -p "$HOST:$REMOTE_REPO/groups/investice/google-service-account.json" "$REPO_DIR/groups/investice/"
chmod 600 "$REPO_DIR/groups/investice/google-service-account.json"

echo "✓ Hotovo"
