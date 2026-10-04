#!/bin/bash
# Unloads and removes all launchd jobs installed by mac/install.sh.
set -euo pipefail

PLIST_DIR="$HOME/Library/LaunchAgents"
LABEL_PREFIX="com.nanoclaw.mac"

for plist in "$PLIST_DIR/$LABEL_PREFIX".*.plist; do
  [ -e "$plist" ] || continue
  label="$(basename "$plist" .plist)"
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  rm -f "$plist"
  echo "✗ $label"
done
