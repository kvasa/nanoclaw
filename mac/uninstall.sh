#!/bin/bash
# Unloads and removes all launchd jobs installed by mac/install.sh.
set -euo pipefail

LABEL_PREFIX="com.nanoclaw.mac"

for plist in "$HOME/Library/LaunchAgents/$LABEL_PREFIX".*.plist "/Library/LaunchAgents/$LABEL_PREFIX".*.plist; do
  [ -e "$plist" ] || continue
  label="$(basename "$plist" .plist)"
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  case "$plist" in
    /Library/*) sudo rm -f "$plist" ;;
    *) rm -f "$plist" ;;
  esac
  echo "✗ $label"
done
