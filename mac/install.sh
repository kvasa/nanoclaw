#!/bin/bash
# Installs the jobs from mac/jobs.conf as launchd agents on macOS.
# Re-run after editing jobs.conf; jobs removed from the file get unloaded.
#
#   ./mac/install.sh              install / update
#   PLIST_DIR=/tmp/x ./mac/install.sh --generate-only   only write plists (for testing)
set -euo pipefail

MAC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$MAC_DIR")"
JOBS_FILE="$MAC_DIR/jobs.conf"
LOG_DIR="$MAC_DIR/logs"
PLIST_DIR="${PLIST_DIR:-$HOME/Library/LaunchAgents}"
LABEL_PREFIX="com.nanoclaw.mac"
GENERATE_ONLY=false
[ "${1:-}" = "--generate-only" ] && GENERATE_ONLY=true

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
  printf '%s' "$s"
}

# "*" → nothing, "1-5" → "1 2 3 4 5", "1,3,6-7" → "1 3 6 7"
expand_days() {
  local spec="$1" part from to d out=""
  [ "$spec" = "*" ] && return 0
  local IFS=','
  for part in $spec; do
    if [[ "$part" =~ ^([1-7])-([1-7])$ ]]; then
      from="${BASH_REMATCH[1]}"; to="${BASH_REMATCH[2]}"
      for ((d = from; d <= to; d++)); do out="$out $d"; done
    elif [[ "$part" =~ ^[1-7]$ ]]; then
      out="$out $part"
    else
      echo "Neplatné dny: '$spec'" >&2; return 1
    fi
  done
  echo $out
}

# --- Checks ---------------------------------------------------------------
NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ]; then
  echo "Node.js nenalezen. Nainstaluj: brew install node" >&2; exit 1
fi
NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Potřeba Node.js 18+, máš $("$NODE_BIN" --version)" >&2; exit 1
fi
NODE_DIR="$(dirname "$NODE_BIN")"

if ! $GENERATE_ONLY; then
  [ "$(uname)" = "Darwin" ] || { echo "Tohle je pro macOS (launchd)." >&2; exit 1; }

  for f in "$HOME/.config/nanoclaw/master.key" "$HOME/.config/nanoclaw/secrets.enc" \
           "$HOME/.garmin-mcp/oauth2_token.json" "$REPO_DIR/groups/investice/google-service-account.json"; do
    [ -f "$f" ] || echo "⚠️  Chybí $f — spusť ./mac/pull-secrets.sh <server>"
  done

  echo "→ Kontroluju Slack token…"
  "$NODE_BIN" "$MAC_DIR/run-and-post.mjs" --check

  for dir in groups/main groups/investice; do
    echo "→ npm install v $dir"
    (cd "$REPO_DIR/$dir" && npm install --no-fund --no-audit --loglevel=error)
  done
fi

# --- Generate plists ------------------------------------------------------
mkdir -p "$PLIST_DIR" "$LOG_DIR"
UID_DOMAIN="gui/$(id -u)"

# Unload and remove previously installed jobs so deletions from jobs.conf apply
for old in "$PLIST_DIR/$LABEL_PREFIX".*.plist; do
  [ -e "$old" ] || continue
  $GENERATE_ONLY || launchctl bootout "$UID_DOMAIN/$(basename "$old" .plist)" 2>/dev/null || true
  rm -f "$old"
done

set -f # no globbing when splitting commands into words
installed=0
while IFS='|' read -r name channel workdir cmd days time || [ -n "${name:-}" ]; do
  name="$(trim "${name:-}")"
  [ -z "$name" ] || [[ "$name" == \#* ]] && continue
  channel="$(trim "$channel")"; workdir="$(trim "$workdir")"; cmd="$(trim "$cmd")"
  days="$(trim "$days")"; time="$(trim "$time")"

  if ! [[ "$time" =~ ^([0-9]{1,2}):([0-9]{2})$ ]]; then
    echo "Neplatný čas u '$name': '$time'" >&2; exit 1
  fi
  hour=$((10#${BASH_REMATCH[1]})); minute=$((10#${BASH_REMATCH[2]}))
  weekdays="$(expand_days "$days")"
  [ -d "$REPO_DIR/$workdir" ] || echo "⚠️  '$name': složka $workdir neexistuje"

  label="$LABEL_PREFIX.$name"
  plist="$PLIST_DIR/$label.plist"

  {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "$NODE_BIN")</string>
    <string>$(xml_escape "$MAC_DIR/run-and-post.mjs")</string>
    <string>$(xml_escape "$channel")</string>
    <string>$(xml_escape "$workdir")</string>
EOF
    for word in $cmd; do
      echo "    <string>$(xml_escape "$word")</string>"
    done
    cat <<EOF
  </array>
  <key>WorkingDirectory</key>
  <string>$(xml_escape "$REPO_DIR")</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>$(xml_escape "$NODE_DIR"):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StartCalendarInterval</key>
  <array>
EOF
    if [ -z "$weekdays" ]; then
      echo "    <dict><key>Hour</key><integer>$hour</integer><key>Minute</key><integer>$minute</integer></dict>"
    else
      for wd in $weekdays; do
        echo "    <dict><key>Weekday</key><integer>$wd</integer><key>Hour</key><integer>$hour</integer><key>Minute</key><integer>$minute</integer></dict>"
      done
    fi
    cat <<EOF
  </array>
  <key>StandardOutPath</key>
  <string>$(xml_escape "$LOG_DIR/$name.log")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "$LOG_DIR/$name.log")</string>
</dict>
</plist>
EOF
  } > "$plist"

  if ! $GENERATE_ONLY; then
    plutil -lint -s "$plist"
    launchctl bootout "$UID_DOMAIN/$label" 2>/dev/null || true
    if ! launchctl bootstrap "$UID_DOMAIN" "$plist"; then
      echo >&2
      echo "✗ launchd odmítl $label ($plist)" >&2
      ls -l "$plist" >&2
      if [ -n "${SSH_CONNECTION:-}" ]; then
        echo "  Běžíš přes SSH — spusť install.sh v Terminálu přímo na Macu (gui session)." >&2
      fi
      if [ "$(stat -f %u "$plist")" != "$(id -u)" ]; then
        echo "  Plist nevlastníš ty — na externím disku zapni vlastnictví: sudo diskutil enableOwnership <disk>" >&2
      fi
      echo "  Podrobnosti: sudo launchctl bootstrap $UID_DOMAIN \"$plist\"" >&2
      exit 1
    fi
  fi
  printf '✓ %-20s %-4s %s  → %s\n' "$name" "$days" "$time" "$channel"
  installed=$((installed + 1))
done < "$JOBS_FILE"
set +f

echo
echo "Nainstalováno úloh: $installed (plisty v $PLIST_DIR, logy v $LOG_DIR)"
if ! $GENERATE_ONLY; then
  echo "Ruční spuštění:  launchctl kickstart $UID_DOMAIN/$LABEL_PREFIX.<název>"
  echo "Stav:            launchctl list | grep $LABEL_PREFIX"
fi
