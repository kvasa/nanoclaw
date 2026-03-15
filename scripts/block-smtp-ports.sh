#!/bin/bash
# Block outbound SMTP ports (25, 465, 587) from Docker containers.
# Uses the DOCKER-USER chain which Docker preserves across restarts.
# Safe to run multiple times — skips rules that already exist.

set -euo pipefail

PORTS=(25 465 587)
IFACE="docker0"

# Ensure DOCKER-USER chain exists (created by Docker daemon on first start)
if ! iptables -L DOCKER-USER -n &>/dev/null; then
  echo "DOCKER-USER chain not found — start Docker first."
  exit 1
fi

for PORT in "${PORTS[@]}"; do
  # Check if rule already exists before adding
  if ! iptables -C DOCKER-USER -i "$IFACE" -p tcp --dport "$PORT" -j DROP 2>/dev/null; then
    iptables -I DOCKER-USER -i "$IFACE" -p tcp --dport "$PORT" -j DROP
    echo "Blocked port $PORT on $IFACE"
  else
    echo "Port $PORT already blocked (skipping)"
  fi
done

echo "SMTP port blocking applied."
