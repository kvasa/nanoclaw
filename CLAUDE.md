# NanoClaw

Personal Claude assistant. See [README.md](README.md) for philosophy and setup. See [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) for architecture decisions.

> **Architektura, technologie a prioritizovaný backlog zlepšení (ověřený proti kódu):** [docs/ANALYSIS.md](docs/ANALYSIS.md). Než začneš na něčem pracovat, projdi `docs/` (zejm. `ANALYSIS.md`, `nanoclaw-architecture-final.md`, `SECURITY.md`, `SPEC.md`); u vyřešených nálezů aktualizuj sloupec **Stav** v `ANALYSIS.md`.

## Quick Context

Single Node.js process that connects to WhatsApp, routes messages to Claude Agent SDK running in containers (Linux VMs). Each group has isolated filesystem and memory.

## Key Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Orchestrator: state, message loop, agent invocation |
| `src/channels/whatsapp.ts` | WhatsApp connection, auth, send/receive |
| `src/ipc.ts` | IPC watcher and task processing |
| `src/router.ts` | Message formatting and outbound routing |
| `src/config.ts` | Trigger pattern, paths, intervals |
| `src/container-runner.ts` | Spawns agent containers with mounts |
| `src/task-scheduler.ts` | Runs scheduled tasks |
| `src/db.ts` | SQLite operations |
| `groups/{name}/CLAUDE.md` | Per-group memory (isolated) |
| `container/skills/agent-browser.md` | Browser automation tool (available to all agents via Bash) |

## Skills

| Skill | When to Use |
|-------|-------------|
| `/setup` | First-time installation, authentication, service configuration |
| `/customize` | Adding channels, integrations, changing behavior |
| `/debug` | Container issues, logs, troubleshooting |
| `/update` | Pull upstream NanoClaw changes, merge with customizations, run migrations |
| `/qodo-pr-resolver` | Fetch and fix Qodo PR review issues interactively or in batch |
| `/get-qodo-rules` | Load org- and repo-level coding rules from Qodo before code tasks |

## Databáze

Hlavní SQLite databáze: **`store/messages.db`** (cesta `STORE_DIR` v `src/config.ts`, běží ve WAL módu).
CLI je nainstalované v `~/.local/bin/sqlite3` (na PATH) — používej ho přímo místo obcházení přes node.

```bash
sqlite3 store/messages.db ".tables"
sqlite3 store/messages.db "SELECT id, group_folder, schedule_value, status FROM scheduled_tasks;"
```

Tabulky a co obsahují:
| Tabulka | Obsah |
|---------|-------|
| `chats` | Registrované chaty/kanály (WhatsApp/Slack JIDs) |
| `messages` | Historie zpráv |
| `scheduled_tasks` | Naplánované úlohy (cron/interval/once) — sloupce: `id, group_folder, chat_jid, prompt, schedule_type, schedule_value, next_run, last_run, last_result, status, created_at, context_mode` |
| `task_run_logs` | Logy běhů naplánovaných úloh |
| `router_state` | Stav routeru |
| `sessions` | Session IDs agentů per skupina |
| `registered_groups` | Registrované skupiny — sloupce: `jid, name, folder, trigger_pattern, added_at, container_config, requires_trigger, is_main` |
| `gmail_processed_ids` | Už zpracované Gmail zprávy (dedup) |

Pozn.: `data/messages.db` a `data/nanoclaw.db` jsou prázdné zbytky, nepoužívají se.

## Development

Run commands directly—don't tell the user to run them.

```bash
npm run dev          # Run with hot reload
npm run build        # Compile TypeScript
./container/build.sh # Rebuild agent container
```

Service management:
```bash
# macOS (launchd)
launchctl load ~/Library/LaunchAgents/com.nanoclaw.plist
launchctl unload ~/Library/LaunchAgents/com.nanoclaw.plist
launchctl kickstart -k gui/$(id -u)/com.nanoclaw  # restart

# Linux (systemd)
systemctl --user start nanoclaw
systemctl --user stop nanoclaw
systemctl --user restart nanoclaw
```

## Backup

Daily encrypted backup runs via cron at midnight. Backs up SQLite DB, WhatsApp auth, group memory, sessions, .env, and skills state into AES-256-GCM encrypted archive in `backups/`.

**The archive is credential-bearing** (plaintext `.env`, WhatsApp session, every API key) — it must only ever be uploaded to a private channel. The Slack upload goes exclusively to `BACKUP_SLACK_CHANNEL` or the dedicated `backups` group; if neither exists the upload is skipped (never falls back to the main channel).

```bash
npm run backup               # Manual backup
npm run restore               # Restore from latest backup
npm run restore -- --force    # Overwrite existing data
```

Cron setup (already configured on this server):
```bash
# View current cron
crontab -l
# Set daily midnight backup
echo '0 0 * * * /home/kvasa/.nvm/versions/node/v22.22.0/bin/node /home/kvasa/code/NanoClaw/backup/backup.js >> /home/kvasa/code/NanoClaw/logs/backup.log 2>&1' | crontab -
```

Password is set via `BACKUP_PASSWORD` in `.env`.

## Container Build Cache

The container buildkit caches the build context aggressively. `--no-cache` alone does NOT invalidate COPY steps — the builder's volume retains stale files. To force a truly clean rebuild, prune the builder then re-run `./container/build.sh`.
