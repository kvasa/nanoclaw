# Analýza NanoClaw — architektura, technologie a doporučená zlepšení

> Vzniklo z multi-agentní analýzy kódu (20 agentů: 8 mapovalo subsystémy, 1 prioritizoval, 10 adversariálně ověřovalo nálezy proti reálnému kódu, 1 syntéza). Datum: 2026-06-20. Verze repo: 1.2.12.
>
> Tento dokument je živá reference — při řešení nálezů aktualizuj sloupec **Stav**. Detaily k jednotlivým subsystémům viz [nanoclaw-architecture-final.md](nanoclaw-architecture-final.md), [SPEC.md](SPEC.md), [SECURITY.md](SECURITY.md).

## Shrnutí

NanoClaw je dobře navržený kompaktní osobní Claude asistent se silnou per-group izolací v Docker/Apple kontejnerech. Jeden Node.js proces přijímá zprávy z více kanálů, ukládá je do SQLite, polluje je a každou skupinu obsluhuje v izolovaném kontejneru s Claude Agent SDK. Kód je zralý a slušně otestovaný (~16 400 řádků v `src`, rozsáhlé testy). Hlavní rezervy jsou: **chybějící resource limity kontejnerů**, **neladěná SQLite** (WAL, indexy), **závodní podmínky v IPC a API serveru** a **slabá CI/test disciplína** (73 z 75 Slack testů padá, CI běží jen na PR).

## Technologický stack

| Vrstva | Technologie |
|--------|-------------|
| Runtime | Node.js 22, TypeScript 5.7, ESM |
| Agent | `@anthropic-ai/claude-agent-sdk` + MCP (stdio server pro host IPC nástroje) |
| Izolace | Docker / Apple Container, per-group filesystem mounty |
| Kanály | `@whiskeysockets/baileys` (WhatsApp), `@slack/bolt` Socket Mode (Slack), `googleapis` (Gmail), `openai` (Whisper transkripce + TTS) |
| Data | `better-sqlite3` 11, `zod` 4 (validace), `cron-parser` 5 (plánování) |
| Log/ops | `pino` + `pino-pretty`, `vitest` 4 (+ coverage), `husky` + `prettier`, AES-256-GCM šifrované zálohy přes cron |
| V kontejneru | Chromium (agent-browser skill), Python 3 + běžné knihovny, Gemini "Nano Banana" pro `generate_image` |

## Jak fungují jednotlivé subsystémy

1. **Orchestrátor a smyčka zpráv** (`src/index.ts`, `group-queue.ts`, `router.ts`, `reaction-tracker.ts`) — hlavní smyčka každé 2 s (`POLL_INTERVAL`) volá `getNewMessages`, deduplikuje, formátuje a řadí zprávy do per-group fronty s globálním limitem souběhu. `group-queue.ts` má exponenciální backoff pro retry.
2. **Kanály** (`src/channels/*`) — každý kanál normalizuje příchozí zprávy do společného tvaru a stará se o connect/auth, odesílání, vlákna a reakce. Gmail i group-queue mají capped exponenciální backoff; WhatsApp má jen pevný 5s retry.
3. **Izolace a bezpečnost** (`container-runner.ts`, `mount-security.ts`, `sender-allowlist.ts`, `credential-proxy.ts`, `keystore.ts`) — `buildContainerArgs` sestavuje `docker run` flagy, `mount-security` validuje mounty, allowlist hlídá, kdo smí agenta spustit, credentials se do kontejneru dostávají přes proxy (nejsou v image).
4. **IPC a úlohy** (`ipc.ts`, `task-scheduler.ts`, `api-server.ts`) — kontejner komunikuje s hostem přes soubory (watcher čte/zapisuje JSON zprávy), `task-scheduler` plánuje cron úlohy, `api-server` poskytuje HTTP API pro dotazy do skupin.
5. **Datová vrstva** (`db.ts`, `schemas.ts`) — SQLite přes better-sqlite3: tabulky `messages`, `groups`, `sessions`, `state`, `task_run_logs`, `gmail_processed_ids` aj.
6. **Agent runner v kontejneru** (`container/agent-runner/src/*`, `Dockerfile`) — spouští Claude Agent SDK, přes MCP stdio server zpřístupní hostí IPC nástroje, streamuje progress eventy zpět, implementuje `generate_image`.
7. **Model skupin** — každá skupina má vlastní složku `groups/{name}/` s izolovaným filesystémem, pamětí `CLAUDE.md`, historií konverzací a soubory. `groups/global/CLAUDE.md` poskytuje sdílený kontext, per-group `CLAUDE.md` ho specializuje. Skupiny pokrývají široké use-cases (automatizace nákupů, investice, parkování, kotel, školka, dovolená, pracovní integrace, sebezlepšování asistenta) typicky kombinací plánovaných úloh, browser automatizace a integrací.

## Doporučená zlepšení (ověřená proti kódu)

Seřazeno podle poměru přínos/úsilí. Verdikt = výsledek adversariálního ověření.

| # | Zlepšení | Dopad | Úsilí | Místo | Verdikt | Stav |
|---|----------|-------|-------|-------|---------|------|
| 1 | **Resource limity kontejneru** — `--memory`, `--cpus`, `--pids-limit`. Defaulty 2 GB / 2 CPU / 512 PIDs, konfigurovatelné přes `CONTAINER_MEMORY/CPUS/PIDS_LIMIT`. | high | low | `src/container-runner.ts` | confirmed | ✅ Hotovo — `resourceLimitArgs()` v `container-runtime.ts`, `--pids-limit` jen pro Docker. |
| 2 | **SQLite pragmas** — `journal_mode=WAL`, `synchronous=NORMAL`, `cache_size`. | high | low | `src/db.ts:159` | partially-valid | ✅ Hotovo (`applyPragmas`). **`foreign_keys=ON` záměrně NEzapnuto** — `storeMessage` negarantuje existenci parent `chats` řádku, zapnutí by zahazovalo zprávy; integritu `task_run_logs` řeší manuální kaskáda v `deleteTask`. |
| 3 | **Index `messages(chat_jid, timestamp DESC)`** — nejvytíženější dotaz (`getNewMessages` každé 2 s). | high | low | `src/db.ts:43` | partially-valid | ✅ Hotovo (`idx_messages_chat_jid`). Gmail index už existoval. |
| 4 | **Async mutex na callbacky `activeContainers` per-group** — souběžné `/api/query` si přepíšou output callback → únik dat mezi volajícími. | high | medium | `src/api-server.ts` | confirmed | ✅ Hotovo (`withGroupLock`, per-key serializace) + 3 testy. |
| 5 | **Atomické IPC: rename-before-read** — claim souboru přes `renameSync` na `.processing` před `readFileSync`, tolerance `ENOENT`. Odstraní TOCTOU okno. | high | medium | `src/ipc.ts` | confirmed | ✅ Hotovo pro messages i tasks smyčku. |
| 6 | **Opravit Slack testy** — `action()` do `MockApp`. | high | low | `src/channels/slack.test.ts` | confirmed | ✅ Hotovo — 75 Slack testů zelených (bylo 73 padajících). Při tom odhalena chybějící `headers` v fetch fixture (oprava fixture, ne kódu). |
| 7 | **CI i na push do `main`** + build kontejneru. | high | low | `.github/workflows/ci.yml` | partially-valid | ✅ Hotovo — `push: [main]` trigger + job `container` (build agent-runneru + `docker build --check`). |
| 8 | **Timeout na credential-proxy fetch při startu** — `req.setTimeout(5000)` + `destroy()`. | high | low | `container/Dockerfile` | confirmed | ✅ Hotovo (fail-fast místo minutového bloku). |
| 9 | **Exponenciální backoff reconnectu WhatsApp** — `5s/10s/20s … cap 5 min`, reset po úspěchu. | medium | low | `src/channels/whatsapp.ts` | confirmed | ✅ Hotovo (`reconnectAttempts`). |
| — | **Model v kontejnerech → nejnovější** (`claude-opus-4-8`). | — | low | `container/agent-runner/src/index.ts`, `.env.example` | — | ✅ Hotovo — default byl `claude-sonnet-4-6`. Fable 5 záměrně nezvolen (vyšší cena, 30denní retence, jiné API chování — jen na explicitní vyžádání). |

### Výsledek implementace (2026-06-20)

Všech 9 ověřených nálezů + výměna modelu **implementováno a otestováno**:

- **Typecheck:** root `tsc --noEmit` ✅, `container/agent-runner` `tsc` ✅
- **Testy:** `vitest run` → **601 passed / 0 failed** (45 souborů). Před tím byl celý Slack kanál (75 testů) nefunkční kvůli pádu v konstruktoru; nově zelený.
- **Nové testy:** `resourceLimitArgs` (3), `withGroupLock` serializace/izolace/uvolnění při chybě (3).
- **Formát:** `prettier --check` ✅. **Build:** `npm run build` ✅. Node snippet v Dockerfile prošel `node --check`.

Záměrná rozhodnutí proti doslovnému znění nálezů (s odůvodněním):

- **#2 — `foreign_keys=ON` nezapnuto.** `storeMessage`/`storeMessageDirect` vkládají zprávy bez záruky parent řádku v `chats`; zapnutí FK by za běhu zahazovalo zprávy. Aplikováno jen bezpečné WAL/synchronous/cache_size.
- **API_TOKEN** (původní quick-win) — **už ošetřeno**: server startuje jen `if (API_TOKEN)` (`index.ts:784`), bez tokenu se nezvedne.
- **Model** — zvolen `claude-opus-4-8` (nejnovější rozumný default dle skillu `claude-api`), ne Fable 5.

### Nálezy zamítnuté ověřením (neřešeno — správně)

- **Gmail header injection** — `already-handled`. Regex v `sanitize()` (`gmail.ts:390-393`) už stripuje CR/LF i `0x7F`, vysoké Unicode řeší `encodeHeader()` (RFC 2047).
- **Index `gmail_processed_ids(processed_at)`** — už existuje (`db.ts:95`).

## Konfigurace přidaná tímto kolem

| Proměnná | Default | Účel |
|----------|---------|------|
| `CONTAINER_MEMORY` | `2g` | strop paměti kontejneru (prázdné = vypnuto) |
| `CONTAINER_CPUS` | `2` | strop CPU |
| `CONTAINER_PIDS_LIMIT` | `512` | strop počtu procesů (jen Docker) |
| `CLAUDE_MODEL` | `claude-opus-4-8` | model agenta v kontejneru |
