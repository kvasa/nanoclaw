# Naplánované úlohy na Mac mini

Spouští skripty z `groups/` přes launchd a výstup posílá do Slacku jako bot Jarmil.
Chová se stejně jako script-mode tasky v NanoClaw. Při chybě pošle `Chyba skriptu: …`.

| Soubor | Co dělá |
|---|---|
| `jobs.conf` | seznam úloh (kanál, složka, příkaz, dny, čas) |
| `run-and-post.mjs` | spustí skript (timeout 60 s), výstup pošle do Slacku |
| `install.sh` | z `jobs.conf` vygeneruje a načte launchd agenty |
| `uninstall.sh` | všechny úlohy odebere |
| `pull-secrets.sh` | zkopíruje tajné soubory ze serveru přes SSH |

## Instalace

```bash
brew install node                          # Node 18+
git clone -b honza honza@<server>:code/nanoclaw ~/code/nanoclaw && cd ~/code/nanoclaw   # přímo ze serveru přes SSH
./mac/pull-secrets.sh honza@<server>       # keystore, Garmin tokeny, Google service account
./mac/install.sh                           # ověří Slack token, npm install, načte úlohy
sudo pmset -a sleep 0                      # ať Mac nespí (jinak úloha poběží až po probuzení)
```

Slack token se čte z keystore NanoClaw (`~/.config/nanoclaw`). Pokud keystore nemáš,
dej `SLACK_BOT_TOKEN=xoxb-…` do `~/.config/slack-bot.env` (`chmod 600`).

## Běžné operace

```bash
launchctl kickstart gui/$(id -u)/com.nanoclaw.mac.morning-prices   # spustit hned
launchctl list | grep com.nanoclaw.mac                              # stav (2. sloupec = poslední exit kód)
tail -f mac/logs/morning-prices.log                                 # log
DRY_RUN=1 node mac/run-and-post.mjs C0ALM0LPQLS groups/investice node morning-prices.js  # test bez posílání
```

Po úpravě `jobs.conf` znovu spusť `./mac/install.sh`. Novou verzi ze serveru stáhneš přes `git pull`.

Časy jsou v lokálním čase Macu, takže přechod na letní a zimní čas řeší macOS sám.
Pokud Mac v danou dobu spal, launchd úlohu spustí po probuzení.
