'use strict';
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios');

// ─── Keystore ───────────────────────────────────────────────────────────
function getSecret(key) {
  try {
    const masterKeyFile = path.join(os.homedir(), '.config/nanoclaw/master.key');
    const secretsFile = path.join(os.homedir(), '.config/nanoclaw/secrets.enc');
    const masterKey = fs.readFileSync(masterKeyFile);
    if (masterKey.length !== 32) return null;
    const content = fs.readFileSync(secretsFile, 'utf-8');
    const { iv, tag, data } = JSON.parse(content);
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const dec = Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf-8');
    return JSON.parse(dec)[key] ?? null;
  } catch { return null; }
}

// WMO weather code → Czech description
const WMO_DESC = {
  0: 'jasno', 1: 'převážně jasno', 2: 'částečně oblačno', 3: 'zataženo',
  45: 'mlha', 48: 'mlha s jinovatkou',
  51: 'slabé mrholení', 53: 'mrholení', 55: 'silné mrholení',
  61: 'slabý déšť', 63: 'déšť', 65: 'silný déšť',
  71: 'slabé sněžení', 73: 'sněžení', 75: 'silné sněžení',
  80: 'přeháňky', 81: 'přeháňky', 82: 'silné přeháňky',
  95: 'bouřka', 96: 'bouřka s krupobitím', 99: 'bouřka s krupobitím',
};

// ─── Weather ────────────────────────────────────────────────────────────
async function getWeather() {
  const url = 'https://api.open-meteo.com/v1/forecast?latitude=50.0755&longitude=14.4378' +
    '&current=temperature_2m,weathercode&daily=temperature_2m_max,temperature_2m_min,precipitation_sum' +
    '&timezone=Europe%2FPrague&forecast_days=1';
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      if (attempt > 0) await new Promise(r => setTimeout(r, attempt * 3000));
      const res = await axios.get(url, { timeout: 8000 });
      const temp = Math.round(res.data.current.temperature_2m);
      const code = res.data.current.weathercode;
      const maxT = Math.round(res.data.daily.temperature_2m_max[0]);
      const minT = Math.round(res.data.daily.temperature_2m_min[0]);
      const rain = parseFloat(res.data.daily.precipitation_sum[0] ?? 0);
      const desc = WMO_DESC[code] ?? `kód ${code}`;
      const rainStr = rain > 0.5 ? `, srážky ${rain.toFixed(1)} mm` : '';
      return `${temp}°C (${minT}–${maxT}°C), ${desc}${rainStr}`;
    } catch (e) {
      lastErr = e;
      const status = e.response?.status;
      if (status && status < 500) break; // 4xx — don't retry
    }
  }
  return `nedostupné (${lastErr.message})`;
}

// ─── Calendar ───────────────────────────────────────────────────────────
function parseIcalEvents(icalStr, targetDate) {
  const eventBlocks = icalStr.match(/BEGIN:VEVENT[\s\S]*?END:VEVENT/g) || [];
  const events = [];
  for (const block of eventBlocks) {
    const get = (key) => {
      const m = block.match(new RegExp(`^${key}[^:]*:(.+)`, 'm'));
      return m ? m[1].trim() : null;
    };
    const summary = get('SUMMARY');
    const dtstartRaw = get('DTSTART');
    if (!summary || !dtstartRaw) continue;

    const raw = dtstartRaw.includes(':') ? dtstartRaw.split(':').pop() : dtstartRaw;
    const isAllDay = /^\d{8}$/.test(raw);
    let date;
    if (isAllDay) {
      date = new Date(`${raw.slice(0,4)}-${raw.slice(4,6)}-${raw.slice(6,8)}T00:00:00`);
    } else {
      const isUTC = raw.endsWith('Z');
      const base = `${raw.slice(0,4)}-${raw.slice(4,6)}-${raw.slice(6,8)}T${raw.slice(9,11)}:${raw.slice(11,13)}:00`;
      date = new Date(isUTC ? base + 'Z' : base);
    }

    // Filter to target date in Prague timezone
    const pragueDateStr = date.toLocaleDateString('cs-CZ', { timeZone: 'Europe/Prague', year: 'numeric', month: '2-digit', day: '2-digit' });
    const targetDateStr = targetDate.toLocaleDateString('cs-CZ', { timeZone: 'Europe/Prague', year: 'numeric', month: '2-digit', day: '2-digit' });
    if (pragueDateStr !== targetDateStr) continue;

    const timeStr = isAllDay
      ? 'celý den'
      : date.toLocaleTimeString('cs-CZ', { timeZone: 'Europe/Prague', hour: '2-digit', minute: '2-digit' });

    events.push({ summary, date, timeStr });
  }
  events.sort((a, b) => a.date - b.date);
  return events;
}

async function getCalendarEvents(targetDate) {
  try {
    const appleId = 'honzakvasnicka@icloud.com';
    const applePass = getSecret('APPLE_APP_PASSWORD');
    if (!applePass) return ['chybí Apple App Password'];

    const calUrl = 'https://p169-caldav.icloud.com/1447482121/calendars/F9064B0F-E541-4332-BBB0-5E9D6B694004/';

    // Time range: start of today to start of tomorrow (UTC)
    const start = new Date(targetDate);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    const fmt = (d) => d.toISOString().replace(/[-:.]/g, '').slice(0, 15) + 'Z';

    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        <C:time-range start="${fmt(start)}" end="${fmt(end)}"/>
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>`;

    const res = await axios({
      method: 'REPORT',
      url: calUrl,
      auth: { username: appleId, password: applePass },
      headers: { 'Content-Type': 'application/xml', 'Depth': '1' },
      data: reportBody,
      timeout: 10000,
    });

    // Extract iCal blocks from XML response
    const calDataRegex = /<[^:>]*:?calendar-data[^>]*>([\s\S]*?)<\/[^:>]*:?calendar-data>/g;
    let fullIcal = '';
    let m;
    while ((m = calDataRegex.exec(res.data)) !== null) {
      fullIcal += m[1] + '\n';
    }

    const events = parseIcalEvents(fullIcal, targetDate);
    if (events.length === 0) return ['žádné události'];
    return events.map(e => `• ${e.timeStr}: ${e.summary}`);
  } catch (e) {
    return [`nedostupné (${e.message})`];
  }
}

// ─── Garmin ─────────────────────────────────────────────────────────────
const GARMIN_API = 'https://connectapi.garmin.com';
const OAUTH_CONSUMER_URL = 'https://thegarth.s3.amazonaws.com/oauth_consumer.json';
const OAUTH_EXCHANGE = `${GARMIN_API}/oauth-service/oauth/exchange/user/2.0`;
const UA = 'com.garmin.android.apps.connectmobile';

function pct(s) {
  return encodeURIComponent(String(s)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function oauthQueryString(method, url, consumerKey, consumerSecret, tokenKey, tokenSecret) {
  const params = {
    oauth_consumer_key: consumerKey,
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: String(Math.floor(Date.now() / 1000)),
    oauth_token: tokenKey,
    oauth_version: '1.0',
  };
  const sortedKeys = Object.keys(params).sort();
  const paramStr = sortedKeys.map(k => `${pct(k)}=${pct(params[k])}`).join('&');
  const baseStr = `${method.toUpperCase()}&${pct(url)}&${pct(paramStr)}`;
  const sigKey = `${pct(consumerSecret)}&${pct(tokenSecret)}`;
  params.oauth_signature = crypto.createHmac('sha1', sigKey).update(baseStr).digest('base64');
  return new URLSearchParams(params).toString();
}

async function refreshGarminToken(tokenDir) {
  try {
    const oauth1 = JSON.parse(fs.readFileSync(path.join(tokenDir, 'oauth1_token.json'), 'utf-8'));
    const consumerRes = await axios.get(OAUTH_CONSUMER_URL, { timeout: 8000 });
    const c = consumerRes.data;
    const qs = oauthQueryString('POST', OAUTH_EXCHANGE, c.consumer_key, c.consumer_secret, oauth1.oauth_token, oauth1.oauth_token_secret);
    const res = await axios.post(`${OAUTH_EXCHANGE}?${qs}`, null, {
      headers: { 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000,
    });
    const now = Math.floor(Date.now() / 1000);
    const oauth2 = { ...res.data, expires_at: now + res.data.expires_in, refresh_token_expires_at: now + res.data.refresh_token_expires_in };
    fs.writeFileSync(path.join(tokenDir, 'oauth2_token.json'), JSON.stringify(oauth2, null, 2));
    return oauth2;
  } catch { return null; }
}

async function getGarmin() {
  try {
    const tokenDir = path.join(os.homedir(), '.garmin-mcp');
    let oauth2 = JSON.parse(fs.readFileSync(path.join(tokenDir, 'oauth2_token.json'), 'utf-8'));
    const profile = JSON.parse(fs.readFileSync(path.join(tokenDir, 'profile.json'), 'utf-8'));

    const now = Math.floor(Date.now() / 1000);
    if (oauth2.expires_at < now + 60) {
      const refreshed = await refreshGarminToken(tokenDir);
      if (!refreshed) return 'nedostupný (token)';
      oauth2 = refreshed;
    }

    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const dateStr = yesterday.toISOString().split('T')[0];

    const headers = { Authorization: `Bearer ${oauth2.access_token}`, 'User-Agent': UA };
    const reqOpts = { headers, timeout: 8000, validateStatus: () => true };

    const [summaryRes, sleepRes, hrvRes] = await Promise.all([
      axios.get(`${GARMIN_API}/usersummary-service/usersummary/daily/${profile.displayName}?calendarDate=${dateStr}`, reqOpts),
      axios.get(`${GARMIN_API}/wellness-service/wellness/dailySleepData/${profile.displayName}?date=${dateStr}&nonSleepBufferMinutes=60`, reqOpts),
      axios.get(`${GARMIN_API}/hrv-service/hrv/${dateStr}`, reqOpts),
    ]);

    if (summaryRes.status === 429) return 'nedostupný (rate limit)';
    if (summaryRes.status !== 200) return `nedostupný (${summaryRes.status})`;

    const d = summaryRes.data;
    const steps = d.totalSteps != null ? d.totalSteps.toLocaleString('cs-CZ') : null;

    // Body Battery
    const bbHigh = d.bodyBatteryHighestValue ?? d.averageBodyBattery ?? null;
    const bbLow = d.bodyBatteryLowestValue ?? d.minBodyBattery ?? null;
    const bbStr = bbHigh != null && bbLow != null ? `${bbLow}→${bbHigh}` : (bbHigh ?? bbLow ?? null);

    // Sleep
    let sleepStr = null;
    let sleepScore = null;
    let sleepPhases = null;
    if (sleepRes.status === 200 && sleepRes.data) {
      const s = sleepRes.data;
      const totalSec = s.sleepTimeSeconds ?? s.unmeasurableSleepSeconds ?? 0;
      if (totalSec > 0) {
        sleepStr = `${Math.floor(totalSec / 3600)}h${String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0')}m`;
      }
      sleepScore = s.sleepScores?.overall?.value ?? s.sleepScores?.totalDuration?.qualifierKey ?? null;
      const deepSec = s.deepSleepSeconds ?? 0;
      const lightSec = s.lightSleepSeconds ?? 0;
      const remSec = s.remSleepSeconds ?? 0;
      if (deepSec + lightSec + remSec > 0) {
        const fmtH = (sec) => `${Math.floor(sec / 3600)}h${String(Math.floor((sec % 3600) / 60)).padStart(2, '0')}m`;
        sleepPhases = `deep ${fmtH(deepSec)}, light ${fmtH(lightSec)}, REM ${fmtH(remSec)}`;
      }
    }
    // Fallback sleep from summary
    if (!sleepStr) {
      const sleepSec = d.sleepingSeconds ?? 0;
      if (sleepSec > 0) sleepStr = `${Math.floor(sleepSec / 3600)}h${String(Math.floor((sleepSec % 3600) / 60)).padStart(2, '0')}m`;
    }

    // HRV
    let hrvVal = null;
    if (hrvRes.status === 200 && hrvRes.data) {
      const h = hrvRes.data;
      hrvVal = h.lastNightAvg ?? h.weeklyAvg ?? h.hrvValue ?? null;
    }

    const parts = [];
    if (steps) parts.push(`🚶 ${steps} kroků`);
    const sleepParts = [sleepStr, sleepScore != null ? `score ${sleepScore}` : null].filter(Boolean).join(' (') + (sleepScore != null ? ')' : '');
    if (sleepStr) parts.push(`💤 ${sleepParts}`);
    if (sleepPhases) parts.push(`   ${sleepPhases}`);
    if (bbStr != null) parts.push(`🔋 BB: ${bbStr}`);
    if (hrvVal != null) parts.push(`💓 HRV: ${hrvVal} ms`);
    return parts.length ? parts.join('\n') : 'bez dat';
  } catch (e) {
    return `nedostupný (${e.message})`;
  }
}

// ─── Main ────────────────────────────────────────────────────────────────
async function main() {
  const nowPrague = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Prague' }));
  const dateLabel = nowPrague.toLocaleDateString('cs-CZ', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  const [weather, events, garmin] = await Promise.all([
    getWeather(),
    getCalendarEvents(nowPrague),
    getGarmin(),
  ]);

  const lines = [
    `🌅 *Dobré ráno, Honzo!* — ${dateLabel}`,
    '',
    `🌤 *Počasí Praha:* ${weather}`,
    '',
    `📅 *Dnes:*`,
    ...events,
    '',
    `⌚ *Garmin (včera):*`,
    garmin,
  ];

  process.stdout.write(lines.join('\n'));
}

main().catch(e => process.stdout.write(`🌅 *Ranní briefing* — chyba: ${e.message}`));
