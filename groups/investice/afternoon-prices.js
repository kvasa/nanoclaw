const YahooFinance = require('yahoo-finance2').default;
const yf = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });
const { getPortfolioFromSheet } = require('./portfolio-from-sheet.js');
const { getFxRate } = require('./fx-rates.js');

const indices = [
  { name: 'S&P 500',  yahoo: '^GSPC' },
  { name: 'NASDAQ',   yahoo: '^IXIC' },
  { name: 'DAX',      yahoo: '^GDAXI' },
  { name: 'FTSE 100', yahoo: '^FTSE' },
];

function fmt(n) {
  return Math.round(n).toLocaleString('cs-CZ');
}

function s(n) {
  return n >= 0 ? '+' : '';
}

function nowCET() {
  return new Date().toLocaleString('cs-CZ', {
    timeZone: 'Europe/Prague',
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

async function retry(fn, attempts = 3, delayMs = 2000) {
  for (let i = 0; i < attempts; i++) {
    try { return await fn(); } catch (e) {
      if (i === attempts - 1) throw e;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

async function run() {
  // Načti aktuální pozice ze sheetu
  const { positions, cashCZK } = await getPortfolioFromSheet();

  const [eurczk, usdczk] = await Promise.all([
    getFxRate('EUR', 'CZK'),
    getFxRate('USD', 'CZK'),
  ]);
  const eurRate = eurczk.price;
  const usdRate = usdczk.price;
  const eurDay = eurczk.changePercent;
  const usdDay = usdczk.changePercent;

  // Fetch all positions
  const posData = [];
  let totalCZK = cashCZK;
  let totalPrevCZK = cashCZK;
  for (const t of positions) {
    const q = await yf.quote(t.yahoo).catch(e => { throw new Error(t.yahoo + ' (' + t.name + '): ' + e.message); });
    const day = q.regularMarketChangePercent;
    const price = q.regularMarketPrice;
    const name = t.name;
    const rate = t.currency === 'EUR' ? eurRate : usdRate;
    const valCZK = t.count * price * rate;
    const prevValCZK = valCZK / (1 + day / 100);
    totalCZK += valCZK;
    totalPrevCZK += prevValCZK;
    posData.push({ t: { ...t, name }, day, price, currency: q.currency, valCZK });
  }
  const totalDayPct = (totalCZK - totalPrevCZK) / totalPrevCZK * 100;
  const totalDayCZK = totalCZK - totalPrevCZK;
  posData.sort((a, b) => Math.abs(b.day) - Math.abs(a.day));

  const posLines = posData.map(({ t, day, price, currency, valCZK }) => {
    const icon = day >= 0 ? '🟢' : '🔴';
    return icon + ' *' + t.name + '* (' + t.id + ') - ' + t.count + ' Ks\n   '
      + price.toFixed(2) + ' ' + currency + '  '
      + s(day) + day.toFixed(2) + '%  →  '
      + fmt(valCZK) + ' Kč';
  });

  // Fetch indices
  const idxLines = [];
  for (const idx of indices) {
    const q = await yf.quote(idx.yahoo).catch(e => { throw new Error(idx.yahoo + ' (' + idx.name + '): ' + e.message); });
    const day = q.regularMarketChangePercent;
    const icon = day >= 0 ? '🟢' : '🔴';
    idxLines.push(icon + ' ' + idx.name + ': ' + fmt(q.regularMarketPrice) + ' (' + s(day) + day.toFixed(2) + '%)');
  }

  const sep = '─────────────────────';

  const output = '🌙 *Portfolio – večerní přehled*\n'
    + '_' + nowCET() + '_\n'
    + sep + '\n\n'
    + '💼 *Hodnota portfolia: ' + fmt(totalCZK) + ' Kč*\n'
    + '   _' + s(totalDayPct) + totalDayPct.toFixed(2) + '% (' + s(totalDayCZK) + fmt(totalDayCZK) + ' Kč) za dnešní den_\n\n'
    + posLines.join('\n\n')
    + '\n\n' + sep + '\n\n'
    + '*💱 Kurzy CZK*\n'
    + '  EUR/CZK: *' + eurRate.toFixed(3) + '*  ' + s(eurDay) + eurDay.toFixed(2) + '%\n'
    + '  USD/CZK: *' + usdRate.toFixed(3) + '*  ' + s(usdDay) + usdDay.toFixed(2) + '%\n'
    + '\n' + sep + '\n\n'
    + '*📊 Trhy dnes*\n'
    + idxLines.join('\n');

  process.stdout.write(output);
}
run().catch(e => process.stderr.write('ERROR: ' + e.message + '\n' + (e.stack || '')));
