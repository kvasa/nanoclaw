const YahooFinance = require('yahoo-finance2').default;
const yf = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });
const { getPortfolioFromSheet } = require('./portfolio-from-sheet.js');

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

async function run() {
  // Načti aktuální pozice ze sheetu
  const { positions, cashCZK } = await getPortfolioFromSheet();

  const [eurczk, usdczk] = await Promise.all([
    yf.quote('EURCZK=X'),
    yf.quote('USDCZK=X'),
  ]);
  const eurRate = eurczk.regularMarketPrice;
  const usdRate = usdczk.regularMarketPrice;
  const eurDay = eurczk.regularMarketChangePercent;
  const usdDay = usdczk.regularMarketChangePercent;

  // Fetch all positions
  const posData = [];
  let totalCZK = cashCZK;
  let totalPrevCZK = cashCZK;
  for (const t of positions) {
    const q = await yf.quote(t.yahoo);
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
    return icon + ' *' + t.name + '* (' + t.id + ')\n   '
      + price.toFixed(2) + ' ' + currency + '  '
      + s(day) + day.toFixed(2) + '%  →  '
      + fmt(valCZK) + ' Kč';
  });

  // Fetch indices
  const idxLines = [];
  for (const idx of indices) {
    const q = await yf.quote(idx.yahoo);
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
run().catch(e => process.stderr.write('ERROR: ' + e.message));
