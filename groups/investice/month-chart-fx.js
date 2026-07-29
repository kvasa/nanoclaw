const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });
const { ChartJSNodeCanvas } = require('chartjs-node-canvas');
const fs = require('fs');

// Aktuální držené pozice (počty ověřené proti sheetu All-time)
const POSITIONS = [
  { id: 'VUAA', yahoo: 'VUAA.L',  shares: 150,  ccy: 'USD', color: '#3b82f6' },
  { id: 'VWRA', yahoo: 'VWRA.L',  shares: 133,  ccy: 'USD', color: '#10b981' },
  { id: 'FWRA', yahoo: 'FWRA.L',  shares: 1281, ccy: 'USD', color: '#f59e0b' },
  { id: 'XNAS', yahoo: 'XNAS.L',  shares: 552,  ccy: 'USD', color: '#06b6d4' },
  { id: 'GLE',  yahoo: 'GLE.PA',  shares: 510,  ccy: 'EUR', color: '#ef4444' },
  { id: 'ASML', yahoo: 'ASML.AS', shares: 15,   ccy: 'EUR', color: '#8b5cf6' },
];
const CASH_CZK = 2069;

async function fetchHistory(sym, p1, p2) {
  const data = await yahooFinance.chart(sym, { period1: p1, period2: p2, interval: '1d' });
  return Object.fromEntries((data.quotes || [])
    .map(q => [q.date.toISOString().slice(0, 10), q.close])
    .filter(([, v]) => v != null));
}

function ffill(map, dates) {
  const out = {}; let last = null;
  for (const d of dates) { if (map[d] != null) last = map[d]; out[d] = last; }
  return out;
}

async function run() {
  const p2 = new Date();
  const p1 = new Date(Date.now() - 35 * 864e5);

  const hist = {};
  for (const pos of POSITIONS) hist[pos.id] = await fetchHistory(pos.yahoo, p1, p2);
  const usdczk = await fetchHistory('USDCZK=X', p1, p2);
  const eurczk = await fetchHistory('EURCZK=X', p1, p2);

  // Sjednocená osa dat = obchodní dny VUAA
  const dates = Object.keys(hist['VUAA']).sort();
  const fUSD = ffill(usdczk, dates);
  const fEUR = ffill(eurczk, dates);
  const fPos = {}; for (const pos of POSITIONS) fPos[pos.id] = ffill(hist[pos.id], dates);

  const labels = [], valWithFX = [], valNoFX = [];
  // kurz k prvnímu dni pro variantu "bez pohybu kurzu"
  const usd0 = fUSD[dates[0]], eur0 = fEUR[dates[0]];

  for (const d of dates) {
    let vfx = CASH_CZK, vno = CASH_CZK;
    for (const pos of POSITIONS) {
      const price = fPos[pos.id][d]; if (price == null) continue;
      const kNow = pos.ccy === 'USD' ? fUSD[d] : fEUR[d];
      const kFix = pos.ccy === 'USD' ? usd0 : eur0;
      vfx += pos.shares * price * kNow;   // s pohybem kurzu
      vno += pos.shares * price * kFix;   // kurz zafixovaný na start
    }
    labels.push(d);
    valWithFX.push(Math.round(vfx));
    valNoFX.push(Math.round(vno));
  }

  const start = valWithFX[0], end = valWithFX[valWithFX.length - 1];
  const pctFX = valWithFX.map(v => +((v / start - 1) * 100).toFixed(2));
  const pctNo = valNoFX.map(v => +((v / valNoFX[0] - 1) * 100).toFixed(2));

  console.log('Období:', labels[0], '->', labels[labels.length - 1]);
  console.log('Hodnota start:', start.toLocaleString('cs'), 'Kč  -> end:', end.toLocaleString('cs'), 'Kč');
  console.log('Změna s FX:', pctFX[pctFX.length - 1] + '%   bez FX:', pctNo[pctNo.length - 1] + '%');
  console.log('Kurz USD/CZK:', usd0.toFixed(3), '->', fUSD[dates[dates.length-1]].toFixed(3));
  console.log('Kurz EUR/CZK:', eur0.toFixed(3), '->', fEUR[dates[dates.length-1]].toFixed(3));

  const canvas = new ChartJSNodeCanvas({ width: 1200, height: 650, backgroundColour: '#1a1a2e' });
  const config = {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Hodnota portfolia (Kč, vč. kurzu)', data: valWithFX, yAxisID: 'y',
          borderColor: '#ffffff', backgroundColor: 'rgba(255,255,255,0.08)', borderWidth: 3, pointRadius: 0, fill: true, tension: 0.3 },
        { label: 'Kdyby kurz stál na místě (Kč)', data: valNoFX, yAxisID: 'y',
          borderColor: '#f59e0b', borderWidth: 1.8, pointRadius: 0, fill: false, tension: 0.3, borderDash: [6, 5] },
      ]
    },
    options: {
      responsive: false,
      plugins: {
        legend: { labels: { color: '#ccc', font: { size: 13 } } },
        title: { display: true, text: 'Vývoj portfolia za poslední měsíc — vč. pohybu kurzu CZK',
          color: '#fff', font: { size: 18, weight: 'bold' }, padding: { bottom: 18 } }
      },
      scales: {
        x: { ticks: { color: '#aaa', maxTicksLimit: 12, maxRotation: 0 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#aaa', callback: v => (v/1e6).toFixed(2) + 'M' }, grid: { color: 'rgba(255,255,255,0.08)' } }
      }
    }
  };
  fs.writeFileSync('/workspace/group/month-chart-fx.png', await canvas.renderToBuffer(config));
  console.log('Graf uložen.');
}
run().catch(e => console.error('ERROR:', e.message));
