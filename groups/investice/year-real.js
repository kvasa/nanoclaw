const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });
const { ChartJSNodeCanvas } = require('chartjs-node-canvas');
const fs = require('fs');

// Loty tvořící SOUČASNÉ pozice (z All-time transakčního logu), datum pořízení -> mark-to-market
// date ISO, shares, yahoo ticker, měna, nákupní cena v měně
const LOTS = [
  { d: '2023-07-24', sh: 403,          y: 'GLE.PA',  ccy: 'EUR', px: 16.161 },
  { d: '2023-10-27', sh: 150,          y: 'VUAA.L',  ccy: 'USD', px: 77.920 },
  { d: '2023-10-27', sh: 73,           y: 'VWRA.L',  ccy: 'USD', px: 102.960 },
  { d: '2024-07-25', sh: 107,          y: 'GLE.PA',  ccy: 'EUR', px: 15.720 },
  { d: '2025-04-07', sh: 15,           y: 'ASML.AS', ccy: 'EUR', px: 526.200 },
  { d: '2025-04-09', sh: 1148.831503,  y: 'FWRA.L',  ccy: 'USD', px: 5.996 },
  { d: '2026-03-27', sh: 552,          y: 'XNAS.L',  ccy: 'USD', px: 54.260 },
  { d: '2026-04-14', sh: 60,           y: 'VWRA.L',  ccy: 'USD', px: 176.200 },
  { d: '2026-07-03', sh: 106.289288,   y: 'FWRA.L',  ccy: 'USD', px: 9.354 },
  { d: '2026-07-03', sh: 23.87920897,  y: 'FWRA.L',  ccy: 'USD', px: 9.355 },
  { d: '2026-07-06', sh: 1.26761575,   y: 'FWRA.L',  ccy: 'USD', px: 9.349 },
  { d: '2026-07-06', sh: 0.73238425,   y: 'FWRA.L',  ccy: 'USD', px: 9.345 },
];
// Celkové pořizovací náklady dle sheetu (Nákupní hodnota CZK) — pro linku "investováno"
const COST_TOTAL_CZK = 273593 + 394264 + 183013 + 638737 + 200033 + 198864; // 1 888 504

async function fetchHistory(sym, p1, p2) {
  const data = await yahooFinance.chart(sym, { period1: p1, period2: p2, interval: '1d' });
  return Object.fromEntries((data.quotes || [])
    .map(q => [q.date.toISOString().slice(0, 10), q.close]).filter(([, v]) => v != null));
}
function ffill(map, dates) {
  const out = {};
  const prior = Object.keys(map).filter(k => k <= dates[0]).sort();
  let last = prior.length ? map[prior.at(-1)] : null;
  for (const d of dates) { if (map[d] != null) last = map[d]; out[d] = last; }
  return out;
}

async function run() {
  const p2 = new Date();
  const p1 = new Date(Date.now() - 400 * 864e5);
  const tickers = [...new Set(LOTS.map(l => l.y))];

  const hist = {};
  for (const t of tickers) hist[t] = await fetchHistory(t, p1, p2);
  const usdczk = await fetchHistory('USDCZK=X', p1, p2);
  const eurczk = await fetchHistory('EURCZK=X', p1, p2);

  const dates = Object.keys(hist['VUAA.L']).sort();
  const fUSD = ffill(usdczk, dates), fEUR = ffill(eurczk, dates);
  const fH = {}; for (const t of tickers) fH[t] = ffill(hist[t], dates);
  const kOf = (ccy, d) => ccy === 'USD' ? fUSD[d] : fEUR[d];

  // Náklady in-window lotů (kurz k datu nákupu) -> zbytek je pre-window báze
  const inWindow = LOTS.filter(l => l.d >= dates[0]);
  const invCostCZK = new Map(); // lot index -> CZK cost
  let inWindowCost = 0;
  for (const l of inWindow) {
    const k = kOf(l.ccy, l.d) ?? kOf(l.ccy, dates[0]);
    const c = l.sh * l.px * k;
    invCostCZK.set(l, c); inWindowCost += c;
  }
  const baseCost = COST_TOTAL_CZK - inWindowCost; // pre-window investováno

  const labels = [], value = [], invested = [];
  for (const d of dates) {
    let v = 0, inv = baseCost;
    for (const l of LOTS) {
      if (d < l.d) continue;              // lot ještě nekoupen
      const px = fH[l.y][d]; if (px == null) continue;
      v += l.sh * px * kOf(l.ccy, d);     // tržní hodnota vč. kurzu
      if (l.d >= dates[0]) inv += invCostCZK.get(l); // přičti in-window náklad po nákupu
    }
    labels.push(d); value.push(Math.round(v)); invested.push(Math.round(inv));
  }

  const v0 = value[0], vN = value.at(-1);
  console.log('Období:', labels[0], '->', labels.at(-1));
  console.log('Hodnota:', v0.toLocaleString('cs'), '->', vN.toLocaleString('cs'), 'Kč');
  console.log('Investováno:', invested[0].toLocaleString('cs'), '->', invested.at(-1).toLocaleString('cs'), 'Kč');
  console.log('Zisk teď:', (vN - invested.at(-1)).toLocaleString('cs'), 'Kč');

  const canvas = new ChartJSNodeCanvas({ width: 1200, height: 650, backgroundColour: '#1a1a2e' });
  const config = {
    type: 'line',
    data: { labels, datasets: [
      { label: 'Skutečná hodnota portfolia (Kč, vč. kurzu)', data: value,
        borderColor: '#ffffff', backgroundColor: 'rgba(255,255,255,0.08)', borderWidth: 3, pointRadius: 0, fill: true, tension: 0.25 },
      { label: 'Investováno (kumulativně)', data: invested,
        borderColor: '#f59e0b', borderWidth: 2, pointRadius: 0, fill: false, stepped: true },
    ] },
    options: {
      responsive: false,
      plugins: { legend: { labels: { color: '#ccc', font: { size: 13 } } },
        title: { display: true, text: 'Skutečný vývoj portfolia za rok — reálné loty, ceny i kurz',
          color: '#fff', font: { size: 18, weight: 'bold' }, padding: { bottom: 18 } } },
      scales: {
        x: { ticks: { color: '#aaa', maxTicksLimit: 12, maxRotation: 0 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#aaa', callback: v => (v / 1e6).toFixed(2) + 'M' }, grid: { color: 'rgba(255,255,255,0.08)' } }
      }
    }
  };
  fs.writeFileSync('/workspace/group/year-real.png', await canvas.renderToBuffer(config));
  console.log('Graf uložen.');
}
run().catch(e => console.error('ERROR:', e.message));
