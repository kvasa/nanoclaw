const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });
const { ChartJSNodeCanvas } = require('chartjs-node-canvas');
const fs = require('fs');

// Starting CZK values directly from the "2026 YTD" sheet (1.1.2026)
const POSITIONS = [
  { id: 'VUAA',  yahoo: 'VUAA.L',  startCZK: 480583,  jan1Price: 132.190, color: '#3b82f6' },
  { id: 'VWRA',  yahoo: 'VWRA.L',  startCZK: 504243,  jan1Price: 170.530, color: '#10b981' },
  { id: 'FWRA',  yahoo: 'FWRA.L',  startCZK: 220278,  jan1Price: 8.410,   color: '#f59e0b' },
  { id: 'GLE',   yahoo: 'GLE.PA',  startCZK: 882664,  jan1Price: 68.720,  color: '#ef4444' },
  { id: 'ASML',  yahoo: 'ASML.AS', startCZK: 348220,  jan1Price: 921.400, color: '#8b5cf6' },
];

// Full portfolio starting value (includes sold positions + cash component)
const START_VALUE_CZK = 2652468;
// Sum of tracked positions
const TRACKED_START = POSITIONS.reduce((s, p) => s + p.startCZK, 0); // 2,435,988
// Residual (sold positions + starting cash): treated as flat
const RESIDUAL_START = START_VALUE_CZK - TRACKED_START; // 216,480

async function fetchHistory(yahoo, startDate, endDate) {
  try {
    const data = await yahooFinance.chart(yahoo, { period1: startDate, period2: endDate, interval: '1d' });
    return Object.fromEntries((data.quotes || []).map(q => [q.date.toISOString().slice(0,10), q.close]).filter(([,v]) => v));
  } catch (e) { console.error('Fetch error', yahoo, e.message.slice(0, 60)); return {}; }
}

async function run() {
  const startDate = new Date('2026-01-01');
  const endDate = new Date();

  const symbols = POSITIONS.map(p => p.yahoo);
  console.log('Fetching:', symbols.join(', '));

  const histories = {};
  for (const sym of symbols) histories[sym] = await fetchHistory(sym, startDate, endDate);

  // Build date list from VUAA (most complete)
  const allDates = Object.keys(histories['VUAA.L']).sort();
  const lastPrices = {};

  const portfolioValues = [];
  const labels = [];
  const perPositionPct = Object.fromEntries(POSITIONS.map(p => [p.id, []]));

  for (const date of allDates) {
    let portfolioCZK = RESIDUAL_START; // flat component

    for (const pos of POSITIONS) {
      const price = histories[pos.yahoo][date] || lastPrices[pos.yahoo];
      if (price) lastPrices[pos.yahoo] = price;
      if (!price) { perPositionPct[pos.id].push(null); continue; }

      // % change from jan1Price
      const pct = (price / pos.jan1Price - 1);
      // CZK value = startCZK × (1 + pct)
      portfolioCZK += pos.startCZK * (1 + pct);
      perPositionPct[pos.id].push(+(pct * 100).toFixed(2));
    }

    portfolioValues.push(Math.round(portfolioCZK));
    labels.push(date);
  }

  const portfolioPct = portfolioValues.map(v => +((v / START_VALUE_CZK - 1) * 100).toFixed(2));

  console.log('Dates:', labels[0], '->', labels[labels.length - 1]);
  console.log('Portfolio YTD change:', portfolioPct[0] + '% ->', portfolioPct[portfolioPct.length - 1] + '%');
  console.log('Final portfolio value:', Math.round(portfolioValues[portfolioValues.length - 1]).toLocaleString('cs'), 'Kč');
  console.log('Note: includes', Math.round(RESIDUAL_START).toLocaleString('cs'), 'Kč flat (sold positions + starting cash)');

  // Draw chart
  const canvas = new ChartJSNodeCanvas({ width: 1200, height: 650, backgroundColour: '#1a1a2e' });

  const config = {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Portfolio celkem',
          data: portfolioPct,
          borderColor: '#ffffff',
          backgroundColor: 'rgba(255,255,255,0.07)',
          borderWidth: 3, pointRadius: 0, fill: true, tension: 0.3, order: 0
        },
        ...POSITIONS.map(pos => ({
          label: pos.id,
          data: perPositionPct[pos.id],
          borderColor: pos.color,
          borderWidth: 1.5, pointRadius: 0, fill: false, tension: 0.3,
          borderDash: [5, 4], order: 1
        }))
      ]
    },
    options: {
      responsive: false,
      plugins: {
        legend: { labels: { color: '#ccc', font: { size: 13 } } },
        title: {
          display: true,
          text: 'Portfolio YTD 2026 — vývoj v %',
          color: '#fff', font: { size: 18, weight: 'bold' }, padding: { bottom: 20 }
        }
      },
      scales: {
        x: { ticks: { color: '#aaa', maxTicksLimit: 12, maxRotation: 0 }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#aaa', callback: v => v + '%' }, grid: { color: 'rgba(255,255,255,0.08)' } }
      }
    }
  };

  const buffer = await canvas.renderToBuffer(config);
  fs.writeFileSync('/workspace/group/ytd-chart-full.png', buffer);
  console.log('Chart saved.');
}

run().catch(e => console.error('ERROR:', e.stack));
