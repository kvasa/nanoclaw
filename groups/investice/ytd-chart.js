const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance({ suppressNotices: ['yahooSurvey'] });
const { ChartJSNodeCanvas } = require('chartjs-node-canvas');
const fs = require('fs');

const POSITIONS = [
  { ticker: 'VUAA.L', local: 'VUAA', count: 150, currency: 'USD', color: 'rgba(59,130,246,1)' },
  { ticker: 'VWRA.L', local: 'VWRA', count: 122, currency: 'USD', color: 'rgba(16,185,129,1)' },
  { ticker: 'FWRA.L', local: 'FWRA', count: 1150, currency: 'USD', color: 'rgba(245,158,11,1)' },
  { ticker: 'GLE.PA',  local: 'GLE',  count: 510, currency: 'EUR', color: 'rgba(239,68,68,1)' },
  { ticker: 'ASML.AS', local: 'ASML', count: 15,  currency: 'EUR', color: 'rgba(139,92,246,1)' },
];

// Start values from sheet (1.1.2026)
const START_VALUES_CZK = {
  VUAA: 480583,
  VWRA: 504243,  // 73+49 shares combined
  FWRA: 220278,
  GLE:  882664,  // 403+107
  ASML: 348220,
};

async function run() {
  const startDate = new Date('2026-01-01');
  const endDate = new Date();

  // Fetch historical data for all tickers + FX rates
  const symbols = [...POSITIONS.map(p => p.ticker), 'EURCZK=X', 'USDCZK=X'];
  const historicals = {};

  for (const sym of symbols) {
    try {
      const data = await yahooFinance.historical(sym, { period1: startDate, period2: endDate, interval: '1d' });
      historicals[sym] = data;
    } catch (e) {
      console.error('Error fetching', sym, e.message);
      historicals[sym] = [];
    }
  }

  // Build date index from VUAA (most complete)
  const eurData = Object.fromEntries(historicals['EURCZK=X'].map(d => [d.date.toISOString().slice(0,10), d.close]));
  const usdData = Object.fromEntries(historicals['USDCZK=X'].map(d => [d.date.toISOString().slice(0,10), d.close]));

  // Get all trading dates
  const allDates = [...new Set([
    ...historicals['VUAA.L'].map(d => d.date.toISOString().slice(0,10)),
    ...historicals['GLE.PA'].map(d => d.date.toISOString().slice(0,10)),
  ])].sort();

  // Build price maps per ticker
  const priceMap = {};
  for (const pos of POSITIONS) {
    priceMap[pos.local] = Object.fromEntries(
      historicals[pos.ticker].map(d => [d.date.toISOString().slice(0,10), d.close])
    );
  }

  // Calculate portfolio value per day
  const portfolioValues = [];
  const labels = [];
  let lastEur = 24.5, lastUsd = 22.0;
  let lastPrices = {};

  for (const date of allDates) {
    const eur = eurData[date] || lastEur;
    const usd = usdData[date] || lastUsd;
    lastEur = eur; lastUsd = usd;

    let totalCZK = 0;
    for (const pos of POSITIONS) {
      const price = priceMap[pos.local][date] || lastPrices[pos.local];
      if (price) lastPrices[pos.local] = price;
      if (!price) continue;
      const rate = pos.currency === 'EUR' ? eur : usd;
      totalCZK += pos.count * price * rate;
    }
    if (totalCZK > 0) {
      portfolioValues.push(Math.round(totalCZK));
      labels.push(date);
    }
  }

  // Calculate % change from start
  const startValue = portfolioValues[0];
  const pctValues = portfolioValues.map(v => +((v / startValue - 1) * 100).toFixed(2));

  // Per-position % change
  const positionSeries = {};
  for (const pos of POSITIONS) {
    const prices = Object.entries(priceMap[pos.local])
      .filter(([d]) => labels.includes(d))
      .sort(([a],[b]) => a.localeCompare(b));
    if (prices.length === 0) continue;
    const startP = prices[0][1];
    positionSeries[pos.local] = labels.map(d => {
      const p = priceMap[pos.local][d];
      return p ? +((p / startP - 1) * 100).toFixed(2) : null;
    });
  }

  // Draw chart
  const width = 1200, height = 650;
  const canvas = new ChartJSNodeCanvas({ width, height, backgroundColour: '#1a1a2e' });

  const datasets = [
    {
      label: 'Portfolio celkem',
      data: pctValues,
      borderColor: 'rgba(255,255,255,0.9)',
      backgroundColor: 'rgba(255,255,255,0.05)',
      borderWidth: 3,
      pointRadius: 0,
      fill: true,
      tension: 0.3,
      order: 0,
    },
    ...POSITIONS.map(pos => ({
      label: pos.local,
      data: positionSeries[pos.local] || [],
      borderColor: pos.color,
      borderWidth: 1.5,
      pointRadius: 0,
      fill: false,
      tension: 0.3,
      borderDash: [4, 3],
      order: 1,
    }))
  ];

  const config = {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive: false,
      plugins: {
        legend: {
          labels: { color: '#ccc', font: { size: 13 } }
        },
        title: {
          display: true,
          text: 'Portfolio YTD 2026 — vývoj v %',
          color: '#fff',
          font: { size: 18, weight: 'bold' },
          padding: { bottom: 20 }
        }
      },
      scales: {
        x: {
          ticks: {
            color: '#aaa',
            maxTicksLimit: 12,
            maxRotation: 0,
          },
          grid: { color: 'rgba(255,255,255,0.05)' }
        },
        y: {
          ticks: {
            color: '#aaa',
            callback: v => v + '%'
          },
          grid: { color: 'rgba(255,255,255,0.08)' }
        }
      }
    }
  };

  const buffer = await canvas.renderToBuffer(config);
  const outPath = '/workspace/group/ytd-chart.png';
  fs.writeFileSync(outPath, buffer);
  console.log('Saved to', outPath);
  console.log('Data points:', labels.length);
  console.log('Portfolio change:', pctValues[0], '->', pctValues[pctValues.length-1], '%');
}

run().catch(e => console.error('ERROR:', e.stack));
