const YahooFinance = require('yahoo-finance2').default;
const yf = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });

async function retry(fn, attempts = 3, delayMs = 2000) {
  for (let i = 0; i < attempts; i++) {
    try { return await fn(); } catch (e) {
      if (i === attempts - 1) throw e;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

function prevBusinessDay(dateStr) {
  const d = new Date(dateStr);
  do { d.setDate(d.getDate() - 1); } while (d.getDay() === 0 || d.getDay() === 6);
  return d.toISOString().split('T')[0];
}

async function fetchFrankfurterRate(from, to) {
  const r1 = await fetch(`https://api.frankfurter.app/latest?from=${from}&to=${to}`);
  if (!r1.ok) throw new Error(`Frankfurter ${r1.status}`);
  const today = await r1.json();
  const todayRate = today.rates[to];
  const prev = prevBusinessDay(today.date);
  const r2 = await fetch(`https://api.frankfurter.app/${prev}?from=${from}&to=${to}`);
  if (!r2.ok) throw new Error(`Frankfurter prev ${r2.status}`);
  const yesterday = await r2.json();
  const prevRate = yesterday.rates[to];
  return { price: todayRate, changePercent: (todayRate - prevRate) / prevRate * 100 };
}

async function getFxRate(from, to) {
  try {
    const q = await retry(() => yf.quote(`${from}${to}=X`));
    return { price: q.regularMarketPrice, changePercent: q.regularMarketChangePercent };
  } catch (e) {
    process.stderr.write(`WARN: Yahoo ${from}${to}=X failed (${e.message}), falling back to Frankfurter\n`);
    return fetchFrankfurterRate(from, to);
  }
}

module.exports = { getFxRate };
