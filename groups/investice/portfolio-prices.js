const YahooFinance = require('yahoo-finance2').default;
const yahooFinance = new YahooFinance({ suppressNotices: ['yahooSurvey'] });
const { google } = require('googleapis');
const fs = require('fs');

const key = JSON.parse(fs.readFileSync('/workspace/group/google-service-account.json'));
const SHEET_ID = '1PeSJDo3nj0AIIFmqce3ignp0g2aZWNzqWenRcsR8vxo';

const auth = new google.auth.GoogleAuth({
  credentials: key,
  scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly']
});

// Mapping: sheet ticker -> Yahoo Finance symbol
const TICKERS = {
  'VUAA': 'VUAA.L',
  'VWRA': 'VWRA.L',
  'FWRA': 'FWRA.L',
  'GLE':  'GLE.PA',
  'ASML': 'ASML.AS'
};

async function getPortfolioFromSheet() {
  const sheets = google.sheets({ version: 'v4', auth });
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: 'All-time'
  });
  const rows = res.data.values || [];

  // Find the summary rows (Ticker | % | Burza | Měna | Aktuální hodnota v CZK | ... | Počet | Jméno | Nákupní hodnota CZK)
  const positions = [];
  let inPositions = false;
  for (const row of rows) {
    if (row[0] === 'Ticker' && row[7] === 'Počet') { inPositions = true; continue; }
    if (inPositions && TICKERS[row[0]]) {
      positions.push({
        ticker: row[0],
        count: parseFloat(row[7]),
        currency: row[3],
        buyValueCZK: parseFloat((row[9] || '0').replace(/[^0-9.-]/g, '')),
        name: row[8]
      });
    }
    if (inPositions && row[0] === 'CASH') break;
  }
  return positions;
}

async function fetchPrices(tickers) {
  const results = {};
  for (const [local, yahoo] of Object.entries(tickers)) {
    try {
      const quote = await yahooFinance.quote(yahoo);
      results[local] = {
        price: quote.regularMarketPrice,
        dayChange: quote.regularMarketChangePercent,
        currency: quote.currency,
        prevClose: quote.regularMarketPreviousClose
      };
    } catch (e) {
      results[local] = { error: e.message };
    }
  }
  return results;
}

async function getExchangeRates() {
  // Fetch EUR/CZK and USD/CZK from Yahoo Finance
  const [eurczk, usdczk] = await Promise.all([
    yahooFinance.quote('EURCZK=X'),
    yahooFinance.quote('USDCZK=X')
  ]);
  return {
    EUR: eurczk.regularMarketPrice,
    USD: usdczk.regularMarketPrice
  };
}

async function run() {
  const [positions, prices, rates] = await Promise.all([
    getPortfolioFromSheet(),
    fetchPrices(TICKERS),
    getExchangeRates()
  ]);

  console.log('\n=== KURZY ===');
  console.log('EUR/CZK:', rates.EUR.toFixed(3));
  console.log('USD/CZK:', rates.USD.toFixed(3));

  console.log('\n=== PORTFOLIO ===');
  let totalCZK = 0;
  let totalBuyCZK = 0;

  for (const pos of positions) {
    const p = prices[pos.ticker];
    if (!p || p.error) { console.log(pos.ticker, '- chyba:', p?.error); continue; }

    const rate = rates[pos.currency] || 1;
    const valueCZK = pos.count * p.price * rate;
    totalCZK += valueCZK;
    totalBuyCZK += pos.buyValueCZK;

    const gainCZK = valueCZK - pos.buyValueCZK;
    const gainPct = (gainCZK / pos.buyValueCZK * 100).toFixed(2);

    console.log(`${pos.ticker} | ${pos.name}`);
    console.log(`  Cena: ${p.price} ${p.currency} | Denně: ${p.dayChange >= 0 ? '+' : ''}${p.dayChange.toFixed(2)}%`);
    console.log(`  Hodnota: ${Math.round(valueCZK).toLocaleString('cs')} Kč | All-time: ${gainPct >= 0 ? '+' : ''}${gainPct}%`);
  }

  console.log('\n=== CELKEM ===');
  console.log('Hodnota akcií/ETF:', Math.round(totalCZK).toLocaleString('cs'), 'Kč');

  return { positions, prices, rates };
}

module.exports = { run, getPortfolioFromSheet, fetchPrices, getExchangeRates, TICKERS };

if (require.main === module) {
  run().catch(e => console.error('ERROR:', e.message));
}
