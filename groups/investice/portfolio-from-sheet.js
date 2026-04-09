// Načte aktuální pozice portfolia z Google Sheets
const { getValues } = require('./gsheets.js');

// Pěkné zkrácené názvy pro známé tickery
const NAMES = {
  VUAA: 'Vanguard S&P 500',
  VWRA: 'Vanguard All-World',
  FWRA: 'Invesco All-World',
  XNAS: 'Xtrackers NASDAQ 100',
  GLE:  'Société Générale',
  ASML: 'ASML Holding',
};

const SHEET_ID = '1PeSJDo3nj0AIIFmqce3ignp0g2aZWNzqWenRcsR8vxo';

// Mapování burzy na Yahoo Finance suffix
function yahooSuffix(exchange, currency) {
  const map = {
    'LON': '.L',
    'EPA': '.PA',
    'AMS': '.AS',
    'XETRA': '.DE',
    'FRA': '.DE',
    'MI': '.MI',
    'SIX': '.SW',
  };
  if (map[exchange]) return map[exchange];
  // Fallback: USD ETF bez burzy → London
  if (currency === 'USD') return '.L';
  if (currency === 'EUR') return '.PA';
  return '';
}

async function getPortfolioFromSheet() {
  const rows = await getValues('All-time!A28:H37');
  // Row 0 = header, rows 1+ = positions
  const header = rows[0]; // ["Ticker","...","Burza","Měna","...","...","...","Počet"]
  const positions = [];

  for (const row of rows.slice(1)) {
    const ticker = (row[0] || '').trim();
    const exchange = (row[2] || '').trim();
    const currency = (row[3] || '').trim();
    const countStr = (row[7] || '').replace(',', '.').trim();
    const count = parseFloat(countStr);
    const name = ''; // načteme ze sloupce I (index 8) pokud potřeba

    // Přeskočit cash, BTC a nulové pozice
    if (!ticker || ticker === 'CASH' || ticker === 'BTC') continue;
    if (!count || count <= 0) continue;

    const suffix = yahooSuffix(exchange, currency);
    const yahooTicker = ticker + suffix;

    positions.push({ id: ticker, name: NAMES[ticker] || ticker, yahoo: yahooTicker, count, currency });
  }

  // Načíst cash
  const cashRow = rows.find(r => r[0] === 'CASH' && !r[3]);
  // Cash je v sloupci E (index 4) celkového rozsahu — načteme zvlášť
  const cashRows = await getValues('All-time!E36:E36');
  let cashCZK = 0;
  if (cashRows[0] && cashRows[0][0]) {
    cashCZK = parseFloat(cashRows[0][0].replace(/[^0-9.-]/g, '')) || 0;
  }

  return { positions, cashCZK };
}

module.exports = { getPortfolioFromSheet };
