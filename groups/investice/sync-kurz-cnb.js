const https = require('https');
const { getValues, appendValues } = require('./gsheets');

function fetchCNB() {
  return new Promise((resolve, reject) => {
    https.get('https://www.cnb.cz/cs/financni-trhy/devizovy-trh/kurzy-devizoveho-trhu/kurzy-devizoveho-trhu/denni_kurz.txt', res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(d));
    }).on('error', reject);
  });
}

function parseCNB(text) {
  const lines = text.split('\n').filter(l => l.trim());
  const dateMatch = lines[0].match(/(\d{2}\.\d{2}\.\d{4})/);
  if (!dateMatch) throw new Error('Cannot parse date');
  const date = dateMatch[1];
  let eur = null, usd = null;
  for (let i = 2; i < lines.length; i++) {
    const cols = lines[i].split('|').map(c => c.trim().replace(',', '.'));
    if (cols[3] === 'EUR') eur = (parseFloat(cols[4]) / parseInt(cols[2])).toFixed(3);
    if (cols[3] === 'USD') usd = (parseFloat(cols[4]) / parseInt(cols[2])).toFixed(3);
  }
  return { date, eur, usd };
}

async function run() {
  const raw = await fetchCNB();
  const { date, eur, usd } = parseCNB(raw);
  console.log('CNB:', date, '| EUR:', eur, '| USD:', usd);

  const rows = await getValues('KurzCNB');
  const existing = new Set(rows.map(r => r[0]).filter(Boolean));

  if (existing.has(date)) {
    // Already synced today — send nothing
    return;
  }

  await appendValues('KurzCNB!A1', [[date, eur, usd]]);
  process.stdout.write('Portfolio - KurzCNB aktualizován: ' + date + ' — EUR ' + eur + ', USD ' + usd);
}

run().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
