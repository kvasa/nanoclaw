const { getValues, appendValues } = require('./gsheets');

async function run() {
  const [cnbRows, cnb26Rows] = await Promise.all([
    getValues('KurzCNB'),
    getValues('KurzCNB26')
  ]);

  const existingDates = new Set(cnbRows.map(r => r[0]).filter(Boolean));
  console.log('KurzCNB rows:', cnbRows.length, '| last date:', cnbRows[cnbRows.length - 1]?.[0]);
  console.log('KurzCNB26 rows:', cnb26Rows.length, '| last date:', cnb26Rows[cnb26Rows.length - 1]?.[0]);

  const missingRows = cnb26Rows.filter(r => {
    if (!r[0] || r[0] === 'Datum') return false;
    return !existingDates.has(r[0]);
  });

  console.log('Missing rows:', missingRows.length);

  if (missingRows.length === 0) {
    process.stdout.write('RESULT:nothing');
    return;
  }

  await appendValues('KurzCNB!A1', missingRows);
  const last = missingRows[missingRows.length - 1][0];
  const first = missingRows[0][0];
  console.log('Added', missingRows.length, 'rows, last:', last);
  process.stdout.write('RESULT:added:' + first + ':' + last);
}

run().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
