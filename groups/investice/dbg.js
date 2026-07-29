const YahooFinance = require('yahoo-finance2').default;
const yf = new YahooFinance({ suppressNotices: ['yahooSurvey', 'ripHistorical'] });
(async () => {
  const p1 = new Date(Date.now() - 400 * 864e5), p2 = new Date();
  for (const s of ['VUAA.L', 'XNAS.L', 'GLE.PA', 'ASML.AS', 'USDCZK=X', 'EURCZK=X']) {
    try {
      const d = await yf.chart(s, { period1: p1, period2: p2, interval: '1d' });
      const q = (d.quotes || []).filter(x => x.close != null);
      console.log(s.padEnd(10), 'n=' + q.length, 'first=', q[0] && q[0].date.toISOString().slice(0, 10), q[0] && q[0].close, ' last=', q.at(-1) && q.at(-1).close);
    } catch (e) { console.log(s, 'ERR', e.message.slice(0, 80)); }
  }
})();
