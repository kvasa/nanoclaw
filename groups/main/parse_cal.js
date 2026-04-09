const fs = require('fs');
const raw = fs.readFileSync('/tmp/cal_events.txt', 'utf8');

const eventBlocks = raw.match(/BEGIN:VEVENT[\s\S]*?END:VEVENT/g) || [];
const limit = parseInt(process.argv[2]) || 10;

const events = [];
for (const block of eventBlocks) {
  const get = (key) => {
    const m = block.match(new RegExp(`^${key}[^:]*:(.+)`, 'm'));
    return m ? m[1].trim() : null;
  };
  const summary = get('SUMMARY');
  const dtstart = get('DTSTART');
  const dtend = get('DTEND');
  const location = get('LOCATION');
  if (!summary || !dtstart) continue;

  const raw_dt = dtstart.includes(':') ? dtstart.split(':').pop() : dtstart;
  const dateOnly = raw_dt.match(/^\d{8}$/);
  const dateTime = raw_dt.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})/);
  let date;
  if (dateOnly) date = new Date(raw_dt.slice(0,4)+'-'+raw_dt.slice(4,6)+'-'+raw_dt.slice(6,8));
  else if (dateTime) date = new Date(raw_dt.slice(0,4)+'-'+raw_dt.slice(4,6)+'-'+raw_dt.slice(6,8)+'T'+raw_dt.slice(9,11)+':'+raw_dt.slice(11,13)+':00');
  else continue;

  const raw_end = dtend ? (dtend.includes(':') ? dtend.split(':').pop() : dtend) : null;
  events.push({ summary, date, location, isAllDay: !!dateOnly, raw_end });
}

events.sort((a,b) => a.date - b.date);
events.slice(0, limit).forEach((e, i) => {
  const opts = e.isAllDay
    ? {day:'numeric', month:'long', year:'numeric'}
    : {day:'numeric', month:'long', year:'numeric', hour:'2-digit', minute:'2-digit'};
  let dateStr = e.date.toLocaleDateString('cs-CZ', opts);
  if (e.isAllDay && e.raw_end) {
    const endRaw = e.raw_end;
    const endDate = new Date(endRaw.slice(0,4)+'-'+endRaw.slice(4,6)+'-'+endRaw.slice(6,8));
    endDate.setDate(endDate.getDate() - 1);
    if (endDate > e.date) dateStr += ' – ' + endDate.toLocaleDateString('cs-CZ', {day:'numeric', month:'long'});
  }
  const loc = e.location ? ' | 📍 ' + e.location.replace(/\\n/g, ', ').substring(0, 50) : '';
  console.log((i+1) + '. 📅 ' + e.summary + ' | ' + dateStr + loc);
});
