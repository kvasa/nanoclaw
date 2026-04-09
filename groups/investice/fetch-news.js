// Helper: fetch market news from RSS feeds (FT, BBC Business, Investing.com) and translate to Czech
const https = require('https');
const http = require('http');
const { URL } = require('url');

const RSS_FEEDS = [
  { url: 'https://www.ft.com/rss/home/uk', source: 'Financial Times' },
  { url: 'https://feeds.bbci.co.uk/news/business/rss.xml', source: 'BBC Business' },
  { url: 'https://www.investing.com/rss/news_25.rss', source: 'Investing.com' },
];

function fetchUrl(urlStr) {
  return new Promise((resolve) => {
    let parsed;
    try { parsed = new URL(urlStr); } catch { return resolve(''); }
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.get({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Jarmil/1.0)',
        'Accept': 'application/rss+xml, text/xml, application/xml, */*',
      },
      timeout: 8000,
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 200000) res.destroy(); });
      res.on('end', () => resolve(data));
      res.on('error', () => resolve(''));
    });
    req.on('error', () => resolve(''));
    req.on('timeout', () => { req.destroy(); resolve(''); });
  });
}

function decodeEntities(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#\d+;/g, '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .trim();
}

function parseRssItems(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1];
    const titleMatch = block.match(/<title>([\s\S]*?)<\/title>/i);
    const descMatch = block.match(/<description>([\s\S]*?)<\/description>/i);
    const title = titleMatch ? decodeEntities(titleMatch[1]) : '';
    let desc = descMatch ? decodeEntities(descMatch[1]) : '';
    desc = desc.replace(/<[^>]+>/g, '').trim();
    if (title && title.length > 5) {
      items.push({ title, desc });
    }
  }
  return items;
}

function translateText(text) {
  return new Promise((resolve) => {
    if (!text || text.trim().length === 0) return resolve('');
    const encoded = encodeURIComponent(text.slice(0, 450));
    const path = '/get?q=' + encoded + '&langpair=en|cs';
    const req = https.get({
      hostname: 'api.mymemory.translated.net',
      path,
      timeout: 7000,
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.responseData && json.responseData.translatedText) {
            resolve(json.responseData.translatedText);
          } else {
            resolve(text); // fallback to original
          }
        } catch {
          resolve(text);
        }
      });
      res.on('error', () => resolve(text));
    });
    req.on('error', () => resolve(text));
    req.on('timeout', () => { req.destroy(); resolve(text); });
  });
}

async function translateItem(title, desc) {
  const [tTitle, tDesc] = await Promise.all([
    translateText(title),
    desc ? translateText(desc) : Promise.resolve(''),
  ]);
  return { title: tTitle, desc: tDesc };
}

async function fetchMarketNews(maxItems) {
  const results = await Promise.all(
    RSS_FEEDS.map(async ({ url, source }) => {
      try {
        const xml = await fetchUrl(url);
        const items = parseRssItems(xml);
        return items.map(i => ({ ...i, source }));
      } catch {
        return [];
      }
    })
  );

  // Merge and deduplicate
  const all = results.flat();
  const seen = new Set();
  const unique = [];
  for (const item of all) {
    const key = item.title.slice(0, 40).toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(item);
    }
  }

  const selected = unique.slice(0, maxItems || 8);

  // Translate all items in parallel
  const translated = await Promise.all(
    selected.map(item => translateItem(item.title, item.desc).then(t => ({ ...t, source: item.source })))
  );

  return translated.map(({ title, desc, source }) => {
    let line = '• *' + title + '*';
    if (desc && desc.length > 5) {
      const short = desc.length > 200 ? desc.slice(0, 200) + '…' : desc;
      line += '\n   ' + short;
    }
    line += ' _(' + source + ')_';
    return line;
  });
}

module.exports = { fetchMarketNews };
