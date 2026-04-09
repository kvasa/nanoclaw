// Google Sheets helper using direct JWT bearer auth (no oauth2 endpoint needed)
const jwt = require('jsonwebtoken');
const https = require('https');
const fs = require('fs');

const keyPath = fs.existsSync('/workspace/group/google-service-account.json')
  ? '/workspace/group/google-service-account.json'
  : require('path').join(__dirname, 'google-service-account.json');
const key = JSON.parse(fs.readFileSync(keyPath));

function getToken() {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign({
    iss: key.client_email,
    sub: key.client_email,
    aud: 'https://sheets.googleapis.com/',
    iat: now,
    exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/spreadsheets'
  }, key.private_key, { algorithm: 'RS256' });
}

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const token = getToken();
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: 'sheets.googleapis.com',
      path,
      method,
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {})
      }
    };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error('HTTP ' + res.statusCode + ': ' + d.slice(0, 200)));
        resolve(JSON.parse(d));
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

const SHEET_ID = '1PeSJDo3nj0AIIFmqce3ignp0g2aZWNzqWenRcsR8vxo';

async function getValues(range) {
  const res = await request('GET', `/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}`);
  return res.values || [];
}

async function updateValues(range, values) {
  return request('PUT',
    `/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`,
    { values }
  );
}

async function appendValues(range, values) {
  return request('POST',
    `/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`,
    { values }
  );
}

module.exports = { getValues, updateValues, appendValues };
