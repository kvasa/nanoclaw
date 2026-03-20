#!/usr/bin/env node
/**
 * Garmin Connect auth setup with MFA support — two-phase.
 * Phase 1 (no args): starts login, saves session state, tells user to check email
 * Phase 2 (--code=XXXXXX): completes MFA and saves OAuth tokens
 */
import axios from 'axios';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
import { createHmac } from 'crypto';
import OAuth from 'oauth-1.0a';
import fs from 'fs';
import path from 'path';
import os from 'os';

const OAUTH_CONSUMER_URL = 'https://thegarth.s3.amazonaws.com/oauth_consumer.json';
const SSO_EMBED = 'https://sso.garmin.com/sso/embed';
const SSO_SIGNIN = 'https://sso.garmin.com/sso/signin';
const SSO_ORIGIN = 'https://sso.garmin.com';
const GARMIN_CONNECT_API = 'https://connectapi.garmin.com';
const OAUTH_PREAUTHORIZED = `${GARMIN_CONNECT_API}/oauth-service/oauth/preauthorized`;
const OAUTH_EXCHANGE = `${GARMIN_CONNECT_API}/oauth-service/oauth/exchange/user/2.0`;
const PROFILE_URL = `${GARMIN_CONNECT_API}/userprofile-service/socialProfile`;
const SSO_CLIENT_ID = 'GarminConnect';
const SSO_LOCALE = 'en';
const SSO_WIDGET_ID = 'gauth-widget';
const USER_AGENT_MOBILE = 'com.garmin.android.apps.connectmobile';
const USER_AGENT_BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const CSRF_REGEX = /name="_csrf"\s+value="([^"]+)"/;
const TICKET_REGEX = /ticket=([^"]+)"/;
const TOKEN_DIR = path.join(os.homedir(), '.garmin-mcp');
const SESSION_FILE = '/tmp/garmin-session.json';

const EMAIL = process.env.GARMIN_EMAIL;
const PASSWORD = process.env.GARMIN_PASSWORD;

if (!EMAIL || !PASSWORD) {
  console.error('Set GARMIN_EMAIL and GARMIN_PASSWORD environment variables.');
  process.exit(1);
}

const codeArg = process.argv.find(a => a.startsWith('--code='));

async function phase1() {
  console.log('Starting Garmin login...');

  const consumerRes = await axios.get(OAUTH_CONSUMER_URL);
  const consumer = consumerRes.data;

  const jar = new CookieJar();
  const ssoClient = wrapper(axios.create({ jar, withCredentials: true }));

  const signinParams = {
    id: SSO_WIDGET_ID,
    embedWidget: true,
    locale: SSO_LOCALE,
    gauthHost: SSO_EMBED,
    clientId: SSO_CLIENT_ID,
    service: SSO_EMBED,
    source: SSO_EMBED,
    redirectAfterAccountLoginUrl: SSO_EMBED,
    redirectAfterAccountCreationUrl: SSO_EMBED,
  };

  await ssoClient.get(SSO_EMBED, {
    params: { clientId: SSO_CLIENT_ID, locale: SSO_LOCALE, service: SSO_EMBED },
    headers: { 'User-Agent': USER_AGENT_BROWSER },
  });

  const signinResponse = await ssoClient.get(SSO_SIGNIN, {
    params: signinParams,
    headers: { 'User-Agent': USER_AGENT_BROWSER },
  });

  const csrfMatch = CSRF_REGEX.exec(signinResponse.data);
  if (!csrfMatch) throw new Error('Failed to extract CSRF token from SSO page');
  const csrfToken = csrfMatch[1];

  const loginResponse = await ssoClient.post(
    SSO_SIGNIN,
    new URLSearchParams({
      username: EMAIL,
      password: PASSWORD,
      embed: 'true',
      _csrf: csrfToken,
    }).toString(),
    {
      params: signinParams,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': USER_AGENT_BROWSER,
        Origin: SSO_ORIGIN,
        Referer: SSO_SIGNIN,
        Dnt: '1',
      },
    }
  );

  const ticketMatch = TICKET_REGEX.exec(loginResponse.data);
  if (ticketMatch) {
    // No MFA needed — complete auth directly
    console.log('Login successful without MFA.');
    await completeOAuth(consumer, ticketMatch[1]);
    return;
  }

  // MFA required — extract form details and save session
  const formActionMatch = /action="([^"]+)"/.exec(loginResponse.data);
  const mfaUrl = formActionMatch
    ? new URL(formActionMatch[1].replace(/&amp;/g, '&'), SSO_ORIGIN).href
    : 'https://sso.garmin.com/sso/verifyMFA/loginEnterMfaCode';

  const mfaCsrfMatch = CSRF_REGEX.exec(loginResponse.data);
  const mfaCsrf = mfaCsrfMatch ? mfaCsrfMatch[1] : '';

  const serializedJar = jar.serializeSync();

  fs.writeFileSync(SESSION_FILE, JSON.stringify({
    consumer,
    signinParams,
    mfaUrl,
    mfaCsrf,
    cookies: serializedJar,
    loginResponseUrl: loginResponse.request?.res?.responseUrl || mfaUrl,
  }), { mode: 0o600 });

  console.log('Garmin sent a verification code to your email.');
  console.log('Session saved. Run again with --code=XXXXXX to complete.');
}

async function phase2(code) {
  if (!fs.existsSync(SESSION_FILE)) {
    throw new Error('No session found. Run without --code first.');
  }
  const session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8'));
  const { consumer, signinParams, mfaUrl, mfaCsrf, cookies, loginResponseUrl } = session;

  // Always delete the session file, even if MFA or OAuth fails.
  // It contains cookies and CSRF tokens that should not persist on disk.
  try {
    const jar = CookieJar.deserializeSync(cookies);
    const ssoClient = wrapper(axios.create({ jar, withCredentials: true }));

    const postBody = new URLSearchParams({
      'mfa-code': code,
      'fromPage': 'setupEnterMfaCode',
      'embed': 'true',
      '_csrf': mfaCsrf,
    });

    const mfaResponse = await ssoClient.post(mfaUrl, postBody.toString(), {
      params: signinParams,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': USER_AGENT_BROWSER,
        Origin: SSO_ORIGIN,
        Referer: loginResponseUrl,
        Dnt: '1',
      },
    });

    const ticketMatch = TICKET_REGEX.exec(mfaResponse.data);
    if (!ticketMatch) {
      fs.writeFileSync('/tmp/garmin-mfa-debug.html', mfaResponse.data);
      const errDiv = /id="general"[^>]*>([^<]+)</.exec(mfaResponse.data);
      console.error('MFA failed:', errDiv ? errDiv[1].trim() : 'unknown error');
      console.error('Debug saved to /tmp/garmin-mfa-debug.html');
      process.exit(1);
    }

    console.log('MFA verified.');
    await completeOAuth(consumer, ticketMatch[1]);
  } finally {
    try { fs.unlinkSync(SESSION_FILE); } catch { /* already gone */ }
  }
}

async function completeOAuth(consumer, ticket) {
  const oauth = new OAuth({
    consumer: { key: consumer.consumer_key, secret: consumer.consumer_secret },
    signature_method: 'HMAC-SHA1',
    hash_function: (base, key) => createHmac('sha1', key).update(base).digest('base64'),
  });

  const preAuthUrl = `${OAUTH_PREAUTHORIZED}?${new URLSearchParams({
    ticket,
    'login-url': SSO_EMBED,
    'accepts-mfa-tokens': 'true',
  })}`;

  const authHeader = oauth.toHeader(oauth.authorize({ url: preAuthUrl, method: 'GET' }));
  const oauth1Res = await axios.get(preAuthUrl, {
    headers: { ...authHeader, 'User-Agent': USER_AGENT_MOBILE },
  });

  const params = new URLSearchParams(oauth1Res.data);
  const oauthToken = params.get('oauth_token');
  const oauthTokenSecret = params.get('oauth_token_secret');
  if (!oauthToken) throw new Error('Failed to get OAuth1 token');

  const oauth2 = new OAuth({
    consumer: { key: consumer.consumer_key, secret: consumer.consumer_secret },
    signature_method: 'HMAC-SHA1',
    hash_function: (base, key) => createHmac('sha1', key).update(base).digest('base64'),
  });

  const token2 = { key: oauthToken, secret: oauthTokenSecret };
  const auth2Header = oauth2.toHeader(oauth2.authorize({ url: OAUTH_EXCHANGE, method: 'POST' }, token2));

  const oauth2Res = await axios.post(OAUTH_EXCHANGE, null, {
    headers: {
      ...auth2Header,
      'User-Agent': USER_AGENT_MOBILE,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });

  const now = Math.floor(Date.now() / 1000);
  const oauth2Token = {
    ...oauth2Res.data,
    expires_at: now + oauth2Res.data.expires_in,
    refresh_token_expires_at: now + oauth2Res.data.refresh_token_expires_in,
  };

  const profileRes = await axios.get(PROFILE_URL, {
    headers: { Authorization: `Bearer ${oauth2Token.access_token}`, 'User-Agent': USER_AGENT_MOBILE },
  });
  const profile = {
    displayName: profileRes.data.displayName,
    profileId: profileRes.data.profileId ?? profileRes.data.userProfileNumber,
  };

  if (!fs.existsSync(TOKEN_DIR)) fs.mkdirSync(TOKEN_DIR, { recursive: true });
  fs.writeFileSync(path.join(TOKEN_DIR, 'oauth1_token.json'), JSON.stringify({ oauth_token: oauthToken, oauth_token_secret: oauthTokenSecret }, null, 2));
  fs.writeFileSync(path.join(TOKEN_DIR, 'oauth2_token.json'), JSON.stringify(oauth2Token, null, 2));
  fs.writeFileSync(path.join(TOKEN_DIR, 'profile.json'), JSON.stringify(profile, null, 2));

  console.log(`Authenticated as: ${profile.displayName}`);
  console.log(`Tokens saved to: ${TOKEN_DIR}`);
}

if (codeArg) {
  phase2(codeArg.split('=')[1]).catch(e => { console.error(e.message); process.exit(1); });
} else {
  phase1().catch(e => { console.error(e.message); process.exit(1); });
}
