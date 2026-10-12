// OAuth with your own Google Cloud client (type "Desktop app").
//
// The login runs a one-shot server on 127.0.0.1, uses PKCE and a random state,
// and after the exchange asks Gmail which address actually signed in. If it is not
// the one requested, the token is revoked and nothing is stored.
import { google } from 'googleapis';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DIR, getTokens, updateTokens } from './store.js';

// gmail.modify covers reading, labels, archiving and drafts. Google bundles sending
// into that same scope, so the "never send" guarantee lives in the code: no tool
// calls a send endpoint, and test/safety.test.js fails if one ever appears.
// gmail.settings.basic is needed for filters.
export const SCOPES = [
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.settings.basic',
];

const OAUTH_FILE = process.env.GMAIL_TIDY_OAUTH ?? join(DIR, 'oauth-client.json');
const LOGIN_TIMEOUT_MS = 5 * 60 * 1000;

function clientCredentials() {
  try {
    const data = JSON.parse(readFileSync(OAUTH_FILE, 'utf8'));
    const c = data.installed ?? data.web;
    return { clientId: c.client_id, clientSecret: c.client_secret };
  } catch {
    throw new Error(`OAuth client not found at ${OAUTH_FILE}. See the README for how to create one.`);
  }
}

export function isTokenError(err) {
  const msg = String(err?.message ?? '').toLowerCase();
  return (
    err?.status === 401 ||
    err?.code === 401 ||
    ['invalid_grant', 'token has been expired', 'token has been revoked', 'invalid credentials'].some((s) =>
      msg.includes(s)
    )
  );
}

export function authedClient(email) {
  const stored = getTokens(email);
  if (!stored) throw new Error(`"${email}" is not connected. Use connect_account first.`);
  const { clientId, clientSecret } = clientCredentials();
  const client = new google.auth.OAuth2(clientId, clientSecret);
  client.setCredentials(stored);
  client.on('tokens', (t) => updateTokens(email, t));
  return client;
}

// Opens a URL in the default browser without going through a shell.
export function openBrowser(url) {
  if (process.platform === 'win32') execFile('rundll32', ['url.dll,FileProtocolHandler', url], () => {});
  else if (process.platform === 'darwin') execFile('open', [url], () => {});
  else execFile('xdg-open', [url], () => {});
}

// Two steps: you get the Google URL right away, and a promise that settles with
// { email, tokens } once the user finishes signing in. Used by the CLI and by the
// connect_account tool.
export async function startLogin(email) {
  const { clientId, clientSecret } = clientCredentials();
  const server = createServer();
  await new Promise((ok, fail) => server.listen(0, '127.0.0.1', ok).on('error', fail));
  const redirectUri = `http://127.0.0.1:${server.address().port}`;
  const client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);
  const { codeVerifier, codeChallenge } = await client.generateCodeVerifierAsync();
  const state = randomBytes(16).toString('hex');

  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    login_hint: email,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  const result = (async () => {
    const code = await waitForCode(server, state, LOGIN_TIMEOUT_MS);
    const { tokens } = await client.getToken({ code, codeVerifier });
    const revoke = () => client.revokeToken(tokens.access_token);
    try {
      client.setCredentials(tokens);
      const { data } = await google.gmail({ version: 'v1', auth: client }).users.getProfile({ userId: 'me' });
      return await checkGrant({ requested: email, signedIn: data.emailAddress, tokens, revoke });
    } catch (err) {
      // Whatever went wrong after Google issued the token, don't leave it alive.
      await revoke().catch(() => {});
      throw err;
    }
  })();
  result.catch(() => {}); // nobody may be awaiting it yet; don't crash the process
  return { url, result };
}

// Resolves with the auth code once Google redirects back with the right state.
// Requests with a wrong state get a 400 and are otherwise ignored, so a stray local
// request can't abort a sign-in in progress.
export function waitForCode(server, state, timeoutMs) {
  return new Promise((resolve, reject) => {
    const finish = (fn, value) => {
      clearTimeout(timer);
      server.close();
      fn(value);
    };
    const timer = setTimeout(() => finish(reject, new Error('Sign-in timed out after 5 minutes.')), timeoutMs);
    server.on('request', (req, res) => {
      const params = new URL(req.url, 'http://127.0.0.1').searchParams;
      const headers = { 'content-type': 'text/plain; charset=utf-8', connection: 'close' };
      if (params.get('state') !== state) {
        res.writeHead(params.has('state') ? 400 : 404, headers).end();
        return;
      }
      if (params.get('code')) {
        res.writeHead(200, headers).end('All set. You can close this tab.');
        finish(resolve, params.get('code'));
      } else {
        res.writeHead(400, headers).end('Sign-in failed. You can close this tab.');
        finish(reject, new Error(`Google returned an error: ${params.get('error') ?? 'unknown'}`));
      }
    });
  });
}

// The upstream project stored the token under whatever address the user typed.
// Here the signed-in address and the granted scopes must match, or nothing is kept.
export async function checkGrant({ requested, signedIn, tokens, revoke }) {
  const fail = async (message) => {
    await revoke().catch(() => {});
    throw new Error(message);
  };
  if (typeof requested !== 'string' || !requested) return fail('No account was requested.');
  if (String(signedIn).toLowerCase() !== requested.toLowerCase()) {
    return fail(`You signed in as ${signedIn}, not ${requested}. Nothing was saved.`);
  }
  const granted = new Set(String(tokens.scope ?? '').trim().split(/\s+/).filter(Boolean));
  const missing = SCOPES.filter((s) => !granted.has(s));
  const extra = [...granted].filter((s) => !SCOPES.includes(s));
  if (missing.length) {
    return fail(`Some permissions were not granted (${missing.join(', ')}). Connect again and keep every box checked.`);
  }
  if (extra.length) return fail(`Google granted unexpected scopes: ${extra.join(', ')}`);
  return { email: String(signedIn).toLowerCase(), tokens };
}
